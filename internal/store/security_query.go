package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

const (
	securityPageMaxLimit       = 200
	securityPageMaxOffset      = 1000000
	securityDetailHistoryLimit = 200
)

// ErrFindingNotFound identifies a missing normalized finding independently of
// database failures. Callers should test it with errors.Is.
var ErrFindingNotFound = errors.New("finding not found")

// FindingQuery selects a bounded page of normalized findings. Search is a
// literal substring, and an empty filter retains all source lifecycle states.
type FindingQuery struct {
	CVEID        string
	Search       string
	Source       string
	Severity     string
	SourceStatus string
	AssetID      string
	Limit        int
	Offset       int
}

// FindingView adds read-only source provenance without changing persisted findings.
type FindingView struct {
	model.Finding
	Source          string `json:"source,omitempty"`
	SourceFindingID string `json:"source_finding_id,omitempty"`
}

// FindingPage contains filtered findings and the matching total before paging.
type FindingPage struct {
	Enrichments map[string]model.FindingEnrichment `json:"enrichments,omitempty"`
	Items       []FindingView                      `json:"items"`
	Total       int                                `json:"total"`
	Limit       int                                `json:"limit"`
	Offset      int                                `json:"offset"`
}

// AssetPage contains a bounded, deterministic page of normalized assets.
type AssetPage struct {
	Items  []model.Asset `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// FindingDetail includes the affected asset and the latest 200 source and audit
// records in chronological order. Truncation flags explicitly identify older
// retained evidence that is not included in this response.
type FindingDetail struct {
	Enrichment            *model.FindingEnrichment `json:"enrichment,omitempty"`
	Finding               FindingView              `json:"finding"`
	Asset                 model.Asset              `json:"asset"`
	Observations          []model.Observation      `json:"observations"`
	Events                []model.Event            `json:"events"`
	ObservationsTruncated bool                     `json:"observations_truncated"`
	EventsTruncated       bool                     `json:"events_truncated"`
}

// QueryFindingsPage returns retained normalized findings without changing their
// source or triage state. Count and page are read in one consistent snapshot.
func (s *Store) QueryFindingsPage(ctx context.Context, query FindingQuery) (FindingPage, error) {
	if err := validateFindingQuery(query); err != nil {
		return FindingPage{}, fmt.Errorf("validate finding query: %w", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FindingPage{}, fmt.Errorf("begin finding page: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	page, err := readFindingPage(ctx, tx, query, "")
	if err != nil {
		return FindingPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return FindingPage{}, fmt.Errorf("finish finding page: %w", err)
	}
	return page, nil
}

// QueryAssetsPage returns assets in stable ID order with bounded pagination.
func (s *Store) QueryAssetsPage(ctx context.Context, limit, offset int) (AssetPage, error) {
	if err := validateSecurityPagination(limit, offset); err != nil {
		return AssetPage{}, fmt.Errorf("validate asset query: %w", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AssetPage{}, fmt.Errorf("begin asset page: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	page := AssetPage{Limit: limit, Offset: offset}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets`).Scan(&page.Total); err != nil {
		return AssetPage{}, fmt.Errorf("count asset page: %w", err)
	}
	page.Items, err = readSecurityPageItems[model.Asset](ctx, tx, `SELECT body_json FROM assets ORDER BY id ASC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return AssetPage{}, fmt.Errorf("read asset page: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AssetPage{}, fmt.Errorf("finish asset page: %w", err)
	}
	return page, nil
}

// GetFindingDetail returns a finding and bounded evidence in one read snapshot.
// Missing IDs wrap ErrFindingNotFound; storage errors remain distinguishable.
func (s *Store) GetFindingDetail(ctx context.Context, id string) (FindingDetail, error) {
	if id == "" || !validSecurityQueryText(id, 128) {
		return FindingDetail{}, fmt.Errorf("get finding detail: %w", ErrFindingNotFound)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FindingDetail{}, fmt.Errorf("begin finding detail: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var findingBody, assetBody string
	if err := tx.QueryRowContext(ctx, `SELECT f.body_json,a.body_json FROM findings AS f JOIN assets AS a ON a.id=f.asset_id WHERE f.id=?`, id).Scan(&findingBody, &assetBody); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FindingDetail{}, fmt.Errorf("get finding detail: %w", ErrFindingNotFound)
		}
		return FindingDetail{}, fmt.Errorf("read finding detail: %w", err)
	}
	var detail FindingDetail
	var finding model.Finding
	if err := json.Unmarshal([]byte(findingBody), &finding); err != nil {
		return FindingDetail{}, fmt.Errorf("decode finding detail: %w", err)
	}
	detail.Finding, err = projectFinding(ctx, tx, finding, "")
	if err != nil {
		return FindingDetail{}, fmt.Errorf("project finding detail: %w", err)
	}
	if err := json.Unmarshal([]byte(assetBody), &detail.Asset); err != nil {
		return FindingDetail{}, fmt.Errorf("decode finding asset: %w", err)
	}
	detail.Observations, err = readSecurityPageItems[model.Observation](ctx, tx, `SELECT body_json FROM observations WHERE finding_id=? ORDER BY `+securityTimeDescending("observed_at")+`, id DESC LIMIT ?`, id, securityDetailHistoryLimit+1)
	if err != nil {
		return FindingDetail{}, fmt.Errorf("read finding observations: %w", err)
	}
	detail.Events, err = readSecurityPageItems[model.Event](ctx, tx, `SELECT body_json FROM events WHERE entity_id=? ORDER BY `+securityTimeDescending("timestamp")+`, id DESC LIMIT ?`, id, securityDetailHistoryLimit+1)
	if err != nil {
		return FindingDetail{}, fmt.Errorf("read finding events: %w", err)
	}
	if len(detail.Observations) > securityDetailHistoryLimit {
		detail.ObservationsTruncated = true
		detail.Observations = detail.Observations[:securityDetailHistoryLimit]
	}
	if len(detail.Events) > securityDetailHistoryLimit {
		detail.EventsTruncated = true
		detail.Events = detail.Events[:securityDetailHistoryLimit]
	}
	slices.Reverse(detail.Observations)
	slices.Reverse(detail.Events)
	enrichments, err := readFindingEnrichments(ctx, tx, []model.Finding{finding}, time.Now().UTC())
	if err != nil {
		return FindingDetail{}, fmt.Errorf("read detail enrichment: %w", err)
	}
	if enrichment, ok := enrichments[detail.Finding.ID]; ok {
		detail.Enrichment = &enrichment
	}
	if err := tx.Commit(); err != nil {
		return FindingDetail{}, fmt.Errorf("finish finding detail: %w", err)
	}
	return detail, nil
}

func findingQuerySQL(query FindingQuery) (string, []any) {
	var clauses []string
	var args []any
	for _, filter := range []struct {
		clause string
		value  string
	}{
		{`EXISTS (SELECT 1 FROM observations AS o WHERE o.finding_id=f.id AND o.source=?)`, query.Source},
		{`f.severity=?`, query.Severity},
		{`f.source_status=?`, query.SourceStatus},
		{`f.asset_id=?`, query.AssetID},
	} {
		if filter.value != "" {
			clauses = append(clauses, filter.clause)
			args = append(args, filter.value)
		}
	}
	if query.CVEID != "" {
		clauses = append(clauses, "f.category='vulnerability' AND json_extract(f.body_json,'$.category')='vulnerability' AND json_extract(f.body_json,'$.vulnerability_id')=?")
		args = append(args, query.CVEID)
	}
	if query.Search != "" {
		literal := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query.Search) + "%"
		var searches []string
		for _, field := range []string{
			`f.canonical_key`, `a.native_id`, `f.id`,
			`json_extract(f.body_json,'$.title')`, `json_extract(f.body_json,'$.secret_type')`, `json_extract(f.body_json,'$.secret_resolution')`, `json_extract(f.body_json,'$.rule_id')`, `json_extract(f.body_json,'$.tool_name')`, `json_extract(f.body_json,'$.file_path')`, `json_extract(f.body_json,'$.vulnerability_id')`,
			`json_extract(f.body_json,'$.package_name')`, `json_extract(f.body_json,'$.package_ecosystem')`,
			`json_extract(f.body_json,'$.installed_version')`, `json_extract(f.body_json,'$.fixed_version')`,
		} {
			searches = append(searches, field+` LIKE ? ESCAPE '\'`)
			args = append(args, literal)
		}
		searches = append(searches, `EXISTS (SELECT 1 FROM observations AS search_o WHERE search_o.finding_id=f.id AND (search_o.source_finding_id LIKE ? ESCAPE '\' OR search_o.source LIKE ? ESCAPE '\'))`)
		args = append(args, literal, literal)
		clauses = append(clauses, "("+strings.Join(searches, " OR ")+")")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// All security timestamps are written in UTC RFC3339Nano. Pad fractional
// seconds for ordering: lexical RFC3339Nano alone incorrectly places a whole
// second ending in Z ahead of later sub-second observations of that second.
// column is an internal SQL identifier, never request input.
func securityTimeDescending(column string) string {
	return `substr(` + column + `,1,19) DESC, substr(replace(substr(` + column + `,21),'Z','') || '000000000',1,9) DESC`
}

func readSecurityPageItems[T any](ctx context.Context, tx *sql.Tx, query string, args ...any) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query security page items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]T, 0)
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("scan security page item: %w", err)
		}
		var item T
		if err := json.Unmarshal([]byte(body), &item); err != nil {
			return nil, fmt.Errorf("decode security page item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate security page items: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close security page items: %w", err)
	}
	return items, nil
}

func validateFindingQuery(query FindingQuery) error {
	if query.CVEID != "" && !canonicalFindingCVE(query.CVEID) {
		return fmt.Errorf("invalid canonical CVE ID")
	}
	if err := validateSecurityPagination(query.Limit, query.Offset); err != nil {
		return err
	}
	if !validSecurityQueryText(query.Search, 256) || !validSecurityQueryText(query.AssetID, 128) {
		return fmt.Errorf("invalid finding search or asset ID")
	}
	if query.Source != "" && (len(query.Source) > 64 || query.Source[0] < 'a' || query.Source[0] > 'z' || strings.IndexFunc(query.Source, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-'
	}) >= 0) {
		return fmt.Errorf("invalid finding source")
	}
	switch query.Severity {
	case "", "critical", "high", "medium", "low", "unknown":
	default:
		return fmt.Errorf("invalid finding severity")
	}
	switch model.SourceStatus(query.SourceStatus) {
	case "", model.SourceStatusActive, model.SourceStatusResolved, model.SourceStatusSuppressed, model.SourceStatusUnknown:
	default:
		return fmt.Errorf("invalid finding source status")
	}
	return nil
}

func validateSecurityPagination(limit, offset int) error {
	if limit < 1 || limit > securityPageMaxLimit || offset < 0 || offset > securityPageMaxOffset {
		return fmt.Errorf("invalid security pagination bounds")
	}
	return nil
}

func validSecurityQueryText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func canonicalFindingCVE(id string) bool {
	ids, err := threat.NormalizeOfflineCVEs([]string{id})
	return err == nil && len(ids) == 1 && ids[0] == id
}

// projectFinding reads provenance in the caller's snapshot. A source filter
// chooses the latest matching observation, not unrelated newer provenance.
func projectFinding(ctx context.Context, tx *sql.Tx, finding model.Finding, source string) (FindingView, error) {
	view := FindingView{Finding: finding}
	query := "SELECT source,source_finding_id FROM observations WHERE finding_id=?"
	args := []any{finding.ID}
	if source != "" {
		query += " AND source=?"
		args = append(args, source)
	}
	err := tx.QueryRowContext(ctx, query+" ORDER BY "+securityTimeDescending("observed_at")+", id DESC LIMIT 1", args...).Scan(&view.Source, &view.SourceFindingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return FindingView{}, fmt.Errorf("read finding provenance: %w", err)
	}
	return view, nil
}

func readFindingPage(ctx context.Context, tx *sql.Tx, query FindingQuery, excludedID string) (FindingPage, error) {
	where, args := findingQuerySQL(query)
	if excludedID != "" {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += "f.id<>?"
		args = append(args, excludedID)
	}
	from := ` FROM findings AS f JOIN assets AS a ON a.id=f.asset_id` + where
	page := FindingPage{Items: make([]FindingView, 0), Limit: query.Limit, Offset: query.Offset}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+from, args...).Scan(&page.Total); err != nil {
		return FindingPage{}, fmt.Errorf("count finding page: %w", err)
	}
	pageArgs := append(slices.Clone(args), query.Limit, query.Offset)
	findings, err := readSecurityPageItems[model.Finding](ctx, tx, "SELECT f.body_json"+from+" ORDER BY "+securityTimeDescending("f.last_seen")+", f.id ASC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return FindingPage{}, fmt.Errorf("read finding page: %w", err)
	}
	for _, finding := range findings {
		view, err := projectFinding(ctx, tx, finding, query.Source)
		if err != nil {
			return FindingPage{}, fmt.Errorf("project finding page: %w", err)
		}
		page.Items = append(page.Items, view)
	}
	page.Enrichments, err = readFindingEnrichments(ctx, tx, findings, time.Now().UTC())
	if err != nil {
		return FindingPage{}, fmt.Errorf("read finding enrichments: %w", err)
	}
	return page, nil
}
