package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

const (
	findingsAPIDefaultLimit = 50
	findingsAPIMaxLimit     = 200
	findingsAPIMaxOffset    = 1000000
	findingsAPIMaxRawQuery  = 4096
)

// registerFindingsAPI shares the existing Handler middleware and deployment
// access boundary. It deliberately exposes no ingestion, triage or action route.
func (s *Server) registerFindingsAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/findings", s.handleFindingsAPI)
	mux.HandleFunc("GET /api/v1/findings/{id}", s.handleFindingDetailAPI)
	mux.HandleFunc("GET /api/v1/findings/{id}/related", s.handleRelatedFindingsAPI)
	mux.HandleFunc("GET /api/v1/findings/{id}/priority-preview", s.handleFindingPriorityPreview)
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		mux.HandleFunc(method+" /api/v1/findings/{id}/priority-preview", s.handleFindingPriorityPreview)
	}
	mux.HandleFunc("GET /api/v1/assets", s.handleAssetsAPI)
	mux.HandleFunc("GET /api/v1/connectors/status", s.handleConnectorStatusAPI)
	mux.HandleFunc("GET /api/v2/connectors/status", s.handleConnectorStatusAPIV2)
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		mux.HandleFunc(method+" /api/v1/connectors/status", s.handleConnectorStatusAPI)
		mux.HandleFunc(method+" /api/v2/connectors/status", s.handleConnectorStatusAPIV2)
	}
	// The legacy GET / dashboard is a subtree route. Keep unknown API paths
	// from silently rendering that HTML page with a successful status.
	mux.HandleFunc("GET /api/v1/", func(w http.ResponseWriter, r *http.Request) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
	})
	mux.HandleFunc("GET /api/v2/", func(w http.ResponseWriter, r *http.Request) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
	})
}

func (s *Server) handleFindingsAPI(w http.ResponseWriter, r *http.Request) {
	query, err := parseFindingsAPIQuery(r.URL.RawQuery)
	if err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	page, err := s.store.QueryFindingsPage(r.Context(), query)
	if err != nil {
		slog.ErrorContext(r.Context(), "Findings API read failed", "operation", "query_findings", "error", err)
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if page.Items == nil {
		page.Items = []store.FindingView{}
	}
	writeFindingsAPIJSON(w, http.StatusOK, page)
}

func (s *Server) handleFindingDetailAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validFindingAPIID(id) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := parseFindingsAPIValues(r.URL.RawQuery); err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	detail, err := s.store.GetFindingDetail(r.Context(), id)
	if errors.Is(err, store.ErrFindingNotFound) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Findings API read failed", "operation", "get_finding", "finding_id", id, "error", err)
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if detail.Observations == nil {
		detail.Observations = []model.Observation{}
	}
	if detail.Events == nil {
		detail.Events = []model.Event{}
	}
	writeFindingsAPIJSON(w, http.StatusOK, detail)
}

func (s *Server) handleRelatedFindingsAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validFindingAPIID(id) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	query, err := parseFindingsAPIQueryFor(r.URL.RawQuery, false)
	if err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	page, err := s.store.QueryRelatedFindings(r.Context(), id, query)
	if errors.Is(err, store.ErrFindingNotFound) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Findings API read failed", "operation", "query_related_findings", "finding_id", id, "error", err)
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if page.Items == nil {
		page.Items = []store.FindingView{}
	}
	writeFindingsAPIJSON(w, http.StatusOK, page)
}

func (s *Server) handleAssetsAPI(w http.ResponseWriter, r *http.Request) {
	values, err := parseFindingsAPIValues(r.URL.RawQuery, "limit", "offset")
	if err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	page, err := s.store.QueryAssetsPage(r.Context(), limit, offset)
	if err != nil {
		slog.ErrorContext(r.Context(), "Findings API read failed", "operation", "query_assets", "error", err)
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if page.Items == nil {
		page.Items = []model.Asset{}
	}
	writeFindingsAPIJSON(w, http.StatusOK, page)
}

func parseFindingsAPIQuery(raw string) (store.FindingQuery, error) {
	return parseFindingsAPIQueryFor(raw, true)
}

func parseFindingsAPIQueryFor(raw string, allowCVE bool) (store.FindingQuery, error) {
	allowed := []string{"q", "source", "severity", "source_status", "asset_id", "limit", "offset"}
	if allowCVE {
		allowed = append(allowed, "cve")
	}
	values, err := parseFindingsAPIValues(raw, allowed...)
	if err != nil {
		return store.FindingQuery{}, err
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil {
		return store.FindingQuery{}, err
	}
	query := store.FindingQuery{
		Search: values.Get("q"), Source: values.Get("source"), Severity: values.Get("severity"),
		SourceStatus: values.Get("source_status"), AssetID: values.Get("asset_id"), Limit: limit, Offset: offset,
	}
	if values.Has("cve") {
		// Only explicit CVE identifiers are canonicalized. Never infer a CVE
		// from a GHSA, source rule, title, package or arbitrary substring.
		if !validFindingsAPIText(values.Get("cve"), 28) {
			return store.FindingQuery{}, fmt.Errorf("invalid findings CVE")
		}
		cves, err := threat.NormalizeOfflineCVEs([]string{values.Get("cve")})
		if err != nil {
			return store.FindingQuery{}, fmt.Errorf("invalid findings CVE")
		}
		query.CVEID = cves[0]
	}
	if !validFindingsAPIText(query.Search, 256) {
		return store.FindingQuery{}, fmt.Errorf("invalid findings search")
	}
	if values.Has("source") && !validFindingsAPISource(query.Source) {
		return store.FindingQuery{}, fmt.Errorf("invalid findings source")
	}
	if values.Has("severity") {
		switch query.Severity {
		case "critical", "high", "medium", "low", "unknown":
		default:
			return store.FindingQuery{}, fmt.Errorf("invalid findings severity")
		}
	}
	if values.Has("source_status") {
		switch model.SourceStatus(query.SourceStatus) {
		case model.SourceStatusActive, model.SourceStatusResolved, model.SourceStatusSuppressed, model.SourceStatusUnknown:
		default:
			return store.FindingQuery{}, fmt.Errorf("invalid findings source status")
		}
	}
	if values.Has("asset_id") && (query.AssetID == "" || !validFindingsAPIText(query.AssetID, 128)) {
		return store.FindingQuery{}, fmt.Errorf("invalid findings asset ID")
	}
	return query, nil
}

func parseFindingsAPIValues(raw string, allowed ...string) (url.Values, error) {
	if len(raw) > findingsAPIMaxRawQuery {
		return nil, fmt.Errorf("findings query is too long")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("parse findings query: %w", err)
	}
	for key, items := range values {
		known := false
		for _, name := range allowed {
			if name == key {
				known = true
				break
			}
		}
		if !known || len(items) != 1 {
			return nil, fmt.Errorf("unknown or duplicate findings parameter")
		}
	}
	return values, nil
}

func findingsAPIPagination(values url.Values) (int, int, error) {
	limit, offset := findingsAPIDefaultLimit, 0
	for _, field := range []struct {
		name string
		min  int
		max  int
		dest *int
	}{
		{"limit", 1, findingsAPIMaxLimit, &limit},
		{"offset", 0, findingsAPIMaxOffset, &offset},
	} {
		if !values.Has(field.name) {
			continue
		}
		raw := values.Get(field.name)
		if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, 0, fmt.Errorf("invalid findings pagination")
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < field.min || value > field.max {
			return 0, 0, fmt.Errorf("findings pagination is out of range")
		}
		*field.dest = value
	}
	return limit, offset, nil
}

func validFindingsAPIText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validFindingsAPISource(source string) bool {
	if len(source) == 0 || len(source) > 64 || source[0] < 'a' || source[0] > 'z' {
		return false
	}
	return strings.IndexFunc(source, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-'
	}) < 0
}

func validFindingAPIID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := range len(id) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return false
			}
			continue
		}
		if (id[i] < '0' || id[i] > '9') && (id[i] < 'a' || id[i] > 'f') && (id[i] < 'A' || id[i] > 'F') {
			return false
		}
	}
	return true
}

func findingsAPIError(w http.ResponseWriter, status int, code string) {
	writeFindingsAPIJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: code})
}

func writeFindingsAPIJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		slog.Error("Findings API response failed", "operation", "encode_response", "error", err)
		status = http.StatusInternalServerError
		body = []byte(`{"error":"internal_error"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(append(body, '\n')); err != nil {
		slog.Error("Findings API response failed", "operation", "write_response", "error", err)
	}
}
