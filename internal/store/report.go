package store

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ReportFilter selects persisted RSS records without performing network I/O.
type ReportFilter struct {
	Days     int
	Feed     string
	CVE      string
	Repo     string
	Page     int
	PageSize int
}

// ReportRow pairs a feed item with the CVE identifiers it references.
type ReportRow struct{ Item feed.Item }

// ReportPage contains one page and counts across the complete filtered result.
type ReportPage struct {
	Rows     []ReportRow
	Total    int
	CVECount int
}

func reportWhere(filter ReportFilter) (string, []any) {
	clauses := []string{"1=1"}
	var args []any
	if filter.Days > 0 {
		clauses = append(clauses, "(ri.published_at IS NULL OR julianday(ri.published_at) >= julianday(?))")
		args = append(args, time.Now().UTC().Add(-time.Duration(filter.Days)*24*time.Hour).Format(time.RFC3339Nano))
	}
	if filter.Feed != "" {
		clauses = append(clauses, "instr(lower(ri.feed_url || ' ' || ri.link), ?) > 0")
		args = append(args, strings.ToLower(filter.Feed))
	}
	if filter.CVE != "" {
		clauses = append(clauses, "EXISTS (SELECT 1 FROM rss_item_cves c WHERE c.item_id=ri.id AND c.cve_id=?)")
		args = append(args, strings.ToUpper(strings.TrimSpace(filter.CVE)))
	}
	if filter.Repo != "" {
		parts := strings.SplitN(filter.Repo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			clauses = append(clauses, "0=1")
		} else {
			clauses = append(clauses, "EXISTS (SELECT 1 FROM rss_item_cves c JOIN alert_records a ON UPPER(json_extract(a.alert_json, '$.CVEID'))=c.cve_id WHERE c.item_id=ri.id AND a.resolved_at IS NULL AND a.owner=? COLLATE NOCASE AND a.repo=? COLLATE NOCASE)")
			args = append(args, parts[0], parts[1])
		}
	}
	return strings.Join(clauses, " AND "), args
}

// QueryReport filters before pagination and reads CVEs with the article query.
// It never materializes the complete article or alert history in memory.
func (s *Store) QueryReport(ctx context.Context, filter ReportFilter) (ReportPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var page ReportPage
	if filter.PageSize <= 0 {
		filter.PageSize = 100
	}
	if filter.PageSize > 1000 {
		filter.PageSize = 1000
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.Page > math.MaxInt/filter.PageSize {
		return page, fmt.Errorf("レポートページ番号が大きすぎます")
	}
	where, args := reportWhere(filter)
	countSQL := "SELECT COUNT(DISTINCT ri.id), COUNT(DISTINCT c.cve_id) FROM rss_items ri LEFT JOIN rss_item_cves c ON c.item_id=ri.id WHERE " + where
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&page.Total, &page.CVECount); err != nil {
		return page, fmt.Errorf("レポート件数取得失敗: %w", err)
	}
	query := "SELECT ri.feed_url,ri.external_id,ri.title,ri.link,ri.summary,ri.published_at, " +
		"COALESCE((SELECT group_concat(c.cve_id, ' ') FROM rss_item_cves c WHERE c.item_id=ri.id), '') " +
		"FROM rss_items ri WHERE " + where + " ORDER BY COALESCE(ri.published_at,ri.first_seen_at) DESC,ri.id DESC LIMIT ? OFFSET ?"
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return page, fmt.Errorf("レポート記事取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item feed.Item
		var published *string
		var cves string
		if err := rows.Scan(&item.FeedURL, &item.ExternalID, &item.Title, &item.Link, &item.Summary, &published, &cves); err != nil {
			return page, fmt.Errorf("レポート記事読込失敗: %w", err)
		}
		if published != nil {
			item.Published, err = time.Parse(time.RFC3339Nano, *published)
			if err != nil {
				return page, fmt.Errorf("記事公開日時解析失敗: %w", err)
			}
		}
		item.CVEIDs = strings.Fields(cves)
		page.Rows = append(page.Rows, ReportRow{Item: item})
	}
	return page, rows.Err()
}

// ListReport returns a bounded page from the complete filtered article set.
func (s *Store) ListReport(ctx context.Context, filter ReportFilter) ([]ReportRow, error) {
	page, err := s.QueryReport(ctx, filter)
	return page.Rows, err
}

// ListReportAlerts reads only scoring/display fields of alerts associated with
// the visible CVEs. Large descriptions and evaluation bodies are not loaded.
func (s *Store) ListReportAlerts(ctx context.Context, cves []string) ([]*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	seen := make(map[string]bool, len(cves))
	for _, cve := range cves {
		key := strings.ToUpper(strings.TrimSpace(cve))
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	var records []*model.AlertRecord
	for start := 0; start < len(keys); start += 200 {
		end := start + 200
		if end > len(keys) {
			end = len(keys)
		}
		args := make([]any, end-start)
		for i, key := range keys[start:end] {
			args[i] = key
		}
		query := "SELECT id,owner,repo,COALESCE(json_extract(alert_json,'$.CVEID'),'')," +
			"COALESCE(json_extract(alert_json,'$.PackageName'),''),COALESCE(json_extract(alert_json,'$.CVSSScore'),0)," +
			"COALESCE(json_extract(alert_json,'$.CVSSKnown'),0),COALESCE(json_extract(alert_json,'$.CVSSVersion'),'')," +
			"COALESCE(json_extract(alert_json,'$.CVSSVector'),''),state " +
			"FROM alert_records WHERE resolved_at IS NULL AND UPPER(json_extract(alert_json,'$.CVEID')) IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ") ORDER BY owner,repo,id"
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("レポート関連アラート取得失敗: %w", err)
		}
		for rows.Next() {
			record := &model.AlertRecord{}
			a := &record.Alert
			if err := rows.Scan(&a.ID, &a.Owner, &a.Repo, &a.CVEID, &a.PackageName, &a.CVSSScore, &a.CVSSKnown, &a.CVSSVersion, &a.CVSSVector, &record.State); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("レポート関連アラート読込失敗: %w", err)
			}
			records = append(records, record)
		}
		iterErr := rows.Err()
		closeErr := rows.Close()
		if iterErr != nil {
			return nil, fmt.Errorf("レポート関連アラート走査失敗: %w", iterErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("レポート関連アラート読込終了失敗: %w", closeErr)
		}
	}
	return records, nil
}
