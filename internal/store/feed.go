package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/feed"
)

// FeedStatus はフィード取得状況。
type FeedStatus struct {
	FeedURL       string
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastError     string
	ItemCount     int
	ETag          string
	LastModified  string
	NextAttemptAt *time.Time
}

// FeedBatch is the atomic unit committed after a successful parse.
type FeedBatch struct {
	FeedURL      string
	Items        []feed.Item
	FetchedAt    time.Time
	Retention    time.Duration
	ETag         string
	LastModified string
}

// CommitFeed atomically stores items and success status. Existing rows are
// retained when the caller records a failure instead.
func (s *Store) CommitFeed(ctx context.Context, batch FeedBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if batch.FetchedAt.IsZero() {
		batch.FetchedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("フィード保存transaction開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveFeedItemsTx(ctx, tx, batch.FeedURL, batch.Items, batch.FetchedAt, batch.Retention); err != nil {
		return err
	}
	now := batch.FetchedAt
	if err := saveFeedStatus(ctx, tx, FeedStatus{FeedURL: batch.FeedURL, LastAttemptAt: &now, LastSuccessAt: &now, ItemCount: len(batch.Items), ETag: batch.ETag, LastModified: batch.LastModified}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("フィード保存commit失敗: %w", err)
	}
	return nil
}

// SaveFeedItems は記事とCVE索引をupsertする。
func (s *Store) SaveFeedItems(ctx context.Context, feedURL string, items []feed.Item, fetchedAt time.Time) error {
	return s.SaveFeedItemsWithRetention(ctx, feedURL, items, fetchedAt, 90*24*time.Hour)
}

// SaveFeedItemsWithRetention upserts a successful feed response.
func (s *Store) SaveFeedItemsWithRetention(ctx context.Context, feedURL string, items []feed.Item, fetchedAt time.Time, retention time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("フィード保存transaction開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveFeedItemsTx(ctx, tx, feedURL, items, fetchedAt, retention); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("フィード保存commit失敗: %w", err)
	}
	return nil
}

func saveFeedItemsTx(ctx context.Context, tx *sql.Tx, feedURL string, items []feed.Item, fetchedAt time.Time, retention time.Duration) error {
	for _, item := range items {
		published := interface{}(nil)
		if !item.Published.IsZero() {
			published = item.Published.UTC().Format(time.RFC3339Nano)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO rss_items(feed_url, external_id, title, link, summary, published_at, first_seen_at, last_seen_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(feed_url, external_id) DO UPDATE SET title=excluded.title, link=excluded.link, summary=excluded.summary, published_at=excluded.published_at, last_seen_at=excluded.last_seen_at`, feedURL, item.ExternalID, item.Title, item.Link, item.Summary, published, fetchedAt.UTC().Format(time.RFC3339Nano), fetchedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("RSS記事保存失敗: %w", err)
		}
		var itemID int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM rss_items WHERE feed_url=? AND external_id=?`, feedURL, item.ExternalID).Scan(&itemID); err != nil {
			return fmt.Errorf("RSS記事ID取得失敗: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM rss_item_cves WHERE item_id=?`, itemID); err != nil {
			return fmt.Errorf("RSS CVE索引削除失敗: %w", err)
		}
		for _, cve := range item.CVEIDs {
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO rss_item_cves(item_id,cve_id) VALUES(?,?)`, itemID, strings.ToUpper(cve)); err != nil {
				return fmt.Errorf("RSS CVE索引保存失敗: %w", err)
			}
		}
	}
	if retention > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM rss_items WHERE feed_url=? AND last_seen_at < ?`, feedURL, fetchedAt.Add(-retention).UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("RSS保持期間整理失敗: %w", err)
		}
	}
	return nil
}

// RecordFeedFailure records a failed attempt without touching successful
// items, so a partial/outage response cannot resolve existing findings.
func (s *Store) RecordFeedFailure(ctx context.Context, status FeedStatus) error {
	if status.LastAttemptAt == nil {
		now := time.Now().UTC()
		status.LastAttemptAt = &now
	}
	return s.SaveFeedStatus(ctx, status)
}

// SaveFeedStatus はフィードの取得状態を保存する。
func (s *Store) SaveFeedStatus(ctx context.Context, status FeedStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return saveFeedStatus(ctx, s.db, status)
}

type feedStatusWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveFeedStatus(ctx context.Context, db feedStatusWriter, status FeedStatus) error {
	var attempt, success interface{}
	if status.LastAttemptAt != nil {
		attempt = status.LastAttemptAt.UTC().Format(time.RFC3339Nano)
	}
	if status.LastSuccessAt != nil {
		success = status.LastSuccessAt.UTC().Format(time.RFC3339Nano)
	}
	var next interface{}
	if status.NextAttemptAt != nil {
		next = status.NextAttemptAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO rss_feed_status(feed_url,last_attempt_at,last_success_at,last_error,item_count,etag,last_modified,next_attempt_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(feed_url) DO UPDATE SET
		last_attempt_at=excluded.last_attempt_at,
		last_success_at=COALESCE(excluded.last_success_at,rss_feed_status.last_success_at),
		last_error=excluded.last_error,
		item_count=CASE WHEN excluded.last_success_at IS NULL THEN rss_feed_status.item_count ELSE excluded.item_count END,
		etag=CASE WHEN excluded.last_success_at IS NULL THEN rss_feed_status.etag ELSE excluded.etag END,
		last_modified=CASE WHEN excluded.last_success_at IS NULL THEN rss_feed_status.last_modified ELSE excluded.last_modified END,
		next_attempt_at=excluded.next_attempt_at`, status.FeedURL, attempt, success, status.LastError, status.ItemCount, status.ETag, status.LastModified, next)
	if err != nil {
		return fmt.Errorf("フィード状態保存失敗: %w", err)
	}
	return nil
}

// ListFeedStatuses returns the latest attempt and last successful metadata.
func (s *Store) ListFeedStatuses(ctx context.Context) ([]FeedStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `SELECT feed_url,last_attempt_at,last_success_at,last_error,item_count,etag,last_modified,next_attempt_at FROM rss_feed_status ORDER BY feed_url`)
	if err != nil {
		return nil, fmt.Errorf("フィード状態一覧取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var statuses []FeedStatus
	for rows.Next() {
		var status FeedStatus
		var attempt, success, next sql.NullString
		if err := rows.Scan(&status.FeedURL, &attempt, &success, &status.LastError, &status.ItemCount, &status.ETag, &status.LastModified, &next); err != nil {
			return nil, fmt.Errorf("フィード状態読込失敗: %w", err)
		}
		for _, date := range []struct {
			value sql.NullString
			dest  **time.Time
		}{{attempt, &status.LastAttemptAt}, {success, &status.LastSuccessAt}, {next, &status.NextAttemptAt}} {
			if date.value.Valid {
				tm, err := time.Parse(time.RFC3339Nano, date.value.String)
				if err != nil {
					return nil, fmt.Errorf("フィード状態日時解析失敗: %w", err)
				}
				*date.dest = &tm
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, rows.Err()
}

// ListFeedItems は保存記事を新しい順で返す。
func (s *Store) ListFeedItems(ctx context.Context, limit int) ([]feed.Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,feed_url,external_id,title,link,summary,published_at FROM rss_items ORDER BY COALESCE(published_at, first_seen_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("RSS記事一覧取得失敗: %w", err)
	}
	var out []feed.Item
	var ids []int64
	for rows.Next() {
		var id int64
		var item feed.Item
		var published *string
		if err := rows.Scan(&id, &item.FeedURL, &item.ExternalID, &item.Title, &item.Link, &item.Summary, &published); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("RSS記事読込失敗: %w", err)
		}
		if published != nil {
			item.Published, _ = time.Parse(time.RFC3339Nano, *published)
		}
		ids = append(ids, id)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i, id := range ids {
		crows, err := s.db.QueryContext(ctx, `SELECT cve_id FROM rss_item_cves WHERE item_id=? ORDER BY cve_id`, id)
		if err != nil {
			return nil, err
		}
		for crows.Next() {
			var c string
			if err := crows.Scan(&c); err != nil {
				_ = crows.Close()
				return nil, err
			}
			out[i].CVEIDs = append(out[i].CVEIDs, c)
		}
		if err := crows.Close(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MarshalFeedItems は記事のテスト・履歴保存用JSONを作る。
func MarshalFeedItems(items []feed.Item) ([]byte, error) { return json.Marshal(items) }
