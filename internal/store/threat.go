package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// UpsertThreat stores the latest source snapshot without erasing a positive
// KEV observation when a later response is incomplete.
func (s *Store) UpsertThreat(ctx context.Context, source string, snapshots []model.ThreatSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, snap := range snapshots {
		body, err := json.Marshal(snap)
		if err != nil {
			return err
		}
		fetched := snap.FetchedAt
		if fetched.IsZero() {
			fetched = time.Now().UTC()
		}
		var sourceDate interface{}
		if snap.KEVDate != nil {
			sourceDate = snap.KEVDate.UTC().Format(time.RFC3339Nano)
		} else if snap.EPSSDate != nil {
			sourceDate = snap.EPSSDate.UTC().Format(time.RFC3339Nano)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO threat_snapshots(source,advisory_key,fetched_at,source_date,body_json) VALUES(?,?,?,?,?) ON CONFLICT(source,advisory_key) DO UPDATE SET fetched_at=excluded.fetched_at,source_date=excluded.source_date,body_json=excluded.body_json`, source, snap.AdvisoryKey, fetched.UTC().Format(time.RFC3339Nano), sourceDate, string(body))
		if err != nil {
			return fmt.Errorf("threat snapshot save: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("脅威スナップショット確定失敗: %w", err)
	}
	if len(snapshots) > 0 {
		scope := RiskScope{All: len(snapshots) > 200}
		if !scope.All {
			seen := make(map[string]bool, len(snapshots))
			for _, snapshot := range snapshots {
				if !seen[snapshot.AdvisoryKey] {
					seen[snapshot.AdvisoryKey] = true
					scope.Advisories = append(scope.Advisories, snapshot.AdvisoryKey)
				}
			}
		}
		s.riskChangedLocked(scope)
	}
	return nil
}

// ListThreatSnapshots returns the most recent normalized snapshot for each
// advisory across all configured sources.
func (s *Store) ListThreatSnapshots(ctx context.Context) (map[string]model.ThreatSnapshot, error) {
	return s.listThreatSnapshots(ctx, nil)
}

// ListThreatSnapshotsFor returns only the advisories needed for a report page.
func (s *Store) ListThreatSnapshotsFor(ctx context.Context, advisoryKeys []string) (map[string]model.ThreatSnapshot, error) {
	out := make(map[string]model.ThreatSnapshot)
	seen := make(map[string]bool, len(advisoryKeys))
	var keys []string
	for _, key := range advisoryKeys {
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	for start := 0; start < len(keys); start += 200 {
		end := start + 200
		if end > len(keys) {
			end = len(keys)
		}
		batch, err := s.listThreatSnapshots(ctx, keys[start:end])
		if err != nil {
			return nil, err
		}
		for key, snapshot := range batch {
			out[key] = snapshot
		}
	}
	return out, nil
}

func (s *Store) listThreatSnapshots(ctx context.Context, keys []string) (map[string]model.ThreatSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT advisory_key,source,fetched_at,body_json FROM threat_snapshots"
	var args []any
	if len(keys) > 0 {
		query += " WHERE advisory_key IN (" + strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",") + ")"
		for _, key := range keys {
			args = append(args, key)
		}
	}
	query += " ORDER BY fetched_at DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]model.ThreatSnapshot{}
	for rows.Next() {
		var key, source, fetched, body string
		if err := rows.Scan(&key, &source, &fetched, &body); err != nil {
			return nil, err
		}
		var snap model.ThreatSnapshot
		if err := json.Unmarshal([]byte(body), &snap); err != nil {
			return nil, fmt.Errorf("脅威情報解析失敗 (%s/%s): %w", source, key, err)
		}
		snap.FetchedAt, err = time.Parse(time.RFC3339Nano, fetched)
		if err != nil {
			return nil, fmt.Errorf("脅威情報取得日時解析失敗 (%s/%s): %w", source, key, err)
		}
		if snap.EPSS != nil {
			at := snap.FetchedAt
			snap.EPSSFetchedAt = &at
		}
		if source == "kev" {
			snap.KEVKnown = true
		}
		if existing, exists := out[key]; exists {
			existing.KEVKnown = existing.KEVKnown || snap.KEVKnown
			if snap.KEV {
				existing.KEV = true
				existing.KEVKnown = true
				existing.KEVDate = snap.KEVDate
			}
			if snap.EPSS != nil && (existing.EPSSFetchedAt == nil || snap.EPSSFetchedAt.After(*existing.EPSSFetchedAt)) {
				existing.EPSS = snap.EPSS
				existing.EPSSPercentile = snap.EPSSPercentile
				existing.EPSSDate = snap.EPSSDate
				existing.EPSSFetchedAt = snap.EPSSFetchedAt
			}
			if existing.FetchedAt.Before(snap.FetchedAt) {
				existing.FetchedAt = snap.FetchedAt
			}
			out[key] = existing
		} else {
			out[key] = snap
		}
	}
	return out, rows.Err()
}
