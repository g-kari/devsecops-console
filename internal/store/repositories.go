package store

import (
	"context"
	"fmt"
	"log/slog"
)

// RepositoryStatus summarizes acquired data for the settings screen.
type RepositoryStatus struct {
	Owner      string
	Repo       string
	AlertCount int
}

// ListRepositories returns repositories represented by persisted alerts.
func (s *Store) ListRepositories() []RepositoryStatus {
	repos, err := s.QueryRepositories(context.Background())
	if err != nil {
		slog.Error("リポジトリ一覧取得失敗", "error", err)
	}
	return repos
}

// QueryRepositories counts acquired alerts using repository columns only.
func (s *Store) QueryRepositories(ctx context.Context) ([]RepositoryStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `SELECT MIN(owner),MIN(repo),COUNT(*) FROM alert_records GROUP BY owner COLLATE NOCASE,repo COLLATE NOCASE ORDER BY owner COLLATE NOCASE,repo COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("リポジトリ集計取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var repos []RepositoryStatus
	for rows.Next() {
		var repo RepositoryStatus
		if err := rows.Scan(&repo.Owner, &repo.Repo, &repo.AlertCount); err != nil {
			return nil, fmt.Errorf("リポジトリ集計読込失敗: %w", err)
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}
