package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestScoreHistoryRecordsTransitionsAndSnapshotTime(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 12, 0, 0, 123, time.UTC)
	input := model.ScoreInput{At: at}
	result := model.ScoreResult{ModelVersion: "urgency-v1", Upper: 95}
	for _, hash := range []string{"A", "A", "B", "A"} {
		if err := s.SaveScoreHistory(ctx, "api", "owner/repo", "CVE-2026-1234", hash, input, result); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.db.Query(`SELECT input_hash,computed_at,input_json FROM score_history ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var hashes []string
	for rows.Next() {
		var hash, computed, body string
		if err := rows.Scan(&hash, &computed, &body); err != nil {
			t.Fatal(err)
		}
		var saved model.ScoreInput
		if err := json.Unmarshal([]byte(body), &saved); err != nil {
			t.Fatal(err)
		}
		if computed != at.Format(time.RFC3339Nano) || !saved.At.Equal(at) {
			t.Fatalf("snapshot time mismatch: computed=%q input=%v", computed, saved.At)
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 3 || hashes[0] != "A" || hashes[1] != "B" || hashes[2] != "A" {
		t.Fatalf("expected A -> B -> A, got %v", hashes)
	}
}

func TestDeadlineNeverExtendsAndKeepsEpisodeStart(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	record := DeadlineRecord{ProfileID: "api", AdvisoryKey: "CVE-2026-1234", Episode: 1, OpenedAt: start, DueAt: start.Add(time.Hour), Priority: "immediate"}
	if err := s.SaveDeadline(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.OpenedAt = start.Add(20 * time.Minute)
	record.DueAt = start.Add(24 * time.Hour)
	record.Priority = "planned"
	if err := s.SaveDeadline(ctx, record); err != nil {
		t.Fatal(err)
	}
	var opened, due string
	if err := s.db.QueryRow(`SELECT opened_at,due_at FROM risk_deadlines`).Scan(&opened, &due); err != nil {
		t.Fatal(err)
	}
	if opened != start.Format(time.RFC3339Nano) || due != start.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("episode start/deadline changed: opened=%q due=%q", opened, due)
	}
	record.DueAt = start.Add(30 * time.Minute)
	if err := s.SaveDeadline(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT due_at FROM risk_deadlines`).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != record.DueAt.Format(time.RFC3339Nano) {
		t.Fatalf("escalation didn't shorten deadline: %q", due)
	}
}

func TestRiskEvaluationIsAtomicAndReopenStartsNewEpisode(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	input := model.ScoreInput{At: at}
	result := model.ScoreResult{ModelVersion: "urgency-v1", Priority: "today", Status: "provisional"}
	// A failed deadline write must not leave an orphan history row.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_deadline BEFORE INSERT ON risk_deadlines BEGIN SELECT RAISE(ABORT,'fixture deadline failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRiskEvaluation(ctx, "api", "owner/repo", "cve:CVE-2026-1234", "first", input, result, at.Add(8*time.Hour), false); err == nil {
		t.Fatal("want deadline failure")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM score_history`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial score write: %d histories", count)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_deadline`); err != nil {
		t.Fatal(err)
	}
	deadline, err := s.SaveRiskEvaluation(ctx, "api", "owner/repo", "cve:CVE-2026-1234", "first", input, result, at.Add(8*time.Hour), false)
	if err != nil || deadline == nil || deadline.Episode != 1 {
		t.Fatalf("first episode=%+v err=%v", deadline, err)
	}
	input.At = at.Add(time.Hour)
	deadline, err = s.SaveRiskEvaluation(ctx, "api", "owner/repo", "cve:CVE-2026-1234", "resolved", input, result, at.Add(9*time.Hour), true)
	if err != nil || deadline.ClosedAt == nil {
		t.Fatalf("resolve episode=%+v err=%v", deadline, err)
	}
	input.At = at.Add(2 * time.Hour)
	deadline, err = s.SaveRiskEvaluation(ctx, "api", "owner/repo", "cve:CVE-2026-1234", "reopened", input, result, at.Add(10*time.Hour), false)
	if err != nil || deadline.Episode != 2 || deadline.ClosedAt != nil || !deadline.OpenedAt.Equal(input.At) {
		t.Fatalf("reopened episode=%+v err=%v", deadline, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM risk_deadlines WHERE closed_at IS NOT NULL`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("closed episode lost: %d", count)
	}
}

func TestSaveDeadlineCannotReopenClosedEpisode(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	closed := at.Add(time.Hour)
	record := DeadlineRecord{ProfileID: "api", AdvisoryKey: "cve:CVE-2026-1234", Episode: 1, OpenedAt: at, DueAt: closed, Priority: "today", ClosedAt: &closed}
	if err := s.SaveDeadline(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.ClosedAt = nil
	if err := s.SaveDeadline(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var saved sql.NullString
	if err := s.db.QueryRow(`SELECT closed_at FROM risk_deadlines`).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Valid || saved.String != closed.Format(time.RFC3339Nano) {
		t.Fatalf("closed episode reopened: %+v", saved)
	}
}
