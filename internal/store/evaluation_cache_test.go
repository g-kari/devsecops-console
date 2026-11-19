package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func cacheTestProvenance(at time.Time) *model.EvaluationProvenance {
	p := &model.EvaluationProvenance{Provider: "codex", Model: "fixture-model", Mode: "sandbox", RuntimeHash: strings.Repeat("a", 64), PromptVersion: "fixture-prompt", InputHash: strings.Repeat("b", 64), EvaluatedAt: at}
	p.CacheKey = p.Key()
	return p
}

func TestEvaluationCacheRequiresFreshMatchingProvenanceAndActiveDoneRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	for _, scenario := range []string{"valid", "legacy", "expired", "future", "default_model", "wrong_key", "wrong_model", "failed", "evaluating", "resolved"} {
		t.Run(scenario, func(t *testing.T) {
			s := New()
			t.Cleanup(func() { _ = s.Close() })
			p := cacheTestProvenance(now.Add(-time.Hour))
			key := p.CacheKey
			r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, EvalStatus: model.EvalStatusDone, Evaluation: &model.Evaluation{Recommendation: "approve", Provenance: p}, NotifiedAt: now}
			switch scenario {
			case "legacy":
				r.Evaluation.Provenance = nil
			case "expired":
				p.EvaluatedAt = now.Add(-25 * time.Hour)
			case "future":
				p.EvaluatedAt = now.Add(time.Second)
			case "default_model":
				p.Model = ""
			case "wrong_key":
				p.CacheKey = strings.Repeat("c", 64)
			case "wrong_model":
				p.Model = "other-model"
			case "failed":
				r.EvalStatus = model.EvalStatusFailed
			case "evaluating":
				r.EvalStatus = model.EvalStatusEvaluating
			}
			s.SaveObserved(r)
			if scenario == "resolved" {
				s.RemoveResolvedAlerts("org", "api", nil)
			}
			got, err := s.FindEvaluationByKey(ctx, key, now)
			if err != nil || (got != nil) != (scenario == "valid") {
				t.Fatalf("%s: got=%+v err=%v", scenario, got, err)
			}
		})
	}
}

func TestEvaluationCacheSurvivesRestartAndUsesIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now().UTC()
	p := cacheTestProvenance(now)
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, Evaluation: &model.Evaluation{Provenance: p}, EvalStatus: model.EvalStatusDone, NotifiedAt: now})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.FindEvaluationByKey(ctx, p.CacheKey, now)
	if err != nil || got == nil || !got.Provenance.EvaluatedAt.Equal(now) {
		t.Fatalf("restart lost identity: %+v %v", got, err)
	}
	rows, err := s.db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+evaluationCacheQuery, p.CacheKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "alert_evaluation_cache_lookup") {
			indexed = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !indexed {
		t.Fatal("cache query scans evaluation bodies instead of keyed index")
	}
}

func TestEvaluationPublicationRejectsChangedInputAndReopenedEpisode(t *testing.T) {
	for _, change := range []string{"summary", "episode", "id_only", "resolved"} {
		t.Run(change, func(t *testing.T) {
			s := New()
			t.Cleanup(func() { _ = s.Close() })
			r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, Summary: "original"}, EvalStatus: model.EvalStatusEvaluating, NotifiedAt: time.Now().UTC()}
			s.SaveObserved(r)
			before, err := s.Get(r.Alert.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "summary":
				r.Alert.Summary = "new input"
				s.SaveObserved(r)
			case "episode":
				s.RemoveResolvedAlerts("org", "api", nil)
				r.NotifiedAt = r.NotifiedAt.Add(time.Hour)
				s.SaveObserved(r)
			case "id_only":
				if err := s.UpdateAlertJSON("org", "api", 1, r.Alert); err != nil {
					t.Fatal(err)
				}
			case "resolved":
				s.RemoveResolvedAlerts("org", "api", nil)
			}
			written, err := s.SaveEvaluationIfCurrent(context.Background(), before, &model.Evaluation{Recommendation: "approve"})
			if change == "id_only" {
				if !written || err != nil {
					t.Fatalf("display ID rejected matching input: %v %v", written, err)
				}
			} else if change == "resolved" {
				if written || err != nil {
					t.Fatalf("resolved publication: %v %v", written, err)
				}
			} else if written || !errors.Is(err, ErrEvaluationInputsChanged) {
				t.Fatalf("stale %s publication accepted: %v %v", change, written, err)
			}
		})
	}
}

func TestEvaluationCacheDoesNotHideStorageOrMetadataErrors(t *testing.T) {
	s := New()
	now := time.Now().UTC()
	p := cacheTestProvenance(now)
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, Evaluation: &model.Evaluation{Provenance: p}, EvalStatus: model.EvalStatusDone, NotifiedAt: now})
	if _, err := s.db.Exec(`UPDATE alert_records SET eval_json=json_set(eval_json,'$.provenance.evaluated_at','invalid')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindEvaluationByKey(context.Background(), p.CacheKey, now); err == nil {
		t.Fatal("corrupt provenance silently became cache miss")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindEvaluationByKey(context.Background(), p.CacheKey, now); err == nil {
		t.Fatal("closed DB silently became cache miss")
	}
}
