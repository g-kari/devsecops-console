package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestPendingPolicySelectionFiltersBeforeLimitAndUsesLightweightFields(t *testing.T) {
	s := New()
	defer func() { _ = s.Close() }()
	for i, input := range []struct {
		owner, repo string
		severity    model.Severity
	}{{"org", "api", model.SeverityCritical}, {"org", "sdk", model.SeverityMedium}, {"other", "api", model.SeverityCritical}, {"org", "sdk", model.SeverityHigh}} {
		s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: input.owner, Repo: input.repo, Number: i + 1, Severity: input.severity, Description: "large fixture"}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()})
	}
	cfg := config.Config{Targets: []config.Target{{Owner: "ORG", Repo: "api"}, {Owner: "org", Excludes: []string{" API "}}}, Evaluator: config.EvaluatorConfig{MinSeverity: "high"}}
	records, err := s.ListPendingForTarget(context.Background(), cfg, config.Target{Owner: "org"}, 1)
	if err != nil || len(records) != 1 || records[0].Alert.ID != 4 || records[0].Alert.Description != "" || records[0].Evaluation != nil {
		t.Fatalf("pending projection: %+v err=%v", records, err)
	}
	records, err = s.ListPendingForTarget(context.Background(), cfg, config.Target{Owner: "other"}, 10)
	if err != nil || len(records) != 0 {
		t.Fatalf("unconfigured owner included: %+v %v", records, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListPendingForTarget(ctx, cfg, config.Target{Owner: "org"}, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not returned: %v", err)
	}
}
