package store

import (
	"context"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"testing"
	"time"
)

func TestClaimEvaluationRejectsDuplicateAndResolvedButAllowsManualRefresh(t *testing.T) {
	s := New()
	defer func() { _ = s.Close() }()
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
	s.SaveObserved(rec)
	if ok, err := s.ClaimEvaluation(context.Background(), rec.Alert.ID, false); err != nil || !ok {
		t.Fatalf("initial claim: %v %v", ok, err)
	}
	if ok, err := s.ClaimEvaluation(context.Background(), rec.Alert.ID, true); err != nil || ok {
		t.Fatalf("duplicate claim: %v %v", ok, err)
	}
	if err := s.UpdateEvalStatus(rec.Alert.ID, model.EvalStatusDone); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimEvaluation(context.Background(), rec.Alert.ID, false); err != nil || ok {
		t.Fatalf("automatic reevaluation: %v %v", ok, err)
	}
	if ok, err := s.ClaimEvaluation(context.Background(), rec.Alert.ID, true); err != nil || !ok {
		t.Fatalf("manual refresh: %v %v", ok, err)
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "api", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimEvaluation(context.Background(), rec.Alert.ID, true); err != nil || ok {
		t.Fatalf("resolved claim: %v %v", ok, err)
	}
}
