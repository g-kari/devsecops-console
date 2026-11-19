package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type policyFetchClient struct {
	result github.FetchResult
	during func()
}

func (c *policyFetchClient) FetchAlertsResult(context.Context, config.Target) (github.FetchResult, error) {
	if c.during != nil {
		c.during()
	}
	return c.result, nil
}
func (c *policyFetchClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	result, err := c.FetchAlertsResult(ctx, target)
	return result.Alerts, err
}
func (c *policyFetchClient) FindDependabotPR(context.Context, string, string, string) (int, error) {
	return 0, nil
}

func TestFetchCompletenessAndCurrentExclusionProtectHistory(t *testing.T) {
	for _, scenario := range []string{"excluded_during_fetch", "partial_specific_repo"} {
		t.Run(scenario, func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			target := config.Target{Owner: "org", Repo: "api"}
			cfg := &config.Config{Targets: []config.Target{target}}
			rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, NotifiedAt: time.Now()}
			s.SaveObserved(rec)
			client := &policyFetchClient{}
			if scenario == "excluded_during_fetch" {
				client.result.CompleteRepos = []string{"org/api"}
				client.during = func() { cfg.Targets[0].Excludes = []string{"api"} }
			}
			if err := makeFetchHandler(cfg, client, s, queue.New(10, 1), nil, nil)(context.Background(), queue.Job{Payload: target}); err != nil {
				t.Fatal(err)
			}
			saved, err := s.Get(rec.Alert.ID)
			if err != nil || saved.ResolvedAt != nil {
				t.Fatalf("missing is not resolved: %+v %v", saved, err)
			}
		})
	}
}

func TestExcludedQueuedAndLateEvaluationsDoNotPublish(t *testing.T) {
	for _, phase := range []string{"queued", "during"} {
		t.Run(phase, func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			cfg := &config.Config{Targets: []config.Target{{Owner: "org"}}, NotifyMinSeverity: "low"}
			rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, Severity: model.SeverityCritical}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
			s.SaveObserved(rec)
			var requests atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, `{"id":"fixture"}`)
			}))
			defer endpoint.Close()
			e := &resolutionEvaluator{}
			if phase == "queued" {
				cfg.Targets[0].Excludes = []string{"api"}
			} else {
				e.during = func() { cfg.Targets[0].Excludes = []string{"api"} }
			}
			if err := makeEvaluateHandler(cfg, e, s, nil, discord.New(endpoint.URL))(context.Background(), queue.Job{Payload: rec.Alert.ID}); err != nil {
				t.Fatal(err)
			}
			saved, err := s.Get(rec.Alert.ID)
			if err != nil || saved.Evaluation != nil || requests.Load() != 0 {
				t.Fatalf("excluded evaluation published: %+v requests=%d err=%v", saved, requests.Load(), err)
			}
			if phase == "queued" && e.calls != 0 {
				t.Fatal("excluded queued job started evaluator")
			}
		})
	}
}

func TestAutoEvaluationLimitDoesNotGetConsumedByExcludedRepos(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	cfg := &config.Config{Targets: []config.Target{{Owner: "org", Excludes: []string{"excluded"}}}, Evaluator: config.EvaluatorConfig{AutoEval: true, MaxEvalPerPoll: 1}}
	for i, repo := range []string{"excluded", "api"} {
		s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: repo, Number: i + 1, Severity: model.SeverityCritical}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()})
	}
	q := queue.New(10, 1)
	if err := makeFetchHandler(cfg, &policyFetchClient{}, s, q, nil, nil)(context.Background(), queue.Job{Payload: config.Target{Owner: "org"}}); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 1 {
		t.Fatalf("excluded record starved monitored evaluation: queue=%d", q.Len())
	}
	q.Stop()
}

func TestLegacyFetchWithoutCompletenessNeverInfersResolution(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	target := config.Target{Owner: "org", Repo: "api"}
	row := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, NotifiedAt: time.Now()}
	s.SaveObserved(row)
	legacy := struct{ github.Client }{&policyFetchClient{}}
	if err := makeFetchHandler(&config.Config{Targets: []config.Target{target}}, legacy, s, queue.New(10, 1), nil, nil)(context.Background(), queue.Job{Payload: target}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Get(row.Alert.ID)
	if err != nil || rec.ResolvedAt != nil {
		t.Fatalf("unproven completeness resolved record: %+v %v", rec, err)
	}
}
