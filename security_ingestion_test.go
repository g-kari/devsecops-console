package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// Keep the richer contract optional: the embedded Client used below exposes
// only the legacy methods, even though its underlying fake is result-aware.
type ingestionFetchClient struct {
	result github.FetchResult
	err    error
	during func()
	calls  int
}

func (c *ingestionFetchClient) FetchAlertsResult(context.Context, config.Target) (github.FetchResult, error) {
	c.calls++
	if c.during != nil {
		c.during()
	}
	return c.result, c.err
}
func (c *ingestionFetchClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	result, err := c.FetchAlertsResult(ctx, target)
	return result.Alerts, err
}
func (c *ingestionFetchClient) FindDependabotPR(context.Context, string, string, string) (int, error) {
	return 0, nil
}

func runningIngestionID(t *testing.T, s *store.Store, scope string) string {
	t.Helper()
	runs, err := s.QueryIngestRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, run := range runs {
		if run.Result != model.IngestResultRunning {
			continue
		}
		if id != "" || run.Scope != scope || run.Connector != "dependabot" || run.Coverage != model.IngestCoverageUnknown || run.FinishedAt != nil {
			t.Fatalf("invalid running fetch ledger: %+v", runs)
		}
		id = run.ID
	}
	if id == "" {
		t.Fatal("fetch contacted source before persisting its ingestion run")
	}
	return id
}

func ingestionByID(t *testing.T, s *store.Store, id string) model.IngestRun {
	t.Helper()
	runs, err := s.QueryIngestRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.ID == id {
			if run.FinishedAt == nil || run.FinishedAt.Before(run.StartedAt) {
				t.Fatalf("fetch ledger was not finalized: %+v", run)
			}
			return run
		}
	}
	t.Fatalf("ingest run %q disappeared", id)
	return model.IngestRun{}
}

func TestFetchIngestionLedgerAndNoFalseResolution(t *testing.T) {
	for _, tc := range []struct {
		name, result, coverage, code string
		fetch                        github.FetchResult
		err                          error
		legacy, filtered, resolved   bool
		wantErr                      bool
	}{
		{name: "complete", fetch: github.FetchResult{CompleteRepos: []string{"ORG/API"}}, result: "success", coverage: "full", resolved: true},
		{name: "partial", result: "partial", coverage: "partial", code: "incomplete_coverage"},
		{name: "wrong_complete_scope", fetch: github.FetchResult{CompleteRepos: []string{"org/other"}}, result: "partial", coverage: "partial", code: "incomplete_coverage"},
		{name: "skipped_scope", fetch: github.FetchResult{CompleteRepos: []string{"org/api"}, SkippedRepos: []string{"org/api"}}, result: "partial", coverage: "partial", code: "scope_skipped"},
		{name: "severity_filtered", fetch: github.FetchResult{CompleteRepos: []string{"org/api"}}, filtered: true, result: "partial", coverage: "partial", code: "filtered_scope"},
		{name: "legacy_unknown", legacy: true, result: "partial", coverage: "unknown", code: "coverage_unknown"},
		{name: "failed", err: errors.New("private source error token=not-for-ledger"), result: "failed", coverage: "unknown", code: "fetch_failed", wantErr: true},
		{name: "rate_limited", err: &github.RateLimitError{Remaining: 0, ResetAt: time.Now().Add(time.Minute)}, result: "failed", coverage: "unknown", code: "rate_limited"},
		{name: "source_skipped", err: &github.SkipError{Owner: "org", Repo: "api", Reason: "private source detail"}, result: "failed", coverage: "unknown", code: "source_skipped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			target := config.Target{Owner: "org", Repo: "api"}
			cfg := &config.Config{Targets: []config.Target{target}}
			if tc.filtered {
				cfg.FetchMinSeverity = "high"
			}
			record := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, Severity: model.SeverityHigh}, State: model.AlertStateApproved, EvalStatus: model.EvalStatusDone, NotifiedAt: time.Now().UTC(), SlackMessageTS: "preserved-ts", DiscordMessageID: "preserved-id", Evaluation: &model.Evaluation{Risk: "preserved"}}
			if !s.SaveObserved(record) {
				t.Fatal("seed legacy record")
			}
			var runID string
			fake := &ingestionFetchClient{result: tc.fetch, err: tc.err, during: func() { runID = runningIngestionID(t, s, "org/api") }}
			var client github.Client = fake
			if tc.legacy {
				client = struct{ github.Client }{fake}
			}
			err := makeFetchHandler(cfg, client, s, queue.New(10, 1), nil, nil)(context.Background(), queue.Job{Payload: target})
			if (err != nil) != tc.wantErr {
				t.Fatalf("handler error=%v, wantErr=%v", err, tc.wantErr)
			}
			run := ingestionByID(t, s, runID)
			if run.Result != tc.result || run.Coverage != tc.coverage || run.Error != tc.code {
				t.Fatalf("ledger=%+v, want %s/%s/%s", run, tc.result, tc.coverage, tc.code)
			}
			if strings.Contains(run.Error, "private") || strings.Contains(run.Error, "token") {
				t.Fatalf("raw source error entered ledger: %+v", run)
			}
			findings, err := s.QueryFindings(context.Background())
			if err != nil || len(findings) != 1 {
				t.Fatalf("finding history missing: %+v %v", findings, err)
			}
			wantStatus := model.SourceStatusActive
			if tc.resolved {
				wantStatus = model.SourceStatusResolved
			}
			if findings[0].SourceStatus != wantStatus {
				t.Fatalf("collection incorrectly changed lifecycle: %+v", findings[0])
			}
			preserved, err := s.Get(record.Alert.ID)
			if err != nil || preserved.State != model.AlertStateApproved || preserved.EvalStatus != model.EvalStatusDone || preserved.Evaluation == nil || preserved.Evaluation.Risk != "preserved" || preserved.SlackMessageTS != record.SlackMessageTS || preserved.DiscordMessageID != record.DiscordMessageID {
				t.Fatalf("legacy approval/notification history changed: %+v %v", preserved, err)
			}
			if (preserved.ResolvedAt != nil) != tc.resolved {
				t.Fatalf("legacy false resolution: %+v", preserved)
			}
		})
	}
}

func TestFetchIngestionRepeatedPollsPreserveIdentityAndEvidence(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	target := config.Target{Owner: "org", Repo: "api"}
	cfg := &config.Config{Targets: []config.Target{target}}
	alert := model.Alert{Owner: "org", Repo: "api", Number: 7, Severity: model.SeverityHigh, PackageName: "sample"}
	client := &ingestionFetchClient{result: github.FetchResult{Alerts: []model.Alert{alert, alert}, CompleteRepos: []string{"org/api"}}}
	var runIDs []string
	client.during = func() { runIDs = append(runIDs, runningIngestionID(t, s, "org/api")) }
	handler := makeFetchHandler(cfg, client, s, queue.New(10, 1), nil, nil)
	var findingID string
	var firstSeen time.Time
	for poll := 0; poll < 3; poll++ {
		if poll == 1 {
			// No metadata: legacy UpdateAlertJSON deliberately does not run.
			client.result.Alerts[0].Severity = model.SeverityCritical
			client.result.Alerts[1].Severity = model.SeverityCritical
		}
		if err := handler(context.Background(), queue.Job{Payload: target}); err != nil {
			t.Fatal(err)
		}
		findings, err := s.QueryFindings(context.Background())
		if err != nil || len(findings) != 1 {
			t.Fatalf("poll duplicated finding: %+v %v", findings, err)
		}
		if poll == 0 {
			findingID, firstSeen = findings[0].ID, findings[0].FirstSeen
		}
		if findings[0].ID != findingID || !findings[0].FirstSeen.Equal(firstSeen) || findings[0].LastSeen.Before(firstSeen) {
			t.Fatalf("poll changed source-native identity/history: %+v", findings[0])
		}
		observations, err := s.QueryObservations(context.Background(), findingID)
		if err != nil || len(observations) != poll+1 {
			t.Fatalf("each poll needs one distinct observation, duplicates within run do not: %+v %v", observations, err)
		}
		found := false
		for _, observation := range observations {
			if observation.IngestRunID == runIDs[poll] {
				found = true
			}
			if observation.Source != "dependabot" || observation.SourceFindingID != "org/api:7" || observation.Fingerprint == "" {
				t.Fatalf("invalid source evidence: %+v", observation)
			}
		}
		if !found {
			t.Fatalf("poll %d observation is not linked to its real fetch run", poll)
		}
		if poll > 0 && findings[0].Severity != model.SeverityCritical {
			t.Fatalf("fresh source evidence discarded by legacy metadata branch: %+v", findings[0])
		}
	}
	legacy := s.List()
	if len(legacy) != 1 || legacy[0].Alert.Severity != model.SeverityHigh {
		t.Fatalf("existing metadata-only legacy behavior changed: %+v", legacy)
	}
}

func TestFetchIngestionHonorsPolicyBeforeAndAfterFetch(t *testing.T) {
	for _, stage := range []string{"before", "during", "unconfigured_owner"} {
		t.Run(stage, func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			target := config.Target{Owner: "org", Repo: "api"}
			cfg := &config.Config{Targets: []config.Target{{Owner: "org"}}}
			client := &ingestionFetchClient{result: github.FetchResult{Alerts: []model.Alert{{Owner: "org", Repo: "api", Number: 1}}, CompleteRepos: []string{"org/api"}}}
			var runID string
			switch stage {
			case "before":
				cfg.Targets[0].Excludes = []string{"api"}
			case "during":
				client.during = func() {
					runID = runningIngestionID(t, s, "org/api")
					cfg.Targets[0].Excludes = []string{"api"}
				}
			default:
				target = config.Target{Owner: "other"}
			}
			if err := makeFetchHandler(cfg, client, s, queue.New(10, 1), nil, nil)(context.Background(), queue.Job{Payload: target}); err != nil {
				t.Fatal(err)
			}
			findings, err := s.QueryFindings(context.Background())
			if err != nil || len(findings) != 0 || len(s.List()) != 0 {
				t.Fatalf("excluded alert persisted: %+v %v", findings, err)
			}
			runs, err := s.QueryIngestRuns(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if stage != "during" {
				if client.calls != 0 || len(runs) != 0 {
					t.Fatalf("policy skip created an actual fetch attempt: calls=%d runs=%+v", client.calls, runs)
				}
			} else {
				run := ingestionByID(t, s, runID)
				if run.Result != "partial" || run.Coverage != "partial" || run.Error != "policy_changed" {
					t.Fatalf("policy change misreported coverage: %+v", run)
				}
			}
		})
	}
}

func TestFetchIngestionFinalizesAfterCancellation(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	target := config.Target{Owner: "org", Repo: "api"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runID string
	client := &ingestionFetchClient{err: context.Canceled, during: func() { runID = runningIngestionID(t, s, "org/api"); cancel() }}
	err := makeFetchHandler(&config.Config{Targets: []config.Target{target}}, client, s, queue.New(10, 1), nil, nil)(ctx, queue.Job{Payload: target})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	run := ingestionByID(t, s, runID)
	if run.Result != "failed" || run.Coverage != "unknown" || run.Error != "canceled" {
		t.Fatalf("canceled fetch left running/incorrect ledger: %+v", run)
	}
}

func TestFetchIngestionFinalizationFailureIsReturned(t *testing.T) {
	for _, rateLimited := range []bool{false, true} {
		t.Run(map[bool]string{false: "fetch_error", true: "rate_limit_nil_legacy_return"}[rateLimited], func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			target := config.Target{Owner: "org", Repo: "api"}
			fetchErr := errors.New("fetch sentinel")
			var sourceErr = fetchErr
			if rateLimited {
				sourceErr = &github.RateLimitError{}
			}
			client := &ingestionFetchClient{err: sourceErr, during: func() { _ = s.Close() }}
			err := makeFetchHandler(&config.Config{Targets: []config.Target{target}}, client, s, queue.New(10, 1), nil, nil)(context.Background(), queue.Job{Payload: target})
			if err == nil || !strings.Contains(err.Error(), "ingest") {
				t.Fatalf("ingest finalization failure was swallowed: %v", err)
			}
			if !rateLimited && !errors.Is(err, fetchErr) {
				t.Fatalf("original fetch error lost during finalization: %v", err)
			}
		})
	}
}

func TestFetchIngestionLegacySaveFailureIsNotReportedAsSuccess(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "save-failure.db")
	s, err := store.NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER reject_legacy_insert BEFORE INSERT ON alert_records BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	target := config.Target{Owner: "org", Repo: "api"}
	alert := model.Alert{Owner: "org", Repo: "api", Number: 9, Severity: model.SeverityHigh}
	client := &ingestionFetchClient{result: github.FetchResult{Alerts: []model.Alert{alert}, CompleteRepos: []string{"org/api"}}}
	handler := makeFetchHandler(&config.Config{Targets: []config.Target{target}}, client, s, queue.New(10, 1), nil, nil)
	if err := handler(ctx, queue.Job{Payload: target}); err == nil {
		t.Fatal("legacy save failure was reported as success")
	}
	runs, err := s.QueryIngestRuns(ctx)
	if err != nil || len(runs) != 1 || runs[0].Result != "failed" || runs[0].Coverage != "partial" || runs[0].Error != "processing_failed" {
		t.Fatalf("failed save ledger=%+v err=%v", runs, err)
	}
	if s.HasByKey("org", "api", 9) {
		t.Fatal("failed legacy insert persisted")
	}
	findings, err := s.QueryFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatal("valid source observation was lost")
	}
	id := findings[0].ID
	if _, err := db.Exec(`DROP TRIGGER reject_legacy_insert`); err != nil {
		t.Fatal(err)
	}
	if err := handler(ctx, queue.Job{Payload: target}); err != nil {
		t.Fatal(err)
	}
	if rows := s.List(); len(rows) != 1 {
		t.Fatalf("safe retry legacy rows=%d", len(rows))
	}
	findings, err = s.QueryFindings(ctx)
	if err != nil || len(findings) != 1 || findings[0].ID != id {
		t.Fatal("safe retry duplicated finding")
	}
}

func TestFetchIngestionMetadataWriteFailureIsNotReportedAsSuccess(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "metadata-failure.db")
	s, err := store.NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, Summary: "old"}, State: model.AlertStateApproved, NotifiedAt: time.Now()}
	s.SaveObserved(rec)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER reject_metadata_update BEFORE UPDATE OF alert_json ON alert_records BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	alert := rec.Alert
	alert.Summary = "new"
	alert.DefaultBranch = "main"
	target := config.Target{Owner: "org", Repo: "api"}
	client := &ingestionFetchClient{result: github.FetchResult{Alerts: []model.Alert{alert}, CompleteRepos: []string{"org/api"}}}
	handler := makeFetchHandler(&config.Config{Targets: []config.Target{target}}, client, s, queue.New(10, 1), nil, nil)
	if err := handler(ctx, queue.Job{Payload: target}); err == nil {
		t.Fatal("metadata save failure was reported as success")
	}
	runs, err := s.QueryIngestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last := runs[len(runs)-1]
	if last.Result != "failed" || last.Error != "processing_failed" {
		t.Fatalf("metadata failure ledger=%+v", last)
	}
	saved, err := s.Get(rec.Alert.ID)
	if err != nil || saved.Alert.Summary != "old" || saved.State != model.AlertStateApproved {
		t.Fatal("failed write changed legacy workflow")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_metadata_update`); err != nil {
		t.Fatal(err)
	}
	if err := handler(ctx, queue.Job{Payload: target}); err != nil {
		t.Fatal(err)
	}
	saved, err = s.Get(rec.Alert.ID)
	if err != nil || saved.Alert.Summary != "new" || saved.State != model.AlertStateApproved {
		t.Fatal("safe retry did not retain approval/update metadata")
	}
}
