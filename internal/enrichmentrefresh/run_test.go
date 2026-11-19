package enrichmentrefresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

var errSyntheticStore = errors.New("PRIVATE-post-commit-error")

type observedRepository struct {
	Repository
	t                                                                                                                    *testing.T
	calls                                                                                                                map[string]int
	page                                                                                                                 *store.SecurityEnrichmentRefreshTargetPage
	queryError, beginBefore, beginAfter, failBefore, failAfter, completeBefore, completeAfter, readError, reconcileError bool
	onBegin, onFail, onComplete                                                                                          func()
	beginJSON, completeJSON, failJSON, readAttemptJSON, readFailureJSON, reconcileJSON                                   string
	cleanupContexts                                                                                                      []context.Context
	cleanupErrors                                                                                                        []error
	cleanupTimes                                                                                                         []time.Time
}

func observe(t *testing.T, db *store.Store) *observedRepository {
	t.Helper()
	return &observedRepository{Repository: db, t: t, calls: map[string]int{}}
}

func jsonValue(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (r *observedRepository) QuerySecurityEnrichmentRefreshTargets(ctx context.Context, after string, limit int) (store.SecurityEnrichmentRefreshTargetPage, error) {
	r.calls["query"]++
	if r.queryError {
		return store.SecurityEnrichmentRefreshTargetPage{}, errSyntheticStore
	}
	page, err := r.Repository.QuerySecurityEnrichmentRefreshTargets(ctx, after, limit)
	if err == nil && r.page != nil {
		return *r.page, nil
	}
	return page, err
}

func (r *observedRepository) BeginSecurityEnrichmentRefresh(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt) (bool, error) {
	r.calls["begin"]++
	r.beginJSON = jsonValue(r.t, a)
	if r.beginBefore {
		return false, errSyntheticStore
	}
	replay, err := r.Repository.BeginSecurityEnrichmentRefresh(ctx, a)
	if r.onBegin != nil {
		r.onBegin()
	}
	if err == nil && r.beginAfter {
		return false, errSyntheticStore
	}
	return replay, err
}

func (r *observedRepository) FailSecurityEnrichmentRefresh(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt, code string, at time.Time) (bool, error) {
	r.calls["fail"]++
	r.cleanupContexts = append(r.cleanupContexts, ctx)
	r.cleanupTimes = append(r.cleanupTimes, time.Now())
	r.cleanupErrors = append(r.cleanupErrors, ctx.Err())
	r.failJSON = jsonValue(r.t, &store.SecurityEnrichmentRefreshFailure{Code: code, FinishedAt: at})
	if r.failBefore {
		return false, errSyntheticStore
	}
	replay, err := r.Repository.FailSecurityEnrichmentRefresh(ctx, a, code, at)
	if r.onFail != nil {
		r.onFail()
	}
	if err == nil && r.failAfter {
		return false, errSyntheticStore
	}
	return replay, err
}

func (r *observedRepository) ReadSecurityEnrichmentRefreshAttempt(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt, expected *store.SecurityEnrichmentRefreshFailure) (store.SecurityEnrichmentRefreshState, error) {
	r.calls["read"]++
	r.cleanupContexts = append(r.cleanupContexts, ctx)
	r.cleanupTimes = append(r.cleanupTimes, time.Now())
	r.cleanupErrors = append(r.cleanupErrors, ctx.Err())
	r.readAttemptJSON, r.readFailureJSON = jsonValue(r.t, a), jsonValue(r.t, expected)
	if r.readError {
		return store.SecurityEnrichmentRefreshState{State: "unknown"}, errSyntheticStore
	}
	return r.Repository.ReadSecurityEnrichmentRefreshAttempt(ctx, a, expected)
}

func (r *observedRepository) CompleteSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentImportResult, error) {
	r.calls["complete"]++
	r.completeJSON = jsonValue(r.t, c)
	if r.completeBefore {
		return store.SecurityEnrichmentImportResult{}, errSyntheticStore
	}
	result, err := r.Repository.CompleteSecurityEnrichmentRefresh(ctx, c)
	if r.onComplete != nil {
		r.onComplete()
	}
	if err == nil && r.completeAfter {
		return store.SecurityEnrichmentImportResult{}, errSyntheticStore
	}
	return result, err
}

func (r *observedRepository) ReconcileSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentRefreshState, error) {
	r.calls["reconcile"]++
	r.cleanupContexts = append(r.cleanupContexts, ctx)
	r.cleanupTimes = append(r.cleanupTimes, time.Now())
	r.cleanupErrors = append(r.cleanupErrors, ctx.Err())
	r.reconcileJSON = jsonValue(r.t, c)
	if r.reconcileError {
		return store.SecurityEnrichmentRefreshState{State: "unknown"}, errSyntheticStore
	}
	return r.Repository.ReconcileSecurityEnrichmentRefresh(ctx, c)
}

type fetchFunc func(context.Context, string) ([]byte, error)

func (f fetchFunc) Fetch(ctx context.Context, source string) ([]byte, error) { return f(ctx, source) }

type fixtureHarness struct {
	service                           Service
	repo                              *observedRepository
	clockCalls, uuidCalls, fetchCalls int
	times                             []time.Time
	data                              []byte
	fetchError                        error
	clockHook                         func(int)
	fetchHook                         func(context.Context)
}

func harness(t *testing.T, db *store.Store) *fixtureHarness {
	t.Helper()
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	h := &fixtureHarness{repo: observe(t, db), times: []time.Time{start, start.Add(time.Minute), start.Add(2 * time.Minute)}, data: []byte(contractEPSS)}
	h.service = Service{
		Store: h.repo,
		Clock: func() time.Time {
			if h.clockCalls >= len(h.times) {
				t.Fatal("unexpected clock read after retained write")
			}
			i := h.clockCalls
			h.clockCalls++
			if h.clockHook != nil {
				h.clockHook(i)
			}
			return h.times[i]
		},
		NewUUID: func() (string, error) { h.uuidCalls++; return "30000000-0000-4000-8000-000000000101", nil },
		Fetcher: fetchFunc(func(ctx context.Context, source string) ([]byte, error) {
			h.fetchCalls++
			if source != "epss" {
				t.Fatalf("unexpected domain source=%q", source)
			}
			if h.fetchHook != nil {
				h.fetchHook(ctx)
			}
			return h.data, h.fetchError
		}),
	}
	return h
}

func assertPending(t *testing.T, h *fixtureHarness, out Result, err error) {
	t.Helper()
	if !errors.Is(err, ErrPending) || out.Outcome != "pending" || out.Pending == nil || out.Advance || out.NextAfter != "" || h.uuidCalls != 1 || h.repo.calls["begin"] != 1 {
		t.Fatalf("pending result=%+v err=%v uuid=%d calls=%v", out, err, h.uuidCalls, h.repo.calls)
	}
	if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(jsonValue(t, out), "PRIVATE") {
		t.Fatal("untrusted callback error leaked")
	}
	if jsonValue(t, out.Pending.Attempt) != h.repo.beginJSON {
		t.Fatal("attempt was regenerated after write")
	}
}

func TestRefreshOnceBeginUnknownNeverGrantsOwnership(t *testing.T) {
	for _, mode := range []string{"before", "after", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			h.repo.beginBefore = mode == "before"
			h.repo.beginAfter = mode != "before"
			h.repo.readError = mode == "read-error"
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			assertPending(t, h, out, err)
			if h.fetchCalls != 0 || h.clockCalls != 1 || h.repo.calls["read"] != 1 || h.repo.calls["fail"] != 0 || h.repo.calls["complete"] != 0 || h.repo.calls["reconcile"] != 0 {
				t.Fatalf("uncertain Begin continued calls=%v fetch=%d clock=%d", h.repo.calls, h.fetchCalls, h.clockCalls)
			}
			if h.repo.readAttemptJSON != h.repo.beginJSON || h.repo.readFailureJSON != "null" || out.Pending.Completion != nil || out.Pending.ExpectedFailure != nil {
				t.Fatal("Begin readback invented a failure or completion")
			}
		})
	}
}

func TestRefreshOnceFailUnknownUsesExactRetainedFailureWithoutFeed(t *testing.T) {
	for _, mode := range []string{"after", "before", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			h.fetchError = errors.New("PRIVATE-source-error")
			h.repo.failBefore = mode == "before"
			h.repo.failAfter = mode != "before"
			h.repo.readError = mode == "read-error"
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if mode == "after" {
				if err != nil || out.Outcome != "failed" || out.Code != "fetch_failed" || out.Pending != nil || out.Advance {
					t.Fatalf("committed failure=%+v err=%v", out, err)
				}
			} else {
				assertPending(t, h, out, err)
				if out.Pending.ExpectedFailure == nil || jsonValue(t, out.Pending.ExpectedFailure) != h.repo.failJSON || out.Pending.Completion != nil {
					t.Fatal("failure envelope lost or invented feed metadata")
				}
			}
			if h.repo.readFailureJSON != h.repo.failJSON || h.repo.calls["read"] != 1 || h.repo.calls["fail"] != 1 || h.repo.calls["complete"] != 0 || h.repo.calls["reconcile"] != 0 || h.fetchCalls != 1 || h.clockCalls != 2 {
				t.Fatalf("failure regenerated or retried calls=%v clock=%d fetch=%d", h.repo.calls, h.clockCalls, h.fetchCalls)
			}
		})
	}
}

func TestRefreshOnceCompleteUnknownRetainsOneCompletionAndNeverFails(t *testing.T) {
	for _, mode := range []string{"after", "before", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			h.repo.completeBefore = mode == "before"
			h.repo.completeAfter = mode != "before"
			h.repo.reconcileError = mode == "read-error"
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if mode == "after" {
				if err != nil || out.Outcome != "success" || !out.Advance || out.Pending != nil {
					t.Fatalf("committed success=%+v err=%v", out, err)
				}
			} else {
				assertPending(t, h, out, err)
				if out.Pending.Completion == nil || jsonValue(t, *out.Pending.Completion) != h.repo.completeJSON || out.Pending.ExpectedFailure != nil {
					t.Fatal("completion regenerated or downgraded")
				}
			}
			if h.repo.reconcileJSON != h.repo.completeJSON || h.repo.calls["complete"] != 1 || h.repo.calls["reconcile"] != 1 || h.repo.calls["read"] != 0 || h.repo.calls["fail"] != 0 || h.fetchCalls != 1 || h.clockCalls != 3 || h.uuidCalls != 1 {
				t.Fatalf("Complete retried/downgraded calls=%v clock=%d fetch=%d", h.repo.calls, h.clockCalls, h.fetchCalls)
			}
			var c store.SecurityEnrichmentRefreshCompletion
			if err := json.Unmarshal([]byte(h.repo.completeJSON), &c); err != nil {
				t.Fatal(err)
			}
			if c.OriginalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(h.data)) || !c.Attempt.StartedAt.Equal(h.times[0]) || !c.Feed.ObservedAt.Equal(h.times[1]) || !c.FinishedAt.Equal(h.times[2]) || c.Feed.PublishedAt.Equal(c.Feed.ObservedAt) {
				t.Fatal("uncompressed input digest or independent clocks changed")
			}
		})
	}
}

func TestRefreshOnceFailureCleanupSharesOneUncanceledBudget(t *testing.T) {
	type valueKey struct{}
	original, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "synthetic-owner"))
	defer cancel()
	db := contractStore(t, true)
	h := harness(t, db)
	h.fetchError = errors.New("PRIVATE-source-error")
	h.repo.failAfter = true
	h.repo.onFail = cancel
	h.fetchHook = func(ctx context.Context) {
		if ctx != original {
			t.Fatal("fetch used cleanup context")
		}
	}
	out, err := h.service.RefreshOnce(original, Request{Connector: "epss_feed", Limit: 200})
	if err != nil || out.Outcome != "failed" {
		t.Fatalf("cleanup result=%+v err=%v", out, err)
	}
	if len(h.repo.cleanupContexts) != 2 || h.repo.cleanupContexts[0] != h.repo.cleanupContexts[1] {
		t.Fatal("cleanup deadline/context was recreated")
	}
	deadline, ok := h.repo.cleanupContexts[0].Deadline()
	if !ok || deadline.IsZero() || deadline.Sub(h.repo.cleanupTimes[0]) > cleanupBudget {
		t.Fatal("cleanup has no bounded two-second deadline")
	}
	for i, ctx := range h.repo.cleanupContexts {
		if h.repo.cleanupErrors[i] != nil || ctx.Value(valueKey{}) != "synthetic-owner" {
			t.Fatal("original cancellation leaked into cleanup or context values were lost")
		}
		if d, ok := ctx.Deadline(); !ok || !d.Equal(deadline) {
			t.Fatal("Fail/readback do not share one deadline")
		}
	}
	if original.Err() == nil {
		t.Fatal("fixture did not cancel original context")
	}
	select {
	case <-h.repo.cleanupContexts[0].Done():
	default:
		t.Fatal("cleanup context was not released")
	}
}

func TestRefreshOnceCancellationBarriersAndNoSQLLockDuringFetch(t *testing.T) {
	for _, stage := range []string{"before", "after-begin", "after-parse"} {
		t.Run(stage, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			if stage == "after-begin" {
				h.repo.onBegin = cancel
			}
			if stage == "after-parse" {
				h.clockHook = func(i int) {
					if i == 2 {
						cancel()
					}
				}
			}
			h.fetchHook = func(fetchCtx context.Context) {
				if fetchCtx != ctx || fetchCtx.Err() != nil {
					t.Fatal("fetch context differs from active original")
				}
				bounded, stop := context.WithTimeout(fetchCtx, time.Second)
				defer stop()
				if _, err := db.QuerySecurityEnrichmentRefreshTargets(bounded, "", 200); err != nil {
					t.Fatalf("SQL transaction/lock held across fetch: %v", err)
				}
			}
			out, err := h.service.RefreshOnce(ctx, Request{Connector: "epss_feed", Limit: 200})
			if out.Advance || out.NextAfter != "" || h.repo.calls["complete"] != 0 {
				t.Fatalf("cancel became success/advance=%+v calls=%v", out, h.repo.calls)
			}
			if stage == "before" {
				if !errors.Is(err, context.Canceled) || h.repo.calls["query"] != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
					t.Fatal("pre-canceled operation started work")
				}
			} else {
				if err != nil || out.Outcome != "failed" || out.Code != "canceled" || h.repo.calls["fail"] != 1 {
					t.Fatalf("owned cancel was not closed=%+v err=%v", out, err)
				}
				wantFetch := 0
				if stage == "after-parse" {
					wantFetch = 1
				}
				if h.fetchCalls != wantFetch {
					t.Fatalf("cancel stage=%s fetch=%d want=%d", stage, h.fetchCalls, wantFetch)
				}
			}
		})
	}
}

func TestRefreshOnceInvalidClocksAreNeverCorrected(t *testing.T) {
	for _, kind := range []string{"start", "observed", "finish-zero", "finish-before-start", "finish-before-observed"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			switch kind {
			case "start":
				h.times[0] = time.Time{}
			case "observed":
				h.times[1] = h.times[0].Add(-time.Nanosecond)
			case "finish-zero":
				h.times[2] = time.Time{}
			case "finish-before-start":
				h.times[2] = h.times[0].Add(-time.Nanosecond)
			case "finish-before-observed":
				h.times[2] = h.times[1].Add(-time.Nanosecond)
			}
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if h.repo.calls["complete"] != 0 || out.Advance {
				t.Fatal("invalid clock became a completion")
			}
			switch kind {
			case "start":
				if err == nil || h.uuidCalls != 0 || h.repo.calls["begin"] != 0 || h.fetchCalls != 0 {
					t.Fatal("invalid start reached reservation")
				}
			case "observed":
				if err != nil || out.Outcome != "failed" || out.Code != "invalid_metadata" {
					t.Fatalf("backward observation was repaired=%+v err=%v", out, err)
				}
			default:
				assertPending(t, h, out, err)
				if out.Code != "invalid_clock" || out.Pending.ExpectedFailure != nil || h.repo.calls["fail"] != 0 {
					t.Fatal("invalid finish was fabricated for Fail")
				}
			}
		})
	}
}

func TestRefreshOnceMetadataAndPrehashInputCapAreStrict(t *testing.T) {
	for _, kind := range []string{"version", "publication", "future-publication", "empty", "at-cap", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			switch kind {
			case "version":
				h.data = bytes.ReplaceAll(h.data, []byte("model_version:synthetic-contract,"), nil)
			case "publication":
				h.data = bytes.ReplaceAll(h.data, []byte(",score_date:2026-11-10"), nil)
			case "future-publication":
				h.data = bytes.ReplaceAll(h.data, []byte("2026-11-10"), []byte("2026-11-11"))
			case "empty":
				h.data = nil
			case "at-cap":
				h.data = bytes.Repeat([]byte("x"), maxInputBytes)
			case "oversize":
				h.data = bytes.Repeat([]byte("x"), maxInputBytes+1)
			}
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if err != nil || out.Outcome != "failed" || out.Code != "parse_failed" || out.Advance || h.repo.calls["complete"] != 0 {
				t.Fatalf("metadata/cap accepted kind=%s out=%+v err=%v", kind, out, err)
			}
			wantClocks := 3
			if kind == "oversize" {
				wantClocks = 2
			}
			if h.clockCalls != wantClocks {
				t.Fatalf("oversize reached observation/parser clock=%d want=%d", h.clockCalls, wantClocks)
			}
			page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 200})
			if err != nil || len(page.Enrichments) != 0 {
				t.Fatalf("invalid envelope produced evidence=%+v err=%v", page, err)
			}
		})
	}
}

func TestRefreshOnceOnePageCursorGuardsBeforeUUID(t *testing.T) {
	for _, kind := range []string{"skip", "negative", "too-many-scanned", "targets-exceed-scanned", "nonprogress", "backward", "empty-last", "exhausted-last", "bad-last", "duplicate-target", "noncanonical-cve"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, false)
			h := harness(t, db)
			page := store.SecurityEnrichmentRefreshTargetPage{Targets: []store.SecurityEnrichmentRefreshTarget{}, Scanned: 1, After: "zz-last"}
			valid := store.SecurityEnrichmentRefreshTarget{FindingID: "zz-a", CVEID: "CVE-2026-1234", Revision: strings.Repeat("a", 64)}
			switch kind {
			case "negative":
				page.Scanned = -1
			case "too-many-scanned":
				page.Scanned = 201
			case "targets-exceed-scanned":
				page.Targets = []store.SecurityEnrichmentRefreshTarget{valid, valid}
			case "nonprogress":
				page.After = "previous"
			case "backward":
				page.After = "a-before"
			case "empty-last":
				page.After = ""
			case "exhausted-last":
				page.Scanned = 0
			case "bad-last":
				page.After = "zz-\x00"
			case "duplicate-target":
				page.Scanned = 2
				page.Targets = []store.SecurityEnrichmentRefreshTarget{valid, valid}
			case "noncanonical-cve":
				valid.CVEID = " cve-2026-1234 "
				page.Targets = []store.SecurityEnrichmentRefreshTarget{valid}
			}
			h.repo.page = &page
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", After: "previous", Limit: 200})
			if kind == "skip" {
				if err != nil || out.Outcome != "no_targets" || !out.Advance || out.NextAfter != "zz-last" || out.RunID != "" {
					t.Fatalf("all-ineligible page did not advance last scan=%+v err=%v", out, err)
				}
			} else if err == nil || out.Advance || out.NextAfter != "previous" {
				t.Fatalf("invalid page advanced kind=%s out=%+v err=%v", kind, out, err)
			}
			if h.repo.calls["query"] != 1 || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 || h.repo.calls["begin"] != 0 {
				t.Fatalf("invalid/empty page started work calls=%v", h.repo.calls)
			}
		})
	}
}

func TestRefreshOnceRequiresInjectedDependenciesAndBoundedRequest(t *testing.T) {
	db := contractStore(t, false)
	for _, kind := range []string{"store", "typed-nil-store", "fetcher", "typed-nil-fetcher", "clock", "uuid", "source", "limit", "cursor"} {
		t.Run(kind, func(t *testing.T) {
			h := harness(t, db)
			request := Request{Connector: "epss_feed", Limit: 200}
			switch kind {
			case "store":
				h.service.Store = nil
			case "typed-nil-store":
				var absent *store.Store
				h.service.Store = absent
			case "fetcher":
				h.service.Fetcher = nil
			case "typed-nil-fetcher":
				var absent *contractFetcher
				h.service.Fetcher = absent
			case "clock":
				h.service.Clock = nil
			case "uuid":
				h.service.NewUUID = nil
			case "source":
				request.Connector = "epss_offline"
			case "limit":
				request.Limit = 201
			case "cursor":
				request.After = "bad\x00"
			}
			out, err := h.service.RefreshOnce(context.Background(), request)
			if err == nil || out.Advance || h.repo.calls["query"] != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
				t.Fatalf("invalid injection/request started work kind=%s out=%+v err=%v", kind, out, err)
			}
		})
	}
}

func TestRefreshOnceSuccessfulWriteKeepsLegacyStateAndExactDigest(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	before, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
	if err != nil || out.Outcome != "success" {
		t.Fatalf("success=%+v err=%v", out, err)
	}
	after, err := json.Marshal(db.List())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("orchestrator changed legacy alert records")
	}
	var completion store.SecurityEnrichmentRefreshCompletion
	if err := json.Unmarshal([]byte(h.repo.completeJSON), &completion); err != nil {
		t.Fatal(err)
	}
	state, err := db.ReconcileSecurityEnrichmentRefresh(context.Background(), completion)
	if err != nil || state.State != "success" {
		t.Fatalf("full captured completion does not reconcile=%+v err=%v", state, err)
	}
	if !reflect.DeepEqual(completion.Attempt.Targets, outPendingTargets(t, db)) {
		t.Fatal("success mutated finding target binding")
	}
}

func outPendingTargets(t *testing.T, db *store.Store) []store.SecurityEnrichmentRefreshTarget {
	t.Helper()
	page, err := db.QuerySecurityEnrichmentRefreshTargets(context.Background(), "", 200)
	if err != nil {
		t.Fatal(err)
	}
	return page.Targets
}

func TestRefreshOnceCommittedCompletionRecoversAfterOriginalCancellation(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.repo.completeAfter = true
	h.repo.onComplete = cancel
	out, err := h.service.RefreshOnce(ctx, Request{Connector: "epss_feed", Limit: 200})
	if err != nil || out.Outcome != "success" || !out.Advance || out.Pending != nil || ctx.Err() == nil {
		t.Fatalf("committed write was falsely canceled/failed=%+v err=%v", out, err)
	}
	if h.repo.calls["reconcile"] != 1 || h.repo.calls["fail"] != 0 || h.fetchCalls != 1 || h.uuidCalls != 1 || len(h.repo.cleanupErrors) != 1 || h.repo.cleanupErrors[0] != nil {
		t.Fatalf("canceled post-commit recovery retried/degraded calls=%v", h.repo.calls)
	}
}

func TestRefreshOnceInvalidUUIDFactoryNeverReachesBegin(t *testing.T) {
	for _, returnsError := range []bool{false, true} {
		db := contractStore(t, true)
		h := harness(t, db)
		h.service.NewUUID = func() (string, error) {
			h.uuidCalls++
			if returnsError {
				return "", errors.New("PRIVATE-UUID-error")
			}
			return "invalid-uuid", nil
		}
		out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
		if err == nil || out.RunID != "" || out.Pending != nil || out.Advance || h.uuidCalls != 1 || h.repo.calls["begin"] != 0 || h.fetchCalls != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid UUID reached write=%+v err=%v calls=%v", out, err, h.repo.calls)
		}
	}
}

func TestRefreshOnceAllEligiblePageCannotSkipBeyondLastTarget(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "all-eligible"
		if partial {
			name = "partially-eligible"
		}
		t.Run(name, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			page, err := db.QuerySecurityEnrichmentRefreshTargets(context.Background(), "", 200)
			if err != nil || page.Scanned != 1 || len(page.Targets) != 1 {
				t.Fatalf("fixture page=%+v err=%v", page, err)
			}
			page.After = "zz-last-scanned-ineligible"
			if partial {
				page.Scanned++
			}
			h.repo.page = &page
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if !partial {
				if err == nil || out.Outcome != "invalid" || out.Code != "invalid_page" || out.Advance || out.NextAfter != "" || out.RunID != "" || out.Pending != nil || h.clockCalls != 0 || h.uuidCalls != 0 || h.repo.calls["begin"] != 0 || h.fetchCalls != 0 {
					t.Fatalf("all-eligible page skipped unseen rows=%+v err=%v calls=%v", out, err, h.repo.calls)
				}
			} else if err != nil || out.Outcome != "success" || !out.Advance || out.NextAfter != page.After || h.repo.calls["begin"] != 1 || h.uuidCalls != 1 || h.fetchCalls != 1 {
				t.Fatalf("legitimate ineligible tail was rejected=%+v err=%v calls=%v", out, err, h.repo.calls)
			}
		})
	}
}
