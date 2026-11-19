package enrichmentrefresh

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestManualControllerContractResponseLossReplaysWithoutServiceIO(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000001"
	request := Request{Connector: "epss_feed", Limit: 200}
	first, replay, err := controller.Call(context.Background(), id, request)
	if err != nil {
		t.Fatalf("manual controller call failed: %v", err)
	}
	if replay || first.OperationID != id || first.Request != request || first.State != "resolved" || first.Result.Outcome != "success" || first.Result.RunID == id || !first.Result.Advance {
		t.Fatalf("first manual operation=%+v replay=%v", first, replay)
	}
	// Simulate a lost outer response: retry the same operation/request instead
	// of inventing a service UUID, source clock or replacement operation.
	again, replay, err := controller.Call(context.Background(), id, request)
	if err != nil || !replay || !reflect.DeepEqual(again, first) {
		t.Fatalf("response-loss replay=%+v replay=%v err=%v", again, replay, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || h.repo.calls["begin"] != 1 || h.repo.calls["complete"] != 1 {
		t.Fatalf("cached replay repeated service work: uuid=%d fetch=%d clock=%d calls=%v", h.uuidCalls, h.fetchCalls, h.clockCalls, h.repo.calls)
	}
}

func TestManualControllerContractPendingAndSnapshotKeepOwnedFullCompletion(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.completeAfter, h.repo.reconcileError = true, true
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000002"
	request := Request{Connector: "epss_feed", Limit: 200}
	first, replay, err := controller.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || replay || first.State != "pending" || first.Result.Pending == nil || first.Result.Pending.Completion == nil {
		t.Fatalf("manual controller pending failed: %+v replay=%v err=%v", first, replay, err)
	}
	want := h.repo.completeJSON
	wantPending := jsonValue(t, first.Result.Pending)
	if jsonValue(t, first.Result.Pending.Completion) != want {
		t.Fatal("returned pending lost full prepared completion")
	}
	first.Result.Pending.Completion.OriginalDigest = "caller-mutated"
	first.Result.Pending.Attempt.Targets[0].CVEID = "CVE-2026-9999"
	snapshot, ok := controller.Snapshot(id)
	if !ok || snapshot.Result.Pending == nil || jsonValue(t, snapshot.Result.Pending) != wantPending || jsonValue(t, snapshot.Result.Pending.Completion) != want {
		t.Fatal("caller mutation damaged retained full completion")
	}
	snapshot.Result.Pending.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
	*snapshot.Result.Pending.Completion.Feed.Entries[0].EPSS = 1
	again, replay, err := controller.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || !replay || again.Result.Pending == nil || jsonValue(t, again.Result.Pending) != wantPending || jsonValue(t, again.Result.Pending.Completion) != want {
		t.Fatalf("owned snapshot/replay lost pending: %+v replay=%v err=%v", again, replay, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || h.repo.calls["complete"] != 1 || h.repo.calls["reconcile"] != 1 {
		t.Fatalf("pending replay performed service/readback I/O: %v", h.repo.calls)
	}
}

func TestManualControllerContractBeginReadbackNeverAcquiresFetchOwnership(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.beginAfter = true
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000003"
	first, _, err := controller.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || first.Result.Pending == nil || first.Result.Pending.Completion != nil {
		t.Fatalf("manual controller Begin pending failed: %+v err=%v", first, err)
	}
	kept := jsonValue(t, first.Result.Pending)
	again, err := controller.Reconcile(context.Background(), id)
	if !errors.Is(err, ErrPending) || again.State != "pending" || jsonValue(t, again.Result.Pending) != kept || again.Result.Advance {
		t.Fatalf("running readback changed ownership: %+v err=%v", again, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 0 || h.clockCalls != 1 || h.repo.calls["begin"] != 1 || h.repo.calls["read"] != 2 || h.repo.calls["fail"] != 0 || h.repo.calls["complete"] != 0 {
		t.Fatalf("manual Begin readback started replacement work: %v", h.repo.calls)
	}
}

func manualOperationID(number int) string {
	return fmt.Sprintf("40000000-0000-4000-8000-%012d", number)
}

func manualCounts(t *testing.T, h *fixtureHarness) string {
	t.Helper()
	return fmt.Sprintf("%d/%d/%d/%s", h.clockCalls, h.uuidCalls, h.fetchCalls, jsonValue(t, h.repo.calls))
}

func flexibleManualHarness(t *testing.T, db *store.Store) *fixtureHarness {
	t.Helper()
	h := harness(t, db)
	h.service.Clock = func() time.Time {
		value := h.times[0].Add(time.Duration(h.clockCalls) * time.Minute)
		h.clockCalls++
		return value
	}
	h.service.NewUUID = func() (string, error) {
		h.uuidCalls++
		return fmt.Sprintf("30000000-0000-4000-8000-%012d", 1000+h.uuidCalls), nil
	}
	h.service.Fetcher = fetchFunc(func(ctx context.Context, source string) ([]byte, error) {
		h.fetchCalls++
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if h.fetchError != nil {
			return nil, h.fetchError
		}
		if source == "epss" {
			return h.data, nil
		}
		if source != "kev" {
			t.Fatal("unexpected domain source")
		}
		return []byte(`{"catalogVersion":"synthetic-manual.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`), nil
	})
	return h
}

func TestManualControllerRejectsDependenciesAndBindingsWithoutIO(t *testing.T) {
	db := contractStore(t, true)
	for _, kind := range []string{"store", "typed-nil-store", "fetcher", "typed-nil-fetcher", "clock", "uuid"} {
		h := harness(t, db)
		switch kind {
		case "store":
			h.service.Store = nil
		case "typed-nil-store":
			var absent *observedRepository
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
		}
		before := manualCounts(t, h)
		c, err := NewManualController(h.service)
		if !errors.Is(err, ErrManualInvalid) || c != nil || manualCounts(t, h) != before {
			t.Fatalf("constructor kind=%s performed IO/accepted missing dependency: %v", kind, err)
		}
	}
	h := harness(t, db)
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"id", "uppercase-id", "source", "limit-zero", "limit-large", "cursor-control", "cursor-size", "cursor-utf8", "nil-context", "canceled"} {
		id, request, ctx := manualOperationID(10), Request{Connector: "epss_feed", Limit: 200}, context.Background()
		switch kind {
		case "id":
			id = "not-an-operation"
		case "uppercase-id":
			id = "ABCDEF00-0000-4000-8000-000000000010"
		case "source":
			request.Connector = "epss"
		case "limit-zero":
			request.Limit = 0
		case "limit-large":
			request.Limit = 201
		case "cursor-control":
			request.After = "bad\x00"
		case "cursor-size":
			request.After = strings.Repeat("x", 129)
		case "cursor-utf8":
			request.After = "\xff"
		case "nil-context":
			ctx = nil
		case "canceled":
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			ctx = canceled
		}
		before := manualCounts(t, h)
		_, replay, err := c.Call(ctx, id, request)
		if err == nil || replay || manualCounts(t, h) != before {
			t.Fatalf("invalid kind=%s acquired IO or slot: replay=%v err=%v", kind, replay, err)
		}
		if _, ok := c.Snapshot(id); ok {
			t.Fatalf("invalid kind=%s consumed retention slot", kind)
		}
	}
	before := manualCounts(t, h)
	if _, err := c.Reconcile(context.Background(), manualOperationID(99)); !errors.Is(err, ErrManualNotFound) {
		t.Fatal("unknown operation read back external state")
	}
	if _, err := c.Reconcile(nil, manualOperationID(99)); !errors.Is(err, ErrManualInvalid) { //nolint:staticcheck // nil context is the test input: the callee must reject it explicitly
		t.Fatal("nil recovery context accepted")
	}
	var absent *ManualController
	if _, _, err := absent.Call(context.Background(), manualOperationID(99), Request{Connector: "epss_feed", Limit: 1}); !errors.Is(err, ErrManualInvalid) {
		t.Fatal("nil controller accepted")
	}
	if _, ok := absent.Snapshot(manualOperationID(99)); ok || manualCounts(t, h) != before {
		t.Fatal("invalid controller/recovery performed IO")
	}
}

func TestManualControllerFullRetentionStillReplaysAndNeverEvicts(t *testing.T) {
	db := contractStore(t, false)
	h := harness(t, db)
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= manualMaxRecords; i++ {
		request := Request{Connector: "epss_feed", After: fmt.Sprintf("after-%02d", i), Limit: 1}
		op, replay, err := c.Call(context.Background(), manualOperationID(i), request)
		if err != nil || replay || op.State != "resolved" || !op.Result.Exhausted || op.Result.NextAfter != request.After {
			t.Fatalf("slot=%d result=%+v replay=%v err=%v", i, op, replay, err)
		}
	}
	before := manualCounts(t, h)
	request := Request{Connector: "epss_feed", After: "after-01", Limit: 1}
	if _, replay, err := c.Call(context.Background(), manualOperationID(1), request); err != nil || !replay {
		t.Fatalf("full retention blocked cached replay: %v", err)
	}
	changed := request
	changed.Limit = 2
	if _, _, err := c.Call(context.Background(), manualOperationID(1), changed); !errors.Is(err, ErrManualConflict) {
		t.Fatal("full retention hid same-ID content conflict")
	}
	if _, _, err := c.Call(context.Background(), manualOperationID(17), request); !errors.Is(err, ErrManualCapacity) {
		t.Fatal("retention automatically evicted/replaced a record")
	}
	if _, ok := c.Snapshot(manualOperationID(17)); ok || manualCounts(t, h) != before {
		t.Fatal("full rejection allocated a slot or performed IO")
	}
	for i := 1; i <= manualMaxRecords; i++ {
		if _, ok := c.Snapshot(manualOperationID(i)); !ok {
			t.Fatalf("retained operation %d evicted", i)
		}
	}
}

func TestManualControllerPendingBlocksFreshSourceAndStrictlyBindsOperation(t *testing.T) {
	db := contractStore(t, true)
	h := flexibleManualHarness(t, db)
	h.repo.completeAfter, h.repo.reconcileError = true, true
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Connector: "epss_feed", Limit: 200}
	first, _, err := c.Call(context.Background(), manualOperationID(20), request)
	if !errors.Is(err, ErrPending) || first.State != "pending" {
		t.Fatalf("pending source fixture failed: %+v %v", first, err)
	}
	before := manualCounts(t, h)
	for _, changed := range []Request{
		{Connector: "epss_feed", Limit: 199},
		{Connector: "epss_feed", After: "different-cursor", Limit: 200},
		{Connector: "kev_feed", Limit: 200},
	} {
		if _, _, err := c.Call(context.Background(), manualOperationID(20), changed); !errors.Is(err, ErrManualConflict) {
			t.Fatal("same operation ID accepted different canonical content")
		}
	}
	if _, _, err := c.Call(context.Background(), manualOperationID(21), Request{Connector: "epss_feed", After: "another-page", Limit: 1}); !errors.Is(err, ErrManualPendingSource) {
		t.Fatal("unresolved source minted a fresh operation")
	}
	if manualCounts(t, h) != before {
		t.Fatal("binding/source gate performed dependency IO")
	}
	// An independent connector is not implicitly made pending by the EPSS
	// outcome, although the global in-flight call limit still applies.
	h.repo.completeAfter, h.repo.reconcileError = false, false
	second, _, err := c.Call(context.Background(), manualOperationID(22), Request{Connector: "kev_feed", Limit: 200})
	if err != nil || second.State != "resolved" || second.Result.Outcome != "success" || h.uuidCalls != 2 || h.fetchCalls != 2 {
		t.Fatalf("unrelated source incorrectly blocked: %+v %v", second, err)
	}
}

func TestManualControllerReservesSlotWithoutHoldingMutexAcrossServiceIO(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(30)
	request := Request{Connector: "epss_feed", Limit: 200}
	h.fetchHook = func(context.Context) {
		type observed struct {
			err error
		}
		done := make(chan observed, 1)
		go func() {
			op, ok := c.Snapshot(id)
			if !ok || op.State != "calling" || op.Request != request {
				done <- observed{errors.New("slot not reserved before service call")}
				return
			}
			if _, _, err := c.Call(context.Background(), manualOperationID(31), Request{Connector: "kev_feed", Limit: 1}); !errors.Is(err, ErrManualBusy) {
				done <- observed{errors.New("fresh concurrent call acquired IO")}
				return
			}
			if _, replay, err := c.Call(context.Background(), id, request); !errors.Is(err, ErrManualBusy) || !replay {
				done <- observed{errors.New("calling slot was executed again")}
				return
			}
			if _, err := c.Reconcile(context.Background(), id); !errors.Is(err, ErrManualBusy) {
				done <- observed{errors.New("recovery overlapped service IO")}
				return
			}
			done <- observed{}
		}()
		select {
		case result := <-done:
			if result.err != nil {
				t.Fatal(result.err)
			}
		case <-time.After(time.Second):
			t.Fatal("controller mutex held over fetch/Store IO")
		}
	}
	if _, _, err := c.Call(context.Background(), id, request); err != nil {
		t.Fatal(err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 1 || h.repo.calls["read"] != 0 || h.repo.calls["reconcile"] != 0 {
		t.Fatalf("concurrent refusal caused IO: %v", h.repo.calls)
	}
	if _, ok := c.Snapshot(manualOperationID(31)); ok {
		t.Fatal("busy refusal consumed retention slot")
	}
}

type manualCaptureRepository struct {
	Repository
	completion store.SecurityEnrichmentRefreshCompletion
	afterRead  func()
}

func (r *manualCaptureRepository) CompleteSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentImportResult, error) {
	r.completion = c
	return r.Repository.CompleteSecurityEnrichmentRefresh(ctx, c)
}

func (r *manualCaptureRepository) ReconcileSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentRefreshState, error) {
	state, err := r.Repository.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if r.afterRead != nil {
		r.afterRead()
	}
	return state, err
}

func TestManualControllerNestedCopiesKeepDependencyAndOuterMutationOut(t *testing.T) {
	for _, source := range []string{"epss", "kev", "empty-entries"} {
		t.Run(source, func(t *testing.T) {
			db := contractStore(t, true)
			h := flexibleManualHarness(t, db)
			h.repo.completeAfter, h.repo.reconcileError = true, true
			capture := &manualCaptureRepository{Repository: h.repo}
			h.service.Store = capture
			connector := source + "_feed"
			if source == "empty-entries" {
				connector = "epss_feed"
				h.data = []byte(strings.ReplaceAll(contractEPSS, "CVE-2026-1234", "CVE-2026-5678"))
			}
			c, err := NewManualController(h.service)
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(40)
			op, _, err := c.Call(context.Background(), id, Request{Connector: connector, Limit: 200})
			if !errors.Is(err, ErrPending) || op.Result.Pending == nil || op.Result.Pending.Completion == nil {
				t.Fatalf("pending fixture failed: %+v %v", op, err)
			}
			want := jsonValue(t, op.Result.Pending)
			if jsonValue(t, op.Result.Pending.Completion) != h.repo.completeJSON {
				t.Fatal("copy changed nil/empty slices or original metadata")
			}
			op.Result.Pending.Completion.Attempt.Targets[0].Revision = strings.Repeat("b", 64)
			op.Result.Pending.Attempt.Targets[0].FindingID = "caller-changed"
			op.Result.Pending.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
			// The Store wrapper retained aliases of the original Service
			// argument. Mutating it after return must not alter controller state.
			capture.completion.Attempt.Targets[0].CVEID = "CVE-2026-9999"
			if len(op.Result.Pending.Completion.Feed.Entries) != 0 {
				entry := &op.Result.Pending.Completion.Feed.Entries[0]
				original := &capture.completion.Feed.Entries[0]
				if entry.EPSS != nil {
					*entry.EPSS, *entry.Percentile = 1, 1
					*original.EPSS, *original.Percentile = 0.5, 0.5
				}
				if entry.KEVDateAdded != nil {
					*entry.KEVDateAdded = entry.KEVDateAdded.AddDate(0, 0, 1)
					*original.KEVDateAdded = original.KEVDateAdded.AddDate(0, 0, 2)
				}
			}
			snapshot, ok := c.Snapshot(id)
			if !ok || jsonValue(t, snapshot.Result.Pending) != want {
				t.Fatal("nested caller/dependency alias damaged retained evidence")
			}
			snapshot.Result.Pending.Completion.OriginalDigest = "snapshot-changed"
			again, _ := c.Snapshot(id)
			if jsonValue(t, again.Result.Pending) != want {
				t.Fatal("Snapshot shares retained nested pointers")
			}
		})
	}
}

func TestManualControllerReadonlyResolutionKeepsUUIDClocksAndReceipts(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.completeAfter, h.repo.reconcileError = true, true
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(50)
	op, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	before, err := db.QueryIngestRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	clock, uuid, fetch := h.clockCalls, h.uuidCalls, h.fetchCalls
	h.repo.reconcileError = false
	resolved, err := c.Reconcile(context.Background(), id)
	if err != nil || resolved.State != "resolved" || resolved.Result.Outcome != "success" || resolved.Result.RunID != op.Result.RunID || !resolved.Result.Advance || resolved.Result.NextAfter != op.Result.ScanAfter || resolved.Result.Pending != nil {
		t.Fatalf("verified success not resolved with stored cursor: %+v %v", resolved, err)
	}
	after, err := db.QueryIngestRuns(context.Background())
	if err != nil || jsonValue(t, before) != jsonValue(t, after) || h.clockCalls != clock || h.uuidCalls != uuid || h.fetchCalls != fetch || h.repo.calls["complete"] != 1 || h.repo.calls["fail"] != 0 || h.repo.calls["reconcile"] != 2 {
		t.Fatalf("readonly resolution repeated writes/clocks/fetch or changed receipts: %v", h.repo.calls)
	}
	counts := manualCounts(t, h)
	if _, err := c.Reconcile(context.Background(), id); err != nil || manualCounts(t, h) != counts {
		t.Fatal("resolved operation read back or executed again")
	}
}

func TestManualControllerUnknownAndCanceledReadbackKeepFullPending(t *testing.T) {
	for _, kind := range []string{"begin-missing", "completion-running", "read-error", "canceled-before", "canceled-after-read"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			switch kind {
			case "begin-missing":
				h.repo.beginBefore = true
			case "completion-running":
				h.repo.completeBefore = true
			default:
				h.repo.completeAfter, h.repo.reconcileError = true, true
			}
			capture := &manualCaptureRepository{Repository: h.repo}
			h.service.Store = capture
			c, err := NewManualController(h.service)
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(60)
			op, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
			if !errors.Is(err, ErrPending) {
				t.Fatal(err)
			}
			want := jsonValue(t, op.Result.Pending)
			clock, uuid, fetch := h.clockCalls, h.uuidCalls, h.fetchCalls
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled-before" {
				cancel()
			}
			if kind == "canceled-after-read" {
				h.repo.reconcileError = false
				capture.afterRead = cancel
			}
			again, err := c.Reconcile(ctx, id)
			if kind == "canceled-before" || kind == "canceled-after-read" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel not preserved: %v", err)
				}
			} else if !errors.Is(err, ErrPending) {
				t.Fatalf("unknown readback became resolved: %+v %v", again, err)
			}
			snapshot, ok := c.Snapshot(id)
			if !ok || snapshot.State != "pending" || snapshot.Result.Advance || jsonValue(t, snapshot.Result.Pending) != want || h.clockCalls != clock || h.uuidCalls != uuid || h.fetchCalls != fetch || h.repo.calls["complete"] > 1 || h.repo.calls["fail"] != 0 {
				t.Fatalf("unknown/cancel lost evidence or acquired ownership: %+v calls=%v", snapshot, h.repo.calls)
			}
		})
	}
}

func TestManualControllerFailureCopyAndExactReadonlyRecovery(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.fetchError = errors.New("PRIVATE-synthetic-fetch-error")
	h.repo.failAfter, h.repo.readError = true, true
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(70)
	op, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || op.Result.Pending == nil || op.Result.Pending.ExpectedFailure == nil {
		t.Fatalf("failure pending not retained: %+v %v", op, err)
	}
	want := jsonValue(t, op.Result.Pending)
	op.Result.Pending.ExpectedFailure.Code = "caller-changed"
	op.Result.Pending.ExpectedFailure.FinishedAt = op.Result.Pending.ExpectedFailure.FinishedAt.Add(time.Hour)
	snapshot, _ := c.Snapshot(id)
	if jsonValue(t, snapshot.Result.Pending) != want {
		t.Fatal("failure pointer mutation damaged exact retained code/finish")
	}
	h.repo.readError = false
	clock, uuid, fetch := h.clockCalls, h.uuidCalls, h.fetchCalls
	resolved, err := c.Reconcile(context.Background(), id)
	if err != nil || resolved.State != "resolved" || resolved.Result.Outcome != "failed" || resolved.Result.Code != "fetch_failed" || resolved.Result.Advance || resolved.Result.Pending != nil || resolved.Result.NextAfter != "" {
		t.Fatalf("exact failure did not resolve readonly: %+v %v", resolved, err)
	}
	if h.clockCalls != clock || h.uuidCalls != uuid || h.fetchCalls != fetch || h.repo.calls["fail"] != 1 || h.repo.calls["read"] != 2 || strings.Contains(jsonValue(t, resolved), "PRIVATE") {
		t.Fatalf("failure recovery regenerated/wrote/leaked: %v", h.repo.calls)
	}
}

func TestManualControllerCopiesServiceValueAndReleasesMutexForReadback(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.completeAfter, h.repo.reconcileError = true, true
	capture := &manualCaptureRepository{Repository: h.repo}
	h.service.Store = capture
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	// Replacing the caller's Service fields must not replace injected ownership.
	h.service.Store, h.service.Fetcher, h.service.Clock, h.service.NewUUID = nil, nil, nil, nil
	id := manualOperationID(80)
	op, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) {
		t.Fatalf("copied Service lost its dependencies: %+v %v", op, err)
	}
	h.repo.reconcileError = false
	capture.afterRead = func() {
		done := make(chan error, 1)
		go func() {
			snapshot, ok := c.Snapshot(id)
			if !ok || snapshot.State != "pending" {
				done <- errors.New("readback lost retained pending slot")
				return
			}
			if _, _, err := c.Call(context.Background(), manualOperationID(81), Request{Connector: "kev_feed", Limit: 1}); !errors.Is(err, ErrManualBusy) {
				done <- errors.New("readback allowed overlapping fresh work")
				return
			}
			if _, err := c.Reconcile(context.Background(), id); !errors.Is(err, ErrManualBusy) {
				done <- errors.New("readback recursively acquired IO")
				return
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("controller mutex held over readonly Store IO")
		}
	}
	resolved, err := c.Reconcile(context.Background(), id)
	if err != nil || resolved.Result.Outcome != "success" || h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || h.repo.calls["reconcile"] != 2 {
		t.Fatalf("readback reentry/injection changed operation: %+v %v calls=%v", resolved, err, h.repo.calls)
	}
}

func TestManualControllerRetainsOnlyClosedErrorClassification(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.queryError = true
	c, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(90)
	request := Request{Connector: "epss_feed", Limit: 200}
	op, _, err := c.Call(context.Background(), id, request)
	if !errors.Is(err, ErrManualExecution) || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(jsonValue(t, op), "PRIVATE") || op.Result.Pending != nil {
		t.Fatalf("raw dependency error retained: %+v %v", op, err)
	}
	before := manualCounts(t, h)
	again, replay, err := c.Call(context.Background(), id, request)
	if !errors.Is(err, ErrManualExecution) || !replay || !reflect.DeepEqual(again, op) || manualCounts(t, h) != before || h.uuidCalls != 0 || h.clockCalls != 0 || h.fetchCalls != 0 {
		t.Fatal("failed response-loss replay acquired dependency work")
	}
}

type manualArgumentMutatingRepository struct {
	Repository
	mutate    bool
	mutations int
}

func (r *manualArgumentMutatingRepository) ReadSecurityEnrichmentRefreshAttempt(ctx context.Context, attempt store.SecurityEnrichmentRefreshAttempt, expected *store.SecurityEnrichmentRefreshFailure) (store.SecurityEnrichmentRefreshState, error) {
	state, err := r.Repository.ReadSecurityEnrichmentRefreshAttempt(ctx, attempt, expected)
	if r.mutate && err == nil {
		r.mutations++
		if len(attempt.Targets) != 0 {
			attempt.Targets[0].FindingID = "PRIVATE-mutated-target"
		}
		if expected != nil {
			// Mutate only after real Store readback has verified the original
			// failed receipt. These must never become resolution inputs.
			expected.Code = "PRIVATE-mutated"
			expected.FinishedAt = expected.FinishedAt.Add(time.Hour)
		}
	}
	return state, err
}

func (r *manualArgumentMutatingRepository) ReconcileSecurityEnrichmentRefresh(ctx context.Context, completion store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentRefreshState, error) {
	state, err := r.Repository.ReconcileSecurityEnrichmentRefresh(ctx, completion)
	if r.mutate && err == nil {
		r.mutations++
		if len(completion.Attempt.Targets) != 0 {
			completion.Attempt.Targets[0].FindingID = "PRIVATE-mutated-target"
		}
		if len(completion.Feed.SelectedCVEs) != 0 {
			completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
		}
		if len(completion.Feed.Entries) != 0 {
			entry := &completion.Feed.Entries[0]
			if entry.EPSS != nil {
				*entry.EPSS = 1
			}
			if entry.Percentile != nil {
				*entry.Percentile = 1
			}
			if entry.KEVDateAdded != nil {
				*entry.KEVDateAdded = entry.KEVDateAdded.Add(time.Hour)
			}
		}
	}
	return state, err
}

func manualPrivatePendingJSON(t *testing.T, c *ManualController, id string) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.operations[id]
	if !ok {
		t.Fatal("private operation record absent")
	}
	return jsonValue(t, record.retained)
}

func TestManualControllerReadbackArgumentMutationCannotSupplyResolvedValues(t *testing.T) {
	for _, kind := range []string{"failure", "completion"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			if kind == "failure" {
				h.fetchError = errors.New("PRIVATE-synthetic-fetch-error")
				h.repo.failAfter, h.repo.readError = true, true
			} else {
				h.repo.completeAfter, h.repo.reconcileError = true, true
			}
			mutator := &manualArgumentMutatingRepository{Repository: h.repo}
			h.service.Store = mutator
			c, err := NewManualController(h.service)
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(100)
			request := Request{Connector: "epss_feed", Limit: 200}
			pending, _, err := c.Call(context.Background(), id, request)
			if !errors.Is(err, ErrPending) || pending.Result.Pending == nil {
				t.Fatalf("pending fixture failed: %+v %v", pending, err)
			}
			private := manualPrivatePendingJSON(t, c, id)
			clock, uuid, fetch := h.clockCalls, h.uuidCalls, h.fetchCalls
			begin, complete, fail := h.repo.calls["begin"], h.repo.calls["complete"], h.repo.calls["fail"]
			h.repo.readError, h.repo.reconcileError, mutator.mutate = false, false, true
			resolved, err := c.Reconcile(context.Background(), id)
			if err != nil || resolved.State != "resolved" || resolved.Result.RunID != pending.Result.RunID || resolved.Result.Pending != nil || mutator.mutations != 1 {
				t.Fatalf("real receipt did not resolve once: %+v err=%v mutations=%d", resolved, err, mutator.mutations)
			}
			if kind == "failure" {
				if resolved.Result.Outcome != "failed" || resolved.Result.Code != "fetch_failed" || resolved.Result.Advance || resolved.Result.NextAfter != request.After || h.repo.calls["read"] != 2 {
					t.Fatalf("dependency mutation supplied failure result: %+v", resolved)
				}
			} else if resolved.Result.Outcome != "success" || resolved.Result.Code != "" || !resolved.Result.Advance || resolved.Result.NextAfter != pending.Result.ScanAfter || h.repo.calls["reconcile"] != 2 {
				t.Fatalf("dependency mutation supplied completion/cursor result: %+v", resolved)
			}
			if manualPrivatePendingJSON(t, c, id) != private || strings.Contains(jsonValue(t, resolved), "PRIVATE") || h.clockCalls != clock || h.uuidCalls != uuid || h.fetchCalls != fetch || h.repo.calls["begin"] != begin || h.repo.calls["complete"] != complete || h.repo.calls["fail"] != fail {
				t.Fatal("readback changed private evidence, leaked mutation or performed fresh write/clock/fetch")
			}
			counts := manualCounts(t, h)
			snapshot, ok := c.Snapshot(id)
			replay, cached, err := c.Call(context.Background(), id, request)
			if !ok || err != nil || !cached || !reflect.DeepEqual(snapshot, resolved) || !reflect.DeepEqual(replay, resolved) || manualCounts(t, h) != counts || manualPrivatePendingJSON(t, c, id) != private {
				t.Fatalf("resolved snapshot/cached replay changed owned result: %+v %+v %v", snapshot, replay, err)
			}
			again, err := c.Reconcile(context.Background(), id)
			if err != nil || !reflect.DeepEqual(again, resolved) || manualCounts(t, h) != counts || mutator.mutations != 1 {
				t.Fatal("resolved recovery repeated dependency I/O")
			}
		})
	}
}
