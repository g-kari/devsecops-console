package enrichmentrefresh

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type recoveryRepository struct {
	*faultJournalRepository
	db           *store.Store
	inspectCalls int
	inspectHook  func(context.Context, *store.SecurityEnrichmentOperationInspection, *error)
}

func (r *recoveryRepository) InspectSecurityEnrichmentOperation(ctx context.Context, id string) (store.SecurityEnrichmentOperationInspection, error) {
	r.inspectCalls++
	state, err := r.db.InspectSecurityEnrichmentOperation(ctx, id)
	if r.inspectHook != nil {
		r.inspectHook(ctx, &state, &err)
	}
	return state, err
}

func recoveryFixture(t *testing.T, failed bool) (*ManualController, *recoveryRepository, *fixtureHarness, string, ManualOperation) {
	t.Helper()
	db := contractStore(t, true)
	h := harness(t, db)
	if failed {
		h.fetchError = errSyntheticStore
	}
	r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
	r.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
		if request.Checkpoint.Stage == enrichmentjournal.Returned {
			*err = errSyntheticStore
		}
	}
	r.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, _ *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
		*err = errSyntheticStore
	}
	c, err := NewRecoverableJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(801)
	pending, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || pending.State != "pending" || pending.Result.Code != "preservation_unknown" {
		t.Fatalf("missing terminal acknowledgement fixture: %+v %v", pending, err)
	}
	return c, r, h, id, pending
}

func TestJournalTerminalRecoveryExactOriginalTerminalAndCachedReplay(t *testing.T) {
	for _, failed := range []bool{false, true} {
		c, r, h, id, pending := recoveryFixture(t, failed)
		want := cloneManualResult(c.operations[id].checkpoint.Result)
		private := adapterPrivateJSON(t, c, id)
		counts, appends, reads := manualCounts(t, h), r.appendCalls, r.readCalls
		out, err := c.ReconcileJournalTerminal(context.Background(), id)
		if err != nil || out.State != "resolved" || !reflect.DeepEqual(out.Result, want) || r.inspectCalls != 1 {
			t.Fatalf("original terminal not restored: %+v %v", out, err)
		}
		if c.operations[id].preservationUnknown || c.recovery.adapter.records[id].unknown || !c.recovery.adapter.records[id].acknowledged || c.operations[id].retained == nil || adapterPrivateJSON(t, c, id) != private {
			t.Fatal("resolution lost evidence or failed to clear both gates")
		}
		mutatePreservationPending(pending.Result.Pending)
		for i := 0; i < 2; i++ {
			again, err := c.ReconcileJournalTerminal(context.Background(), id)
			if err != nil || !reflect.DeepEqual(out, again) {
				t.Fatal("resolved recovery did not replay original")
			}
		}
		again, cached, err := c.Call(context.Background(), id, out.Request)
		if err != nil || !cached || !reflect.DeepEqual(out, again) || r.inspectCalls != 1 || manualCounts(t, h) != counts || r.appendCalls != appends || r.readCalls != reads {
			t.Fatal("recovery/replay performed business, append, clock, UUID or fetch work")
		}
	}
}

func TestJournalTerminalRecoveryRejectsUncertainProofWithoutChangingEvidence(t *testing.T) {
	for _, kind := range []string{"missing", "unknown", "error", "proof-error", "operation", "newer-head", "digest", "nil-checkpoint", "payload", "corrupt", "business", "receipt", "failed-receipt", "cancel-before", "cancel-after-read"} {
		t.Run(kind, func(t *testing.T) {
			c, r, h, id, pending := recoveryFixture(t, kind == "failed-receipt")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := adapterPrivateJSON(t, c, id)
			counts := manualCounts(t, h)
			r.inspectHook = func(_ context.Context, state *store.SecurityEnrichmentOperationInspection, err *error) {
				switch kind {
				case "missing", "unknown":
					state.State = kind
				case "error", "proof-error":
					*err = errSyntheticStore
				case "operation":
					state.OperationID = manualOperationID(802)
				case "newer-head":
					state.HeadSequence++
				case "digest":
					state.HeadDigest = "sha256:" + strings.Repeat("f", 64)
				case "nil-checkpoint":
					state.Checkpoint = nil
				case "payload":
					state.Checkpoint.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
				case "corrupt":
					state.Checkpoint.Version = 99
				case "business":
					state.Business.State = "failed"
				case "receipt":
					state.Business.Receipt = ""
				case "failed-receipt":
					state.Business.Receipt = "unexpected-failure-receipt"
				case "cancel-after-read":
					cancel()
				}
			}
			if kind == "cancel-before" {
				cancel()
			}
			_, err := c.ReconcileJournalTerminal(ctx, id)
			if err == nil {
				t.Fatal("uncertain proof resolved")
			}
			after, _ := c.Snapshot(id)
			if !reflect.DeepEqual(pending, after) || adapterPrivateJSON(t, c, id) != before || manualCounts(t, h) != counts || !c.operations[id].preservationUnknown || !c.recovery.adapter.records[id].unknown {
				t.Fatal("uncertain read changed private evidence or result")
			}
			if kind == "cancel-before" && r.inspectCalls != 0 {
				t.Fatal("cancelled caller acquired I/O")
			}
			r.inspectHook = nil
			if _, err := c.ReconcileJournalTerminal(context.Background(), id); err != nil {
				t.Fatalf("later explicit read could not resolve: %v", err)
			}
		})
	}
}

func TestJournalTerminalRecoveryBusyReentryAndIndependentSnapshots(t *testing.T) {
	c, r, h, id, pending := recoveryFixture(t, false)
	counts := manualCounts(t, h)
	r.inspectHook = func(ctx context.Context, _ *store.SecurityEnrichmentOperationInspection, _ *error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > cleanupBudget {
			t.Fatal("inspection missing caller-bounded cleanup deadline")
		}
		if _, err := c.ReconcileJournalTerminal(ctx, id); !errors.Is(err, ErrManualBusy) {
			t.Fatal("reentrant inspection was admitted")
		}
		if _, _, err := c.Call(ctx, manualOperationID(802), Request{Connector: "kev_feed", Limit: 1}); !errors.Is(err, ErrManualBusy) {
			t.Fatal("reentrant fresh call was admitted")
		}
		snapshot, ok := c.Snapshot(id)
		if !ok || !reflect.DeepEqual(snapshot, pending) {
			t.Fatal("pending snapshot unavailable during read")
		}
		mutatePreservationPending(snapshot.Result.Pending)
		cached, replay, err := c.Call(ctx, id, pending.Request)
		if !replay || !errors.Is(err, ErrPending) || !reflect.DeepEqual(cached, pending) {
			t.Fatal("snapshot mutation affected cached pending state")
		}
		if err := c.recovery.adapter.Preserve(ctx, *c.operations[id].checkpoint); !errors.Is(err, ErrManualBusy) {
			t.Fatal("adapter busy slot was not reserved")
		}
	}
	if _, err := c.ReconcileJournalTerminal(context.Background(), id); err != nil || r.inspectCalls != 1 || manualCounts(t, h) != counts {
		t.Fatalf("reentry changed outer resolution: %v", err)
	}
}

func TestJournalTerminalRecoveryAlreadyAcknowledgedAdapterAndFullCapacity(t *testing.T) {
	c, r, _, id, _ := recoveryFixture(t, false)
	// Model the precise boundary where adapter acknowledgement succeeds but the
	// preserving seam observes cancellation before publishing its terminal.
	c.recovery.adapter.records[id].unknown = false
	c.recovery.adapter.records[id].acknowledged = true
	for len(c.operations) < manualMaxRecords {
		other := manualOperationID(900 + len(c.operations))
		c.operations[other] = &manualRecord{operation: ManualOperation{OperationID: other, State: "resolved"}}
	}
	if _, err := c.ReconcileJournalTerminal(context.Background(), id); err != nil || r.inspectCalls != 1 || len(c.operations) != manualMaxRecords {
		t.Fatalf("acknowledged adapter or full retention blocked readonly resolution: %v", err)
	}
}

func TestJournalTerminalRecoveryRejectsEarlierStagesPendingAndOtherControllers(t *testing.T) {
	for _, stage := range []enrichmentjournal.Stage{enrichmentjournal.Reserved, enrichmentjournal.Begin, enrichmentjournal.Fail, enrichmentjournal.Complete, enrichmentjournal.Returned} {
		t.Run(string(stage), func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			if stage == enrichmentjournal.Fail {
				h.fetchError = errSyntheticStore
			}
			if stage == enrichmentjournal.Returned {
				h.repo.completeAfter, h.repo.reconcileError = true, true
			}
			r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
			r.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
				if request.Checkpoint.Stage == stage {
					*err = errSyntheticStore
				}
			}
			r.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, _ *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
				*err = errSyntheticStore
			}
			c, err := NewRecoverableJournalManualController(h.service, r)
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(803)
			pending, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
			if !errors.Is(err, ErrPending) {
				t.Fatalf("stage=%s did not become pending: %v", stage, err)
			}
			counts := manualCounts(t, h)
			out, err := c.ReconcileJournalTerminal(context.Background(), id)
			if !errors.Is(err, ErrPending) || !reflect.DeepEqual(out, pending) || r.inspectCalls != 0 || manualCounts(t, h) != counts {
				t.Fatal("unsupported stage acquired inspection or changed state")
			}
		})
	}
	c, r, h, id, pending := recoveryFixture(t, false)
	fresh, err := NewRecoverableJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.ReconcileJournalTerminal(context.Background(), id); !errors.Is(err, ErrManualNotFound) || r.inspectCalls != 0 {
		t.Fatal("new controller restored a foreign record")
	}
	old, err := NewJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.ReconcileJournalTerminal(context.Background(), id); !errors.Is(err, ErrManualInvalid) || r.inspectCalls != 0 {
		t.Fatal("old constructor gained recovery capability")
	}
	out, err := c.Reconcile(context.Background(), id)
	if !errors.Is(err, ErrPending) || !reflect.DeepEqual(out, pending) || r.inspectCalls != 0 {
		t.Fatal("ordinary Reconcile changed unknown acknowledgement contract")
	}
}

func TestJournalTerminalRecoveryCancellationDuringInspectionKeepsPending(t *testing.T) {
	c, r, _, id, pending := recoveryFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	r.inspectHook = func(readCtx context.Context, _ *store.SecurityEnrichmentOperationInspection, _ *error) {
		close(entered)
		<-release
		if readCtx.Err() == nil {
			t.Error("inspection context did not inherit cancellation")
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.ReconcileJournalTerminal(ctx, id)
		done <- err
	}()
	<-entered
	if _, err := c.ReconcileJournalTerminal(context.Background(), id); !errors.Is(err, ErrManualBusy) {
		t.Error("concurrent recovery was admitted")
	}
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error=%v", err)
	}
	out, _ := c.Snapshot(id)
	if !reflect.DeepEqual(out, pending) || !c.operations[id].preservationUnknown || !c.recovery.adapter.records[id].unknown {
		t.Fatal("cancelled inspection changed evidence or gates")
	}
}

func TestJournalTerminalRecoveryConstructorAndNoRunDoNotGrantInspection(t *testing.T) {
	db := contractStore(t, false)
	h := harness(t, db)
	var nilRepository *recoveryRepository
	for _, repository := range []RecoverableJournalRepository{nil, nilRepository} {
		if _, err := NewRecoverableJournalManualController(h.service, repository); !errors.Is(err, ErrManualInvalid) {
			t.Fatal("nil recovery repository accepted")
		}
	}
	r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
	bad := h.service
	bad.Clock = nil
	if _, err := NewRecoverableJournalManualController(bad, r); !errors.Is(err, ErrManualInvalid) {
		t.Fatal("invalid service accepted")
	}
	c, err := NewRecoverableJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	if r.inspectCalls != 0 || r.appendCalls != 0 || r.readCalls != 0 || len(h.repo.calls) != 0 {
		t.Fatal("constructor performed I/O")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := c.ReconcileJournalTerminal(ctx, "bad-id"); !errors.Is(err, ErrManualInvalid) {
			t.Fatal("invalid recovery request accepted")
		}
	}
	r.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
		if request.Checkpoint.Stage == enrichmentjournal.Returned {
			*err = errSyntheticStore
		}
	}
	r.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, _ *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
		*err = errSyntheticStore
	}
	id := manualOperationID(804)
	pending, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || pending.Result.RunID != "" {
		t.Fatal("no-run terminal fixture failed")
	}
	out, err := c.ReconcileJournalTerminal(context.Background(), id)
	if !errors.Is(err, ErrPending) || !reflect.DeepEqual(pending, out) || r.inspectCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
		t.Fatal("no-run terminal acquired recovery authority")
	}
}
