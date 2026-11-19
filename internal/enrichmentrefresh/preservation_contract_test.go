package enrichmentrefresh

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type preservationSinkFunc func(context.Context, PreservationCheckpoint) error

func (f preservationSinkFunc) Preserve(ctx context.Context, checkpoint PreservationCheckpoint) error {
	return f(ctx, checkpoint)
}

func TestPreservationContractAcknowledgesBeforeRealSQLiteWritesWithoutAliases(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	id := manualOperationID(201)
	request := Request{Connector: "epss_feed", Limit: 200}
	var stages []PreservationStage
	var beforeBegin, beforeComplete PreservationCheckpoint
	var controller *ManualController
	sink := preservationSinkFunc(func(ctx context.Context, checkpoint PreservationCheckpoint) error {
		if checkpoint.Version != 1 || checkpoint.OperationID != id || checkpoint.Request != request {
			t.Fatal("checkpoint lost exact version/operation/request binding")
		}
		if ctx == nil || ctx.Err() != nil {
			t.Fatal("preservation did not receive an active explicit context")
		}
		// No metadata lock is held over the injected sink.
		if snapshot, ok := controller.Snapshot(id); !ok || snapshot.State != "calling" {
			t.Fatal("before-call reservation was not visible during preservation")
		}
		if _, _, err := controller.Call(ctx, manualOperationID(202), Request{Connector: "kev_feed", Limit: 1}); !errors.Is(err, ErrManualBusy) {
			t.Fatal("preservation allowed reentrant Service work")
		}
		stages = append(stages, checkpoint.Stage)
		switch checkpoint.Stage {
		case PreserveReserved:
			if h.repo.calls["query"] != 0 || h.clockCalls != 0 || h.uuidCalls != 0 || checkpoint.Prepared != nil || checkpoint.Result.RunID != "" {
				t.Fatal("reservation was not preserved before Service I/O")
			}
		case PreserveBegin:
			if h.repo.calls["begin"] != 0 || h.fetchCalls != 0 || checkpoint.Prepared == nil || checkpoint.Result.Scanned != 1 || checkpoint.Result.Targets != 1 || checkpoint.Result.ScanAfter == "" || checkpoint.Result.NextAfter != request.After || checkpoint.Result.Advance {
				t.Fatal("Begin checkpoint was late or omitted scan/cursor/prepared values")
			}
			beforeBegin = checkpoint
			beforeBegin.Prepared = cloneManualPending(checkpoint.Prepared)
			if checkpoint.Prepared.Completion != nil || checkpoint.Prepared.ExpectedFailure != nil {
				t.Fatal("Begin checkpoint invented source metadata")
			}
			checkpoint.Prepared.Attempt.Targets[0].FindingID = "PRIVATE-mutated-target"
			checkpoint.Result.Pending.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
		case PreserveComplete:
			if h.repo.calls["begin"] != 1 || h.repo.calls["complete"] != 0 || h.fetchCalls != 1 || checkpoint.Prepared == nil || checkpoint.Prepared.Completion == nil {
				t.Fatal("completion checkpoint was not before the real completion write")
			}
			if !reflect.DeepEqual(checkpoint.Prepared.Attempt, beforeBegin.Prepared.Attempt) {
				t.Fatal("sink mutation changed the privately prepared attempt")
			}
			beforeComplete = checkpoint
			beforeComplete.Prepared = cloneManualPending(checkpoint.Prepared)
			checkpoint.Prepared.Completion.Attempt.Targets[0].FindingID = "PRIVATE-mutated-completion"
			checkpoint.Prepared.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
			*checkpoint.Prepared.Completion.Feed.Entries[0].EPSS = 1
			*checkpoint.Prepared.Completion.Feed.Entries[0].Percentile = 1
			checkpoint.Result.Pending.Completion.OriginalDigest = "PRIVATE-mutated-digest"
		case PreserveReturned:
			if h.repo.calls["complete"] != 1 || checkpoint.Result.Outcome != "success" || !checkpoint.Result.Advance || checkpoint.Prepared == nil || checkpoint.Prepared.Completion == nil {
				t.Fatal("terminal candidate lost its original prepared Completion")
			}
			if !reflect.DeepEqual(checkpoint.Prepared, beforeComplete.Prepared) {
				t.Fatal("sink alias changed the retained completion")
			}
		default:
			t.Fatalf("unexpected checkpoint stage %q", checkpoint.Stage)
		}
		return nil
	})
	var err error
	controller, err = NewPreservingManualController(h.service, sink)
	if err != nil {
		t.Fatal(err)
	}
	h.repo.onBegin = func() {
		if len(stages) != 2 || stages[1] != PreserveBegin || jsonValue(t, beforeBegin.Prepared.Attempt) != h.repo.beginJSON {
			t.Fatal("real Begin ran before exact checkpoint acknowledgement")
		}
	}
	h.repo.onComplete = func() {
		if len(stages) != 3 || stages[2] != PreserveComplete || jsonValue(t, *beforeComplete.Prepared.Completion) != h.repo.completeJSON {
			t.Fatal("real Complete ran before exact checkpoint acknowledgement")
		}
	}
	op, replay, err := controller.Call(context.Background(), id, request)
	if err != nil || replay || op.State != "resolved" || op.Result.Outcome != "success" || !op.Result.Advance || op.Result.Pending != nil {
		t.Fatalf("acknowledged preserved operation did not complete: %+v %v", op, err)
	}
	if !reflect.DeepEqual(stages, []PreservationStage{PreserveReserved, PreserveBegin, PreserveComplete, PreserveReturned}) || h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 {
		t.Fatal("checkpoint/write sequence changed or values were regenerated")
	}
	state, err := db.ReconcileSecurityEnrichmentRefresh(context.Background(), *beforeComplete.Prepared.Completion)
	if err != nil || state.State != "success" || state.Receipt == "" {
		t.Fatalf("real SQLite evidence did not match preserved completion: %+v %v", state, err)
	}
	counts, checkpoints := manualCounts(t, h), len(stages)
	again, cached, err := controller.Call(context.Background(), id, request)
	if err != nil || !cached || !reflect.DeepEqual(op, again) || manualCounts(t, h) != counts || len(stages) != checkpoints {
		t.Fatal("response-loss replay regenerated work or preservation")
	}
}

func TestPreservationContractUnknownCheckpointStopsWritesAndKeepsSameSourceGate(t *testing.T) {
	for _, stopAt := range []PreservationStage{PreserveReserved, PreserveBegin, PreserveFail, PreserveComplete, PreserveReturned} {
		t.Run(string(stopAt), func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			if stopAt == PreserveFail {
				h.fetchError = errors.New("PRIVATE-fetch-error")
			}
			id := manualOperationID(210)
			request := Request{Connector: "epss_feed", Limit: 200}
			var saved PreservationCheckpoint
			sinkCalls := 0
			controller, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
				sinkCalls++
				if checkpoint.Stage == stopAt {
					// The sink may have retained the checkpoint before losing
					// its acknowledgement. This is unknown, not a safe retry.
					saved = checkpoint
					return errors.New("PRIVATE-preservation-result-unknown")
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			op, replay, err := controller.Call(context.Background(), id, request)
			if !errors.Is(err, ErrPending) || replay || op.State != "pending" || op.Result.Outcome != "pending" || op.Result.Code != "preservation_unknown" || op.Result.Advance || op.Result.NextAfter != request.After || saved.Stage != stopAt {
				t.Fatalf("unknown preservation became executable/resolved: %+v %v", op, err)
			}
			wantBegin, wantFail, wantComplete, wantFetch, wantUUID := 0, 0, 0, 0, 0
			switch stopAt {
			case PreserveReserved:
				if h.repo.calls["query"] != 0 || h.clockCalls != 0 || saved.Prepared != nil {
					t.Fatal("unacknowledged reservation entered Service")
				}
			case PreserveBegin:
				wantUUID = 1
			case PreserveFail:
				wantBegin, wantFetch, wantUUID = 1, 1, 1
				if saved.Prepared == nil || saved.Prepared.ExpectedFailure == nil || saved.Prepared.ExpectedFailure.Code != "fetch_failed" || !saved.Prepared.ExpectedFailure.FinishedAt.Equal(h.times[1]) || saved.Prepared.Completion != nil {
					t.Fatal("failure checkpoint lost exact fixed code/finish or invented feed")
				}
			case PreserveComplete:
				wantBegin, wantFetch, wantUUID = 1, 1, 1
				if saved.Prepared == nil || saved.Prepared.Completion == nil {
					t.Fatal("completion was not preserved before refusing its write")
				}
			case PreserveReturned:
				wantBegin, wantComplete, wantFetch, wantUUID = 1, 1, 1, 1
				if saved.Prepared == nil || saved.Prepared.Completion == nil {
					t.Fatal("lost terminal acknowledgement discarded original completion")
				}
			}
			if h.repo.calls["begin"] != wantBegin || h.repo.calls["fail"] != wantFail || h.repo.calls["complete"] != wantComplete || h.fetchCalls != wantFetch || h.uuidCalls != wantUUID {
				t.Fatalf("unpreserved write/fetch/UUID occurred: calls=%v fetch=%d uuid=%d", h.repo.calls, h.fetchCalls, h.uuidCalls)
			}
			// Check the real SQLite state, not just wrapper call counts.
			if saved.Prepared != nil {
				state, readErr := db.ReadSecurityEnrichmentRefreshAttempt(context.Background(), saved.Prepared.Attempt, nil)
				if readErr != nil {
					t.Fatal(readErr)
				}
				want := "running"
				switch stopAt {
				case PreserveBegin:
					want = "missing"
				case PreserveReturned:
					want = "unknown" // Full completion is required to verify success.
				}
				if state.State != want {
					t.Fatalf("unexpected actual SQLite state: %+v want=%s", state, want)
				}
			}
			counts, checkpoints := manualCounts(t, h), sinkCalls
			again, cached, againErr := controller.Call(context.Background(), id, request)
			if !cached || !errors.Is(againErr, ErrPending) || !reflect.DeepEqual(op, again) {
				t.Fatal("same-ID response loss did not replay exact pending state")
			}
			if _, _, err := controller.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 1}); !errors.Is(err, ErrManualConflict) {
				t.Fatal("same operation accepted different content")
			}
			if _, _, err := controller.Call(context.Background(), manualOperationID(211), request); !errors.Is(err, ErrManualPendingSource) {
				t.Fatal("unknown preservation allowed a fresh same-source operation")
			}
			if _, err := controller.Reconcile(context.Background(), id); !errors.Is(err, ErrPending) {
				t.Fatal("Store readback bypassed unknown preservation acknowledgement")
			}
			if manualCounts(t, h) != counts || sinkCalls != checkpoints || strings.Contains(jsonValue(t, op), "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unknown retry/recovery acquired I/O or leaked raw error")
			}
		})
	}
}

func TestPreservationContractNoRunProgressNeedsTerminalAcknowledgement(t *testing.T) {
	for _, acknowledge := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "acknowledged"}[acknowledge], func(t *testing.T) {
			db := contractStore(t, false)
			h := harness(t, db)
			h.repo.page = &store.SecurityEnrichmentRefreshTargetPage{Scanned: 1, After: "zz-scanned-ineligible"}
			var stages []PreservationStage
			controller, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
				stages = append(stages, checkpoint.Stage)
				if checkpoint.Prepared != nil || checkpoint.Result.RunID != "" {
					t.Fatal("no-run preservation invented a UUID or metadata")
				}
				if checkpoint.Stage == PreserveReturned {
					if checkpoint.Result.Scanned != 1 || checkpoint.Result.ScanAfter != "zz-scanned-ineligible" || !checkpoint.Result.Advance {
						t.Fatal("no-target scan/cursor was not retained before publication")
					}
					if !acknowledge {
						return errors.New("PRIVATE-terminal-preservation-unknown")
					}
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			op, _, err := controller.Call(context.Background(), manualOperationID(220), Request{Connector: "epss_feed", After: "previous", Limit: 1})
			if acknowledge {
				if err != nil || op.State != "resolved" || op.Result.Outcome != "no_targets" || !op.Result.Advance || op.Result.NextAfter != "zz-scanned-ineligible" {
					t.Fatalf("preserved no-run progress failed: %+v %v", op, err)
				}
			} else if !errors.Is(err, ErrPending) || op.State != "pending" || op.Result.Advance || op.Result.NextAfter != "previous" {
				t.Fatalf("unpreserved no-run cursor advanced: %+v %v", op, err)
			}
			runs, readErr := db.QueryIngestRuns(context.Background())
			if readErr != nil || len(runs) != 0 || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 || !reflect.DeepEqual(stages, []PreservationStage{PreserveReserved, PreserveReturned}) {
				t.Fatal("no-run preservation used a business clock/UUID/fetch/write")
			}
		})
	}
}
