package enrichmentrefresh

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func adapterContractCheckpoint(t *testing.T) PreservationCheckpoint {
	t.Helper()
	h := harness(t, contractStore(t, true))
	var captured PreservationCheckpoint
	c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
		if checkpoint.Stage == PreserveComplete {
			captured = clonePreservationCheckpoint(checkpoint)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Call(context.Background(), manualOperationID(601), Request{Connector: "epss_feed", Limit: 200}); err != nil {
		t.Fatal(err)
	}
	if captured.Prepared == nil || captured.Prepared.Completion == nil || captured.Result.Pending == nil {
		t.Fatal("existing seam did not generate full duplicate completion")
	}
	return captured
}

func TestJournalAdapterContractLosslessConverterRejectsInconsistentDuplicates(t *testing.T) {
	source := adapterContractCheckpoint(t)
	before := jsonValue(t, source)
	got, err := convertJournalCheckpoint(source)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != source.OperationID || got.Stage != enrichmentjournal.Complete || got.Prepared == nil || got.Prepared.Completion == nil || got.Prepared.Completion.OriginalDigest != source.Prepared.Completion.OriginalDigest || !got.Progress.Pending || got.Prepared.Attempt.RunID != source.Result.RunID || !got.Prepared.Completion.Feed.PublishedAt.Equal(source.Prepared.Completion.Feed.PublishedAt) || jsonValue(t, source) != before {
		t.Fatal("converter changed original prepared/clock/digest/binding")
	}
	for _, kind := range []string{"completion-attempt", "pending-attempt", "pending-digest", "pending-score", "pending-clock", "pending-nil-vs-empty"} {
		bad := clonePreservationCheckpoint(source)
		switch kind {
		case "completion-attempt":
			bad.Prepared.Completion.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
		case "pending-attempt":
			bad.Result.Pending.Attempt.RunID = "30000000-0000-4000-8000-000000000999"
		case "pending-digest":
			bad.Result.Pending.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
		case "pending-score":
			*bad.Result.Pending.Completion.Feed.Entries[0].EPSS = 1
		case "pending-clock":
			bad.Result.Pending.Completion.FinishedAt = bad.Result.Pending.Completion.FinishedAt.AddDate(0, 0, 1)
		case "pending-nil-vs-empty":
			bad.Prepared.Completion.Feed.Entries = nil
			bad.Result.Pending.Completion.Feed.Entries = []model.SecurityEnrichmentEntry{}
		}
		if _, err := convertJournalCheckpoint(bad); err == nil {
			t.Fatalf("converter normalized away unequal %s", kind)
		}
	}
	mutatePreservationPending(source.Prepared)
	mutatePreservationPending(source.Result.Pending)
	if got.Prepared.Completion.OriginalDigest == "" || got.Prepared.Attempt.Targets[0].FindingID == "PRIVATE-late-target" || *got.Prepared.Completion.Feed.Entries[0].EPSS != 0 {
		t.Fatal("converter result aliases caller")
	}
}

type adapterOwnerContextKey struct{}

type adapterContractRepository struct {
	db                           *store.Store
	appendCalls, readCalls       int
	failStage                    enrichmentjournal.Stage
	requests                     []enrichmentjournal.AppendRequest
	appendContexts, readContexts []context.Context
}

func (r *adapterContractRepository) AppendSecurityEnrichmentCheckpoint(ctx context.Context, request enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error) {
	r.appendCalls++
	r.requests = append(r.requests, request)
	r.appendContexts = append(r.appendContexts, ctx)
	ack, err := r.db.AppendSecurityEnrichmentCheckpoint(ctx, request)
	if err == nil && request.Checkpoint.Stage == r.failStage {
		return enrichmentjournal.Acknowledgement{}, errors.New("PRIVATE-journal-post-commit")
	}
	return ack, err
}
func (r *adapterContractRepository) ReadSecurityEnrichmentCheckpointAcknowledgement(ctx context.Context, request enrichmentjournal.AppendRequest) (store.SecurityEnrichmentJournalAcknowledgementState, error) {
	r.readCalls++
	r.readContexts = append(r.readContexts, ctx)
	return r.db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, request)
}

func TestJournalAdapterContractOwnedControllerConfirmsOnlyKnownLaterCommit(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	journal := &adapterContractRepository{db: db, failStage: enrichmentjournal.Complete}
	c, err := NewJournalManualController(h.service, journal)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), adapterOwnerContextKey{}, "synthetic-adapter-owner")
	id := manualOperationID(610)
	request := Request{Connector: "epss_feed", Limit: 200}
	op, replay, err := c.Call(ctx, id, request)
	if err != nil || replay || op.State != "resolved" || op.Result.Outcome != "success" || !op.Result.Advance || h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || journal.appendCalls != 4 || journal.readCalls != 1 {
		t.Fatalf("known-owned post-commit readback failed: %+v %v append=%d read=%d", op, err, journal.appendCalls, journal.readCalls)
	}
	if journal.readContexts[0] != journal.appendContexts[2] || journal.readContexts[0] != ctx {
		t.Fatal("adapter replaced the seam context/deadline")
	}
	var completion store.SecurityEnrichmentRefreshCompletion
	if err := json.Unmarshal([]byte(h.repo.completeJSON), &completion); err != nil {
		t.Fatal(err)
	}
	if completion.OriginalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(h.data)) {
		t.Fatal("raw decoded input digest changed")
	}
	state, err := db.ReconcileSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || state.State != "success" || state.Receipt == "" {
		t.Fatal("journal ack substituted for real business evidence")
	}
	counts, appends, reads := manualCounts(t, h), journal.appendCalls, journal.readCalls
	again, cached, err := c.Call(ctx, id, request)
	if err != nil || !cached || !reflect.DeepEqual(op, again) || manualCounts(t, h) != counts || journal.appendCalls != appends || journal.readCalls != reads {
		t.Fatal("same-ID cached response repeated preservation or Service")
	}
	reserved := PreservationCheckpoint{Version: 1, OperationID: id, Request: request, Stage: PreserveReserved, Result: Result{NextAfter: request.After}}
	if err := c.preservation.Preserve(ctx, reserved); err == nil || journal.appendCalls != appends || journal.readCalls != reads {
		t.Fatal("second reserved callback became Service execution permission")
	}
	// A fresh factory cannot treat an old durable reservation as ownership.
	freshHarness := harness(t, db)
	freshJournal := &adapterContractRepository{db: db}
	fresh, err := NewJournalManualController(freshHarness.service, freshJournal)
	if err != nil {
		t.Fatal(err)
	}
	stopped, _, err := fresh.Call(ctx, id, request)
	if !errors.Is(err, ErrPending) || stopped.State != "pending" || stopped.Result.Advance || freshHarness.repo.calls["query"] != 0 || freshHarness.uuidCalls != 0 || freshHarness.clockCalls != 0 || freshHarness.fetchCalls != 0 || freshJournal.appendCalls != 1 || freshJournal.readCalls != 0 {
		t.Fatal("fresh journal replay acquired an execution")
	}
	// Even a newly committed reserved row with a lost return is not a fresh
	// ownership proof. No same-ID retry or readonly match may resume Service.
	unknownHarness := harness(t, db)
	unknownJournal := &adapterContractRepository{db: db, failStage: enrichmentjournal.Reserved}
	unknown, err := NewJournalManualController(unknownHarness.service, unknownJournal)
	if err != nil {
		t.Fatal(err)
	}
	unknownID := manualOperationID(611)
	pending, _, err := unknown.Call(ctx, unknownID, request)
	if !errors.Is(err, ErrPending) || pending.State != "pending" || pending.Result.RunID != "" || unknownHarness.repo.calls["query"] != 0 || unknownHarness.uuidCalls != 0 || unknownJournal.readCalls != 0 {
		t.Fatal("unknown reserved commit acquired ownership")
	}
	_, _, err = unknown.Call(ctx, unknownID, request)
	if !errors.Is(err, ErrPending) || unknownJournal.appendCalls != 1 || unknownJournal.readCalls != 0 {
		t.Fatal("unknown reserved callback was retried")
	}
}
