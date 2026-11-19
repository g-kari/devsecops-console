package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func fencedContractFixture(t *testing.T, source string, id int) (*Store, SecurityEnrichmentRefreshCompletion, SecurityEnrichmentReservationRequest, []enrichmentjournal.Checkpoint) {
	t.Helper()
	db, completion := refreshContractFixture(t, source, id)
	reservation := reservationContractRequest(t, id, source+"_feed")
	frames := inspectionContractFrames(t, completion, id)
	for i := range frames {
		frames[i].OperationID = reservation.Reserved.Checkpoint.OperationID
	}
	reservation.Reserved.Checkpoint = frames[0]
	reservationContractDigest(t, &reservation)
	reservationContractRequire(t, db, reservation)
	return db, completion, reservation, frames
}
func fencedContractRequest(t *testing.T, reservation SecurityEnrichmentReservationRequest, checkpoint enrichmentjournal.Checkpoint, sequence int64, previous string) SecurityEnrichmentFencedRequest {
	t.Helper()
	payload, err := enrichmentjournal.Encode(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	return SecurityEnrichmentFencedRequest{Reservation: reservation, Checkpoint: enrichmentjournal.AppendRequest{Sequence: sequence, PreviousDigest: previous, Checkpoint: checkpoint}, CheckpointDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(payload))}
}
func fencedContractClone(t *testing.T, request SecurityEnrichmentFencedRequest) SecurityEnrichmentFencedRequest {
	t.Helper()
	for _, checkpoint := range []*enrichmentjournal.Checkpoint{&request.Reservation.Reserved.Checkpoint, &request.Checkpoint.Checkpoint} {
		data, err := enrichmentjournal.Encode(*checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := enrichmentjournal.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		*checkpoint = owned
	}
	return request
}
func fencedContractRedigest(t *testing.T, request *SecurityEnrichmentFencedRequest) {
	t.Helper()
	data, err := enrichmentjournal.Encode(request.Checkpoint.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	request.CheckpointDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}
func fencedContractAckMatches(ack SecurityEnrichmentFencedAcknowledgement, request SecurityEnrichmentFencedRequest, replay bool) bool {
	return ack.OperationID == request.Checkpoint.Checkpoint.OperationID && ack.IntentID == request.Reservation.IntentID &&
		ack.Connector == request.Reservation.Reserved.Checkpoint.Request.Connector && ack.Generation == request.Reservation.ExpectedGeneration+1 &&
		ack.Sequence == request.Checkpoint.Sequence && ack.Digest == request.CheckpointDigest && ack.Replay == replay
}
func fencedContractAppend(t *testing.T, db *Store, request SecurityEnrichmentFencedRequest) SecurityEnrichmentFencedAcknowledgement {
	t.Helper()
	ack, err := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !fencedContractAckMatches(ack, request, false) {
		t.Fatalf("fenced checkpoint ack mismatch: %+v", ack)
	}
	return ack
}
func fencedContractApply(t *testing.T, db *Store, request SecurityEnrichmentFencedRequest, business string) SecurityEnrichmentFencedProof {
	t.Helper()
	proof, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if proof.State != "matched" || !fencedContractAckMatches(proof.Acknowledgement, request, false) || proof.Business.State != business || proof.HeadSequence != request.Checkpoint.Sequence || proof.HeadDigest != request.CheckpointDigest {
		t.Fatalf("business write not bound to exact current CP: %+v", proof)
	}
	if business != "success" && proof.Business.Receipt != "" {
		t.Fatal("attempt/failure acknowledgement invented a success receipt")
	}
	return proof
}
func fencedContractRead(t *testing.T, db *Store, request SecurityEnrichmentFencedRequest, business bool, want string) SecurityEnrichmentFencedProof {
	t.Helper()
	before := journalSnapshot(t, db, false)
	var proof SecurityEnrichmentFencedProof
	var err error
	if business {
		proof, err = db.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
	} else {
		proof, err = db.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), request)
	}
	if err != nil || proof.State != "matched" || !fencedContractAckMatches(proof.Acknowledgement, request, true) || proof.HeadSequence != request.Checkpoint.Sequence || proof.HeadDigest != request.CheckpointDigest || proof.Business.State != want || journalSnapshot(t, db, false) != before {
		t.Fatalf("exact readonly proof=%+v err=%v want business=%s", proof, err, want)
	}
	if want != "success" && proof.Business.Receipt != "" {
		t.Fatal("checkpoint/running/failure proof invented business success")
	}
	return proof
}
func fencedContractRejectWithoutWrites(t *testing.T, db *Store, request SecurityEnrichmentFencedRequest) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	ack, appendErr := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
	written, writeErr := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
	if appendErr == nil || writeErr == nil || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) || !reflect.DeepEqual(written.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || written.HeadSequence != 0 || written.HeadDigest != "" || written.Business.Receipt != "" {
		t.Fatal("wrong/stale/old-phase request wrote or exposed acknowledgement")
	}
	for _, business := range []bool{false, true} {
		var proof SecurityEnrichmentFencedProof
		var err error
		if business {
			proof, err = db.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
		} else {
			proof, err = db.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), request)
		}
		if proof.State == "matched" || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || proof.HeadSequence != 0 || proof.HeadDigest != "" || proof.Business.Receipt != "" {
			t.Fatal("wrong/stale/old-phase request borrowed a current proof")
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("raw read error escaped")
		}
	}
	if journalSnapshot(t, db, false) != before || strings.Contains(appendErr.Error(), "PRIVATE") || strings.Contains(writeErr.Error(), "PRIVATE") {
		t.Fatal("refused request changed a table or leaked raw error text")
	}
}

func TestFencedEnrichmentContractExactCurrentCheckpointAndSameUUIDBusinessProof(t *testing.T) {
	for index, source := range []string{"epss", "kev"} {
		t.Run(source, func(t *testing.T) {
			db, completion, reservation, frames := fencedContractFixture(t, source, 2300+index)
			begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			// Every top-level contract first reaches this positive new API,
			// so Red is its fixed runtime error, not compile/schema/old-test failure.
			fencedContractAppend(t, db, begin)
			fencedContractRead(t, db, begin, false, "unknown")
			unwritten, err := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), begin)
			if err != nil || unwritten.State == "matched" || !reflect.DeepEqual(unwritten.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || unwritten.Business.Receipt != "" {
				t.Fatal("stored Begin CP was mistaken for a committed business attempt")
			}
			fencedContractApply(t, db, begin, "running")
			fencedContractRead(t, db, begin, true, "running")

			complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
			fencedContractAppend(t, db, complete)
			written := fencedContractApply(t, db, complete, "success")
			fencedContractRead(t, db, complete, false, "unknown")
			exact := fencedContractRead(t, db, complete, true, "success")
			legacy, err := db.ReconcileSecurityEnrichmentRefresh(context.Background(), completion)
			if err != nil || exact.Business.Receipt == "" || exact.Business.Receipt != written.Business.Receipt || exact.Business.Receipt != legacy.Receipt {
				t.Fatal("full same-UUID receipt/manifest/observation proof differs")
			}
			var manifests, observations int
			if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_runs WHERE ingest_run_id=?", completion.Attempt.RunID).Scan(&manifests); err != nil {
				t.Fatal(err)
			}
			if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_observations WHERE ingest_run_id=?", completion.Attempt.RunID).Scan(&observations); err != nil || manifests != 1 || observations != len(completion.Feed.Entries) {
				t.Fatal("fenced completion did not commit exact same-UUID evidence")
			}
			beforeReplay := journalSnapshot(t, db, false)
			ack, err := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), complete)
			if err != nil || !fencedContractAckMatches(ack, complete, true) {
				t.Fatal("exact current CP replay changed identity")
			}
			replay, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), complete)
			if err != nil || !fencedContractAckMatches(replay.Acknowledgement, complete, true) || replay.Business.Receipt != exact.Business.Receipt || journalSnapshot(t, db, false) != beforeReplay {
				t.Fatal("exact current business replay rewrote data")
			}
			for _, kind := range []string{"intent", "operation", "source", "generation", "reserved-request", "full-cp", "digest", "previous", "sequence"} {
				t.Run(kind, func(t *testing.T) {
					wrong := fencedContractClone(t, complete)
					switch kind {
					case "intent":
						wrong.Reservation.IntentID = "a2000000-0000-4000-8000-000000009999"
					case "operation":
						wrong.Reservation.Reserved.Checkpoint.OperationID = "a1000000-0000-4000-8000-000000009999"
						reservationContractDigest(t, &wrong.Reservation)
					case "source":
						if source == "epss" {
							wrong.Reservation.Reserved.Checkpoint.Request.Connector = "kev_feed"
						} else {
							wrong.Reservation.Reserved.Checkpoint.Request.Connector = "epss_feed"
						}
						reservationContractDigest(t, &wrong.Reservation)
					case "generation":
						wrong.Reservation.ExpectedGeneration++
					case "reserved-request":
						wrong.Reservation.Reserved.Checkpoint.Request.After, wrong.Reservation.Reserved.Checkpoint.Progress.NextAfter = "changed", "changed"
						reservationContractDigest(t, &wrong.Reservation)
					case "full-cp":
						wrong.Checkpoint.Checkpoint.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
						fencedContractRedigest(t, &wrong)
					case "digest":
						wrong.CheckpointDigest = "sha256:" + strings.Repeat("f", 64)
					case "previous":
						wrong.Checkpoint.PreviousDigest = "sha256:" + strings.Repeat("f", 64)
					case "sequence":
						wrong.Checkpoint.Sequence++
					}
					fencedContractRejectWithoutWrites(t, db, wrong)
				})
			}
		})
	}
	t.Run("exact-expected-failure", func(t *testing.T) {
		db, completion, reservation, frames := fencedContractFixture(t, "epss", 2302)
		begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
		fencedContractAppend(t, db, begin)
		fencedContractApply(t, db, begin, "running")
		fail := frames[1]
		prepared := *fail.Prepared
		prepared.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: completion.FinishedAt}
		fail.Stage, fail.Prepared = enrichmentjournal.Fail, &prepared
		expected := fencedContractRequest(t, reservation, fail, 3, begin.CheckpointDigest)
		fencedContractAppend(t, db, expected)
		fencedContractApply(t, db, expected, "failed")
		fencedContractRead(t, db, expected, true, "failed")
	})
}

func TestFencedEnrichmentContractOldPhaseStaleFixtureCompetitionAndRollback(t *testing.T) {
	probe, _, root, frames := fencedContractFixture(t, "epss", 2310)
	first := fencedContractRequest(t, root, frames[1], 2, root.ReservedDigest)
	fencedContractAppend(t, probe, first)

	t.Run("old-phase-after-complete", func(t *testing.T) {
		db, _, reservation, frames := fencedContractFixture(t, "epss", 2311)
		begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
		fencedContractAppend(t, db, begin)
		fencedContractApply(t, db, begin, "running")
		complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
		fencedContractAppend(t, db, complete)
		fencedContractApply(t, db, complete, "success")
		fencedContractRejectWithoutWrites(t, db, begin)
	})
	t.Run("synthetic-stale-generation-not-real-handoff", func(t *testing.T) {
		db, _, reservation, frames := fencedContractFixture(t, "epss", 2312)
		begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
		// Owned fixture corruption changes the current stored generation while
		// the old complete request is retained. No release/real handoff is claimed.
		if _, err := db.db.Exec("UPDATE security_enrichment_reservations SET expected_generation=1,generation=2"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec("UPDATE security_enrichment_source_generations SET generation=2 WHERE connector='epss_feed'"); err != nil {
			t.Fatal(err)
		}
		fencedContractRejectWithoutWrites(t, db, begin)
	})
	t.Run("independent-connections-at-most-one-current-cp", func(t *testing.T) {
		db, _, reservation, frames := fencedContractFixture(t, "epss", 2313)
		var path string
		if err := db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned fixture SQLite path unavailable")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		first := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
		other := fencedContractClone(t, first)
		other.Checkpoint.Checkpoint.Prepared.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
		fencedContractRedigest(t, &other)
		requests := []SecurityEnrichmentFencedRequest{first, other}
		type result struct {
			request SecurityEnrichmentFencedRequest
			ack     SecurityEnrichmentFencedAcknowledgement
			err     error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		for i, store := range []*Store{db, second} {
			go func(store *Store, request SecurityEnrichmentFencedRequest) {
				<-start
				ack, err := store.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
				results <- result{request, ack, err}
			}(store, requests[i])
		}
		close(start)
		winners := 0
		for i := 0; i < 2; i++ {
			got := <-results
			if got.err == nil {
				winners++
				if !fencedContractAckMatches(got.ack, got.request, false) {
					t.Fatal("competition winner borrowed the other payload")
				}
			} else if !reflect.DeepEqual(got.ack, SecurityEnrichmentFencedAcknowledgement{}) {
				t.Fatal("competition error exposed acknowledgement")
			}
		}
		var count, head int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_checkpoints WHERE operation_id=?", reservation.Reserved.Checkpoint.OperationID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := db.db.QueryRow("SELECT head_sequence FROM security_enrichment_operations WHERE operation_id=?", reservation.Reserved.Checkpoint.OperationID).Scan(&head); err != nil || count < 1 || count > 2 || head != count || winners > 1 || count-1 < winners {
			t.Fatal("competing current CP created a partial/forked head")
		}
		beforeRead := journalSnapshot(t, db, false)
		matched := 0
		for _, request := range requests {
			proof, err := db.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if proof.State == "matched" {
				matched++
				if !fencedContractAckMatches(proof.Acknowledgement, request, true) {
					t.Fatal("wrong competing payload was acknowledged")
				}
			} else if !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) {
				t.Fatal("losing payload borrowed checkpoint proof")
			}
		}
		if matched != count-1 || journalSnapshot(t, db, false) != beforeRead {
			t.Fatal("competition readback changed tables or differs from committed CP")
		}
	})
	t.Run("checkpoint-and-business-trigger-rollback", func(t *testing.T) {
		db, _, reservation, frames := fencedContractFixture(t, "epss", 2314)
		begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
		if _, err := db.db.Exec("CREATE TRIGGER fenced_cp_abort BEFORE INSERT ON security_enrichment_checkpoints WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'PRIVATE-cp-block'); END"); err != nil {
			t.Fatal(err)
		}
		before := journalSnapshot(t, db, false)
		ack, err := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), begin)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) || journalSnapshot(t, db, false) != before {
			t.Fatal("checkpoint trigger failure left a partial head/body")
		}
		if _, err := db.db.Exec("DROP TRIGGER fenced_cp_abort"); err != nil {
			t.Fatal(err)
		}
		fencedContractAppend(t, db, begin)
		fencedContractApply(t, db, begin, "running")
		complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
		fencedContractAppend(t, db, complete)
		if _, err := db.db.Exec("CREATE TRIGGER fenced_obs_abort BEFORE INSERT ON security_enrichment_observations BEGIN SELECT RAISE(ABORT,'PRIVATE-observation-block'); END"); err != nil {
			t.Fatal(err)
		}
		before = journalSnapshot(t, db, false)
		proof, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), complete)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || proof.Business.Receipt != "" || journalSnapshot(t, db, false) != before {
			t.Fatal("business trigger failure partially committed receipt/manifest/observations")
		}
		checkpoint := fencedContractRead(t, db, complete, false, "unknown")
		business, err := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), complete)
		if err != nil || checkpoint.State != "matched" || business.State == "matched" || !reflect.DeepEqual(business.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || business.Business.Receipt != "" || journalSnapshot(t, db, false) != before {
			t.Fatal("stored full CP was substituted for rolled-back business success")
		}
	})
}

type fencedContractLostReturn struct {
	db        *Store
	calls     int
	committed bool
	business  SecurityEnrichmentRefreshState
}

func (w *fencedContractLostReturn) apply(ctx context.Context, request SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	w.calls++
	proof, err := w.db.ApplySecurityEnrichmentFencedRefresh(ctx, request)
	if err != nil {
		return proof, err
	}
	w.committed, w.business = true, proof.Business
	// Actual successful Store commit followed by an outer synthetic lost
	// return. This is not an injected SQLite-driver Commit uncertainty.
	return SecurityEnrichmentFencedProof{}, errors.New("PRIVATE-lost-return")
}

func TestFencedEnrichmentContractCommittedLostReturnUsesRetainedReadonlyProofOnly(t *testing.T) {
	db, completion, reservation, frames := fencedContractFixture(t, "epss", 2320)
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, complete)
	wrapper := &fencedContractLostReturn{db: db}
	lost, err := wrapper.apply(context.Background(), complete)
	if !wrapper.committed {
		t.Fatal(err)
	}
	if err == nil || wrapper.calls != 1 || !reflect.DeepEqual(lost.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) {
		t.Fatal("lost return exposed ack or retried a write")
	}
	before := journalSnapshot(t, db, false)
	proof := fencedContractRead(t, db, complete, true, "success")
	if proof.Business.Receipt == "" || proof.Business.Receipt != wrapper.business.Receipt {
		t.Fatal("retained full completion did not prove the exact committed receipt")
	}
	wrong := fencedContractClone(t, complete)
	wrong.Checkpoint.Checkpoint.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
	fencedContractRedigest(t, &wrong)
	rejected, _ := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), wrong)
	if rejected.State == "matched" || !reflect.DeepEqual(rejected.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || rejected.Business.Receipt != "" {
		t.Fatal("different retained full completion received the old receipt")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	unknown, err := db.ReadSecurityEnrichmentFencedRefresh(cancelled, complete)
	if !errors.Is(err, context.Canceled) || unknown.State != "unknown" || !reflect.DeepEqual(unknown.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || unknown.Business.Receipt != "" || unknown.HeadSequence != 0 || unknown.HeadDigest != "" {
		t.Fatal("canceled read exposed acknowledgement or guessed success")
	}
	if wrapper.calls != 1 || journalSnapshot(t, db, false) != before {
		t.Fatal("readonly recovery changed data or resubmitted the business write")
	}
	var runs int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM ingest_runs WHERE connector='epss_feed'").Scan(&runs); err != nil || runs != 1 {
		t.Fatal("lost-return recovery generated a replacement business UUID")
	}
	legacy, err := db.ReconcileSecurityEnrichmentRefresh(context.Background(), completion)
	if err != nil || legacy.Receipt != proof.Business.Receipt {
		t.Fatal("new proof did not preserve the existing business receipt contract")
	}
}
