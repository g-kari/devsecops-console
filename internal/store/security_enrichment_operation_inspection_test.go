package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func inspectWithoutTableChanges(t *testing.T, db *Store, id, journalState, businessState string, wantError bool) SecurityEnrichmentOperationInspection {
	t.Helper()
	before := inspectionContractHash(t, db)
	out, err := db.InspectSecurityEnrichmentOperation(context.Background(), id)
	if out.State != journalState || out.Business.State != businessState || (err != nil) != wantError || inspectionContractHash(t, db) != before {
		t.Fatalf("inspection state=%+v error=%v want journal=%s business=%s error=%v", out, err, journalState, businessState, wantError)
	}
	if businessState != "success" && out.Business.Receipt != "" {
		t.Fatal("unverified success receipt exposed")
	}
	if journalState != "valid" && (out.Checkpoint != nil || out.HeadSequence != 0 || out.HeadDigest != "") {
		t.Fatal("invalid history exposed a verified candidate")
	}
	if err != nil && strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("raw stored/SQL content leaked")
	}
	return out
}

func TestOperationInspectionExactFailureAndCompletionAreDifferentProofs(t *testing.T) {
	for _, kind := range []string{"exact-failure", "finish-mismatch", "completion-not-failure", "failure-not-success"} {
		t.Run(kind, func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 1900)
			ctx := context.Background()
			frames := inspectionContractFrames(t, c, 1900)
			if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			fail := frames[1]
			p := *fail.Prepared
			p.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: c.FinishedAt}
			if kind == "finish-mismatch" {
				p.Failure.FinishedAt = c.FinishedAt.Add(time.Nanosecond)
			}
			fail.Stage, fail.Prepared = enrichmentjournal.Fail, &p
			selected := []enrichmentjournal.Checkpoint{frames[0], frames[1], fail}
			if kind == "completion-not-failure" {
				selected = frames[:3]
			}
			if kind == "failure-not-success" {
				if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
					t.Fatal(err)
				}
			} else if _, err := db.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "fetch_failed", c.FinishedAt); err != nil {
				t.Fatal(err)
			}
			head := inspectionAppendFrames(t, db, selected)
			if _, err := db.db.Exec("PRAGMA query_only=ON"); err != nil {
				t.Fatal(err)
			}
			want, wantError := "unknown", false
			switch kind {
			case "exact-failure":
				want = "failed"
			case "finish-mismatch":
				wantError = true
			}
			out := inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", want, wantError)
			if out.HeadDigest != head.Digest || out.Business.Receipt != "" || out.Checkpoint.Prepared == nil {
				t.Fatal("journal acknowledgement became business receipt or lost candidate")
			}
			if kind == "exact-failure" {
				out.Checkpoint.Prepared.Failure.Code = "PRIVATE-caller"
				out.Checkpoint.Prepared.Failure.FinishedAt = time.Time{}
				again := inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", "failed", false)
				if again.Checkpoint.Prepared.Failure.Code != "fetch_failed" || !again.Checkpoint.Prepared.Failure.FinishedAt.Equal(c.FinishedAt) {
					t.Fatal("caller mutated retained failure")
				}
			}
		})
	}
}

func TestOperationInspectionPendingCandidateDoesNotRewriteJournalToBusinessTerminal(t *testing.T) {
	db, c := refreshContractFixture(t, "kev", 1950)
	frames := inspectionContractFrames(t, c, 1950)
	pending := frames[3]
	pending.Progress.Outcome, pending.Progress.Code = "pending", "completion_unknown"
	pending.Progress.Pending, pending.Progress.Advance, pending.Progress.NextAfter = true, false, pending.Request.After
	head := inspectionAppendFrames(t, db, append(frames[:3:3], pending))
	ctx := context.Background()
	if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	out := inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", "success", false)
	if out.HeadDigest != head.Digest || out.HeadSequence != 4 || out.Checkpoint.Progress.Outcome != "pending" || !out.Checkpoint.Progress.Pending || out.Checkpoint.Progress.Advance || out.Business.Receipt == "" {
		t.Fatal("business proof silently restored/advanced the pending journal candidate")
	}
}

func TestOperationInspectionPreBeginRejectionWithScannedTargetsStillHasNoUUID(t *testing.T) {
	db := journalOwnedStore(t)
	reserved := journalStoreFrames(t)[0]
	first := inspectionAppendFrames(t, db, []enrichmentjournal.Checkpoint{reserved})
	returned := reserved
	returned.Stage = enrichmentjournal.Returned
	returned.Progress = enrichmentjournal.Progress{Outcome: "invalid", Code: "invalid_uuid", Scanned: 1, Targets: 1, ScanAfter: "finding-001", NextAfter: returned.Request.After}
	appendJournalFrame(t, db, returned, 2, first.Digest)
	out := inspectWithoutTableChanges(t, db, reserved.OperationID, "valid", "no_run", false)
	if out.Checkpoint.Prepared != nil || out.Checkpoint.Progress.RunID != "" || out.Checkpoint.Progress.Targets != 1 || out.Checkpoint.Progress.ScanAfter != "finding-001" || out.Checkpoint.Progress.Advance {
		t.Fatal("pre-Begin scan was converted into execution authority or cursor progress")
	}
}

func TestOperationInspectionRejectsJournalCorruptionWithoutCandidateOrRepair(t *testing.T) {
	for _, kind := range []string{"payload-blob", "operation-blob", "checkpoint-operation-blob", "oversize", "orphan", "digest", "header-source", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			frame := journalStoreFrames(t)[0]
			inspectionAppendFrames(t, db, []enrichmentjournal.Checkpoint{frame})
			for _, query := range []string{"PRAGMA ignore_check_constraints=ON", "PRAGMA foreign_keys=OFF"} {
				if _, err := db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			query := ""
			var args []any
			switch kind {
			case "payload-blob":
				query = "UPDATE security_enrichment_checkpoints SET payload_json=CAST(payload_json AS BLOB)"
			case "operation-blob":
				query = "INSERT INTO security_enrichment_operations SELECT CAST(operation_id AS BLOB),format_version,connector,request_after,request_limit,run_id,head_sequence,head_digest FROM security_enrichment_operations"
			case "checkpoint-operation-blob":
				query = "UPDATE security_enrichment_checkpoints SET operation_id=CAST(operation_id AS BLOB)"
			case "oversize":
				query, args = "UPDATE security_enrichment_checkpoints SET payload_json=?", []any{strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1)}
			case "orphan":
				query = "DELETE FROM security_enrichment_operations"
			case "digest":
				query, args = "UPDATE security_enrichment_checkpoints SET payload_digest=?", []any{"sha256:" + strings.Repeat("f", 64)}
			case "header-source":
				query = "UPDATE security_enrichment_operations SET connector='kev_feed'"
			case "overflow":
				for seq := 2; seq <= 6; seq++ {
					if _, err := db.db.Exec("INSERT INTO security_enrichment_checkpoints SELECT operation_id,?,stage,previous_digest,payload_digest,payload_json FROM security_enrichment_checkpoints WHERE sequence=1", seq); err != nil {
						t.Fatal(err)
					}
				}
			}
			if query != "" {
				if _, err := db.db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			inspectWithoutTableChanges(t, db, frame.OperationID, "unknown", "unknown", true)
		})
	}
}

func TestOperationInspectionBusinessCorruptionDoesNotInvalidateJournalOrInventProof(t *testing.T) {
	for _, kind := range []string{"receipt-body", "receipt-blob", "run-alias", "observation-missing", "observation-body", "observation-identity", "observation-clock", "observation-blob", "manifest-digest", "manifest-clock", "manifest-oversize", "manifest-alias", "observation-alias", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 1910)
			ctx := context.Background()
			frames := inspectionContractFrames(t, c, 1910)
			head := inspectionAppendFrames(t, db, frames)
			if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			query := ""
			args := []any{c.Attempt.RunID}
			switch kind {
			case "receipt-body":
				query = "UPDATE ingest_runs SET body_json=json_set(body_json,'$.cursor','PRIVATE-wrong-receipt') WHERE id=?"
			case "receipt-blob":
				query = "UPDATE ingest_runs SET body_json=CAST(body_json AS BLOB) WHERE id=?"
			case "run-alias":
				query = "INSERT INTO ingest_runs(id,connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json) SELECT CAST(id AS BLOB),connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json FROM ingest_runs WHERE id=?"
			case "observation-missing":
				query = "DELETE FROM security_enrichment_observations WHERE ingest_run_id=?"
			case "observation-body":
				query = "UPDATE security_enrichment_observations SET body_json='{}' WHERE ingest_run_id=?"
			case "observation-identity":
				query = "UPDATE security_enrichment_observations SET evidence_identity='PRIVATE-wrong-identity' WHERE ingest_run_id=?"
			case "observation-clock":
				query = "UPDATE security_enrichment_observations SET observed_at='2026-11-10T12:00:01Z' WHERE ingest_run_id=?"
			case "observation-blob":
				query = "UPDATE security_enrichment_observations SET id=CAST(id AS BLOB) WHERE ingest_run_id=?"
			case "manifest-digest":
				query = "UPDATE security_enrichment_runs SET original_digest=? WHERE ingest_run_id=?"
				args = []any{"sha256:" + strings.Repeat("f", 64), c.Attempt.RunID}
			case "manifest-clock":
				query = "UPDATE security_enrichment_runs SET published_at='2026-11-10T10:59:59Z' WHERE ingest_run_id=?"
			case "manifest-oversize":
				query = "UPDATE security_enrichment_runs SET version=? WHERE ingest_run_id=?"
				args = []any{strings.Repeat("PRIVATE", 1000), c.Attempt.RunID}
			case "manifest-alias":
				query = "INSERT INTO security_enrichment_runs SELECT CAST(ingest_run_id AS BLOB),source,version,published_at,observed_at,selected_cves_json,entries,original_digest FROM security_enrichment_runs WHERE ingest_run_id=?"
			case "observation-alias":
				query = "INSERT INTO security_enrichment_observations SELECT id||'-alias',CAST(ingest_run_id AS BLOB),source,cve_id,published_at,observed_at,evidence_identity,body_json FROM security_enrichment_observations WHERE ingest_run_id=?"
			case "orphan":
				query = "DELETE FROM ingest_runs WHERE id=?"
			}
			if _, err := db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			out := inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", "unknown", true)
			if out.HeadDigest != head.Digest || out.Checkpoint == nil || out.Checkpoint.Stage != enrichmentjournal.Returned {
				t.Fatal("valid journal candidate was lost with business-proof conflict")
			}
		})
	}
}

func TestOperationInspectionMissingInvalidCancelledAndReadErrorHaveNoAuthority(t *testing.T) {
	db, c := refreshContractFixture(t, "epss", 1920)
	ctx := context.Background()
	frames := inspectionContractFrames(t, c, 1920)
	// An old, unbound common attempt is not adopted into a missing operation.
	if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	inspectWithoutTableChanges(t, db, frames[0].OperationID, "missing", "unknown", false)
	inspectionAppendFrames(t, db, frames[:2])
	before := inspectionContractHash(t, db)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	expired, expire := context.WithDeadline(ctx, time.Unix(1, 0))
	defer expire()
	for _, readCtx := range []context.Context{nil, cancelled, expired} {
		out, err := db.InspectSecurityEnrichmentOperation(readCtx, frames[0].OperationID)
		if err == nil || out.State != "unknown" || out.Checkpoint != nil || out.Business.Receipt != "" {
			t.Fatal("invalid/cancelled context exposed a candidate or proof")
		}
		if readCtx != nil && !errors.Is(err, readCtx.Err()) {
			t.Fatal("context error identity lost")
		}
	}
	var absent *Store
	for _, id := range []string{"", strings.Repeat("x", 4096), "90000000-0000-4000-8000-00000000192A", "90000000-0000-4000-8000-0000000000--", " " + frames[0].OperationID} {
		out, err := absent.InspectSecurityEnrichmentOperation(ctx, id)
		if err == nil || out.State != "unknown" || out.Checkpoint != nil {
			t.Fatal("invalid ID reached dependency or became missing")
		}
	}
	if out, err := absent.InspectSecurityEnrichmentOperation(ctx, frames[0].OperationID); err == nil || out.State != "unknown" {
		t.Fatal("nil Store accepted")
	}
	if inspectionContractHash(t, db) != before {
		t.Fatal("rejected/context calls changed database")
	}
	inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", "running", false)
	if _, err := db.db.Exec("ALTER TABLE security_enrichment_checkpoints RENAME TO PRIVATE_unavailable_checkpoints"); err != nil {
		t.Fatal(err)
	}
	inspectWithoutTableChanges(t, db, frames[0].OperationID, "unknown", "unknown", true)
	closed, err := NewWithPath(filepath.Join(t.TempDir(), "closed-inspection.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := closed.InspectSecurityEnrichmentOperation(ctx, frames[0].OperationID); err == nil || out.State != "unknown" || out.Checkpoint != nil || out.Business.Receipt != "" {
		t.Fatal("closed DB exposed proof")
	}
}

func TestOperationInspectionPreparedConversionPreservesPartialEmptyAndIndependentPointers(t *testing.T) {
	_, c := refreshContractFixture(t, "epss", 1930)
	for _, empty := range []string{"nil", "empty", "known-zero"} {
		t.Run(empty, func(t *testing.T) {
			frame := inspectionContractFrames(t, c, 1930)[2]
			feed := &frame.Prepared.Completion.Feed
			switch empty {
			case "nil":
				feed.Entries = nil
			case "empty":
				feed.Entries = []enrichmentjournal.Entry{}
			case "known-zero":
				zero := 0.0
				feed.Entries[0].EPSS, feed.Entries[0].Percentile = &zero, &zero
			}
			before := jsonValueForInspection(t, frame)
			a, failure, full := operationInspectionPrepared(*frame.Prepared)
			if failure != nil || full == nil || !reflect.DeepEqual(a, full.Attempt) || full.OriginalDigest != frame.Prepared.Completion.OriginalDigest || (full.Feed.Entries == nil) != (feed.Entries == nil) || len(full.Feed.Entries) != len(feed.Entries) || !full.Feed.PublishedAt.Equal(feed.PublishedAt) || !full.Feed.ObservedAt.Equal(feed.ObservedAt) {
				t.Fatal("lossless conversion changed clocks/digest/manifest/nil-empty evidence")
			}
			if empty == "known-zero" && (full.Feed.Entries[0].EPSS == nil || *full.Feed.Entries[0].EPSS != 0 || full.Feed.Entries[0].Percentile == nil || *full.Feed.Entries[0].Percentile != 0) {
				t.Fatal("explicit zero became missing")
			}
			a.Targets[0].FindingID = "PRIVATE-local"
			full.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
			full.Feed.SelectedCVEs[0] = "CVE-2026-9999"
			if len(full.Feed.Entries) > 0 {
				*full.Feed.Entries[0].EPSS = 1
				*full.Feed.Entries[0].Percentile = 1
			}
			if jsonValueForInspection(t, frame) != before {
				t.Fatal("converted Store argument aliased journal candidate")
			}
		})
	}
}

func TestOperationInspectionPartialCompletionCanVerifyHistoricalEmptyEvidence(t *testing.T) {
	for _, nonnil := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "empty"}[nonnil], func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 1940)
			if nonnil {
				c.Feed.Entries = c.Feed.Entries[:0:0]
			} else {
				c.Feed.Entries = nil
			}
			frames := inspectionContractFrames(t, c, 1940)
			inspectionAppendFrames(t, db, frames[:3])
			ctx := context.Background()
			if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
				t.Fatal(err)
			}
			out := inspectWithoutTableChanges(t, db, frames[0].OperationID, "valid", "success", false)
			proof, err := db.ReconcileSecurityEnrichmentRefresh(ctx, c)
			if err != nil || out.Business.Receipt == "" || out.Business.Receipt != proof.Receipt || len(out.Checkpoint.Prepared.Completion.Feed.Entries) != 0 {
				t.Fatal("legal partial evidence lost exact historical proof")
			}
		})
	}
}
