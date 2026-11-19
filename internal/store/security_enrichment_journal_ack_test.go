package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func TestJournalAckMissingConflictAndCorruptionNeverMutateTables(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-previous", "payload-blob", "operation-blob", "oversize", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			frames := journalStoreFrames(t)
			expected := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frames[0]}
			if kind != "missing" {
				ack := appendJournalFrame(t, db, frames[0], 1, "")
				if kind == "wrong-previous" {
					expected = enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: "sha256:" + strings.Repeat("f", 64), Checkpoint: frames[1]}
				}
				if _, err := db.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "payload-blob":
					_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET payload_json=CAST(payload_json AS BLOB)")
				case "operation-blob":
					_, err = db.db.Exec("INSERT INTO security_enrichment_operations SELECT CAST(operation_id AS BLOB),format_version,connector,request_after,request_limit,run_id,head_sequence,head_digest FROM security_enrichment_operations WHERE operation_id=?", frames[0].OperationID)
				case "oversize":
					_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET payload_json=?", strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1))
				case "orphan":
					if _, err = db.db.Exec("PRAGMA foreign_keys=OFF"); err == nil {
						_, err = db.db.Exec("DELETE FROM security_enrichment_operations")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if ack.Digest == "" {
					t.Fatal("fixture ack absent")
				}
			}
			before := journalSnapshot(t, db, false)
			state, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(context.Background(), expected)
			if kind == "missing" {
				if err != nil || state.State != "missing" {
					t.Fatal("empty valid snapshot did not report missing")
				}
			} else if kind == "wrong-previous" {
				if err != nil || state.State != "conflict" {
					t.Fatal("wrong previous digest did not conflict")
				}
			} else if err == nil || state.State != "unknown" {
				t.Fatalf("corruption became valid acknowledgement: %+v %v", state, err)
			}
			if state.Acknowledgement.Digest != "" || state.HeadSequence != 0 || state.HeadDigest != "" || journalSnapshot(t, db, false) != before {
				t.Fatal("nonmatched snapshot returned proof or changed tables")
			}
		})
	}
}
func TestJournalAckInvalidContextAndClosedDBReturnUnknown(t *testing.T) {
	db, err := NewWithPath(filepath.Join(t.TempDir(), "closed-ack.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	expected := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: journalStoreFrames(t)[0]}
	if state, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(nil, expected); err == nil || state.State != "unknown" { //nolint:staticcheck // nil context is the test input: the callee must reject it explicitly
		t.Fatal("nil context accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(context.Background(), expected)
	if err == nil || state.State != "unknown" || state.Acknowledgement.Digest != "" {
		t.Fatal("closed DB returned acknowledgement")
	}
}
