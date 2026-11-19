package enrichmentrefresh

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// Keep the owned fixture path so an independent connection can compare every
// table and deliberately damage evidence. No operational database is opened.
func recoveryContractStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal-recovery.sqlite")
	db, err := store.NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close recovery Store: %v", err)
		}
	})
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Errorf("close recovery observer: %v", err)
		}
	})
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	_, err = db.SaveObservedWithError(context.Background(), &model.AlertRecord{
		Alert: model.Alert{
			Owner: "example", Repo: "synthetic", Number: 1, State: "open",
			CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm",
			Summary: "Synthetic recovery fixture", Severity: model.SeverityHigh,
			CreatedAt: at, UpdatedAt: at,
			HTMLURL: "https://github.com/example/synthetic/security/dependabot/1",
		},
		NotifiedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, raw
}

// Include schema and all table rows, including internal SQLite tables. Sorting
// encoded rows preserves duplicates while avoiding dependence on SELECT order.
// This checks logical typed contents, not physical SQLite/WAL file bytes.
func recoveryContractTables(t *testing.T, db *sql.DB) string {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"sqlite_master"}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	var snapshot []string
	for _, name := range names {
		quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		rows, err := tx.Query("SELECT * FROM " + quoted)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		var records []string
		for rows.Next() {
			values := make([]any, len(columns))
			arguments := make([]any, len(columns))
			for i := range values {
				arguments[i] = &values[i]
			}
			if err := rows.Scan(arguments...); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			cells := make([]string, len(values))
			for i, value := range values {
				cells[i] = fmt.Sprintf("%T:%s", value, jsonValue(t, value))
			}
			records = append(records, jsonValue(t, cells))
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(records)
		snapshot = append(snapshot, jsonValue(t, []any{name, columns, records}))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return jsonValue(t, snapshot)
}

func TestJournalTerminalRecoveryContractLostReturnAndReadonlyProof(t *testing.T) {
	for _, failed := range []bool{false, true} {
		for _, reconcileFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("failed=%t/reconcile=%t", failed, reconcileFirst), func(t *testing.T) {
				db, raw := recoveryContractStore(t)
				h := harness(t, db)
				if failed {
					h.fetchError = errSyntheticStore
					h.repo.failAfter, h.repo.readError = reconcileFirst, reconcileFirst
				} else {
					h.repo.completeAfter, h.repo.reconcileError = reconcileFirst, reconcileFirst
				}
				r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
				terminalCommits, lostReads := 0, 0
				r.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, ack *enrichmentjournal.Acknowledgement, err *error) {
					if request.Checkpoint.Stage == enrichmentjournal.Returned && !request.Checkpoint.Progress.Pending {
						if *err != nil || ack.Replay || ack.Sequence != request.Sequence {
							t.Fatalf("terminal did not actually commit: %+v %v", *ack, *err)
						}
						terminalCommits++
						*ack, *err = enrichmentjournal.Acknowledgement{}, errSyntheticStore
					}
				}
				r.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, proof *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
					if *err != nil || proof.State != "matched" || !proof.Acknowledgement.Replay {
						t.Fatalf("initial readonly acknowledgement did not actually match: %+v %v", *proof, *err)
					}
					lostReads++
					*proof, *err = store.SecurityEnrichmentJournalAcknowledgementState{}, errSyntheticStore
				}
				c, err := NewRecoverableJournalManualController(h.service, r)
				if err != nil {
					t.Fatal(err)
				}
				id := manualOperationID(850)
				pending, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
				if !errors.Is(err, ErrPending) || pending.State != "pending" {
					t.Fatalf("expected retained pending call: %+v %v", pending, err)
				}
				sequence := int64(4)
				if reconcileFirst {
					if c.operations[id].preservationUnknown || terminalCommits != 0 || r.appendCalls != 4 {
						t.Fatal("pending sequence-four result was not acknowledged")
					}
					h.repo.readError, h.repo.reconcileError = false, false
					pending, err = c.Reconcile(context.Background(), id)
					if !errors.Is(err, ErrPending) || pending.State != "pending" {
						t.Fatalf("ordinary recovery did not retain lost terminal: %+v %v", pending, err)
					}
					sequence = 5
				}
				if terminalCommits != 1 || lostReads != 1 || r.appendCalls != int(sequence) || r.readCalls != 1 || !c.operations[id].preservationUnknown || !c.recovery.adapter.records[id].unknown {
					t.Fatal("fixture did not lose exactly one committed terminal and acknowledgement")
				}
				want := cloneManualResult(c.operations[id].checkpoint.Result)
				proof, err := db.InspectSecurityEnrichmentOperation(context.Background(), id)
				if err != nil || proof.State != "valid" || proof.HeadSequence != sequence || proof.Business.State != want.Outcome {
					t.Fatalf("real terminal business proof absent: %+v %v", proof, err)
				}
				before := recoveryContractTables(t, raw)
				counts, appends, reads := manualCounts(t, h), r.appendCalls, r.readCalls
				out, err := c.ReconcileJournalTerminal(context.Background(), id)
				if err != nil || out.State != "resolved" || !reflect.DeepEqual(out.Result, want) || r.inspectCalls != 1 {
					t.Fatalf("exact original terminal not restored: %+v %v", out, err)
				}
				if recoveryContractTables(t, raw) != before || manualCounts(t, h) != counts || r.appendCalls != appends || r.readCalls != reads {
					t.Fatal("explicit recovery changed tables or performed non-inspection I/O")
				}
				if c.operations[id].preservationUnknown || c.recovery.adapter.records[id].unknown || !c.recovery.adapter.records[id].acknowledged || c.operations[id].retained == nil {
					t.Fatal("recovery lost original evidence or failed to clear both gates")
				}
			})
		}
	}
}

func TestJournalTerminalRecoveryContractPostAdapterAcknowledgementCancellation(t *testing.T) {
	db, raw := recoveryContractStore(t)
	h := harness(t, db)
	r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
	c, err := NewRecoverableJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := c.preservation
	c.preservation = preservationSinkFunc(func(ctx context.Context, checkpoint PreservationCheckpoint) error {
		err := original.Preserve(ctx, checkpoint)
		if err == nil && checkpoint.Stage == PreserveReturned {
			// The real adapter has finished and accepted the real Store ack.
			// Only now cancel, before the controller's preserving seam returns.
			cancel()
		}
		return err
	})
	id := manualOperationID(851)
	pending, _, err := c.Call(ctx, id, Request{Connector: "epss_feed", Limit: 200})
	journal := c.recovery.adapter.records[id]
	if !errors.Is(err, ErrPending) || pending.State != "pending" || !c.operations[id].preservationUnknown || journal == nil || journal.unknown || !journal.acknowledged || r.appendCalls != 4 || r.readCalls != 0 {
		t.Fatalf("real post-adapter cancellation boundary was not exercised: %+v %v", pending, err)
	}
	want := cloneManualResult(c.operations[id].checkpoint.Result)
	before := recoveryContractTables(t, raw)
	counts := manualCounts(t, h)
	out, err := c.ReconcileJournalTerminal(context.Background(), id)
	if err != nil || out.State != "resolved" || !reflect.DeepEqual(out.Result, want) || r.inspectCalls != 1 || c.operations[id].preservationUnknown || journal.unknown {
		t.Fatalf("acknowledged adapter could not resolve controller uncertainty: %+v %v", out, err)
	}
	if recoveryContractTables(t, raw) != before || manualCounts(t, h) != counts || r.appendCalls != 4 || r.readCalls != 0 {
		t.Fatal("cancellation recovery changed tables or acquired execution")
	}
}

func TestJournalTerminalRecoveryContractDamagedBusinessProofStaysPending(t *testing.T) {
	db, raw := recoveryContractStore(t)
	h := harness(t, db)
	r := &recoveryRepository{faultJournalRepository: &faultJournalRepository{JournalRepository: db}, db: db}
	r.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, ack *enrichmentjournal.Acknowledgement, err *error) {
		if request.Checkpoint.Stage == enrichmentjournal.Returned {
			if *err != nil {
				t.Fatal(*err)
			}
			*ack, *err = enrichmentjournal.Acknowledgement{}, errSyntheticStore
		}
	}
	r.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, _ *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
		*err = errSyntheticStore
	}
	c, err := NewRecoverableJournalManualController(h.service, r)
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(852)
	pending, _, err := c.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || pending.State != "pending" {
		t.Fatalf("fixture did not become pending: %+v %v", pending, err)
	}
	// Corrupt only the owned synthetic historical manifest after the journal
	// committed. The journal can still be valid; its success is not proof.
	result, err := raw.Exec("UPDATE security_enrichment_runs SET original_digest=? WHERE ingest_run_id=?", "sha256:"+strings.Repeat("f", 64), pending.Result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		t.Fatalf("owned evidence damage count=%d err=%v", count, err)
	}
	proof, proofErr := db.InspectSecurityEnrichmentOperation(context.Background(), id)
	if proofErr == nil || proof.State != "valid" || proof.Business.State != "unknown" {
		t.Fatalf("damaged business proof was not independent of valid journal: %+v %v", proof, proofErr)
	}
	before := recoveryContractTables(t, raw)
	counts, appends, reads := manualCounts(t, h), r.appendCalls, r.readCalls
	for i := 0; i < 2; i++ {
		out, err := c.ReconcileJournalTerminal(context.Background(), id)
		if !errors.Is(err, ErrPending) || !reflect.DeepEqual(out, pending) || !c.operations[id].preservationUnknown || !c.recovery.adapter.records[id].unknown {
			t.Fatalf("damaged evidence resolved or changed pending: %+v %v", out, err)
		}
	}
	if r.inspectCalls != 2 || recoveryContractTables(t, raw) != before || manualCounts(t, h) != counts || r.appendCalls != appends || r.readCalls != reads {
		t.Fatal("repeated explicit proof checks repaired data or retried work")
	}
}
