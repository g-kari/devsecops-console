package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestIngestGuardRejectsAmbiguousStoredModelBeforeMutation(t *testing.T) {
	for _, kind := range []string{"invalid-json", "array", "null", "missing-key", "duplicate-long-s", "scope-type", "clock-mismatch", "coverage-mismatch", "row-connector-blob", "body-oversize-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
			run := ingestGuardContractPositive(t, db, "dependabot", "scope", at)
			raw, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			query := "UPDATE ingest_runs SET body_json=? WHERE id=?"
			args := []any{body, run.ID}
			switch kind {
			case "invalid-json":
				if _, err := db.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
					t.Fatal(err)
				}
				body = "{PRIVATE-not-json"
			case "array":
				body = "[]"
			case "null":
				body = "null"
			case "missing-key":
				body = strings.Replace(body, "\"cursor\":\"\",", "", 1)
			case "duplicate-long-s":
				body = strings.Replace(body, "\"scope\":\"scope\"", "\"scope\":\"scope\",\"\\u017fcope\":\"PRIVATE-other\"", 1)
			case "scope-type":
				body = strings.Replace(body, "\"scope\":\"scope\"", "\"scope\":123", 1)
			case "clock-mismatch":
				body = strings.Replace(body, "\"started_at\":\"2026-11-10T12:00:00Z\"", "\"started_at\":\"2026-11-10T11:00:00Z\"", 1)
			case "coverage-mismatch":
				body = strings.Replace(body, "\"coverage\":\"unknown\"", "\"coverage\":\"full\"", 1)
			case "row-connector-blob":
				query, args = "UPDATE ingest_runs SET connector=CAST(connector AS BLOB) WHERE id=?", []any{run.ID}
			case "body-oversize-mismatch":
				run.Connector = strings.Repeat("PRIVATE", 10000)
				raw, err = json.Marshal(run)
				if err != nil {
					t.Fatal(err)
				}
				body = string(raw)
			}
			if len(args) == 2 {
				args[0] = body
			}
			if _, err := db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			err = db.FinishIngestRun(context.Background(), run.ID, "failed", "unknown", "store_failed", at.Add(time.Minute))
			if !errors.Is(err, errReservationCorrupt) || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
				t.Fatalf("invalid model %s was not a closed read-only refusal: %v", kind, err)
			}
		})
	}
}

func TestIngestGuardValidJSONAttributeAliasesAndLiteralSourceValues(t *testing.T) {
	for _, kind := range []string{"escaped-connector", "case-connector", "long-s-scope", "case-id", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
			// The value contains the Kelvin sign. Attribute names fold as Go
			// JSON does; values must not be rewritten into kev_feed.
			run := ingestGuardContractPositive(t, db, "\u212aev_feed", "scope", at)
			raw, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			switch kind {
			case "escaped-connector":
				body = strings.Replace(body, "\"connector\":", "\"conne\\u0063tor\":", 1)
			case "case-connector":
				body = strings.Replace(body, "\"connector\":", "\"ConnecTOR\":", 1)
			case "long-s-scope":
				body = strings.Replace(body, "\"scope\":", "\"\\u017fcope\":", 1)
			case "case-id":
				body = strings.Replace(body, "\"id\":", "\"ID\":", 1)
			case "unknown-field":
				body = "{\"extra_ignored\":\"synthetic\"," + body[1:]
			}
			if !json.Valid([]byte(body)) {
				t.Fatal("attribute alias fixture is invalid")
			}
			if _, err := db.db.Exec("UPDATE ingest_runs SET body_json=? WHERE id=?", body, run.ID); err != nil {
				t.Fatal(err)
			}
			ingestGuardContractFinishPositive(t, db, run, at.Add(time.Minute))
		})
	}
	t.Run("legacy-valid-calendar-range-is-not-refresh-range", func(t *testing.T) {
		for _, year := range []int{0, 9999} {
			db := journalOwnedStore(t)
			at := time.Date(year, 1, 1, 12, 0, 0, 1, time.UTC)
			run := ingestGuardContractPositive(t, db, "epss_feed", "scope", at)
			ingestGuardContractFinishPositive(t, db, run, at.Add(time.Minute))
		}
	})
}

func TestIngestGuardContextClosedDatabaseAndReadFailureKeepBoundaries(t *testing.T) {
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	db := journalOwnedStore(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()
	for _, ctx := range []context.Context{cancelled, expired} {
		before := journalSnapshot(t, db, false)
		run, err := db.StartIngestRun(ctx, "epss_feed", "scope", at)
		if !errors.Is(err, ctx.Err()) || !reflect.DeepEqual(run, model.IngestRun{}) {
			t.Fatal("feed Begin failure must precede UUID allocation/return")
		}
		run, err = db.StartIngestRun(ctx, "dependabot", "scope", at)
		if !errors.Is(err, ctx.Err()) || !securityUUID(run.ID) {
			t.Fatal("nonfeed old UUID-before-Begin error result changed")
		}
		if err := db.FinishIngestRun(ctx, "arbitrary-missing-id", "success", "full", "", at); !errors.Is(err, ctx.Err()) || journalSnapshot(t, db, false) != before {
			t.Fatal("Finish transaction cancellation lost context identity or changed data")
		}
	}
	if run, err := startGuardedFeedIngestRun(nil, nil, "epss_feed", "scope", at); err == nil || !reflect.DeepEqual(run, model.IngestRun{}) { //nolint:staticcheck // nil context is the test input: the callee must reject it explicitly
		t.Fatal("nil private Start dependency accepted")
	}
	if err := guardLegacyIngestFinishTx(nil, nil, "id"); !errors.Is(err, errReservationConflict) { //nolint:staticcheck // nil context is the test input: the callee must reject it explicitly
		t.Fatal("nil private Finish dependency accepted")
	}
	known := ingestGuardContractPositive(t, db, "dependabot", "scope", at)
	if _, err := db.db.Exec("ALTER TABLE ingest_runs RENAME TO PRIVATE_unavailable_ingest"); err != nil {
		t.Fatal(err)
	}
	before := journalSnapshot(t, db, false)
	if err := db.FinishIngestRun(context.Background(), known.ID, "success", "full", "", at.Add(time.Minute)); !errors.Is(err, errReservationStorage) || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatalf("metadata SQL failure leaked provider text or mutated rows: %v", err)
	}
	closed := journalOwnedStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"epss_feed", "kev_feed", "dependabot"} {
		run, err := closed.StartIngestRun(context.Background(), source, "scope", at)
		if err == nil || source != "dependabot" && !reflect.DeepEqual(run, model.IngestRun{}) || source == "dependabot" && !securityUUID(run.ID) {
			t.Fatal("closed DB changed feed/nonfeed UUID allocation boundary")
		}
	}
	if err := closed.FinishIngestRun(context.Background(), "id", "success", "full", "", at); err == nil {
		t.Fatal("closed DB Finish accepted")
	}
}

func TestIngestGuardMetadataEmitsOnlySmallFlagsAndUsesIndexedIDs(t *testing.T) {
	db := journalOwnedStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	run := ingestGuardContractPositive(t, db, strings.Repeat("source-value", 1000), strings.Repeat("scope-value", 1000), at)
	before := journalSnapshot(t, db, false)
	tx, err := db.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(context.Background(), legacyIngestFinishMetadataSQL, run.ID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := rows.Columns()
	if err != nil || len(columns) != 4 || !rows.Next() {
		_ = rows.Close()
		t.Fatal("bounded metadata did not emit exactly four flags")
	}
	var row, running, source, body int
	if err := rows.Scan(&row, &running, &source, &body); err != nil || row != 1 || running != 1 || source != 0 || body != 1 || rows.Next() {
		_ = rows.Close()
		t.Fatal("large healthy values were materialized/classified as a feed")
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := tx.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+legacyIngestFinishMetadataSQL, run.ID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	indexed := false
	for plan.Next() {
		var id, parent, unused int
		var detail string
		if err := plan.Scan(&id, &parent, &unused, &detail); err != nil {
			_ = plan.Close()
			t.Fatal(err)
		}
		if strings.Contains(detail, "SEARCH ingest_runs") && strings.Contains(detail, "INDEX") && strings.Contains(detail, "id=?") {
			indexed = true
		}
	}
	if err := plan.Err(); err != nil {
		_ = plan.Close()
		t.Fatal(err)
	}
	if err := plan.Close(); err != nil || !indexed {
		t.Fatal("finite ID candidate lookup did not use its existing index")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if journalSnapshot(t, db, false) != before {
		t.Fatal("metadata/plan read changed an owned table")
	}
}
