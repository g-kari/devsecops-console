package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func refreshAttemptTableHashes(t *testing.T, s *Store) map[string]string {
	t.Helper()
	hashes := map[string]string{}
	for name, rows := range previewDatabaseState(t, s) {
		body, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		hashes[name] = fmt.Sprintf("%x", sha256.Sum256(body))
	}
	return hashes
}

func readAttemptWithoutWrites(t *testing.T, s *Store, ctx context.Context, attempt SecurityEnrichmentRefreshAttempt, failure *SecurityEnrichmentRefreshFailure, want string, wantError bool) error {
	t.Helper()
	before := refreshAttemptTableHashes(t, s)
	state, err := s.ReadSecurityEnrichmentRefreshAttempt(ctx, attempt, failure)
	if state.State != want || state.Receipt != "" || (err != nil) != wantError {
		t.Fatalf("attempt readback=%+v err=%v, want state=%s error=%v", state, err, want, wantError)
	}
	if !reflect.DeepEqual(before, refreshAttemptTableHashes(t, s)) {
		t.Fatal("attempt readback changed at least one database table hash")
	}
	return err
}

func TestRefreshAttemptReadbackIsReadOnlyAndPreservesLastGoodEvidence(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 1101)
	ctx := context.Background()
	old, feed := enrichmentFixture(t, 1102, "epss", c.Feed.PublishedAt.Add(-time.Hour), c.Feed.ObservedAt)
	mustEnrichment(t, s, old, feed)
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Enrichment == nil || before.Enrichment.EPSS == nil || before.Enrichment.EPSS.RunID != old.ID {
		t.Fatal("last-good fixture absent")
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "running", false)
	after, err := s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("last-good evidence changed: %v", err)
	}
}

func TestRefreshAttemptReadbackDoesNotSubstituteAnotherRunOrIdentity(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 1110)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	other := c.Attempt
	other.RunID = "10000000-0000-4000-8000-000000001111"
	_ = readAttemptWithoutWrites(t, s, ctx, other, nil, "missing", false)
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, other); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "running", false)
	_ = readAttemptWithoutWrites(t, s, ctx, other, nil, "running", false)
	for _, change := range []string{"source", "scope", "start", "revision", "target-id", "cve", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			a := c.Attempt
			a.Targets = append([]SecurityEnrichmentRefreshTarget(nil), a.Targets...)
			switch change {
			case "source":
				a.Connector = "kev_feed"
			case "scope":
				a.Scope = "wrong"
			case "start":
				a.StartedAt = a.StartedAt.Add(time.Nanosecond)
			case "revision":
				a.Targets[0].Revision = strings.Repeat("b", 64)
			case "target-id":
				a.Targets[0].FindingID = "different-finding"
			case "cve":
				a.Targets[0].CVEID = "CVE-2026-5678"
				var err error
				a.Scope, err = threat.OfflineSelectionScope([]string{a.Targets[0].CVEID})
				if err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				a.Targets = append(a.Targets, a.Targets[0])
			}
			_ = readAttemptWithoutWrites(t, s, ctx, a, nil, "unknown", true)
		})
	}
	zone := time.FixedZone("equivalent", -8*60*60)
	equivalent := c.Attempt
	equivalent.StartedAt = equivalent.StartedAt.In(zone)
	_ = readAttemptWithoutWrites(t, s, ctx, equivalent, nil, "running", false)
	// This is a historical reservation binding, not a new target scan.
	if _, err := s.db.Exec("UPDATE findings SET body_json=json_set(body_json,'$.title','later mutation')"); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "running", false)
}

func TestRefreshAttemptReadbackRequiresExactFailureAndNeverReturnsSuccess(t *testing.T) {
	s, c := refreshContractFixture(t, "kev", 1120)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "fetch_failed", c.FinishedAt); err != nil {
		t.Fatal(err)
	}
	expected := &SecurityEnrichmentRefreshFailure{Code: "fetch_failed", FinishedAt: c.FinishedAt}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, expected, "failed", false)
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "unknown", false)
	for _, f := range []*SecurityEnrichmentRefreshFailure{
		{Code: "parse_failed", FinishedAt: c.FinishedAt},
		{Code: "fetch_failed", FinishedAt: c.FinishedAt.Add(time.Nanosecond)},
		{Code: "fetch_failed", FinishedAt: c.FinishedAt.Add(-time.Nanosecond)},
	} {
		_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, f, "unknown", true)
	}
	c.Attempt.RunID = "10000000-0000-4000-8000-000000001121"
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "unknown", false)
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, expected, "unknown", false)
	full, err := s.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if err != nil || full.State != "success" || full.Receipt == "" {
		t.Fatalf("full-completion verification lost=%+v err=%v", full, err)
	}
}

func insertAttemptOrphan(t *testing.T, s *Store, id, kind string, c SecurityEnrichmentRefreshCompletion) {
	t.Helper()
	if kind == "manifest" {
		_, err := s.db.Exec("INSERT INTO security_enrichment_runs(ingest_run_id,source,version,published_at,observed_at,selected_cves_json,entries,original_digest) VALUES(?,?,?,?,?,?,?,?)", id, "epss", "synthetic", c.Feed.PublishedAt.Format(time.RFC3339Nano), c.Feed.ObservedAt.Format(time.RFC3339Nano), "[]", 0, "sha256:"+strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		_, err := s.db.Exec("INSERT INTO security_enrichment_observations(id,ingest_run_id,source,cve_id,published_at,observed_at,evidence_identity,body_json) VALUES(?,?,?,?,?,?,?,?)", "synthetic-orphan", id, "epss", "CVE-2026-1234", c.Feed.PublishedAt.Format(time.RFC3339Nano), c.Feed.ObservedAt.Format(time.RFC3339Nano), "synthetic", "{}")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRefreshAttemptReadbackRejectsEvidenceOrphansInEveryNonSuccessState(t *testing.T) {
	for _, status := range []string{"missing", "running", "failed"} {
		for _, kind := range []string{"manifest", "observation"} {
			t.Run(status+"/"+kind, func(t *testing.T) {
				s, c := refreshContractFixture(t, "epss", 1130)
				ctx := context.Background()
				if status != "missing" {
					if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
						t.Fatal(err)
					}
				}
				var failure *SecurityEnrichmentRefreshFailure
				if status == "failed" {
					failure = &SecurityEnrichmentRefreshFailure{Code: "store_failed", FinishedAt: c.FinishedAt}
					if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, failure.Code, failure.FinishedAt); err != nil {
						t.Fatal(err)
					}
				}
				// Deliberate corruption of this disposable fixture only.
				if _, err := s.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
					t.Fatal(err)
				}
				insertAttemptOrphan(t, s, c.Attempt.RunID, kind, c)
				_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, failure, "unknown", true)
			})
		}
	}
	s, c := refreshContractFixture(t, "epss", 1131)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DELETE FROM ingest_runs WHERE id=?", c.Attempt.RunID); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "unknown", true)
}

func TestRefreshAttemptReadbackRejectsCorruptAndOversizeStoredRows(t *testing.T) {
	for _, change := range []string{"body-binding", "extra-body-field", "duplicate-body-key", "noncanonical-body", "body-size", "cursor-size", "scope-size", "connector-size", "started-size", "finished-size", "error-size", "blob-cursor", "column-source", "column-scope", "column-start", "running-finish", "coverage", "partial"} {
		t.Run(change, func(t *testing.T) {
			s, c := refreshContractFixture(t, "epss", 1140)
			if _, err := s.BeginSecurityEnrichmentRefresh(context.Background(), c.Attempt); err != nil {
				t.Fatal(err)
			}
			query, value := "", ""
			switch change {
			case "body-binding":
				query, value = "UPDATE ingest_runs SET body_json=? WHERE id=?", "{}"
			case "extra-body-field":
				query = "UPDATE ingest_runs SET body_json=json_set(body_json,'$.unexpected','private-sentinel') WHERE id=?"
			case "duplicate-body-key":
				var body string
				if err := s.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", c.Attempt.RunID).Scan(&body); err != nil {
					t.Fatal(err)
				}
				prefix, err := json.Marshal(map[string]string{"id": c.Attempt.RunID})
				if err != nil {
					t.Fatal(err)
				}
				query, value = "UPDATE ingest_runs SET body_json=? WHERE id=?", string(prefix[:len(prefix)-1])+","+body[1:]
			case "noncanonical-body":
				query = "UPDATE ingest_runs SET body_json=' '||body_json WHERE id=?"
			case "body-size":
				body, err := json.Marshal(map[string]string{"oversize": strings.Repeat("x", 4097)})
				if err != nil {
					t.Fatal(err)
				}
				query, value = "UPDATE ingest_runs SET body_json=? WHERE id=?", string(body)
			case "cursor-size":
				query, value = "UPDATE ingest_runs SET cursor=? WHERE id=?", strings.Repeat("x", 129)
			case "scope-size":
				query, value = "UPDATE ingest_runs SET scope=? WHERE id=?", strings.Repeat("x", 257)
			case "connector-size":
				query, value = "UPDATE ingest_runs SET connector=? WHERE id=?", strings.Repeat("x", 65)
			case "started-size":
				query, value = "UPDATE ingest_runs SET started_at=? WHERE id=?", strings.Repeat("x", 41)
			case "finished-size":
				query, value = "UPDATE ingest_runs SET finished_at=? WHERE id=?", strings.Repeat("x", 41)
			case "error-size":
				query, value = "UPDATE ingest_runs SET error=? WHERE id=?", strings.Repeat("x", 65)
			case "blob-cursor":
				query = "UPDATE ingest_runs SET cursor=x'61' WHERE id=?"
			case "column-source":
				query = "UPDATE ingest_runs SET connector='kev_feed' WHERE id=?"
			case "column-scope":
				query = "UPDATE ingest_runs SET scope='different' WHERE id=?"
			case "column-start":
				query = "UPDATE ingest_runs SET started_at='2026-11-10T11:59:01Z' WHERE id=?"
			case "running-finish":
				query = "UPDATE ingest_runs SET finished_at='2026-11-10T12:00:00Z' WHERE id=?"
			case "coverage":
				query = "UPDATE ingest_runs SET coverage='full' WHERE id=?"
			case "partial":
				query = "UPDATE ingest_runs SET result='partial' WHERE id=?"
			}
			var err error
			if value != "" {
				_, err = s.db.Exec(query, value, c.Attempt.RunID)
			} else {
				_, err = s.db.Exec(query, c.Attempt.RunID)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = readAttemptWithoutWrites(t, s, context.Background(), c.Attempt, nil, "unknown", true)
			if strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("stored content leaked through read error")
			}
		})
	}
}

func TestRefreshAttemptReadbackRejectsWrongUUIDBodyAndMalformedFailureLifecycle(t *testing.T) {
	for _, change := range []string{"body-id", "failure-finish", "failure-code", "failure-cursor", "failure-coverage"} {
		t.Run(change, func(t *testing.T) {
			s, c := refreshContractFixture(t, "epss", 1150)
			ctx := context.Background()
			if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "fetch_failed", c.FinishedAt); err != nil {
				t.Fatal(err)
			}
			var body string
			if err := s.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", c.Attempt.RunID).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var run model.IngestRun
			if err := json.Unmarshal([]byte(body), &run); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "body-id":
				run.ID = "10000000-0000-4000-8000-000000001151"
			case "failure-finish":
				run.FinishedAt = nil
			case "failure-code":
				run.Error = "unrecognized_fixed_code"
			case "failure-cursor":
				run.Cursor = "refresh-attempt-v1:sha256:" + strings.Repeat("b", 64)
			case "failure-coverage":
				run.Coverage = "partial"
			}
			encoded, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			var finished any
			if run.FinishedAt != nil {
				finished = run.FinishedAt.Format(time.RFC3339Nano)
			}
			if _, err := s.db.Exec("UPDATE ingest_runs SET finished_at=?,error=?,cursor=?,coverage=?,body_json=? WHERE id=?", finished, run.Error, run.Cursor, run.Coverage, string(encoded), c.Attempt.RunID); err != nil {
				t.Fatal(err)
			}
			_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, &SecurityEnrichmentRefreshFailure{Code: "fetch_failed", FinishedAt: c.FinishedAt}, "unknown", true)
		})
	}
}

func TestRefreshAttemptReadbackCancelReadErrorAndSameUUIDRecovery(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 1160)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err := readAttemptWithoutWrites(t, s, canceled, c.Attempt, nil, "unknown", true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "running", false)
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM ingest_runs WHERE connector='epss_feed'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("recovery created extra attempt count=%d err=%v", count, err)
	}
	// Keep all fixture rows, but make the expected table unavailable to the reader.
	if _, err := s.db.Exec("ALTER TABLE ingest_runs RENAME TO unavailable_ingest_runs"); err != nil {
		t.Fatal(err)
	}
	_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "unknown", true)
}

func TestRefreshAttemptReadbackRejectsInvalidExpectationBeforeDatabase(t *testing.T) {
	_, c := refreshContractFixture(t, "epss", 1170)
	for _, failure := range []*SecurityEnrichmentRefreshFailure{
		{Code: "private-error-sentinel", FinishedAt: c.FinishedAt},
		{Code: "", FinishedAt: c.FinishedAt},
		{Code: "fetch_failed"},
		{Code: "fetch_failed", FinishedAt: c.Attempt.StartedAt.Add(-time.Nanosecond)},
	} {
		var absent *Store
		state, err := absent.ReadSecurityEnrichmentRefreshAttempt(context.Background(), c.Attempt, failure)
		if err == nil || state.State != "unknown" || state.Receipt != "" || strings.Contains(err.Error(), "private-error-sentinel") {
			t.Fatalf("invalid expectation=%+v err=%v", state, err)
		}
	}
}

func TestRefreshAttemptReadbackClosedDatabaseIsUnknown(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 1180)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := s.ReadSecurityEnrichmentRefreshAttempt(context.Background(), c.Attempt, nil)
	if err == nil || state.State != "unknown" || state.Receipt != "" {
		t.Fatalf("closed database outcome=%+v err=%v", state, err)
	}
}

func TestRefreshAttemptReadbackRejectsInvalidAttemptBeforeDatabase(t *testing.T) {
	_, c := refreshContractFixture(t, "epss", 1181)
	for _, change := range []string{"id", "source", "scope", "start", "cve", "count"} {
		a := c.Attempt
		a.Targets = append([]SecurityEnrichmentRefreshTarget(nil), a.Targets...)
		switch change {
		case "id":
			a.RunID = "invalid"
		case "source":
			a.Connector = "epss_offline"
		case "scope":
			a.Scope = "wrong"
		case "start":
			a.StartedAt = time.Time{}
		case "cve":
			a.Targets[0].CVEID = " cve-2026-1234 "
		case "count":
			a.Targets = make([]SecurityEnrichmentRefreshTarget, 201)
		}
		var absent *Store
		state, err := absent.ReadSecurityEnrichmentRefreshAttempt(context.Background(), a, nil)
		if err == nil || state.State != "unknown" || state.Receipt != "" {
			t.Fatalf("invalid %s reached database: outcome=%+v err=%v", change, state, err)
		}
	}
}

func TestRefreshAttemptReadbackRejectsUUIDStorageAliases(t *testing.T) {
	for _, kind := range []string{"run-only", "run-shadow", "manifest-reference", "observation-reference"} {
		t.Run(kind, func(t *testing.T) {
			s, c := refreshContractFixture(t, "epss", 1190)
			ctx := context.Background()
			if _, err := s.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "run-only", "run-shadow":
				if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
					t.Fatal(err)
				}
				query := "UPDATE ingest_runs SET id=CAST(id AS BLOB) WHERE id=?"
				if kind == "run-shadow" {
					query = "INSERT INTO ingest_runs(id,connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json) SELECT CAST(id AS BLOB),connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json FROM ingest_runs WHERE id=?"
				}
				if _, err := s.db.Exec(query, c.Attempt.RunID); err != nil {
					t.Fatal(err)
				}
			case "manifest-reference":
				if _, err := s.db.Exec("INSERT INTO security_enrichment_runs(ingest_run_id,source,version,published_at,observed_at,selected_cves_json,entries,original_digest) VALUES(?,?,?,?,?,?,?,?)", []byte(c.Attempt.RunID), "epss", "synthetic", c.Feed.PublishedAt.Format(time.RFC3339Nano), c.Feed.ObservedAt.Format(time.RFC3339Nano), "[]", 0, "sha256:"+strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			case "observation-reference":
				if _, err := s.db.Exec("INSERT INTO security_enrichment_observations(id,ingest_run_id,source,cve_id,published_at,observed_at,evidence_identity,body_json) VALUES(?,?,?,?,?,?,?,?)", "blob-orphan", []byte(c.Attempt.RunID), "epss", "CVE-2026-1234", c.Feed.PublishedAt.Format(time.RFC3339Nano), c.Feed.ObservedAt.Format(time.RFC3339Nano), "synthetic", "{}"); err != nil {
					t.Fatal(err)
				}
			}
			_ = readAttemptWithoutWrites(t, s, ctx, c.Attempt, nil, "unknown", true)
		})
	}
}
