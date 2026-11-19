package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func legacyGuardContextCall(ctx context.Context, db *Store, api string, f legacyGuardContractFixture) (bool, error) {
	switch api {
	case "append":
		ack, err := db.AppendSecurityEnrichmentCheckpoint(ctx, f.call)
		return reflect.DeepEqual(ack, enrichmentjournal.Acknowledgement{}), err
	case "begin":
		replay, err := db.BeginSecurityEnrichmentRefresh(ctx, f.completion.Attempt)
		return !replay, err
	case "complete":
		result, err := db.CompleteSecurityEnrichmentRefresh(ctx, f.completion)
		return reflect.DeepEqual(result, SecurityEnrichmentImportResult{}), err
	case "fail":
		replay, err := db.FailSecurityEnrichmentRefresh(ctx, f.completion.Attempt, "fetch_failed", f.completion.FinishedAt)
		return !replay, err
	default:
		panic("unknown test API")
	}
}

func TestLegacyFeedGuardBoundedRegistryAndResidualAliasesFailClosed(t *testing.T) {
	for index, kind := range []string{"unknown-source", "source-oversize", "source-generation-negative", "source-generation-overflow", "source-active-oversize", "source-active-blob", "source-half-active", "idle-reservation-connector-alias", "idle-reservation-mislabeled", "idle-reservation-operation-alias"} {
		t.Run(kind, func(t *testing.T) {
			f := legacyGuardContractFixtureFor(t, "epss", 3100+index)
			legacyGuardContractPrepare(t, &f, "append", false, true)
			for _, query := range []string{"PRAGMA foreign_keys=OFF", "PRAGMA ignore_check_constraints=ON"} {
				if _, err := f.db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			query, args := "", []any{}
			switch kind {
			case "unknown-source":
				query = "INSERT INTO security_enrichment_source_generations VALUES('PRIVATE-unknown',0,NULL,NULL)"
			case "source-oversize":
				query, args = "UPDATE security_enrichment_source_generations SET connector=? WHERE connector='epss_feed'", []any{strings.Repeat("PRIVATE", 10000)}
			case "source-generation-negative":
				query = "UPDATE security_enrichment_source_generations SET generation=-1 WHERE connector='epss_feed'"
			case "source-generation-overflow":
				query = "UPDATE security_enrichment_source_generations SET generation=9223372036854775808 WHERE connector='epss_feed'"
			case "source-active-oversize":
				query, args = "UPDATE security_enrichment_source_generations SET active_operation_id=? WHERE connector='epss_feed'", []any{strings.Repeat("PRIVATE", 10000)}
			case "source-active-blob":
				query = "UPDATE security_enrichment_source_generations SET active_operation_id=CAST(active_operation_id AS BLOB) WHERE connector='epss_feed'"
			case "source-half-active":
				query = "UPDATE security_enrichment_source_generations SET active_operation_id=NULL WHERE connector='epss_feed'"
			default:
				if _, err := f.db.db.Exec("UPDATE security_enrichment_source_generations SET generation=0,active_operation_id=NULL,active_intent_id=NULL WHERE connector='epss_feed'"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "idle-reservation-connector-alias":
					query = "UPDATE security_enrichment_reservations SET connector=CAST(connector AS BLOB)"
				case "idle-reservation-mislabeled":
					query = "UPDATE security_enrichment_reservations SET connector='kev_feed'"
				case "idle-reservation-operation-alias":
					query = "UPDATE security_enrichment_reservations SET connector='kev_feed',operation_id=CAST(operation_id AS BLOB)"
				}
			}
			if _, err := f.db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, f.db, false)
			zero, err := legacyGuardContextCall(context.Background(), f.db, "append", f)
			if !errors.Is(err, errReservationCorrupt) || !zero || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, f.db, false) != before {
				t.Fatalf("corrupt %s became unadopted or leaked/mutated: %v", kind, err)
			}
		})
	}
}

func TestLegacyFeedGuardCancellationReadErrorsAndPositiveReplayClassification(t *testing.T) {
	for index, api := range []string{"append", "begin", "complete", "fail"} {
		t.Run(api, func(t *testing.T) {
			f := legacyGuardContractFixtureFor(t, "epss", 3150+index)
			legacyGuardContractPrepare(t, &f, api, true, true)
			before := journalSnapshot(t, f.db, false)
			if zero, err := legacyGuardContextCall(context.Background(), f.db, api, f); !errors.Is(err, ErrIngestConflict) || !zero {
				t.Fatalf("adopted replay %s did not return the closed conflict: %v", api, err)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
			defer expire()
			for _, ctx := range []context.Context{cancelled, expired} {
				if zero, err := legacyGuardContextCall(ctx, f.db, api, f); !errors.Is(err, ctx.Err()) || !zero {
					t.Fatalf("context identity/zero acknowledgement changed for %s: %v", api, err)
				}
			}
			if journalSnapshot(t, f.db, false) != before {
				t.Fatal("rejected replay or cancellation changed a table")
			}
			if _, err := f.db.db.Exec("ALTER TABLE security_enrichment_source_generations RENAME TO PRIVATE_unavailable_sources"); err != nil {
				t.Fatal(err)
			}
			before = journalSnapshot(t, f.db, false)
			if zero, err := legacyGuardContextCall(context.Background(), f.db, api, f); !errors.Is(err, errReservationStorage) || !zero || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, f.db, false) != before {
				t.Fatalf("guard read failure became a grant or exposed provider text: %v", err)
			}
		})
	}
	t.Run("private-helper-nil-dependencies-without-io", func(t *testing.T) {
		for _, connector := range []string{"epss_feed", "kev_feed", "epss_offline", "PRIVATE-invalid"} {
			if err := guardLegacyEnrichmentWriteTx(context.Background(), nil, connector); !errors.Is(err, errReservationConflict) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("nil transaction accepted or raw input exposed")
			}
		}
		if err := guardLegacyEnrichmentWriteTx(nil, nil, "epss_feed"); !errors.Is(err, errReservationConflict) { //nolint:staticcheck // nil context is the test input: the callee must reject it explicitly
			t.Fatal("nil private context accepted")
		}
	})
	t.Run("closed-database-keeps-zero-results", func(t *testing.T) {
		f := legacyGuardContractFixtureFor(t, "epss", 3159)
		legacyGuardContractPrepare(t, &f, "append", false, true)
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		for _, api := range []string{"append", "begin", "complete", "fail"} {
			if zero, err := legacyGuardContextCall(context.Background(), f.db, api, f); err == nil || !zero {
				t.Fatalf("closed DB granted legacy %s", api)
			}
		}
	})
}

func TestLegacyFeedGuardOfflineHistoryAndLastGoodRemainIndependent(t *testing.T) {
	f := legacyGuardContractFixtureFor(t, "epss", 3200)
	legacyGuardContractPrepare(t, &f, "complete", true, true)
	original := fencedContractRead(t, f.db, f.fenced, true, "success")
	at := f.completion.Feed.ObservedAt
	newer, newFeed := enrichmentFixture(t, 3201, "epss", f.completion.Feed.PublishedAt.Add(time.Minute), at.Add(time.Minute))
	value := 0.75
	newFeed.Entries[0].EPSS = &value
	mustEnrichment(t, f.db, newer, newFeed)
	older, oldFeed := enrichmentFixture(t, 3202, "epss", f.completion.Feed.PublishedAt.Add(-time.Hour), at.Add(2*time.Minute))
	oldValue := 0.95
	oldFeed.Entries[0].EPSS = &oldValue
	mustEnrichment(t, f.db, older, oldFeed)
	detail, err := f.db.GetFindingDetail(context.Background(), f.completion.Attempt.Targets[0].FindingID)
	if err != nil || detail.Enrichment == nil || detail.Enrichment.EPSS == nil || detail.Enrichment.EPSS.EPSS == nil || *detail.Enrichment.EPSS.EPSS != value || detail.Enrichment.EPSS.RunID != newer.ID {
		t.Fatal("offline publication ordering/latest common fact changed")
	}
	var history int
	if err := f.db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_observations WHERE cve_id=?", newFeed.Entries[0].CVEID).Scan(&history); err != nil || history != 3 {
		t.Fatal("feed plus both nonempty offline histories are not retained")
	}
	failedRun, failedFeed := enrichmentFixture(t, 3203, "epss", f.completion.Feed.PublishedAt.Add(2*time.Minute), at.Add(3*time.Minute))
	if _, err := f.db.db.Exec("CREATE TRIGGER legacy_guard_offline_abort BEFORE INSERT ON security_enrichment_observations BEGIN SELECT RAISE(ABORT,'synthetic-offline-block'); END"); err != nil {
		t.Fatal(err)
	}
	before := journalSnapshot(t, f.db, false)
	if _, err := f.db.ImportSecurityEnrichment(context.Background(), failedRun, failedFeed); err == nil || journalSnapshot(t, f.db, false) != before {
		t.Fatal("independent failed offline import lost history/last-good or left partial rows")
	}
	legacyGuardContractReject(t, f.db, "complete", f)
	after, err := f.db.GetFindingDetail(context.Background(), f.completion.Attempt.Targets[0].FindingID)
	if err != nil || !reflect.DeepEqual(detail, after) {
		t.Fatal("guard or failed offline import changed last-good common fact")
	}
	// A newer current common fact does not rewrite the historical known-zero
	// feed completion, its original digest/clocks, or its full receipt proof.
	exact := fencedContractRead(t, f.db, f.fenced, true, "success")
	if exact.Business.Receipt != original.Business.Receipt || exact.Business.Receipt == exact.HeadDigest {
		t.Fatal("journal acknowledgement substituted for historical business receipt")
	}
}

func TestLegacyFeedGuardResidualLookupsUseExistingSourceIndexes(t *testing.T) {
	db := journalOwnedStore(t)
	checks := []struct {
		query, index string
		args         []any
	}{
		{"EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM security_enrichment_reservations WHERE connector=? OR connector=CAST(? AS BLOB) LIMIT 1)", "security_enrichment_reservations", []any{"epss_feed", "epss_feed"}},
		{"EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM security_enrichment_operations AS o WHERE (o.connector=? OR o.connector=CAST(? AS BLOB)) AND EXISTS(SELECT 1 FROM security_enrichment_reservations AS r WHERE r.operation_id=o.operation_id OR r.operation_id=CAST(o.operation_id AS BLOB) LIMIT 1) LIMIT 1)", "security_enrichment_operation_source", []any{"epss_feed", "epss_feed"}},
	}
	for _, check := range checks {
		rows, err := db.db.Query(check.query, check.args...)
		if err != nil {
			t.Fatal(err)
		}
		used := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			if strings.Contains(detail, "SEARCH") && strings.Contains(detail, check.index) {
				used = true
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil || !used {
			t.Fatalf("existing indexed residual lookup not used: %s %v", check.index, err)
		}
	}
}
