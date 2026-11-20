package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewbridge"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func TestFeedRefreshReceiptsReadPreviewSnapshotAndCLIFullResultParity(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "refresh", 1, model.SeverityHigh, "open")
	ctx := context.Background()
	id := previewFindingID(t, db)
	targets, err := db.QuerySecurityEnrichmentRefreshTargets(ctx, "", 200)
	if err != nil || len(targets.Targets) != 1 {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
	at := time.Date(2026, 11, 10, 12, 3, 0, 0, time.UTC)
	pub, obs, start, finish := at.Add(-time.Hour), at.Add(-2*time.Minute), at.Add(-3*time.Minute), at.Add(-time.Minute)
	scope, err := threat.OfflineSelectionScope([]string{"CVE-2026-0001"})
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	detailBefore, err := db.GetFindingDetail(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	riskBefore, err := db.ListThreatSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runIDs := map[string]string{}
	for i, source := range []string{"epss", "kev"} {
		zero := 0.0
		feed := model.SecurityEnrichmentFeed{Source: source, Version: "synthetic.1", PublishedAt: pub, ObservedAt: obs, SelectedCVEs: []string{"CVE-2026-0001"}, Entries: []model.SecurityEnrichmentEntry{{CVEID: "CVE-2026-0001", EPSS: &zero, Percentile: &zero}}}
		if source == "kev" {
			feed.Entries = []model.SecurityEnrichmentEntry{{CVEID: "CVE-2026-0001", KEV: true, KEVDateAdded: &pub}}
		}
		attempt := store.SecurityEnrichmentRefreshAttempt{RunID: fmt.Sprintf("20000000-0000-4000-8000-%012d", i+1), Connector: source + "_feed", Scope: scope, StartedAt: start, Targets: targets.Targets}
		runIDs[source] = attempt.RunID
		if _, err := db.BeginSecurityEnrichmentRefresh(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, store.SecurityEnrichmentRefreshCompletion{Attempt: attempt, Feed: feed, OriginalDigest: "sha256:" + strings.Repeat("a", 64), FinishedAt: finish}); err != nil {
			t.Fatal(err)
		}
	}
	v1 := decodeConnectorStatusVersionedPage(t, srv, "/api/v1/connectors/status?as_of=2026-11-10T12:03:00Z")
	v2 := decodeConnectorStatusVersionedPage(t, srv, "/api/v2/connectors/status?as_of=2026-11-10T12:03:00Z")
	if v1.Total != 1 || v2.Total != 3 {
		t.Fatalf("versioned receipts v1=%+v v2=%+v", v1, v2)
	}
	seen := map[string]bool{}
	for _, item := range v2.Items {
		source := strings.TrimSuffix(item.Source, "_feed")
		if expectedID := runIDs[source]; expectedID != "" {
			seen[source] = true
			if item.Status != "success" || item.Coverage != "partial" || item.Liveness != "unknown" || item.LatestAttempt.ID != expectedID || !item.LatestAttempt.StartedAt.Equal(start) || item.LatestAttempt.FinishedAt == nil || !item.LatestAttempt.FinishedAt.Equal(finish) || item.LastSuccess == nil || item.LastSuccess.ID != expectedID {
				t.Fatalf("feed receipt identity/clocks=%+v", item)
			}
		}
	}
	if !seen["epss"] || !seen["kev"] {
		t.Fatalf("new feed origins absent from v2 receipts: %+v", v2.Items)
	}
	page, err := db.QueryFindingsPage(ctx, store.FindingQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	enriched := page.Enrichments[id]
	if enriched.EPSS == nil || enriched.EPSS.Source != "epss" || enriched.KEV == nil || enriched.KEV.Source != "kev" {
		t.Fatalf("connector origin contaminated enrichment=%+v", enriched)
	}
	if enriched.EPSS.EPSS == nil || *enriched.EPSS.EPSS != 0 || enriched.EPSS.Percentile == nil || *enriched.EPSS.Percentile != 0 || !enriched.KEV.KEV || enriched.KEV.KEVDateAdded == nil || !enriched.KEV.KEVDateAdded.Equal(pub) {
		t.Fatal("common read lost known zero EPSS or positive KEV")
	}
	for source, evidence := range map[string]*model.SecurityEnrichmentEvidence{"epss": enriched.EPSS, "kev": enriched.KEV} {
		if evidence.RunID != runIDs[source] || evidence.Version != "synthetic.1" || !evidence.PublishedAt.Equal(pub) || !evidence.ObservedAt.Equal(obs) || evidence.PublishedAt.Equal(evidence.ObservedAt) || evidence.ObservedAt.Equal(start) {
			t.Fatalf("common read provenance/independent clocks source=%s evidence=%+v", source, evidence)
		}
	}
	snapshot, err := db.GetFindingPreviewSnapshot(ctx, id, at)
	if err != nil {
		t.Fatal(err)
	}
	_, want, err := findingpreviewbridge.Build(snapshot.Finding.Finding, snapshot.Asset, snapshot.Finding.Source, snapshot.Finding.SourceFindingID, snapshot.Enrichment, at)
	if err != nil {
		t.Fatal(err)
	}
	out := readPreviewResponse(t, srv, id, at)
	if !reflect.DeepEqual(out.Result, want) || out.Result.EPSS == nil || out.Result.KEV == nil || out.Result.InputSnapshot.Threat.EPSS == nil || *out.Result.InputSnapshot.Threat.EPSS != 0 {
		t.Fatal("common read and HTTP full Result differ or zero evidence was lost")
	}
	if !out.Result.InputSnapshot.Threat.KEV || !out.Result.InputSnapshot.Threat.KEVKnown || !out.Result.EPSS.Fresh || !out.Result.KEV.Fresh {
		t.Fatal("preview matched through missing or unknown evidence instead of known feed facts")
	}
	for source, evidence := range map[string]*findingpreview.EvidenceState{"epss": out.Result.EPSS, "kev": out.Result.KEV} {
		if evidence.RunID != runIDs[source] || !evidence.PublishedAt.Equal(pub) || !evidence.ObservedAt.Equal(obs) {
			t.Fatalf("preview feed provenance source=%s evidence=%+v", source, evidence)
		}
	}
	type snapshotFact struct {
		RunID       string    `json:"run_id"`
		PublishedAt time.Time `json:"published_at"`
		ObservedAt  time.Time `json:"observed_at"`
		Probability *float64  `json:"probability"`
		Positive    *bool     `json:"positive"`
	}
	var facts struct {
		Enrichment struct {
			CVEID string        `json:"cve_id"`
			EPSS  *snapshotFact `json:"epss"`
			KEV   *snapshotFact `json:"kev"`
		} `json:"enrichment"`
	}
	if err := json.Unmarshal(out.InputSnapshot, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.Enrichment.CVEID != "CVE-2026-0001" || facts.Enrichment.EPSS == nil || facts.Enrichment.KEV == nil || facts.Enrichment.EPSS.Probability == nil || *facts.Enrichment.EPSS.Probability != 0 || facts.Enrichment.KEV.Positive == nil || !*facts.Enrichment.KEV.Positive {
		t.Fatal("input_snapshot lacks explicit zero EPSS and positive KEV facts")
	}
	for source, fact := range map[string]*snapshotFact{"epss": facts.Enrichment.EPSS, "kev": facts.Enrichment.KEV} {
		if fact.RunID != runIDs[source] || !fact.PublishedAt.Equal(pub) || !fact.ObservedAt.Equal(obs) {
			t.Fatalf("input_snapshot feed provenance source=%s fact=%+v", source, fact)
		}
	}
	for _, forbidden := range []string{"epss_feed", "kev_feed", "refresh-attempt", "refresh-success", "sha256:"} {
		if bytes.Contains(out.InputSnapshot, []byte(forbidden)) {
			t.Fatalf("closed base snapshot leaked connector metadata %q", forbidden)
		}
	}
	// Use the existing offline CLI, not the application or a live listener.
	binary := buildPreviewFindingCLI(t)
	command := exec.Command(binary, "--schema", "base")
	command.Stdin = bytes.NewReader(out.InputSnapshot)
	result, err := command.Output()
	if err != nil {
		t.Fatalf("existing CLI replay: %v", err)
	}
	var cli struct {
		Result findingpreview.Result `json:"result"`
	}
	if err := json.Unmarshal(result, &cli); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Result, cli.Result) {
		t.Fatal("feed receipt HTTP/input_snapshot/CLI full Result mismatch")
	}
	afterDetail, err := db.GetFindingDetail(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	detailBefore.Enrichment = nil
	afterDetail.Enrichment = nil
	if !reflect.DeepEqual(detailBefore, afterDetail) {
		t.Fatal("refresh changed authoritative finding/triage/history")
	}
	legacyAfter, err := json.Marshal(db.List())
	if err != nil || !bytes.Equal(legacyBefore, legacyAfter) {
		t.Fatal("refresh changed legacy alerts")
	}
	riskAfter, err := db.ListThreatSnapshots(ctx)
	if err != nil || !reflect.DeepEqual(riskBefore, riskAfter) {
		t.Fatal("refresh changed legacy threat snapshots")
	}
	findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?source=dependabot", http.StatusOK)
}
