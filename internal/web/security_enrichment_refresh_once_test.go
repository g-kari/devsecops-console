package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewbridge"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type orchestratorFixtureFetcher struct {
	t      *testing.T
	source string
	data   []byte
	calls  int
}

func (f *orchestratorFixtureFetcher) Fetch(ctx context.Context, source string) ([]byte, error) {
	f.calls++
	if source != f.source || ctx.Err() != nil {
		f.t.Fatalf("invalid fixture fetch source=%q context=%v", source, ctx.Err())
	}
	return append([]byte(nil), f.data...), nil
}

type orchestratorReceiptRepository struct {
	*store.Store
	t           *testing.T
	completions []store.SecurityEnrichmentRefreshCompletion
}

func (r *orchestratorReceiptRepository) CompleteSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentImportResult, error) {
	body, err := json.Marshal(c)
	if err != nil {
		r.t.Fatal(err)
	}
	var owned store.SecurityEnrichmentRefreshCompletion
	if err := json.Unmarshal(body, &owned); err != nil {
		r.t.Fatal(err)
	}
	r.completions = append(r.completions, owned)
	return r.Store.CompleteSecurityEnrichmentRefresh(ctx, c)
}

func TestSyntheticRefreshOnceCommonReadPreviewSnapshotAndCLIFullResultParity(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "orchestrator", 1, model.SeverityHigh, "open")
	ctx := context.Background()
	id := previewFindingID(t, db)
	beforeLegacy, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	beforeDetail, err := db.GetFindingDetail(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	beforeRisk, err := db.ListThreatSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	observed, finish, evaluate := start.Add(time.Minute), start.Add(2*time.Minute), start.Add(3*time.Minute)
	published := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	runIDs := map[string]string{}
	repo := &orchestratorReceiptRepository{Store: db, t: t}
	for i, source := range []string{"epss", "kev"} {
		// Explicit synthetic strict-offline envelopes only. These fixtures do not
		// prove real EPSS/CISA wire format, HTTP, compression or transport support.
		data := []byte("#model_version:synthetic-orchestrator,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-0001,0,0\n")
		if source == "kev" {
			data = []byte("{\"catalogVersion\":\"synthetic-orchestrator.1\",\"dateReleased\":\"2026-11-10T00:00:00Z\",\"count\":1,\"vulnerabilities\":[{\"cveID\":\"CVE-2026-0001\",\"dateAdded\":\"2026-11-09\"}]}")
		}
		fetcher := &orchestratorFixtureFetcher{t: t, source: source, data: data}
		times := []time.Time{start, observed, finish}
		clockCalls, uuidCalls := 0, 0
		runID := fmt.Sprintf("30000000-0000-4000-8000-%012d", 201+i)
		runIDs[source] = runID
		service := enrichmentrefresh.Service{
			Store: repo, Fetcher: fetcher,
			Clock: func() time.Time {
				if clockCalls >= len(times) {
					t.Fatal("extra source clock")
				}
				at := times[clockCalls]
				clockCalls++
				return at
			},
			NewUUID: func() (string, error) { uuidCalls++; return runID, nil },
		}
		out, err := service.RefreshOnce(ctx, enrichmentrefresh.Request{Connector: source + "_feed", Limit: 200})
		if err != nil || out.Outcome != "success" || out.RunID != runID || !out.Advance || clockCalls != 3 || uuidCalls != 1 || fetcher.calls != 1 {
			t.Fatalf("synthetic %s result=%+v err=%v clocks=%d UUID=%d fetch=%d", source, out, err, clockCalls, uuidCalls, fetcher.calls)
		}
		c := repo.completions[len(repo.completions)-1]
		if c.OriginalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(data)) || c.Feed.Source != source || !c.Attempt.StartedAt.Equal(start) || !c.Feed.PublishedAt.Equal(published) || !c.Feed.ObservedAt.Equal(observed) || !c.FinishedAt.Equal(finish) {
			t.Fatal("synthetic parser-input digest or source/three clocks changed")
		}
		verified, err := db.ReconcileSecurityEnrichmentRefresh(ctx, c)
		if err != nil || verified.State != "success" || verified.Receipt == "" {
			t.Fatalf("captured completion does not reconcile=%+v err=%v", verified, err)
		}
	}
	v1 := decodeConnectorStatusVersionedPage(t, srv, "/api/v1/connectors/status?as_of=2026-11-10T12:03:00Z")
	v2 := decodeConnectorStatusVersionedPage(t, srv, "/api/v2/connectors/status?as_of=2026-11-10T12:03:00Z")
	if v1.Total != 1 || v2.Total != 3 {
		t.Fatalf("v1/v2 receipt origins differ v1=%+v v2=%+v", v1, v2)
	}
	seen := map[string]bool{}
	for _, item := range v2.Items {
		source := strings.TrimSuffix(item.Source, "_feed")
		if expected := runIDs[source]; expected != "" {
			seen[source] = true
			if item.Status != "success" || item.Coverage != "partial" || item.Liveness != "unknown" || item.LatestAttempt.ID != expected || !item.LatestAttempt.StartedAt.Equal(start) || item.LatestAttempt.FinishedAt == nil || !item.LatestAttempt.FinishedAt.Equal(finish) {
				t.Fatalf("orchestrated receipt=%+v", item)
			}
		}
	}
	if !seen["epss"] || !seen["kev"] {
		t.Fatal("new feed receipts absent")
	}
	page, err := db.QueryFindingsPage(ctx, store.FindingQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	e := page.Enrichments[id]
	if e.EPSS == nil || e.EPSS.EPSS == nil || *e.EPSS.EPSS != 0 || e.KEV == nil || !e.KEV.KEV {
		t.Fatal("common read lacks known zero EPSS or positive KEV")
	}
	for source, evidence := range map[string]*model.SecurityEnrichmentEvidence{"epss": e.EPSS, "kev": e.KEV} {
		if evidence.Source != source || evidence.RunID != runIDs[source] || !evidence.PublishedAt.Equal(published) || !evidence.ObservedAt.Equal(observed) || evidence.PublishedAt.Equal(evidence.ObservedAt) {
			t.Fatalf("common provenance/independent source clocks=%+v", evidence)
		}
	}
	snapshot, err := db.GetFindingPreviewSnapshot(ctx, id, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	_, want, err := findingpreviewbridge.Build(snapshot.Finding.Finding, snapshot.Asset, snapshot.Finding.Source, snapshot.Finding.SourceFindingID, snapshot.Enrichment, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	out := readPreviewResponse(t, srv, id, evaluate)
	if !reflect.DeepEqual(out.Result, want) || out.Result.EPSS == nil || out.Result.KEV == nil || !out.Result.EPSS.Fresh || !out.Result.KEV.Fresh || out.Result.InputSnapshot == nil || out.Result.InputSnapshot.Threat.EPSS == nil || *out.Result.InputSnapshot.Threat.EPSS != 0 || !out.Result.InputSnapshot.Threat.KEVKnown || !out.Result.InputSnapshot.Threat.KEV {
		t.Fatal("HTTP/full Result parity only matched missing or unknown facts")
	}
	for source, evidence := range map[string]*findingpreview.EvidenceState{"epss": out.Result.EPSS, "kev": out.Result.KEV} {
		if evidence.RunID != runIDs[source] || !evidence.PublishedAt.Equal(published) || !evidence.ObservedAt.Equal(observed) {
			t.Fatal("preview lost exact synthetic run/clocks")
		}
	}
	type wireFact struct {
		RunID       string    `json:"run_id"`
		PublishedAt time.Time `json:"published_at"`
		ObservedAt  time.Time `json:"observed_at"`
		Probability *float64  `json:"probability"`
		Positive    *bool     `json:"positive"`
	}
	var wire struct {
		Enrichment struct {
			CVEID string    `json:"cve_id"`
			EPSS  *wireFact `json:"epss"`
			KEV   *wireFact `json:"kev"`
		} `json:"enrichment"`
	}
	if err := json.Unmarshal(out.InputSnapshot, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Enrichment.CVEID != "CVE-2026-0001" || wire.Enrichment.EPSS == nil || wire.Enrichment.EPSS.Probability == nil || *wire.Enrichment.EPSS.Probability != 0 || wire.Enrichment.KEV == nil || wire.Enrichment.KEV.Positive == nil || !*wire.Enrichment.KEV.Positive {
		t.Fatal("closed input_snapshot lacks explicit known facts")
	}
	for source, fact := range map[string]*wireFact{"epss": wire.Enrichment.EPSS, "kev": wire.Enrichment.KEV} {
		if fact.RunID != runIDs[source] || !fact.PublishedAt.Equal(published) || !fact.ObservedAt.Equal(observed) {
			t.Fatal("input_snapshot lost run/clocks")
		}
	}
	for _, excluded := range []string{"epss_feed", "kev_feed", "sha256:", "refresh-success", "raw_ref"} {
		if bytes.Contains(out.InputSnapshot, []byte(excluded)) {
			t.Fatalf("closed snapshot leaked origin/provenance payload %q", excluded)
		}
	}
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
		t.Fatal("orchestrator/common read/HTTP/input_snapshot/CLI full Result mismatch")
	}
	afterLegacy, err := json.Marshal(db.List())
	if err != nil || !bytes.Equal(beforeLegacy, afterLegacy) {
		t.Fatal("legacy alerts changed")
	}
	afterDetail, err := db.GetFindingDetail(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	beforeDetail.Enrichment, afterDetail.Enrichment = nil, nil
	if !reflect.DeepEqual(beforeDetail, afterDetail) {
		t.Fatal("authoritative finding/triage/history changed")
	}
	afterRisk, err := db.ListThreatSnapshots(ctx)
	if err != nil || !reflect.DeepEqual(beforeRisk, afterRisk) {
		t.Fatal("legacy threat snapshots changed")
	}
}
