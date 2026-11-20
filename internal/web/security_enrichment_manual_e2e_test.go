package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

type manualE2ERoundTripFunc func(*http.Request) (*http.Response, error)

func (f manualE2ERoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type manualE2EBody struct {
	reader *bytes.Reader
	eof    bool
	closes int
}

func (b *manualE2EBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *manualE2EBody) Close() error {
	b.closes++
	return nil
}

func TestManualAPITransportCommonReadPreviewAndCLICompleteSyntheticChain(t *testing.T) {
	// Every document is authored synthetic input for the existing parser subset.
	// RoundTrip never delegates to a real transport, listener or provider endpoint.
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "manual-e2e", 1, model.SeverityHigh, "open")
	ctx := context.Background()
	// Seed unrelated, non-empty legacy records through the normal Store APIs.
	// Their identities and contents must survive both common-feed updates.
	legacyAt := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	legacyRun, err := db.StartIngestRun(ctx, "dependabot", "synthetic/manual-e2e-preserved", legacyAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishIngestRun(ctx, legacyRun.ID, "success", "partial", "", legacyAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	legacyEPSS, legacyPercentile := 0.25, 0.75
	legacyPublished := legacyAt.Add(-24 * time.Hour)
	const legacyAdvisory = "cve:CVE-2026-9999"
	if err := db.UpsertThreat(ctx, "epss", []model.ThreatSnapshot{{
		AdvisoryKey: legacyAdvisory, EPSS: &legacyEPSS, EPSSPercentile: &legacyPercentile,
		EPSSDate: &legacyPublished, FetchedAt: legacyAt,
	}}); err != nil {
		t.Fatal(err)
	}
	findingID := previewFindingID(t, db)
	beforePage, err := db.QueryFindingsPage(ctx, store.FindingQuery{Limit: 200})
	if err != nil || beforePage.Enrichments[findingID].EPSS != nil || beforePage.Enrichments[findingID].KEV != nil {
		t.Fatal("fixture already has common threat evidence before manual HTTP calls")
	}
	beforeLegacy, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	beforeDetail, err := db.GetFindingDetail(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	beforeRisk, err := db.ListThreatSnapshots(ctx)
	if err != nil || len(beforeRisk) == 0 {
		t.Fatalf("legacy snapshot preservation requires non-empty input: %+v %v", beforeRisk, err)
	}
	legacyFact, ok := beforeRisk[legacyAdvisory]
	if !ok || legacyFact.EPSS == nil || *legacyFact.EPSS != legacyEPSS || legacyFact.EPSSPercentile == nil || *legacyFact.EPSSPercentile != legacyPercentile || legacyFact.EPSSDate == nil || !legacyFact.EPSSDate.Equal(legacyPublished) || !legacyFact.FetchedAt.Equal(legacyAt) {
		t.Fatalf("legacy snapshot fixture was not persisted: %+v", legacyFact)
	}
	beforeRuns, err := db.QueryIngestRuns(ctx)
	if err != nil || len(beforeRuns) == 0 {
		t.Fatalf("legacy receipt preservation requires non-empty input: %+v %v", beforeRuns, err)
	}
	legacyReceiptPresent := false
	for _, run := range beforeRuns {
		if run.ID == legacyRun.ID {
			legacyReceiptPresent = run.Connector == "dependabot" && run.Scope == "synthetic/manual-e2e-preserved" && run.Result == "success" && run.Coverage == "partial" && run.StartedAt.Equal(legacyAt) && run.FinishedAt != nil && run.FinishedAt.Equal(legacyAt.Add(time.Minute))
		}
	}
	if !legacyReceiptPresent {
		t.Fatal("finished legacy receipt fixture was not persisted")
	}

	decoded := map[string][]byte{
		"epss": []byte("#model_version:synthetic-manual-e2e,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-0001,0,0\n"),
		"kev":  []byte(`{"catalogVersion":"synthetic-manual-e2e.1","dateReleased":"2026-11-09T23:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Synthetic vendor","product":"Synthetic product","vulnerabilityName":"Authored test only","dateAdded":"2026-11-09","shortDescription":"Synthetic acceptance fixture.","requiredAction":"No real-world action.","dueDate":"2026-11-30"}]}`),
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(decoded["epss"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := map[string][]byte{"epss": bytes.Clone(compressed.Bytes()), "kev": bytes.Clone(decoded["kev"])}
	endpoints := map[string]string{"epss": "https://fixture.invalid/manual-e2e/epss.csv.gz", "kev": "https://fixture.invalid/manual-e2e/kev.json"}
	calls := map[string]int{}
	bodies := map[string]*manualE2EBody{}
	var expectedContext context.Context
	transport := manualE2ERoundTripFunc(func(request *http.Request) (*http.Response, error) {
		source := ""
		for candidate, endpoint := range endpoints {
			if request.URL.String() == endpoint {
				source = candidate
			}
		}
		if source == "" || request.Method != http.MethodGet || request.Context() != expectedContext || request.Context().Err() != nil || request.Header.Get("Accept-Encoding") != "identity" || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" {
			t.Fatalf("request escaped fixed fake transport contract: %s %s", request.Method, request.URL)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if request.Header.Get(name) != "" {
				t.Fatalf("unexpected credential header %s", name)
			}
		}
		// The real Store must be usable while Fetch is in progress.
		bounded, stop := context.WithTimeout(request.Context(), time.Second)
		defer stop()
		if _, err := db.QuerySecurityEnrichmentRefreshTargets(bounded, "", 200); err != nil {
			t.Fatalf("Store transaction/lock held across transport: %v", err)
		}
		calls[source]++
		body := &manualE2EBody{reader: bytes.NewReader(encoded[source])}
		bodies[source] = body
		return &http.Response{
			StatusCode: http.StatusOK, Body: body, ContentLength: int64(len(encoded[source])),
			Header: http.Header{"Content-Encoding": {"identity"}, "Content-Length": {fmt.Sprint(len(encoded[source]))}},
		}, nil
	})
	fetcher, err := enrichmentrefresh.NewBoundedHTTPFetcher(transport, map[string]enrichmentrefresh.HTTPSourceProfile{
		"epss": {URL: endpoints["epss"], Encoding: "gzip"},
		"kev":  {URL: endpoints["kev"], Encoding: "identity"},
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sources := []string{"epss", "kev"}
	started := map[string]time.Time{"epss": start, "kev": start.Add(3 * time.Minute)}
	observed := map[string]time.Time{"epss": start.Add(time.Minute), "kev": start.Add(4 * time.Minute)}
	finished := map[string]time.Time{"epss": start.Add(2 * time.Minute), "kev": start.Add(5 * time.Minute)}
	published := map[string]time.Time{
		"epss": time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
		"kev":  time.Date(2026, 11, 9, 23, 0, 0, 0, time.UTC),
	}
	versions := map[string]string{"epss": "synthetic-manual-e2e", "kev": "synthetic-manual-e2e.1"}
	times := []time.Time{started["epss"], observed["epss"], finished["epss"], started["kev"], observed["kev"], finished["kev"]}
	runIDs := map[string]string{"epss": "60000000-0000-4000-8000-000000000001", "kev": "60000000-0000-4000-8000-000000000002"}
	if legacyRun.ID == runIDs["epss"] || legacyRun.ID == runIDs["kev"] {
		t.Fatal("legacy receipt fixture collides with a manual run UUID")
	}
	operationIDs := map[string]string{"epss": "70000000-0000-4000-8000-000000000001", "kev": "70000000-0000-4000-8000-000000000002"}
	clockCalls, uuidCalls := 0, 0
	repo := &orchestratorReceiptRepository{Store: db, t: t}
	controller, err := enrichmentrefresh.NewManualController(enrichmentrefresh.Service{
		Store: repo, Fetcher: fetcher,
		Clock: func() time.Time {
			if clockCalls >= len(times) {
				t.Fatal("unexpected replacement business clock")
			}
			at := times[clockCalls]
			clockCalls++
			return at
		},
		NewUUID: func() (string, error) {
			if uuidCalls >= len(sources) {
				t.Fatal("unexpected replacement run UUID")
			}
			id := runIDs[sources[uuidCalls]]
			uuidCalls++
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetManualEnrichmentController(controller); err != nil {
		t.Fatal(err)
	}

	receipts := map[string]string{}
	for i, source := range sources {
		expectedContext = context.WithValue(ctx, struct{ Source string }{source}, "synthetic-request")
		body := fmt.Sprintf(`{"operation_id":%q,"connector":%q,"after":"","limit":200}`, operationIDs[source], source+"_feed")
		request := manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body).WithContext(expectedContext)
		response := manualAPIRecorded(t, srv, request)
		out := manualAPIDecode(t, response) // Independent closed DTO; no private payload.
		if response.Code != http.StatusOK || out.OperationID != operationIDs[source] || out.Request.Connector != source+"_feed" || out.State != "resolved" || out.Replay || out.Outcome != "success" || out.RunID != runIDs[source] || !out.Advance || out.NextAfter != findingID || out.Scanned != 1 || out.TargetCount != 1 {
			t.Fatalf("manual %s result is not the owned run/cursor: %+v status=%d", source, out, response.Code)
		}
		current, err := db.QueryFindingsPage(ctx, store.FindingQuery{Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		fact := current.Enrichments[findingID].EPSS
		if source == "kev" {
			fact = current.Enrichments[findingID].KEV
		}
		if fact == nil || fact.Source != source || fact.RunID != runIDs[source] || fact.Version != versions[source] || !fact.PublishedAt.Equal(published[source]) || !fact.ObservedAt.Equal(observed[source]) {
			t.Fatalf("manual HTTP success did not update this source's real common evidence: %+v", fact)
		}
		if source == "epss" {
			if fact.EPSS == nil || *fact.EPSS != 0 || fact.Percentile == nil || *fact.Percentile != 0 {
				t.Fatal("manual EPSS update did not retain explicit known zero")
			}
		} else if !fact.KEV || fact.KEVDateAdded == nil || !fact.KEVDateAdded.Equal(time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)) {
			t.Fatal("manual KEV update did not retain explicit positive/date")
		}
		retained, ok := controller.Snapshot(operationIDs[source])
		if !ok || retained.Result.RunID != out.RunID || retained.Result.NextAfter != out.NextAfter || retained.Result.Pending != nil {
			t.Fatal("manual response is not backed by controller retention")
		}
		if len(repo.completions) != i+1 {
			t.Fatal("manual operation did not reach the real Store exactly once")
		}
		c := repo.completions[i]
		if c.Attempt.RunID != runIDs[source] || c.Attempt.Connector != source+"_feed" || c.Feed.Source != source || c.Feed.Version != versions[source] || c.OriginalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(decoded[source])) || !c.Attempt.StartedAt.Equal(started[source]) || !c.Feed.PublishedAt.Equal(published[source]) || !c.Feed.ObservedAt.Equal(observed[source]) || !c.FinishedAt.Equal(finished[source]) || !c.Attempt.StartedAt.Before(c.Feed.ObservedAt) || !c.Feed.ObservedAt.Before(c.FinishedAt) {
			t.Fatalf("captured %s completion lost original digest/independent clocks: %+v", source, c)
		}
		if source == "epss" && c.OriginalDigest == fmt.Sprintf("sha256:%x", sha256.Sum256(encoded[source])) {
			t.Fatal("compressed-body digest mislabeled as decoded parser-input digest")
		}
		state, err := db.ReconcileSecurityEnrichmentRefresh(ctx, c)
		if err != nil || state.State != "success" || state.Receipt == "" {
			t.Fatalf("exact completion/manifest/observation identity did not verify: %+v %v", state, err)
		}
		receipts[source] = state.Receipt
		if calls[source] != 1 || bodies[source] == nil || !bodies[source].eof || bodies[source].closes != 1 {
			t.Fatalf("transport did not finish exactly one body: source=%s calls=%v body=%+v", source, calls, bodies[source])
		}
	}
	if clockCalls != 6 || uuidCalls != 2 || published["epss"].Equal(published["kev"]) || observed["epss"].Equal(observed["kev"]) {
		t.Fatal("source clocks were regenerated or collapsed")
	}
	evaluate := start.Add(6 * time.Minute)
	v1 := decodeConnectorStatusVersionedPage(t, srv, "/api/v1/connectors/status?as_of="+evaluate.Format(time.RFC3339Nano))
	v2 := decodeConnectorStatusVersionedPage(t, srv, "/api/v2/connectors/status?as_of="+evaluate.Format(time.RFC3339Nano))
	if v2.Total != v1.Total+2 {
		t.Fatalf("v1/v2 feed-origin boundary changed: v1=%+v v2=%+v", v1, v2)
	}
	for _, item := range v1.Items {
		if item.Source == "epss_feed" || item.Source == "kev_feed" {
			t.Fatal("v1 silently expanded to feed origins")
		}
	}
	seen := map[string]bool{}
	for _, item := range v2.Items {
		source := strings.TrimSuffix(item.Source, "_feed")
		if runIDs[source] == "" {
			continue
		}
		seen[source] = true
		if item.Status != "success" || item.Coverage != "partial" || item.Liveness != "unknown" || item.LatestAttempt.ID != runIDs[source] || !item.LatestAttempt.StartedAt.Equal(started[source]) || item.LatestAttempt.FinishedAt == nil || !item.LatestAttempt.FinishedAt.Equal(finished[source]) {
			t.Fatalf("feed receipt lost same-UUID/start/finish identity: %+v", item)
		}
	}
	if !seen["epss"] || !seen["kev"] {
		t.Fatal("new-origin receipts absent")
	}

	page, err := db.QueryFindingsPage(ctx, store.FindingQuery{Limit: 200})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("common read failed: %+v %v", page, err)
	}
	evidence := page.Enrichments[findingID]
	if evidence.EPSS == nil || evidence.EPSS.EPSS == nil || *evidence.EPSS.EPSS != 0 || evidence.EPSS.Percentile == nil || *evidence.EPSS.Percentile != 0 || evidence.KEV == nil || !evidence.KEV.KEV || evidence.KEV.KEVDateAdded == nil {
		t.Fatal("common read parity cannot be an empty/unknown match")
	}
	for source, fact := range map[string]*model.SecurityEnrichmentEvidence{"epss": evidence.EPSS, "kev": evidence.KEV} {
		if fact.Source != source || fact.Version != versions[source] || fact.RunID != runIDs[source] || !fact.PublishedAt.Equal(published[source]) || !fact.ObservedAt.Equal(observed[source]) {
			t.Fatalf("common evidence identity/clocks changed: %+v", fact)
		}
	}
	snapshot, err := db.GetFindingPreviewSnapshot(ctx, findingID, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	_, want, err := findingpreviewbridge.Build(snapshot.Finding.Finding, snapshot.Asset, snapshot.Finding.Source, snapshot.Finding.SourceFindingID, snapshot.Enrichment, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	out := readPreviewResponse(t, srv, findingID, evaluate) // Also strict-decodes input_snapshot.
	if !reflect.DeepEqual(out.Result, want) || out.Result.EPSS == nil || out.Result.KEV == nil || !out.Result.EPSS.Fresh || !out.Result.KEV.Fresh || out.Result.InputSnapshot == nil || out.Result.InputSnapshot.Threat.EPSS == nil || *out.Result.InputSnapshot.Threat.EPSS != 0 || !out.Result.InputSnapshot.Threat.KEVKnown || !out.Result.InputSnapshot.Threat.KEV {
		t.Fatal("full preview Result differs or only matches missing facts")
	}
	for source, fact := range map[string]*findingpreview.EvidenceState{"epss": out.Result.EPSS, "kev": out.Result.KEV} {
		if fact.RunID != runIDs[source] || !fact.PublishedAt.Equal(published[source]) || !fact.ObservedAt.Equal(observed[source]) {
			t.Fatal("preview lost exact source receipt/clocks")
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
		t.Fatal("closed input_snapshot has no explicit known-zero/positive facts")
	}
	for source, fact := range map[string]*wireFact{"epss": wire.Enrichment.EPSS, "kev": wire.Enrichment.KEV} {
		if fact.RunID != runIDs[source] || !fact.PublishedAt.Equal(published[source]) || !fact.ObservedAt.Equal(observed[source]) {
			t.Fatal("closed input_snapshot lost exact evidence identity")
		}
	}
	for _, excluded := range []string{"epss_feed", "kev_feed", "sha256:", "refresh-success", "raw_ref"} {
		if bytes.Contains(out.InputSnapshot, []byte(excluded)) {
			t.Fatalf("closed input_snapshot leaked private origin/digest: %s", excluded)
		}
	}

	// CI executes only the existing offline CLI; this test starts no app/server.
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
		t.Fatal("manual API/transport/Store/common read/preview/snapshot/CLI full Result mismatch")
	}

	afterRuns, err := db.QueryIngestRuns(ctx)
	if err != nil || len(afterRuns) != len(beforeRuns)+2 {
		t.Fatalf("unexpected receipt count: %+v %v", afterRuns, err)
	}
	byID := map[string]model.IngestRun{}
	for _, run := range afterRuns {
		byID[run.ID] = run
	}
	for _, old := range beforeRuns {
		if !reflect.DeepEqual(old, byID[old.ID]) {
			t.Fatal("pre-existing ingest evidence changed")
		}
	}
	for i, source := range sources {
		c := repo.completions[i]
		state, err := db.ReconcileSecurityEnrichmentRefresh(ctx, c)
		if err != nil || state.State != "success" || state.Receipt != receipts[source] || byID[runIDs[source]].Cursor != receipts[source] {
			t.Fatal("read/preview/CLI changed exact successful receipt/evidence identity")
		}
		body := fmt.Sprintf(`{"operation_id":%q,"connector":%q,"after":"","limit":200}`, operationIDs[source], source+"_feed")
		replayed := manualAPIRecorded(t, srv, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
		if replayed.Code != http.StatusOK || !manualAPIDecode(t, replayed).Replay || calls[source] != 1 {
			t.Fatal("outer replay redispatched transport instead of owned cached result")
		}
		state, err = db.ReconcileSecurityEnrichmentRefresh(ctx, c)
		if err != nil || state.State != "success" || state.Receipt != receipts[source] {
			t.Fatal("cached replay changed exact successful receipt/manifest/observation identity")
		}
	}
	finalRuns, err := db.QueryIngestRuns(ctx)
	if err != nil || !reflect.DeepEqual(afterRuns, finalRuns) || clockCalls != 6 || uuidCalls != 2 || len(repo.completions) != 2 {
		t.Fatal("cached replay performed fresh collection/write/clock")
	}
	afterLegacy, err := json.Marshal(db.List())
	if err != nil || !bytes.Equal(beforeLegacy, afterLegacy) {
		t.Fatal("legacy alert evidence changed")
	}
	afterDetail, err := db.GetFindingDetail(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	beforeDetail.Enrichment, afterDetail.Enrichment = nil, nil
	if !reflect.DeepEqual(beforeDetail, afterDetail) {
		t.Fatal("authoritative finding/triage/observation/history changed")
	}
	afterRisk, err := db.ListThreatSnapshots(ctx)
	if err != nil || !reflect.DeepEqual(beforeRisk, afterRisk) {
		t.Fatal("legacy threat/risk inputs changed")
	}
}
