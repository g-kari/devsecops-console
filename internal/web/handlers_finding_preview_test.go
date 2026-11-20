package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func previewFindingID(t *testing.T, db *store.Store) string {
	t.Helper()
	page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 50})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("fixture: %+v %v", page, err)
	}
	return page.Items[0].ID
}
func previewURL(id string, at time.Time) string {
	return "/api/v1/findings/" + id + "/priority-preview?as_of=" + url.QueryEscape(at.Format(time.RFC3339Nano))
}
func readPreviewResponse(t *testing.T, srv *Server, id string, at time.Time) findingPreviewResponse {
	t.Helper()
	w := findingsAPIRequest(t, srv, http.MethodGet, previewURL(id, at), http.StatusOK)
	assertFindingsJSON(t, w)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS expanded")
	}
	var out findingPreviewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion != findingPreviewAPIVersion || out.Warning != findingPreviewWarning || !out.Result.PreviewOnly {
		t.Fatal("missing preview contract")
	}
	decoded, err := findingpreviewwire.Decode(out.InputSnapshot)
	if err != nil || !reflect.DeepEqual(out.Result, decoded) {
		t.Fatalf("wire parity: %v", err)
	}
	for _, excluded := range []string{"raw_ref", "observations", "events", "PRIVATE-"} {
		if strings.Contains(w.Body.String(), excluded) {
			t.Fatalf("leaked %s", excluded)
		}
	}
	return out
}

// buildPreviewFindingCLI builds the existing offline preview-finding CLI
// into a test-owned directory and returns the executable path. On Windows
// the go tool writes the binary with a .exe suffix, so the output name must
// carry the suffix explicitly for the returned path to be executable.
func buildPreviewFindingCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "preview-finding")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "./cmd/preview-finding")
	build.Dir = filepath.Join("..", "..")
	if log, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build existing CLI: %v\n%s", err, log)
	}
	return binary
}

func TestFindingPriorityPreviewReplaysThroughExistingCLIWithoutMutation(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "preview", 1, model.SeverityHigh, "open")
	id := previewFindingID(t, db)
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	importAPIEnrichment(t, db, "epss", "#model_version:synthetic,score_date:2026-11-06\ncve,epss,percentile\nCVE-2026-0001,0,0\n", at.Add(-72*time.Hour), 201)
	before, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	detailBefore, err := db.GetFindingDetail(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	riskBefore, err := db.ListThreatSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := readPreviewResponse(t, srv, id, at)
	if out.Result.EPSS == nil || !out.Result.EPSS.Fresh || out.Result.InputSnapshot.Threat.EPSS == nil || *out.Result.InputSnapshot.Threat.EPSS != 0 {
		t.Fatal("zero or inclusive boundary lost")
	}
	later := readPreviewResponse(t, srv, id, at.Add(time.Nanosecond))
	if later.Result.EPSS.Fresh {
		t.Fatal("stale boundary lost")
	}
	// This builds only the existing offline CLI. No application or listener runs.
	binary := buildPreviewFindingCLI(t)
	command := exec.Command(binary, "--schema", "base")
	command.Stdin = bytes.NewReader(out.InputSnapshot)
	result, err := command.Output()
	if err != nil {
		t.Fatalf("run offline CLI: %v", err)
	}
	var cli struct {
		Result findingpreview.Result `json:"result"`
	}
	if err = json.Unmarshal(result, &cli); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Result, cli.Result) {
		t.Fatal("CLI full Result differs")
	}
	after, err := json.Marshal(db.List())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy alerts changed")
	}
	detailAfter, err := db.GetFindingDetail(context.Background(), id)
	if err != nil || !reflect.DeepEqual(detailBefore, detailAfter) {
		t.Fatal("finding/triage/history changed")
	}
	riskAfter, err := db.ListThreatSnapshots(context.Background())
	if err != nil || !reflect.DeepEqual(riskBefore, riskAfter) {
		t.Fatal("risk changed")
	}
}

func TestFindingPriorityPreviewMissingAndStaleEvidence(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "preview", 1, model.SeverityHigh, "open")
	id := previewFindingID(t, db)
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	out := readPreviewResponse(t, srv, id, at)
	if out.Result.EPSS != nil || out.Result.KEV != nil {
		t.Fatal("missing evidence fabricated")
	}
	importAPIEnrichment(t, db, "kev", `{"catalogVersion":"synthetic.1","dateReleased":"2026-11-05T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-11-04","notes":"PRIVATE-IGNORED"}]}`, at.Add(-96*time.Hour), 202)
	out = readPreviewResponse(t, srv, id, at)
	if out.Result.KEV == nil || out.Result.KEV.Fresh || !out.Result.KEV.HistoricalPositive || len(out.Result.MappingWarnings) == 0 {
		t.Fatal("stale KEV semantics changed")
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, previewURL(id, at.Add(-120*time.Hour)), http.StatusUnprocessableEntity)
	assertFindingsJSON(t, w)
	if w.Body.String() != "{\"error\":\"invalid_snapshot\"}\n" {
		t.Fatalf("unsafe error %q", w.Body.String())
	}
}

func TestFindingPriorityPreviewRejectsInvalidQueriesAndWrites(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "preview", 1, model.SeverityHigh, "open")
	id := previewFindingID(t, db)
	base := "/api/v1/findings/" + id + "/priority-preview"
	for _, q := range []string{"", "as_of=", "as_of=bad", "as_of=2026-11-09T00:00:00Z&as_of=2026-11-09T00:00:00Z", "as_of=2026-11-09T00:00:00Z&other=x", "as_of=2026-11-09T0:00:00Z", "as_of=2026-11-09T00:00:00,1Z", "as_of=2026-11-09T00:00:00.1234567890Z", "as_of=0001-01-01T00:00:00Z", "as_of=2026-11-09T00:00:00%2B24:00", "as_of=%ZZ", strings.Repeat("x", 4097)} {
		w := findingsAPIRequest(t, srv, http.MethodGet, base+"?"+q, http.StatusBadRequest)
		assertFindingsJSON(t, w)
		if w.Body.String() != "{\"error\":\"invalid_query\"}\n" {
			t.Fatalf("unsafe error %q", w.Body.String())
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		w := findingsAPIRequest(t, srv, method, base, http.StatusMethodNotAllowed)
		assertFindingsJSON(t, w)
		if w.Body.String() != "{\"error\":\"method_not_allowed\"}\n" || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("method error changed")
		}
	}
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	head := findingsAPIRequest(t, srv, http.MethodHead, previewURL(id, at), http.StatusOK)
	assertFindingsJSON(t, head)
	for _, unknown := range []string{"not-id", "00000000-0000-0000-0000-000000000000"} {
		w := findingsAPIRequest(t, srv, http.MethodGet, previewURL(unknown, at), http.StatusNotFound)
		assertFindingsJSON(t, w)
	}
}
