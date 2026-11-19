package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const manualAPIContractCSV = "#model_version:synthetic-api,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-1234,0,0\n"

type manualAPIContractFixture struct {
	server     *Server
	controller *enrichmentrefresh.ManualController
	clock      int
	uuid       int
	fetch      int
}

type manualAPIContractFetcher struct {
	fixture *manualAPIContractFixture
}

func (f manualAPIContractFetcher) Fetch(ctx context.Context, source string) ([]byte, error) {
	f.fixture.fetch++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source != "epss" {
		return nil, fmt.Errorf("unexpected synthetic source")
	}
	return []byte(manualAPIContractCSV), nil
}

func newManualAPIContractFixture(t *testing.T) *manualAPIContractFixture {
	t.Helper()
	db, err := store.NewWithPath(filepath.Join(t.TempDir(), "synthetic-manual-api.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close owned synthetic database: %v", err)
		}
	})
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if _, err := db.SaveObservedWithError(context.Background(), &model.AlertRecord{
		Alert: model.Alert{
			Owner: "example", Repo: "synthetic", Number: 1, State: "open",
			CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm",
			Summary: "Authored manual API fixture", Severity: model.SeverityHigh,
			CreatedAt: at, UpdatedAt: at,
			HTMLURL: "https://github.com/example/synthetic/security/dependabot/1",
		},
		NotifiedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Web: config.WebConfig{Port: 0}, Targets: []config.Target{{Owner: "example", Repo: "synthetic"}}}
	f := &manualAPIContractFixture{server: New(cfg, "", db, nil)}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	service := enrichmentrefresh.Service{
		Store: db,
		Clock: func() time.Time {
			if f.clock >= 3 {
				t.Fatal("manual replay generated another business clock")
			}
			value := start.Add(time.Duration(f.clock) * time.Minute)
			f.clock++
			return value
		},
		NewUUID: func() (string, error) {
			f.uuid++
			return "30000000-0000-4000-8000-000000000301", nil
		},
		Fetcher: manualAPIContractFetcher{fixture: f},
	}
	f.controller, err = enrichmentrefresh.NewManualController(service)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.SetManualEnrichmentController(f.controller); err != nil {
		t.Fatal(err)
	}
	return f
}

func manualAPIContractRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "localhost:8080"
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", "http://localhost:8080")
	request.AddCookie(&http.Cookie{Name: "csrf_token", Value: "synthetic-manual-csrf"})
	request.Header.Set("X-CSRF-Token", "synthetic-manual-csrf")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

type manualAPIContractSummary struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Replay      bool   `json:"replay"`
	Outcome     string `json:"outcome"`
	Code        string `json:"code"`
	RunID       string `json:"run_id"`
	NextAfter   string `json:"next_after"`
	Advance     bool   `json:"advance"`
}

func TestManualEnrichmentAPIContractCallReturnsOwnedControllerResult(t *testing.T) {
	f := newManualAPIContractFixture(t)
	id := "50000000-0000-4000-8000-000000000001"
	body := fmt.Sprintf(`{"operation_id":%q,"connector":"epss_feed","after":"","limit":200}`, id)
	request := manualAPIContractRequest(http.MethodPost, "/api/tui/enrichment-refresh/operations", body)
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manual API contract status=%d body=%s", response.Code, response.Body.String())
	}
	var out manualAPIContractSummary
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID != id || out.State != "resolved" || out.Replay || out.Outcome != "success" || out.RunID != "30000000-0000-4000-8000-000000000301" || !out.Advance || out.NextAfter == "" || f.clock != 3 || f.uuid != 1 || f.fetch != 1 {
		t.Fatalf("manual API did not return the owned result: %+v clock=%d uuid=%d fetch=%d", out, f.clock, f.uuid, f.fetch)
	}
	retained, ok := f.controller.Snapshot(id)
	if !ok || retained.Result.RunID != out.RunID || retained.Result.NextAfter != out.NextAfter {
		t.Fatal("HTTP result is not bound to injected controller retention")
	}
}

func TestManualEnrichmentAPIContractSnapshotReadsRetainedOutcomeWithoutIO(t *testing.T) {
	f := newManualAPIContractFixture(t)
	id := "50000000-0000-4000-8000-000000000002"
	operation, _, err := f.controller.Call(context.Background(), id, enrichmentrefresh.Request{Connector: "epss_feed", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, manualAPIContractRequest(http.MethodGet, "/api/tui/enrichment-refresh/operations/"+id, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("manual snapshot contract status=%d body=%s", response.Code, response.Body.String())
	}
	var out manualAPIContractSummary
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID != id || out.State != "resolved" || out.Outcome != "success" || out.RunID != operation.Result.RunID || out.NextAfter != operation.Result.NextAfter || f.clock != 3 || f.uuid != 1 || f.fetch != 1 {
		t.Fatalf("snapshot did not use retained state only: %+v", out)
	}
}

type manualAPITrace struct {
	mu        sync.Mutex
	calls     map[string]int
	fetchHook func(context.Context)
}

func (t *manualAPITrace) add(name string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls[name]++
	return t.calls[name]
}

func (t *manualAPITrace) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := json.Marshal(t.calls)
	if err != nil {
		panic("synthetic trace encode failed")
	}
	return string(data)
}

type manualAPIRepo struct {
	enrichmentrefresh.Repository
	trace                         *manualAPITrace
	completeAfter, reconcileError bool
}

func (r *manualAPIRepo) QuerySecurityEnrichmentRefreshTargets(ctx context.Context, after string, limit int) (store.SecurityEnrichmentRefreshTargetPage, error) {
	r.trace.add("query")
	return r.Repository.QuerySecurityEnrichmentRefreshTargets(ctx, after, limit)
}
func (r *manualAPIRepo) BeginSecurityEnrichmentRefresh(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt) (bool, error) {
	r.trace.add("begin")
	return r.Repository.BeginSecurityEnrichmentRefresh(ctx, a)
}
func (r *manualAPIRepo) CompleteSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentImportResult, error) {
	r.trace.add("complete")
	result, err := r.Repository.CompleteSecurityEnrichmentRefresh(ctx, c)
	if err == nil && r.completeAfter {
		return result, errors.New("PRIVATE-synthetic-commit-error")
	}
	return result, err
}
func (r *manualAPIRepo) FailSecurityEnrichmentRefresh(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt, code string, at time.Time) (bool, error) {
	r.trace.add("fail")
	return r.Repository.FailSecurityEnrichmentRefresh(ctx, a, code, at)
}
func (r *manualAPIRepo) ReadSecurityEnrichmentRefreshAttempt(ctx context.Context, a store.SecurityEnrichmentRefreshAttempt, expected *store.SecurityEnrichmentRefreshFailure) (store.SecurityEnrichmentRefreshState, error) {
	r.trace.add("read")
	return r.Repository.ReadSecurityEnrichmentRefreshAttempt(ctx, a, expected)
}
func (r *manualAPIRepo) ReconcileSecurityEnrichmentRefresh(ctx context.Context, c store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentRefreshState, error) {
	r.trace.add("reconcile")
	if r.reconcileError {
		return store.SecurityEnrichmentRefreshState{State: "unknown"}, errors.New("PRIVATE-synthetic-read-error")
	}
	return r.Repository.ReconcileSecurityEnrichmentRefresh(ctx, c)
}

type manualAPIFetchFunc func(context.Context, string) ([]byte, error)

func (f manualAPIFetchFunc) Fetch(ctx context.Context, source string) ([]byte, error) {
	return f(ctx, source)
}

type manualAPIOwnedFixture struct {
	server     *Server
	controller *enrichmentrefresh.ManualController
	db         *store.Store
	repo       *manualAPIRepo
	trace      *manualAPITrace
}

func newManualAPIOwnedFixture(t *testing.T, finding bool) *manualAPIOwnedFixture {
	t.Helper()
	db, err := store.NewWithPath(filepath.Join(t.TempDir(), "owned-manual-api.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close owned DB: %v", err)
		}
	})
	if finding {
		at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
		if _, err := db.SaveObservedWithError(context.Background(), &model.AlertRecord{
			Alert: model.Alert{Owner: "example", Repo: "synthetic", Number: 1, State: "open", CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm", Summary: "Owned synthetic API fixture", Severity: model.SeverityHigh, CreatedAt: at, UpdatedAt: at, HTMLURL: "https://github.com/example/synthetic/security/dependabot/1"}, NotifiedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	trace := &manualAPITrace{calls: map[string]int{}}
	repo := &manualAPIRepo{Repository: db, trace: trace}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	service := enrichmentrefresh.Service{
		Store: repo,
		Clock: func() time.Time { n := trace.add("clock"); return start.Add(time.Duration(n-1) * time.Minute) },
		NewUUID: func() (string, error) {
			return fmt.Sprintf("30000000-0000-4000-8000-%012d", 700+trace.add("uuid")), nil
		},
		Fetcher: manualAPIFetchFunc(func(ctx context.Context, source string) ([]byte, error) {
			trace.add("fetch")
			if trace.fetchHook != nil {
				trace.fetchHook(ctx)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if source == "epss" {
				return []byte(manualAPIContractCSV), nil
			}
			if source == "kev" {
				return []byte(`{"catalogVersion":"synthetic-api.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`), nil
			}
			return nil, errors.New("PRIVATE-invalid-source")
		}),
	}
	controller, err := enrichmentrefresh.NewManualController(service)
	if err != nil {
		t.Fatal(err)
	}
	server := New(&config.Config{Web: config.WebConfig{Port: 0}, Targets: []config.Target{{Owner: "example", Repo: "synthetic"}}}, "", db, nil)
	if err := server.SetManualEnrichmentController(controller); err != nil {
		t.Fatal(err)
	}
	return &manualAPIOwnedFixture{server: server, controller: controller, db: db, repo: repo, trace: trace}
}

func manualAPIBody(id string) string {
	return fmt.Sprintf(`{"operation_id":%q,"connector":"epss_feed","after":"","limit":200}`, id)
}

type manualAPIExpectedResponse struct {
	OperationID string `json:"operation_id"`
	Request     struct {
		Connector string `json:"connector"`
		After     string `json:"after"`
		Limit     int    `json:"limit"`
	} `json:"request"`
	State       string `json:"state"`
	Replay      bool   `json:"replay"`
	Outcome     string `json:"outcome"`
	Code        string `json:"code"`
	RunID       string `json:"run_id"`
	Scanned     int    `json:"scanned"`
	TargetCount int    `json:"target_count"`
	NextAfter   string `json:"next_after"`
	Advance     bool   `json:"advance"`
	Exhausted   bool   `json:"exhausted"`
}

func manualAPIRecorded(t *testing.T, server *Server, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Location") != "" || response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Retry-After") != "" {
		t.Fatalf("unexpected cache/redirect/CORS/retry headers: %v", response.Header())
	}
	return response
}

func manualAPIDecode(t *testing.T, response *httptest.ResponseRecorder) manualAPIExpectedResponse {
	t.Helper()
	var result manualAPIExpectedResponse
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		t.Fatal("response has trailing JSON")
	}
	if response.Body.Len() > 4096 {
		t.Fatal("bounded summary unexpectedly large")
	}
	for _, forbidden := range []string{`"pending":`, `"completion":`, `"feed":`, `"targets":`, `"selected_cves":`, `"original_digest":`, `"published_at":`, `"observed_at":`, "PRIVATE"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("private payload leaked: %s", forbidden)
		}
	}
	return result
}

func TestManualAPIDefaultDisabledAndSetterNeverDropsRetention(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	id := "50000000-0000-4000-8000-000000000010"
	disabled := New(f.server.cfg, "", f.db, nil)
	before := f.trace.snapshot()
	response := manualAPIRecorded(t, disabled, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", manualAPIBody(id)))
	if response.Code != 503 || manualAPIDecode(t, response).Code != "disabled" || disabled.manualRefreshController != nil || f.trace.snapshot() != before {
		t.Fatal("disabled API generated dependencies or executed IO")
	}
	if err := f.server.SetManualEnrichmentController(nil); err == nil {
		t.Fatal("nil clearing accepted")
	}
	if err := f.server.SetManualEnrichmentController(f.controller); err != nil {
		t.Fatal(err)
	}
	other := newManualAPIOwnedFixture(t, false)
	if err := f.server.SetManualEnrichmentController(other.controller); err == nil {
		t.Fatal("controller replacement accepted")
	}
	if f.server.manualEnrichmentControllerSnapshot() != f.controller || f.trace.snapshot() != before {
		t.Fatal("setter changed controller or performed IO")
	}
}

func TestManualAPIGuardsMethodsAndStrictRequestsBeforeController(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	id := "50000000-0000-4000-8000-000000000011"
	body := manualAPIBody(id)
	badBodies := map[string]string{
		"unknown":           strings.TrimSuffix(body, "}") + `,"run_id":"PRIVATE"}`,
		"duplicate":         strings.TrimSuffix(body, "}") + `,"limit":200}`,
		"escaped-duplicate": strings.TrimSuffix(body, "}") + `,"\u006cimit":200}`,
		"trailing":          body + " {}",
		"array":             "[]", "null": "null",
		"missing":       strings.Replace(body, `"after":"",`, "", 1),
		"null-string":   strings.Replace(body, `"after":""`, `"after":null`, 1),
		"number-string": strings.Replace(body, `"limit":200`, `"limit":"200"`, 1),
		"fraction":      strings.Replace(body, `"limit":200`, `"limit":200.0`, 1),
		"exponent":      strings.Replace(body, `"limit":200`, `"limit":2e2`, 1),
		"zero":          strings.Replace(body, `"limit":200`, `"limit":0`, 1),
		"large":         strings.Replace(body, `"limit":200`, `"limit":201`, 1),
		"control":       strings.Replace(body, `"after":""`, `"after":"\u0000"`, 1),
		"format":        strings.Replace(body, `"after":""`, `"after":"\u200b"`, 1),
		"surrogate":     strings.Replace(body, `"after":""`, `"after":"\ud800"`, 1),
		"cursor-size":   strings.Replace(body, `"after":""`, fmt.Sprintf(`"after":%q`, strings.Repeat("x", 129)), 1),
		"source":        strings.Replace(body, "epss_feed", "epss", 1),
		"id":            strings.Replace(body, id, "PRIVATE-not-a-uuid", 1),
		"utf8":          string([]byte{0xff}),
	}
	for name, data := range badBodies {
		t.Run(name, func(t *testing.T) {
			before := f.trace.snapshot()
			response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", data))
			if response.Code != 400 || manualAPIDecode(t, response).Code != "invalid_request" || f.trace.snapshot() != before {
				t.Fatalf("bad body reached controller: status=%d %s", response.Code, response.Body.String())
			}
			if _, ok := f.controller.Snapshot(id); ok {
				t.Fatal("bad body reserved an operation")
			}
		})
	}
	for _, kind := range []string{"remote", "host", "origin", "https-origin", "csrf", "cookie", "method", "query", "empty-query", "media", "charset", "encoding", "duplicate-media", "oversize", "unknown-size", "unclean", "escaped-path"} {
		t.Run(kind, func(t *testing.T) {
			request := manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body)
			status := 403
			switch kind {
			case "remote":
				request.RemoteAddr = "203.0.113.1:4000"
				request.Header.Set("X-Forwarded-For", "127.0.0.1")
			case "host":
				request.Host = "fixture.invalid:8080"
			case "origin":
				request.Header.Set("Origin", "http://fixture.invalid")
			case "https-origin":
				request.Header.Set("Origin", "https://localhost:8080")
			case "csrf":
				request.Header.Del("X-CSRF-Token")
			case "cookie":
				request.Header.Del("Cookie")
			case "method":
				request.Method = http.MethodPut
				status = 405
			case "query":
				request.URL.RawQuery = "limit=1"
				status = 400
			case "empty-query":
				request.URL.ForceQuery = true
				status = 400
			case "media":
				request.Header.Set("Content-Type", "text/plain")
				status = 415
			case "charset":
				request.Header.Set("Content-Type", "application/json;charset=iso-8859-1")
				status = 415
			case "encoding":
				request.Header.Set("Content-Encoding", "gzip")
				status = 415
			case "duplicate-media":
				request.Header.Add("Content-Type", "application/json")
				status = 415
			case "oversize", "unknown-size":
				request.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", 1025)))
				request.ContentLength = 1025
				if kind == "unknown-size" {
					request.ContentLength = -1
				}
				status = 413
			case "unclean":
				request.URL.Path = manualAPIRoot + "//operations"
				status = 400
			case "escaped-path":
				request.URL.RawPath = "/api/tui/enrichment-refresh/%6fperations"
				status = 400
			}
			before := f.trace.snapshot()
			response := manualAPIRecorded(t, f.server, request)
			if response.Code != status || f.trace.snapshot() != before {
				t.Fatalf("kind=%s status=%d want=%d body=%s", kind, response.Code, status, response.Body.String())
			}
			manualAPIDecode(t, response)
		})
	}
}

func TestManualAPISnapshotAndReconcileHaveStrictSeparateInputs(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	id := "50000000-0000-4000-8000-000000000012"
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, manualAPIRoot + "/operations/" + id, "{}", 400},
		{http.MethodGet, manualAPIRoot + "/operations/" + id + "?x=1", "", 400},
		{http.MethodHead, manualAPIRoot + "/operations/" + id, "", 405},
		{http.MethodPost, manualAPIRoot + "/operations/" + id + "/reconcile", `{"after":""}`, 400},
		{http.MethodPost, manualAPIRoot + "/operations/" + id + "/reconcile", "null", 400},
		{http.MethodPost, manualAPIRoot + "/operations/" + id + "/reconcile", "{} {}", 400},
		{http.MethodPost, manualAPIRoot + "/operations/" + id + "/reconcile", "", 400},
		{http.MethodGet, manualAPIRoot + "/operations/not-a-uuid", "", 400},
		{http.MethodGet, manualAPIRoot + "/operations/" + id, "", 404},
		{http.MethodPost, manualAPIRoot + "/operations/" + id + "/reconcile", "{}", 404},
		{http.MethodGet, manualAPIRoot + "/unknown", "", 404},
	} {
		before := f.trace.snapshot()
		response := manualAPIRecorded(t, f.server, manualAPIContractRequest(tc.method, tc.path, tc.body))
		if response.Code != tc.status || f.trace.snapshot() != before {
			t.Fatalf("strict input accepted: %+v status=%d", tc, response.Code)
		}
		manualAPIDecode(t, response)
	}
}

func TestManualAPIPendingReplaySourceGateAndExplicitReadonlyRecovery(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	f.repo.completeAfter, f.repo.reconcileError = true, true
	id := "50000000-0000-4000-8000-000000000020"
	body := manualAPIBody(id)
	response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
	out := manualAPIDecode(t, response)
	if response.Code != 409 || out.State != "pending" || out.Code != "pending" || out.Advance || out.RunID == "" {
		t.Fatalf("unknown receipt not pending: %+v", out)
	}
	kept, ok := f.controller.Snapshot(id)
	if !ok || kept.Result.Pending == nil || kept.Result.Pending.Completion == nil {
		t.Fatal("handler discarded full controller Pending")
	}
	private, err := json.Marshal(kept)
	if err != nil {
		t.Fatal(err)
	}
	counts := f.trace.snapshot()
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodGet, manualAPIRoot+"/operations/"+id, ""))
	if response.Code != 200 || manualAPIDecode(t, response).State != "pending" || f.trace.snapshot() != counts {
		t.Fatal("snapshot performed IO")
	}
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
	if response.Code != 409 || !manualAPIDecode(t, response).Replay || f.trace.snapshot() != counts {
		t.Fatal("pending replay performed work")
	}
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", strings.Replace(body, `"limit":200`, `"limit":199`, 1)))
	if response.Code != 409 || manualAPIDecode(t, response).Code != "operation_conflict" || f.trace.snapshot() != counts {
		t.Fatal("binding mismatch performed IO")
	}
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", strings.Replace(body, id, "50000000-0000-4000-8000-000000000021", 1)))
	if response.Code != 409 || manualAPIDecode(t, response).Code != "source_pending" || f.trace.snapshot() != counts {
		t.Fatal("source gate bypassed")
	}
	again, _ := f.controller.Snapshot(id)
	againJSON, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private, againJSON) {
		t.Fatal("API access mutated retained full envelope")
	}
	f.repo.reconcileError = false
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations/"+id+"/reconcile", "{}"))
	resolved := manualAPIDecode(t, response)
	if response.Code != 200 || resolved.Outcome != "success" || !resolved.Advance || resolved.NextAfter != kept.Result.ScanAfter || resolved.RunID != kept.Result.RunID {
		t.Fatalf("explicit readback lost cursor/run: %+v", resolved)
	}
	f.trace.mu.Lock()
	if f.trace.calls["clock"] != 3 || f.trace.calls["uuid"] != 1 || f.trace.calls["fetch"] != 1 || f.trace.calls["complete"] != 1 || f.trace.calls["fail"] != 0 || f.trace.calls["reconcile"] != 2 {
		t.Errorf("readback performed fresh collection/write: %v", f.trace.calls)
	}
	f.trace.mu.Unlock()
	counts = f.trace.snapshot()
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
	if response.Code != 200 || !manualAPIDecode(t, response).Replay || f.trace.snapshot() != counts {
		t.Fatal("resolved replay repeated IO")
	}
}

type manualAPIFailedWriter struct {
	header http.Header
	status int
}

func (w *manualAPIFailedWriter) Header() http.Header    { return w.header }
func (w *manualAPIFailedWriter) WriteHeader(status int) { w.status = status }
func (w *manualAPIFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("PRIVATE-synthetic-response-loss")
}

func TestManualAPIResponseLossKeepsControllerAndNoServerLockOverCall(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	id := "50000000-0000-4000-8000-000000000030"
	body := manualAPIBody(id)
	f.trace.fetchHook = func(ctx context.Context) {
		done := make(chan error, 1)
		go func() { done <- f.server.SetManualEnrichmentController(f.controller) }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("server pointer lock held over controller/fetch")
		}
	}
	failed := &manualAPIFailedWriter{header: make(http.Header)}
	f.server.Handler().ServeHTTP(failed, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
	if failed.status != 200 {
		t.Fatalf("first operation failed before response loss: %d", failed.status)
	}
	kept, ok := f.controller.Snapshot(id)
	if !ok || kept.Result.Outcome != "success" {
		t.Fatal("response loss lost controller result")
	}
	counts := f.trace.snapshot()
	response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body))
	if response.Code != 200 || !manualAPIDecode(t, response).Replay || f.trace.snapshot() != counts {
		t.Fatal("response-loss retry executed another attempt")
	}
}

type manualAPIReadFunc func([]byte) (int, error)

func (f manualAPIReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestManualAPICancelAndBodyErrorsNeverReserveWork(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	id := "50000000-0000-4000-8000-000000000040"
	body := manualAPIBody(id)
	for _, kind := range []string{"before", "during-body", "read-error"} {
		ctx, cancel := context.WithCancel(context.Background())
		request := manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body).WithContext(ctx)
		status := 408
		switch kind {
		case "before":
			cancel()
		case "during-body":
			request.Body = io.NopCloser(manualAPIReadFunc(func(p []byte) (int, error) { cancel(); return copy(p, body), io.EOF }))
		case "read-error":
			request.Body = io.NopCloser(manualAPIReadFunc(func([]byte) (int, error) { return 0, errors.New("PRIVATE-body-error") }))
			status = 400
		}
		before := f.trace.snapshot()
		response := manualAPIRecorded(t, f.server, request)
		cancel()
		if response.Code != status || f.trace.snapshot() != before {
			t.Fatalf("kind=%s entered dependencies: %d", kind, response.Code)
		}
		manualAPIDecode(t, response)
		if _, ok := f.controller.Snapshot(id); ok {
			t.Fatal("rejected/canceled body reserved operation")
		}
	}
}

func TestManualAPICapacityAllowsCachedReplayAndHandlerBuildNeverConflicts(t *testing.T) {
	f := newManualAPIOwnedFixture(t, false)
	for i := 1; i <= 16; i++ {
		id := fmt.Sprintf("50000000-0000-4000-8000-%012d", 100+i)
		response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", manualAPIBody(id)))
		if response.Code != 200 || !manualAPIDecode(t, response).Exhausted {
			t.Fatal("empty page did not retain resolved operation")
		}
	}
	counts := f.trace.snapshot()
	id := "50000000-0000-4000-8000-000000000101"
	response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", manualAPIBody(id)))
	if response.Code != 200 || !manualAPIDecode(t, response).Replay || f.trace.snapshot() != counts {
		t.Fatal("full retention blocked cached replay")
	}
	response = manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", manualAPIBody("50000000-0000-4000-8000-000000000117")))
	if response.Code != 503 || manualAPIDecode(t, response).Code != "retention_full" || f.trace.snapshot() != counts {
		t.Fatal("full retention entered dependencies")
	}
	// Every request above reconstructs the complete legacy Handler as well.
	// Explicitly exercise its old read surfaces, without starting a listener.
	for _, url := range []string{"/api/v1/findings", "/api/v1/connectors/status?as_of=2026-11-10T12:03:00Z", "/api/v2/connectors/status?as_of=2026-11-10T12:03:00Z", "/api/tui/status"} {
		rec := httptest.NewRecorder()
		f.server.Handler().ServeHTTP(rec, manualAPIContractRequest(http.MethodGet, url, ""))
		if rec.Code != 200 {
			t.Fatalf("legacy Handler route %s changed: %d %s", url, rec.Code, rec.Body.String())
		}
	}
	if f.trace.snapshot() != counts {
		t.Fatal("legacy reads unexpectedly dispatched controller")
	}
}

// Exact old guard decision/response reference from immutable baseline.
func legacyManualAPIGuardReference(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		host, _, hostErr := net.SplitHostPort(r.Host)
		if hostErr != nil {
			host = r.Host
		}
		if err != nil || !loopbackHost(remote) || !loopbackHost(host) {
			http.Error(w, "TUI APIはローカル接続専用です", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || u.Scheme != "http" {
				http.Error(w, "Originが不正です", http.StatusForbidden)
				return
			}
		}
		if r.Method != http.MethodGet {
			cookie, err := r.Cookie("csrf_token")
			token := r.Header.Get("X-CSRF-Token")
			if err != nil || token == "" || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
				http.Error(w, "CSRF tokenが必要です", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	})
}

func TestManualAPIGuardExtractionKeepsLegacyDecisionAndResponse(t *testing.T) {
	for _, kind := range []string{"post", "get-no-token", "no-origin", "bad-remote", "bad-host", "bad-origin", "https", "no-token", "no-cookie", "mismatch", "head", "head-no-token", "ipv6", "bare-host", "legacy-origin-components"} {
		t.Run(kind, func(t *testing.T) {
			request := manualAPIContractRequest(http.MethodPost, "/api/tui/status", "")
			switch kind {
			case "get-no-token":
				request.Method = http.MethodGet
				request.Header.Del("Cookie")
				request.Header.Del("X-CSRF-Token")
			case "no-origin":
				request.Header.Del("Origin")
			case "bad-remote":
				request.RemoteAddr = "203.0.113.1:5000"
			case "bad-host":
				request.Host = "fixture.invalid:8080"
			case "bad-origin":
				request.Header.Set("Origin", "http://[")
			case "https":
				request.Header.Set("Origin", "https://localhost:8080")
			case "no-token":
				request.Header.Del("X-CSRF-Token")
			case "no-cookie":
				request.Header.Del("Cookie")
			case "mismatch":
				request.Header.Set("X-CSRF-Token", "different")
			case "head":
				request.Method = http.MethodHead
			case "head-no-token":
				request.Method = http.MethodHead
				request.Header.Del("X-CSRF-Token")
			case "ipv6":
				request.RemoteAddr = "[::1]:5000"
				request.Host = "[::1]:8080"
				request.Header.Set("Origin", "http://[::1]:8080")
			case "bare-host":
				request.Host = "localhost"
				request.Header.Set("Origin", "http://localhost")
			case "legacy-origin-components":
				request.Header.Set("Origin", "http://synthetic@localhost:8080/path?x=1#part")
			}
			next := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Guard-Next", "yes")
				w.WriteHeader(204)
			}
			expected, actual := httptest.NewRecorder(), httptest.NewRecorder()
			legacyManualAPIGuardReference(next).ServeHTTP(expected, request.Clone(request.Context()))
			(&Server{}).localTUI(next).ServeHTTP(actual, request.Clone(request.Context()))
			if actual.Code != expected.Code || actual.Body.String() != expected.Body.String() || !reflect.DeepEqual(actual.Header(), expected.Header()) {
				t.Fatalf("legacy guard changed kind=%s expected=%d %q %v actual=%d %q %v", kind, expected.Code, expected.Body.String(), expected.Header(), actual.Code, actual.Body.String(), actual.Header())
			}
		})
	}
}

func TestManualAPIStrictUnicodeAndExactBodyBoundary(t *testing.T) {
	id := "50000000-0000-4000-8000-000000000050"
	body := manualAPIBody(id)
	literal := strings.Replace(body, `"after":""`, `"after":"é😀"`, 1)
	escaped := strings.Replace(body, `"after":""`, `"after":"\u00e9\ud83d\ude00"`, 1)
	a, okA := manualAPIParseCall([]byte(literal))
	b, okB := manualAPIParseCall([]byte(escaped))
	if !okA || !okB || a != b || a.After != "é😀" {
		t.Fatal("valid UTF-8 and surrogate pair must have identical canonical request")
	}
	for _, value := range []string{`"after":"\udc00"`, `"after":"\ud800"`, `"after":"\ud800\u0000"`} {
		if _, ok := manualAPIParseCall([]byte(strings.Replace(body, `"after":""`, value, 1))); ok {
			t.Fatalf("invalid surrogate accepted: %s", value)
		}
	}
	f := newManualAPIOwnedFixture(t, true)
	padded := body + strings.Repeat(" ", manualAPIMaxBody-len(body))
	response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", padded))
	if response.Code != 200 {
		t.Fatalf("exact1KiB complete input rejected: %d %s", response.Code, response.Body.String())
	}
	manualAPIDecode(t, response)
	counts := f.trace.snapshot()
	request := manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", padded)
	request.ContentLength = -1
	response = manualAPIRecorded(t, f.server, request)
	if response.Code != 200 || !manualAPIDecode(t, response).Replay || f.trace.snapshot() != counts {
		t.Fatal("complete unknown-length body did not replay")
	}
	request = manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", body)
	request.ContentLength++
	response = manualAPIRecorded(t, f.server, request)
	if response.Code != 400 || f.trace.snapshot() != counts {
		t.Fatal("declared body length mismatch reached controller")
	}
}

func TestManualAPIUsesOriginalRequestContextAndKeepsOldVersionedReads(t *testing.T) {
	f := newManualAPIOwnedFixture(t, true)
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "synthetic-owner")
	id := "50000000-0000-4000-8000-000000000060"
	f.trace.fetchHook = func(actual context.Context) {
		if actual != ctx || actual.Value(marker{}) != "synthetic-owner" {
			t.Error("handler replaced original request context")
		}
	}
	response := manualAPIRecorded(t, f.server, manualAPIContractRequest(http.MethodPost, manualAPIRoot+"/operations", manualAPIBody(id)).WithContext(ctx))
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	counts := f.trace.snapshot()
	totals := []int{}
	for _, version := range []string{"v1", "v2"} {
		rec := httptest.NewRecorder()
		f.server.Handler().ServeHTTP(rec, manualAPIContractRequest(http.MethodGet, "/api/"+version+"/connectors/status?as_of=2026-11-10T12:03:00Z", ""))
		if rec.Code != 200 {
			t.Fatalf("versioned read changed: %s %d", version, rec.Code)
		}
		var page struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		totals = append(totals, page.Total)
	}
	if totals[1] != totals[0]+1 || f.trace.snapshot() != counts {
		t.Fatal("old v1/v2 origin separation changed")
	}
}
