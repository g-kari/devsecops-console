package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type browserQACase struct {
	Name       string `json:"name"`
	Origin     string `json:"origin"`
	Path       string `json:"path"`
	Want       string `json:"want"`
	Status     int    `json:"status"`
	Screenshot bool   `json:"screenshot"`
	Native     bool   `json:"native"`
	Nav        string `json:"nav"`
	Rich       bool   `json:"rich"`
}
type browserQAAudit struct {
	mu         sync.Mutex
	Requests   int      `json:"requests"`
	Active     int      `json:"active"`
	Violations []string `json:"violations"`
}

type browserQABoundary struct {
	mu    sync.Mutex
	calls []string
}

func (b *browserQABoundary) deny(operation string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.calls) < 16 {
		b.calls = append(b.calls, operation)
	}
	return fmt.Errorf("synthetic browser QA forbids %s", operation)
}

type browserQADenyTransport struct{ boundary *browserQABoundary }

func (d browserQADenyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, d.boundary.deny("application HTTP")
}

type browserQADenyMerger struct{ boundary *browserQABoundary }

func (m *browserQADenyMerger) Approve(context.Context, int) error { return m.boundary.deny("approval") }
func (m *browserQADenyMerger) Reject(int) error                   { return m.boundary.deny("rejection") }
func (m *browserQADenyMerger) Merge(context.Context, int) error   { return m.boundary.deny("merge") }

// TestNativeConsoleBrowserQA is opt-in because a normal Go test must not launch
// browsers. Requested QA fails, rather than skips, when any prerequisite is absent.
// It exercises real SQLite, Handler, templates and Goldmark on synthetic data only.
func TestNativeConsoleBrowserQA(t *testing.T) {
	if os.Getenv("DEVSECOPS_BROWSER_QA") != "1" {
		t.Skip("browser QA not requested")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("requested browser QA requires the reviewed Linux runner")
	}
	out := os.Getenv("DEVSECOPS_BROWSER_QA_DIR")
	if !filepath.IsAbs(out) {
		t.Fatal("DEVSECOPS_BROWSER_QA_DIR must be a new absolute evidence directory")
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatalf("create fresh browser evidence directory: %v", err)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("requested Node is unavailable: %v", err)
	}
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		chrome, err = exec.LookPath("google-chrome-stable")
	}
	if err != nil {
		t.Fatalf("requested existing Chrome is unavailable: %v", err)
	}
	// The opt-in command selects only this nonparallel test. Remove ambient
	// provider credentials and home/config state before constructing any Server.
	for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		t.Setenv(key, "")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	globalBoundary := &browserQABoundary{}
	previousTransport := http.DefaultTransport
	http.DefaultTransport = browserQADenyTransport{globalBoundary}
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	primary, db := newFindingsAPITestServer(t)
	primaryBoundary := browserQAConfigure(primary, at)
	anchor := seedConsoleDependabot(t, db, "browser-synthetic", 1, "CVE-2099-0001")
	seedConsoleTrivy(t, db)
	browserQASeedSources(t, db, at)
	record := &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "browser-rich", Number: 11, State: "open", Severity: model.SeverityCritical, CVEID: "CVE-2099-0011", PackageName: "synthetic <browser-package>", Summary: "Synthetic browser advisory", Description: "**Synthetic browser Markdown**\n\n- Real Goldmark fixture\n", CreatedAt: at.Add(-time.Hour), UpdatedAt: at.Add(-time.Hour)}, State: model.AlertStatePending, EvalStatus: model.EvalStatusDone, NotifiedAt: at, Evaluation: &model.Evaluation{Recommendation: "Review synthetic fixture", Reasoning: "**Synthetic reasoning**"}}
	if _, err := db.SaveObservedWithError(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	legacyID := 0
	for _, saved := range db.List() {
		if saved.Alert.Repo == "browser-rich" {
			legacyID = saved.Alert.ID
		}
	}
	if legacyID == 0 {
		t.Fatal("synthetic legacy record missing")
	}
	db.AddLog(model.LogEntry{Timestamp: at, Level: "info", Message: "synthetic browser <log>"})
	detail, err := db.GetFindingDetail(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	overview, err := db.QuerySecurityOverview(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	empty, emptyDB := newFindingsAPITestServer(t)
	emptyBoundary := browserQAConfigure(empty, at)
	partial, partialDB := newFindingsAPITestServer(t)
	partialBoundary := browserQAConfigure(partial, at)
	seedConsoleDependabot(t, partialDB, "browser-partial", 1, "CVE-2099-0001")
	if _, err := partialDB.StartIngestRun(context.Background(), "synthetic_invalid_source", "synthetic", at); err != nil {
		t.Fatal(err)
	}
	servers := []*Server{primary, empty, partial}
	stores := []*store.Store{db, emptyDB, partialDB}
	origins := map[string]string{}
	audits := []*browserQAAudit{}
	before := make([]string, len(stores))
	for i, name := range []string{"primary", "empty", "partial"} {
		before[i] = nativeSnapshot(t, stores[i])
		httpServer, audit := browserQAServer(t, servers[i])
		origins[name] = httpServer.URL
		audits = append(audits, audit)
	}
	cases := []browserQACase{
		{"overview", "primary", "/security", "Active Findings", 200, true, true, "/security", false},
		{"assets", "primary", "/assets", "Assets", 200, true, true, "/assets", false},
		{"asset-detail", "primary", "/assets/" + detail.Asset.ID, detail.Asset.NativeID, 200, true, true, "/assets", false},
		{"findings", "primary", "/findings", "Findings", 200, true, true, "/findings", false},
		{"finding-detail", "primary", "/findings/" + anchor, "CVE-2099-0001", 200, true, true, "/findings", false},
		{"integrations", "primary", "/integrations?as_of=" + url.QueryEscape(at.Format(time.RFC3339Nano)), "最後の成功 receipt", 200, true, true, "/integrations", false},
		{"legacy-dashboard", "primary", "/", "Dependabot アラート一覧", 200, true, false, "/", false},
		{"legacy-detail", "primary", fmt.Sprintf("/alerts/%d", legacyID), "Synthetic browser Markdown", 200, true, false, "/", true},
		{"legacy-logs", "primary", "/logs", "synthetic browser <log>", 200, true, false, "/logs", false},
		{"legacy-settings", "primary", "/settings", "Codex 認証", 200, true, false, "/settings", false},
		{"legacy-reports", "primary", "/reports/vulnerabilities", "脆弱性レポート", 200, false, false, "/reports/vulnerabilities", false},
		{"empty-assets", "empty", "/assets", "一致する Asset がありません", 200, true, true, "/assets", false},
		{"empty-findings", "empty", "/findings", "一致する Finding がありません", 200, false, true, "/findings", false},
		{"empty-integrations", "empty", "/integrations?as_of=" + url.QueryEscape(at.Format(time.RFC3339Nano)), "このページに収集記録はありません", 200, true, true, "/integrations", false},
		{"partial-overview", "partial", "/security", "部分エラー", 200, true, true, "/security", false},
		{"invalid-asset", "primary", "/assets/not-an-id", "見つかりません", 404, true, true, "", false},
	}
	longQuery := store.ConsoleAssetQuery{Search: strings.Repeat("#", 256), Provider: strings.Repeat("界", 85) + "#", Account: strings.Repeat("#", 256), Region: strings.Repeat("界", 85) + "#", Source: "dependabot", Limit: 50}
	if _, err := parseConsoleAssetQuery(consoleAssetValues(longQuery).Encode()); err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{"synthetic": true, "origins": origins, "cases": cases, "as_of": at, "anchor_id": anchor, "asset_id": detail.Asset.ID, "long_asset_url": consoleAssetDetailURL(detail.Asset.ID, consoleAssetValues(longQuery), longQuery.Source), "cleared_source_url": consoleAssetDetailURL(detail.Asset.ID, url.Values{"source": {"trivy"}, "limit": {"50"}, "offset": {"0"}}, ""), "metrics": map[string]int{"Active Findings": overview.Active, "Critical / Active": overview.Critical, "High / Active": overview.High, "保存済み Assets": overview.Assets}, "metadata": browserQAMetadata()}
	fixturePath := filepath.Join(t.TempDir(), "fixture.json")
	browserQAWriteJSON(t, fixturePath, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	script := filepath.Join("..", "..", "scripts", "browser_console_qa.mjs")
	cmd := exec.CommandContext(ctx, node, script, "--fixture", fixturePath, "--chrome", chrome, "--profile", filepath.Join(t.TempDir(), "chrome-profile"), "--out", out)
	// Do not pass CI/runtime tokens, user credentials or inherited browser profiles.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	ownedProcesses, commandErr := browserQARunOwnedProcess(ctx, cmd)
	stability := map[string]any{"synthetic": true, "persistent_unchanged": true, "stores": []map[string]string{}}
	rows := []map[string]string{}
	for i, db := range stores {
		after := nativeSnapshot(t, db)
		b, a := sha256.Sum256([]byte(before[i])), sha256.Sum256([]byte(after))
		rows = append(rows, map[string]string{"before_sha256": hex.EncodeToString(b[:]), "after_sha256": hex.EncodeToString(a[:])})
		if after != before[i] {
			stability["persistent_unchanged"] = false
			t.Errorf("browser changed persistent store %d", i)
		}
	}
	stability["stores"] = rows
	cleanupDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(cleanupDeadline) {
		active := 0
		for _, audit := range audits {
			audit.mu.Lock()
			active += audit.Active
			audit.mu.Unlock()
		}
		if active == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	auditSummary := []map[string]int{}
	for i, audit := range audits {
		audit.mu.Lock()
		bad := append([]string{}, audit.Violations...)
		auditSummary = append(auditSummary, map[string]int{"requests": audit.Requests, "active_after_browser_exit": audit.Active})
		if audit.Active != 0 {
			t.Errorf("fixture requests/SSE did not stop before cleanup deadline: %d", audit.Active)
		}
		audit.mu.Unlock()
		if len(bad) > 0 {
			t.Errorf("unexpected browser fixture requests %d: %v", i, bad)
		}
	}
	for _, srv := range servers {
		if auth, ok := srv.codexAuth.(*fakeCodexAuth); !ok || auth.started {
			t.Error("browser reached a real authentication/login boundary")
		}
	}
	boundaryCalls := 0
	for _, boundary := range []*browserQABoundary{globalBoundary, primaryBoundary, emptyBoundary, partialBoundary} {
		boundary.mu.Lock()
		calls := append([]string{}, boundary.calls...)
		boundary.mu.Unlock()
		boundaryCalls += len(calls)
		if len(calls) > 0 {
			t.Errorf("forbidden external/action boundary reached: %v", calls)
		}
	}
	stability["external_action_calls"] = boundaryCalls
	stability["owned_processes"] = ownedProcesses
	stability["automated_status"] = "passed"
	if commandErr != nil || t.Failed() {
		stability["automated_status"] = "failed"
	}
	if commandErr != nil {
		stability["command_error"] = commandErr.Error()
	}
	stability["request_audit"] = auditSummary
	stability["configured_deadlines_ms"] = map[string]int{"command": 210000, "command_cancel_grace": 5000, "request_sse_cleanup": 2000}
	browserQAWriteJSON(t, filepath.Join(out, "stability.json"), stability)
	browserQAValidateOutput(t, out)
	if commandErr != nil {
		t.Fatalf("requested browser QA failed (evidence retained): %v", commandErr)
	}
}

func TestBrowserQAConfigureRendersSyntheticCodexStatus(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	browserQAConfigure(srv, time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))

	page := httptest.NewRecorder()
	srv.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if !strings.Contains(page.Body.String(), `id="codex-auth-status"`) {
		t.Fatal("synthetic Codex status control is absent from the configured browser-QA settings page")
	}

	status := httptest.NewRecorder()
	srv.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/settings/codex/status", nil))
	var result toolResult
	if err := json.NewDecoder(status.Body).Decode(&result); err != nil || result.OK || result.Message != "Synthetic offline browser QA; no CLI invoked" {
		t.Fatalf("synthetic Codex status = %+v, err=%v", result, err)
	}
	if auth, ok := srv.codexAuth.(*fakeCodexAuth); !ok || auth.started {
		t.Fatal("browser QA Codex status unexpectedly invoked a real login")
	}
}

func browserQAConfigure(s *Server, at time.Time) *browserQABoundary {
	boundary := &browserQABoundary{}
	// Select Codex explicitly so the settings page renders its synthetic auth status; the fake provider below never invokes a CLI.
	s.cfg.Evaluator.Provider = "codex"
	s.consoleNow = func() time.Time { return at }
	s.cfg.RSS.Enabled = false
	s.jobQueue = nil
	s.pollFn = func() { _ = boundary.deny("poll") }
	s.fetchFeed = func(context.Context, string, feed.FetchOptions) (feed.FetchResult, error) {
		return feed.FetchResult{}, boundary.deny("feed refresh")
	}
	s.merger = &browserQADenyMerger{boundary}
	s.codexAuth = &fakeCodexAuth{status: toolResult{OK: false, Message: "Synthetic offline browser QA; no CLI invoked"}}
	return boundary
}

func browserQASeedSources(t *testing.T, db *store.Store, at time.Time) {
	t.Helper()
	ctx := context.Background()
	for i, source := range []string{"github_code_scanning", "github_secret_scanning"} {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", 801+i)
		var items []model.SecurityFinding
		var err error
		if source == "github_code_scanning" {
			items, err = adapter.ParseCodeScanningJSON(strings.NewReader(`[{"number":1,"state":"open","rule":{"id":"synthetic/browser-rule","security_severity_level":"high"},"tool":{"name":"Synthetic"},"most_recent_instance":{"location":{"path":"synthetic.go","start_line":1}}}]`), adapter.CodeScanningOptions{Repository: "example/browser-sources", RunID: id, ObservedAt: at})
		} else {
			items, err = adapter.ParseSecretScanningJSON(strings.NewReader(`[{"number":1,"state":"open","secret_type":"synthetic_example","secret":null}]`), adapter.SecretScanningOptions{Repository: "example/browser-sources", RunID: id, ObservedAt: at})
		}
		if err != nil {
			t.Fatal(err)
		}
		if source == "github_code_scanning" {
			items[0].Finding.Title = "Synthetic <script>window.__qa_injected=true</script>"
		}
		run := model.IngestRun{ID: id, Connector: source, Scope: "example/browser-sources", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}
		if _, err := db.ImportSecurityFindings(ctx, run, items); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{"dependabot", "trivy", "github_code_scanning", "github_secret_scanning", "epss_offline", "kev_offline"} {
		run, err := db.StartIngestRun(ctx, source, "synthetic/recorded", at.Add(-2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.FinishIngestRun(ctx, run.ID, "success", "partial", "", at.Add(-110*time.Minute)); err != nil {
			t.Fatal(err)
		}
		result, coverage, start, finish := "success", "partial", at.Add(-time.Hour), at.Add(-59*time.Minute)
		switch source {
		case "dependabot":
			result, coverage = "failed", "unknown"
		case "trivy":
			result, coverage = "running", "unknown"
		case "github_code_scanning":
			result = "partial"
		case "github_secret_scanning":
			start, finish = at.Add(time.Minute), at.Add(2*time.Minute)
		}
		next, err := db.StartIngestRun(ctx, source, "synthetic/recorded", start)
		if err != nil {
			t.Fatal(err)
		}
		if result != "running" {
			if err := db.FinishIngestRun(ctx, next.ID, result, coverage, "", finish); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func browserQAServer(t *testing.T, s *Server) (*httptest.Server, *browserQAAudit) {
	t.Helper()
	audit := &browserQAAudit{Violations: []string{}}
	// Only exact synthetic object routes and fixed auxiliary reads are exposed;
	// there is no general application-path forward or external fallback.
	allowedPaths := map[string]bool{"/": true, "/security": true, "/assets": true, "/findings": true, "/integrations": true, "/assets/not-an-id": true, "/logs": true, "/settings": true, "/reports/vulnerabilities": true, "/favicon.ico": true, "/api/logs-stream": true, "/settings/codex/status": true}
	assets, err := s.store.QueryAssetsPage(context.Background(), 200, 0)
	if err != nil || assets.Total > 200 {
		t.Fatalf("bounded synthetic asset route snapshot: %v", err)
	}
	for _, asset := range assets.Items {
		allowedPaths["/assets/"+asset.ID] = true
	}
	findings, err := s.store.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 200})
	if err != nil || findings.Total > 200 {
		t.Fatalf("bounded synthetic Finding route snapshot: %v", err)
	}
	for _, finding := range findings.Items {
		allowedPaths["/findings/"+finding.ID] = true
	}
	for _, record := range s.store.List() {
		allowedPaths[fmt.Sprintf("/alerts/%d", record.Alert.ID)] = true
	}
	handler := s.Handler()
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		loopback := err == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
		allowed := r.Method == http.MethodGet || r.Method == http.MethodHead
		path := r.URL.Path
		readPath := allowedPaths[path]
		audit.mu.Lock()
		audit.Requests++
		if !loopback || !allowed || !readPath || audit.Requests > 256 {
			if len(audit.Violations) < 16 {
				audit.Violations = append(audit.Violations, r.Method+" "+path)
			}
			audit.mu.Unlock()
			http.Error(w, "synthetic QA request boundary", http.StatusForbidden)
			return
		}
		audit.Active++
		audit.mu.Unlock()
		defer func() { audit.mu.Lock(); audit.Active--; audit.mu.Unlock() }()
		if path == "/favicon.ico" {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		handler.ServeHTTP(w, r.WithContext(browserQAContext(r.Context(), ctx)))
	}))
	t.Cleanup(func() { cancel(); server.CloseClientConnections(); server.Close() })
	return server, audit
}
func browserQAContext(request, fixture context.Context) context.Context {
	// Requests are canceled when either the browser disconnects or fixture closes.
	ctx, cancel := context.WithCancel(request)
	stop := context.AfterFunc(fixture, cancel)
	context.AfterFunc(ctx, func() { stop() })
	return ctx
}
func browserQAMetadata() map[string]string {
	result := map[string]string{}
	for _, key := range []string{"GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "DEVSECOPS_BROWSER_QA_HEAD_SHA", "DEVSECOPS_BROWSER_QA_BASE_SHA", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"} {
		value := os.Getenv(key)
		if len(value) > 128 {
			continue
		}
		safe := true
		for _, r := range value {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-_.", r) {
				safe = false
			}
		}
		if safe {
			result[key] = value
		}
	}
	return result
}
func browserQAWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 256*1024 {
		t.Fatal("browser JSON evidence exceeds bound")
	}
	if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
func browserQAValidateOutput(t *testing.T, out string) {
	t.Helper()
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 32 {
		t.Fatal("browser evidence exceeds 32 files")
	}
	var size int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		name := entry.Name()
		if !info.Mode().IsRegular() || strings.ContainsAny(name, "/\\") || (!strings.HasSuffix(name, ".png") && name != "checks.json" && name != "manifest.json" && name != "stability.json") {
			t.Fatalf("unexpected artifact entry %q", name)
		}
		size += info.Size()
	}
	if size > 8*1024*1024 {
		t.Fatal("browser evidence exceeds 8 MiB")
	}
}
