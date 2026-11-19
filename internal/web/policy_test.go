package web

import (
	"context"
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebMonitoringDeniesUnconfiguredAndOverlappingExclusions(t *testing.T) {
	for _, targets := range [][]config.Target{nil, {{Owner: "testorg", Repo: "testrepo"}, {Owner: "testorg", Excludes: []string{"testrepo"}}}} {
		t.Run("policy", func(t *testing.T) {
			srv, s, m := newTestServer(t)
			defer func() { _ = s.Close() }()
			srv.cfg.Targets = targets
			saveAlert(s, 1, "pkg", model.SeverityHigh)
			for _, action := range []string{"approve", "reject", "evaluate"} {
				r := httptest.NewRequest(http.MethodPost, "/alerts/1/"+action, nil)
				r.SetPathValue("id", "1")
				w := httptest.NewRecorder()
				switch action {
				case "approve":
					srv.handleApprove(w, r)
				case "reject":
					srv.handleReject(w, r)
				case "evaluate":
					srv.handleEnqueueEvaluate(w, r)
				}
				if w.Code != http.StatusConflict {
					t.Fatalf("%s status=%d", action, w.Code)
				}
			}
			if len(m.approved) != 0 || len(m.rejected) != 0 {
				t.Fatal("excluded mutation reached merger")
			}
			if got := filterByConfig(s.List(), srv.cfg); len(got) != 0 {
				t.Fatalf("normal collection included excluded/unconfigured records: %d", len(got))
			}
		})
	}
}

func TestManualEvaluationClaimsOnceAndRestoresStateWhenQueueFull(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run("admission", func(t *testing.T) {
			srv, s, _ := newTestServer(t)
			defer func() { _ = s.Close() }()
			saveAlert(s, 1, "pkg", model.SeverityHigh)
			q := queue.New(1, 1)
			defer q.Stop()
			srv.SetQueue(q)
			if full {
				q.TryEnqueue(queue.Job{Type: queue.JobFetchAlerts})
			}
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/api/evaluate/1", nil)
				r.SetPathValue("id", "1")
				w := httptest.NewRecorder()
				srv.handleEnqueueEvaluate(w, r)
				return w
			}
			first := request()
			if full {
				saved, err := s.Get(1)
				if first.Code != http.StatusServiceUnavailable || err != nil || saved.EvalStatus != model.EvalStatusDone {
					t.Fatalf("full queue claim not restored: status=%d row=%+v err=%v", first.Code, saved, err)
				}
				return
			}
			second := request()
			if first.Code != http.StatusSeeOther || second.Code != http.StatusConflict || q.Len() != 1 {
				t.Fatalf("duplicate admission: first=%d second=%d queued=%d", first.Code, second.Code, q.Len())
			}
		})
	}
}

func TestSettingsDoesNotLabelUnconfiguredRepositoryAsMonitored(t *testing.T) {
	for _, targets := range [][]config.Target{nil, {{Owner: "testorg", Repo: "different"}}} {
		t.Run("unconfigured", func(t *testing.T) {
			srv, s, _ := newTestServer(t)
			defer func() { _ = s.Close() }()
			srv.cfg.Targets = targets
			saveAlert(s, 1, "pkg", model.SeverityHigh)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/settings", nil))
			body := w.Body.String()
			if w.Code != http.StatusOK || !strings.Contains(body, "監視設定なし") || strings.Contains(body, `action="/settings/repositories/exclude"`) {
				t.Fatalf("unconfigured repository status misleading: status=%d", w.Code)
			}
		})
	}
}

func TestExclusionSaveWaitCanBeCanceledWithoutChangingConfiguration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("save", func(t *testing.T) {
			srv, s, _ := newTestServer(t)
			defer func() { _ = s.Close() }()
			srv.cfg.Targets = []config.Target{{Owner: "testorg"}}
			saveAlert(s, 1, "pkg", model.SeverityHigh)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- srv.RepositoryPolicy().WithAllowed(context.Background(), "testorg", "testrepo", func(config.Snapshot) error { close(entered); <-release; return nil })
			}()
			<-entered
			defer func() {
				close(release)
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("owner=testorg&repo=testrepo&revision=0")).WithContext(ctx)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetPathValue("i", "0")
			w := httptest.NewRecorder()
			if legacy {
				srv.handleExcludeAdd(w, r)
			} else {
				srv.handleRepositoryExclude(w, r)
			}
			if w.Code != http.StatusRequestTimeout || srv.cfg.ConfigRevision != 0 || len(srv.cfg.Targets[0].Excludes) != 0 {
				t.Fatalf("cancel saved configuration: status=%d cfg=%+v", w.Code, srv.cfg)
			}
		})
	}
}
