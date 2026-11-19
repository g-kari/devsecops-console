package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestRiskSettingsSnapshotDetachedAndGuarded(t *testing.T) {
	srv, s, _ := newTestServer(t)
	defer func() { _ = s.Close() }()
	srv.cfg.Targets = []config.Target{{Owner: "org", Excludes: []string{"private"}}}
	source := riskSettingsSource{server: srv}
	snapshot, err := source.Snapshot()
	if err != nil || len(snapshot.Config.Targets) != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	snapshot.Config.Targets[0].Excludes[0] = "mutated"
	if srv.cfg.Targets[0].Excludes[0] != "private" {
		t.Fatal("snapshot aliases live config")
	}
	srv.cfg.ConfigRevision++
	called := false
	err = source.WithRevision(snapshot.Revision, func() error { called = true; return nil })
	if !errors.Is(err, store.ErrRiskInputsChanged) || called {
		t.Fatalf("outdated commit: called=%v err=%v", called, err)
	}
}

func TestRiskRecalculationConnected(t *testing.T) {
	srv, s, _ := newTestServer(t)
	defer func() { _ = s.Close() }()
	srv.cfg.Targets = []config.Target{{Owner: "org"}}
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, CVEID: "CVE-2026-5555"}, NotifiedAt: time.Now()})
	if err := srv.RecalculateRisks(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-5555", 20)
	if err != nil || len(timeline.History) != 1 || timeline.History[0].Result.Status != "provisional" || len(timeline.Deadlines) != 1 {
		t.Fatalf("unknown risk not persisted: %+v err=%v", timeline, err)
	}
}

func TestLegacyMonitoringUpdatesInvalidateRiskGeneration(t *testing.T) {
	for _, action := range []string{"add_target", "delete_target", "add_exclusion", "delete_exclusion"} {
		t.Run(action, func(t *testing.T) {
			srv, s, _ := newTestServer(t)
			defer func() { _ = s.Close() }()
			srv.cfg.Targets = []config.Target{{Owner: "org", Excludes: []string{"old"}}}
			source := riskSettingsSource{server: srv}
			revision := srv.cfg.ConfigRevision
			r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("owner=other&repo=api"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetPathValue("i", "0")
			r.SetPathValue("j", "0")
			w := httptest.NewRecorder()
			switch action {
			case "add_target":
				srv.handleTargetAdd(w, r)
			case "delete_target":
				srv.handleTargetDelete(w, r)
			case "add_exclusion":
				srv.handleExcludeAdd(w, r)
			case "delete_exclusion":
				srv.handleExcludeDelete(w, r)
			}
			if w.Code != http.StatusSeeOther || srv.cfg.ConfigRevision != revision+1 {
				t.Fatalf("revision=%d status=%d", srv.cfg.ConfigRevision, w.Code)
			}
			select {
			case <-source.Changes():
			default:
				t.Fatal("risk configuration event missing")
			}
			if err := source.WithRevision(revision, func() error { return nil }); !errors.Is(err, store.ErrRiskInputsChanged) {
				t.Fatalf("stale revision accepted: %v", err)
			}
		})
	}
}
