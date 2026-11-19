package slack

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	slackgo "github.com/slack-go/slack"
)

func TestExcludedSlackActionsKeepStateAndReportBothFailures(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	cfg := &config.Config{Targets: []config.Target{{Owner: "org", Excludes: []string{"api"}}}}
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1}, State: model.AlertStatePending, NotifiedAt: time.Now()}
	s.SaveObserved(rec)
	var replies atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replies.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"ts":"fixture"}`)
	}))
	defer endpoint.Close()
	c := &SlackClient{api: slackgo.New("fixture", slackgo.OptionAPIURL(endpoint.URL+"/")), store: s, merger: merger.New(cfg, s, nil)}
	callback := &slackgo.InteractionCallback{}
	callback.Channel.ID = "fixture"
	callback.Message.Timestamp = "fixture"
	action := &slackgo.BlockAction{Value: "1"}
	c.handleApprove(context.Background(), action, callback)
	c.handleReject(action, callback)
	saved, err := s.Get(rec.Alert.ID)
	if err != nil || saved.State != model.AlertStatePending || replies.Load() != 2 {
		t.Fatalf("Slack exclusion: state=%+v replies=%d err=%v", saved, replies.Load(), err)
	}
}
