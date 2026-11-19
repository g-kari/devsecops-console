package merger

import (
	"context"
	"errors"
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"testing"
	"time"
)

func TestExcludedActionsDoNotMutateOrSearch(t *testing.T) {
	for _, action := range []string{"approve", "reject", "merge"} {
		t.Run(action, func(t *testing.T) {
			s := store.New()
			defer func() { _ = s.Close() }()
			cfg := &config.Config{Targets: []config.Target{{Owner: "org", Excludes: []string{"api"}}}}
			m := New(cfg, s, &mockGHClient{prErr: errors.New("fixture: must not search")})
			rec := saveRecordWithPR(s, 1, "pkg", "org", "api", 0)
			var err error
			switch action {
			case "approve":
				err = m.Approve(context.Background(), rec.Alert.ID)
			case "reject":
				err = m.Reject(rec.Alert.ID)
			case "merge":
				err = m.Merge(context.Background(), rec.Alert.ID)
			}
			if !errors.Is(err, policy.ErrNotMonitored) {
				t.Fatalf("action=%s err=%v", action, err)
			}
			saved, getErr := s.Get(rec.Alert.ID)
			if getErr != nil || saved.State != model.AlertStatePending {
				t.Fatalf("excluded state changed: %+v %v", saved, getErr)
			}
		})
	}
}

type guardedSearchClient struct {
	mockGHClient
	entered, release chan struct{}
}

func (c *guardedSearchClient) FindDependabotPR(context.Context, string, string, string) (int, error) {
	close(c.entered)
	<-c.release
	return 0, errors.New("fixture PR lookup failure")
}

func TestApproveHoldsSharedPolicyThroughPRSearchWithoutReentering(t *testing.T) {
	s := store.New()
	defer func() { _ = s.Close() }()
	cfg := &config.Config{Targets: []config.Target{{Owner: "org"}}}
	client := &guardedSearchClient{entered: make(chan struct{}), release: make(chan struct{})}
	m := New(cfg, s, client)
	guard := policy.NewGuard(func() (config.Snapshot, error) {
		clone, err := config.Clone(*cfg)
		return config.Snapshot{Config: clone}, err
	})
	m.SetRepositoryPolicy(guard)
	rec := saveRecordWithPR(s, 1, "pkg", "org", "api", 0)
	done := make(chan error, 1)
	go func() { done <- m.Approve(context.Background(), rec.Alert.ID) }()
	defer func() {
		close(client.release)
		select {
		case err := <-done:
			if err == nil {
				t.Error("fixture lookup must fail")
			}
		case <-time.After(time.Second):
			t.Error("approval did not release guard")
		}
	}()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("approval deadlocked before lookup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	unlock, err := guard.LockUpdate(ctx)
	if err == nil {
		unlock()
		t.Fatal("exclusion publication passed in-flight PR lookup")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait cancellation=%v", err)
	}
}
