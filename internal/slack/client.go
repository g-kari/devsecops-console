package slack

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/notification"
	"github.com/g-kari/dependabot-alert-notice/internal/ratelimit"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	slackgo "github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

type SlackClient struct {
	batch           *notification.Batcher
	api             *slackgo.Client
	socket          *socketmode.Client
	channelID       string
	store           *store.Store
	merger          merger.Interface
	limiter         *ratelimit.Limiter
	allowedUserIDs  []string // 承認・却下を許可するSlack User IDリスト（空=全員許可）
	configSource    func() (config.Snapshot, error)
	disableApproval bool
	notifyMu        sync.Mutex
	destination     string
}

func New(cfg *config.Config, s *store.Store, m merger.Interface) *SlackClient {
	api := slackgo.New(
		cfg.Slack.BotToken,
		slackgo.OptionAppLevelToken(cfg.Slack.AppToken),
	)
	socket := socketmode.New(api)

	return &SlackClient{
		api:       api,
		socket:    socket,
		channelID: cfg.Slack.ChannelID,
		store:     s,
		merger:    m,
		// Slack: chat.postMessage は1メッセージ/秒/チャンネルが推奨
		limiter:         ratelimit.NewLimiter(1 * time.Second),
		allowedUserIDs:  cfg.Slack.AllowedUserIDs,
		disableApproval: cfg.DisableApproval,
		destination:     cfg.Slack.BotToken + "\x00" + cfg.Slack.ChannelID,
	}
}

// SetConfigSource は保存済みの通知・承認設定を再起動なしで参照する。
// 起動時、通知ワーカーの開始前に登録する。
func (c *SlackClient) SetConfigSource(source func() (config.Snapshot, error)) {
	c.configSource = source
	if c.store != nil && source != nil {
		c.batch = notification.NewBatcher(c.store, c.groupKey("", ""), source, c.groupKey)
	}
}

func (c *SlackClient) approvalDisabled() bool {
	if c.configSource != nil {
		snapshot, err := c.configSource()
		if err != nil {
			slog.Error("Slack承認設定取得失敗", "error", err)
			return true
		}
		return snapshot.Config.DisableApproval
	}
	return c.disableApproval
}

// RefreshApprovalButtons は追跡可能な未解決メッセージから承認・却下を除去する。
// 編集失敗にかかわらず操作側の拒否を維持し、次回設定保存・起動で再試行する。
func (c *SlackClient) RefreshApprovalButtons() {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	if !c.approvalDisabled() || c.store == nil {
		return
	}
	for _, record := range c.store.List() {
		if record.SlackMessageTS == "" {
			continue
		}
		if err := c.updateEvalMessage(record); err != nil {
			slog.Error("Slack承認ボタン除去失敗", "alertID", record.Alert.ID, "error", err)
		}
	}
}

func (c *SlackClient) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	eventsDone := make(chan struct{})
	go func() { defer close(eventsDone); c.handleEvents(ctx) }()
	defer func() { cancel(); <-eventsDone }()

	slog.Info("Slack Socket Mode 開始")
	// socketmode.Client.RunContext only returns a non-nil error; it never returns nil.
	err := c.socket.RunContext(ctx)
	slog.Error("Slack Socket Mode エラー", "error", err)
}

func (c *SlackClient) API() *slackgo.Client {
	return c.api
}
