package slack

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/notification"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	slackgo "github.com/slack-go/slack"
)

func (c *SlackClient) grouped() bool { return c.store != nil && c.configSource != nil }

func (c *SlackClient) groupKey(owner, repo string) string {
	return store.NotificationGroupKey("slack", c.destination, owner, repo)
}

func (c *SlackClient) refreshSummary(owner, repo string, create bool, delivered ...func(string)) (string, error) {
	if !c.grouped() {
		return "", nil
	}
	var id string
	var fingerprint string
	err := c.store.WithNotificationLock(func() error {
		snapshot, err := c.configSource()
		if err != nil {
			return fmt.Errorf("slack集約設定取得失敗: %w", err)
		}
		if !policy.IsMonitored(snapshot.Config.Targets, owner, repo) {
			return nil
		}
		key := c.groupKey(owner, repo)
		id, err = c.store.NotificationGroup(key)
		if err != nil {
			return err
		}
		records, err := c.store.NotificationRecords(owner, repo)
		if err != nil {
			return err
		}
		summary := notification.Build(records, snapshot.Config, owner, repo)
		if len(delivered) > 0 {
			fingerprint, err = notification.Fingerprint(summary)
			if err != nil {
				return err
			}
		}
		if id == "" && (!create || summary.Total == 0) {
			return nil
		}
		summaryText := summary.Text()
		compact := snapshot.Config.NotificationInterval > 0
		if compact {
			summaryText = summary.CompactText()
		}
		title := notification.Limit(notification.SingleLine(owner+"/"+repo), 150)
		// plain_textで外部入力によるメンション・リンク構文を解釈しない。
		blocks := []slackgo.Block{
			slackgo.NewHeaderBlock(slackgo.NewTextBlockObject(slackgo.PlainTextType, title, false, false)),
			slackgo.NewSectionBlock(slackgo.NewTextBlockObject(slackgo.PlainTextType, summaryText, false, false), nil, nil),
		}
		shown := 0
		for _, record := range summary.Records {
			if compact {
				break
			}
			if record.Evaluation == nil {
				continue
			}
			eval := record.Evaluation
			text := fmt.Sprintf("*#%d %s — AI評価*\n侵害される内容: %s\n侵害される使い方: %s\nAWSで危険になる利用条件（構成未確認）: %s", record.Alert.Number, slackText(notification.SingleLine(record.Alert.PackageName), 100), slackText(eval.Impact, 500), slackText(eval.Reasoning, 500), slackText(nonEmpty(eval.AWSRisk, "未評価（再評価で確認）"), 700))
			blocks = append(blocks, slackgo.NewSectionBlock(slackgo.NewTextBlockObject(slackgo.MarkdownType, text, false, false), nil, nil))
			shown++
			if shown == 3 {
				break
			}
		}
		if err := c.limiter.Wait(context.Background()); err != nil {
			return fmt.Errorf("slack集約待機失敗: %w", err)
		}
		if id != "" {
			_, _, _, err = c.api.UpdateMessage(c.channelID, id, slackgo.MsgOptionBlocks(blocks...), slackgo.MsgOptionText(slackText(title+" — "+summaryText, 3500), false))
			if err == nil {
				return nil
			}
			// 削除が確定した場合のみ再作成。権限・レート制限・通信障害では重複を作らない。
			if err.Error() != "message_not_found" {
				c.recordRateLimit(err)
				return fmt.Errorf("slack集約更新失敗: %w", err)
			}
		}
		_, id, err = c.api.PostMessage(c.channelID, slackgo.MsgOptionBlocks(blocks...), slackgo.MsgOptionText(slackText(title+" — "+summaryText, 3500), false))
		if err != nil {
			c.recordRateLimit(err)
			return fmt.Errorf("slack集約作成失敗: %w", err)
		}
		return c.store.SaveNotificationGroup(key, id)
	})
	if err == nil && fingerprint != "" && len(delivered) > 0 {
		delivered[0](fingerprint)
	}
	return id, err
}

// RefreshSummary は最新DB状態で親を更新し、旧個別通知だけのrepoにも親を作る。
func (c *SlackClient) RefreshSummary(owner, repo string) error {
	if deferred, err := c.deferNotification(owner, repo); deferred || err != nil {
		return err
	}
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	_, err := c.refreshSummary(owner, repo, true)
	return err
}

func (c *SlackClient) deferNotification(owner, repo string) (bool, error) {
	if c.batch == nil {
		return false, nil
	}
	return c.batch.Defer(owner, repo)
}

// FlushNotifications は期限を迎えたrepoごとに親を一度だけ更新する。
func (c *SlackClient) FlushNotifications(ctx context.Context, now time.Time, guards ...*policy.Guard) error {
	if c.batch == nil {
		return nil
	}
	return c.batch.Flush(ctx, now, func(owner, repo string) (string, error) {
		var fingerprint string
		send := func(config.Snapshot) error {
			c.notifyMu.Lock()
			defer c.notifyMu.Unlock()
			_, err := c.refreshSummary(owner, repo, true, func(value string) { fingerprint = value })
			return err
		}
		if len(guards) > 0 && guards[0] != nil {
			err := guards[0].WithAllowed(ctx, owner, repo, send)
			return fingerprint, err
		}
		err := send(config.Snapshot{})
		return fingerprint, err
	})
}

func (c *SlackClient) recordRateLimit(err error) {
	if limited, ok := err.(*slackgo.RateLimitedError); ok {
		c.limiter.SetRetryAfter(limited.RetryAfter)
	}
}

func slackText(value string, max int) string {
	return notification.Limit(strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value), max)
}
