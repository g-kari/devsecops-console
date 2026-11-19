package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/slack"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// notifyPendingRecord は未送信の通知だけ再試行し、成功した通知IDを保持する。
func notifyPendingRecord(cfg *config.Config, s *store.Store, sc *slack.SlackClient, dc *discord.Client, record *model.AlertRecord) {
	if !cfg.ShouldNotify(string(record.Alert.Severity)) {
		return
	}
	if sc != nil && record.SlackMessageTS == "" {
		ts, err := sc.Notify(record)
		if err == nil && ts != "" {
			record.SlackMessageTS = ts
			err = s.UpdateSlackMessageTS(record.Alert.ID, ts)
		}
		if err != nil {
			slog.Error("Slack通知または通知ID保存失敗", "alertID", record.Alert.ID, "error", err)
		}
	}
	if dc != nil && record.DiscordMessageID == "" {
		id, err := dc.Notify(record)
		if err == nil && id != "" {
			record.DiscordMessageID = id
			err = s.UpdateDiscordMessageID(record.Alert.ID, id)
		}
		if err != nil {
			slog.Error("Discord通知または通知ID保存失敗", "alertID", record.Alert.ID, "error", err)
		}
	}
}

func runNotificationScheduler(ctx context.Context, sc *slack.SlackClient, dc *discord.Client, guard *policy.Guard) {
	flush := func() {
		if err := flushNotificationBatches(ctx, time.Now(), sc, dc, guard); err != nil {
			slog.Error("まとめ通知失敗", "error", err)
		}
	}
	flush()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flush()
		}
	}
}

func flushNotificationBatches(ctx context.Context, now time.Time, sc *slack.SlackClient, dc *discord.Client, guard *policy.Guard) error {
	var failures []error
	if sc != nil {
		if err := sc.FlushNotifications(ctx, now, guard); err != nil {
			failures = append(failures, fmt.Errorf("slackまとめ通知失敗: %w", err))
		}
	}
	if dc != nil {
		if err := dc.FlushNotifications(ctx, now, guard); err != nil {
			failures = append(failures, fmt.Errorf("discordまとめ通知失敗: %w", err))
		}
	}
	return errors.Join(failures...)
}

func refreshRepositoryNotifications(sc *slack.SlackClient, dc *discord.Client, owner, repo string) {
	if sc != nil {
		if err := sc.RefreshSummary(owner, repo); err != nil {
			slog.Error("Slackリポジトリ集約更新失敗", "owner", owner, "repo", repo, "error", err)
		}
	}
	if dc != nil {
		if err := dc.RefreshSummary(owner, repo); err != nil {
			slog.Error("Discordリポジトリ集約更新失敗", "owner", owner, "repo", repo, "error", err)
		}
	}
}
