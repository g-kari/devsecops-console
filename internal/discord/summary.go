package discord

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/notification"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// ConfigureGrouping は通知用DBと最新設定の参照元を起動時に登録する。
func (c *Client) ConfigureGrouping(s *store.Store, source func() (config.Snapshot, error)) {
	c.store = s
	c.configSource = source
	if s != nil && source != nil {
		c.batch = notification.NewBatcher(s, c.groupKey("", ""), source, c.groupKey)
	}
}
func (c *Client) grouped() bool { return c.store != nil && c.configSource != nil }
func (c *Client) groupKey(owner, repo string) string {
	return store.NotificationGroupKey("discord", c.webhookURL, owner, repo)
}

// RefreshSummary はリポジトリまとめを更新し、旧個別通知だけのrepoにも作成する。
func (c *Client) RefreshSummary(owner, repo string) error {
	if deferred, err := c.deferNotification(owner, repo); deferred || err != nil {
		return err
	}
	_, err := c.refreshSummary(owner, repo, true)
	return err
}

func (c *Client) deferNotification(owner, repo string) (bool, error) {
	if c.batch == nil {
		return false, nil
	}
	return c.batch.Defer(owner, repo)
}

// FlushNotifications は期限を迎えたrepoごとにまとめを一度だけ更新する。
func (c *Client) FlushNotifications(ctx context.Context, now time.Time, guards ...*policy.Guard) error {
	if c.batch == nil {
		return nil
	}
	return c.batch.Flush(ctx, now, func(owner, repo string) (string, error) {
		var fingerprint string
		send := func(config.Snapshot) error {
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

func (c *Client) refreshSummary(owner, repo string, create bool, delivered ...func(string)) (string, error) {
	if !c.grouped() {
		return "", nil
	}
	var id string
	var fingerprint string
	err := c.store.WithNotificationLock(func() error {
		snapshot, err := c.configSource()
		if err != nil {
			return fmt.Errorf("discord集約設定取得失敗: %w", err)
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
		fields := []embedField{}
		for _, r := range summary.Records {
			if compact {
				break
			}
			if r.Evaluation == nil {
				continue
			}
			e := r.Evaluation
			value := fmt.Sprintf("侵害される内容: %s\n侵害される使い方: %s\nAWSで危険になる利用条件（構成未確認）: %s", notification.Limit(e.Impact, 130), notification.Limit(e.Reasoning, 130), notification.Limit(nonEmpty(e.AWSRisk, "未評価（再評価で確認）"), 260))
			fields = append(fields, embedField{Name: fmt.Sprintf("#%d %s — AI評価", r.Alert.Number, notification.SingleLine(r.Alert.PackageName)), Value: value})
			if len(fields) == 3 {
				break
			}
		}
		payload := webhookPayload{Embeds: []embed{{Title: notification.SingleLine(owner + "/" + repo), Description: summaryText, Fields: fields, Color: colorDefault}}}
		body, err := marshalPayload(payload)
		if err != nil {
			return fmt.Errorf("discord集約変換失敗: %w", err)
		}
		send := func(method, message string) (int, string, error) {
			endpoint, err := url.Parse(c.webhookURL)
			if err != nil {
				return 0, "", fmt.Errorf("Discord通知先の形式が不正です")
			}
			query := endpoint.Query()
			if method == http.MethodPost {
				query.Set("wait", "true")
			} else {
				endpoint.Path += "/messages/" + url.PathEscape(message)
			}
			endpoint.RawQuery = query.Encode()
			if err := c.limiter.Wait(context.Background()); err != nil {
				return 0, "", fmt.Errorf("discord集約待機失敗: %w", err)
			}
			req, err := http.NewRequest(method, endpoint.String(), bytes.NewReader(body))
			if err != nil {
				return 0, "", fmt.Errorf("Discord集約リクエスト作成失敗")
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.httpClient.Do(req)
			if err != nil {
				return 0, "", fmt.Errorf("Discord集約通信失敗")
			}
			defer func() { _ = resp.Body.Close() }()
			c.applyRateLimitHeaders(resp)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return resp.StatusCode, "", fmt.Errorf("Discord集約API失敗: %d", resp.StatusCode)
			}
			if method == http.MethodPatch {
				return resp.StatusCode, message, nil
			}
			var result struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return resp.StatusCode, "", fmt.Errorf("Discord集約ID解析失敗: %w", err)
			}
			if result.ID == "" {
				return resp.StatusCode, "", fmt.Errorf("Discord集約IDが空です")
			}
			return resp.StatusCode, result.ID, nil
		}
		if id != "" {
			status, _, err := send(http.MethodPatch, id)
			if err == nil {
				return nil
			}
			if status != http.StatusNotFound {
				return err
			}
		}
		_, id, err = send(http.MethodPost, "")
		if err != nil {
			return err
		}
		return c.store.SaveNotificationGroup(key, id)
	})
	if err == nil && fingerprint != "" && len(delivered) > 0 {
		delivered[0](fingerprint)
	}
	return id, err
}
