package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

func credentialState(active string, saved *string, env string) control.CredentialState {
	return control.CredentialState{Active: active != "", Saved: saved != nil && *saved != "", Managed: saved != nil, Environment: os.Getenv(env) != ""}
}
func (s *Server) credentialStatus(saved config.Credentials) (control.CredentialsStatus, error) {
	snapshot, err := s.ConfigurationSnapshot()
	if err != nil {
		return control.CredentialsStatus{}, err
	}
	cfg := snapshot.Config
	return control.CredentialsStatus{
		Revision: saved.Revision, RestartRequired: saved.Revision != cfg.CredentialsRevision,
		SlackBot: credentialState(cfg.Slack.BotToken, saved.SlackBotToken, "SLACK_BOT_TOKEN"),
		SlackApp: credentialState(cfg.Slack.AppToken, saved.SlackAppToken, "SLACK_APP_TOKEN"),
		Discord:  credentialState(cfg.Discord.WebhookURL, saved.DiscordWebhookURL, "DISCORD_WEBHOOK_URL"),
	}, nil
}
func (s *Server) handleTUICredentials(w http.ResponseWriter, r *http.Request) {
	if s.cfgPath == "" {
		http.Error(w, "認証設定の保存先がありません", http.StatusServiceUnavailable)
		return
	}
	var saved config.Credentials
	var err error
	if r.Method == http.MethodGet {
		saved, err = config.ReadCredentials(s.cfgPath)
	} else {
		var changes control.CredentialChanges
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&changes) != nil {
			http.Error(w, "認証設定の入力形式が不正です", 400)
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			http.Error(w, "認証設定の入力形式が不正です", 400)
			return
		}
		saved, err = config.UpdateCredentials(s.cfgPath, changes.Revision, changes.Values)
	}
	if err != nil {
		code, message := 500, "認証設定の読込・保存に失敗しました。保存先の所有者・権限を確認してください"
		if errors.Is(err, config.ErrCredentialsConflict) {
			code, message = 409, "認証設定が変更されています。再読込してください"
		}
		if errors.Is(err, config.ErrInvalidCredentials) {
			code, message = 400, "認証情報の形式が不正です（Slackトークンの種類・Discord公式Webhook URLを確認してください）"
		}
		http.Error(w, message, code)
		return
	}
	status, err := s.credentialStatus(saved)
	if err != nil {
		http.Error(w, "認証状態の取得失敗", 500)
		return
	}
	tuiJSON(w, status)
}
