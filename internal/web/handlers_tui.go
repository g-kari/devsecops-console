package web

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
	"gopkg.in/yaml.v3"
)

func (s *Server) registerTUI(mux *http.ServeMux) {
	mux.Handle("GET /api/tui/credentials", s.localTUI(s.handleTUICredentials))
	mux.Handle("PATCH /api/tui/credentials", s.localTUI(s.handleTUICredentials))
	mux.Handle("GET /api/tui/config", s.localTUI(s.handleTUIConfig))
	mux.Handle("PUT /api/tui/config", s.localTUI(s.handleTUISave))
	mux.Handle("GET /api/tui/status", s.localTUI(s.handleTUIStatus))
	mux.Handle("POST /api/tui/poll", s.localTUI(func(w http.ResponseWriter, r *http.Request) {
		if s.pollFn == nil {
			http.Error(w, "取得処理が利用できません", http.StatusServiceUnavailable)
			return
		}
		s.handlePoll(w, r)
	}))
	mux.Handle("POST /api/tui/evaluate/{id}", s.localTUI(s.handleEnqueueEvaluate))
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// localTUIRequestFailure is the shared pure decision used by legacy TUI and the
// manual JSON API. The bool preserves legacy Cache-Control timing exactly.
func localTUIRequestFailure(r *http.Request) (string, bool) {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	host, _, hostErr := net.SplitHostPort(r.Host)
	if hostErr != nil {
		host = r.Host
	}
	if err != nil || !loopbackHost(remote) || !loopbackHost(host) {
		return "TUI APIはローカル接続専用です", false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || u.Scheme != "http" {
			return "Originが不正です", true
		}
	}
	if r.Method != http.MethodGet {
		cookie, err := r.Cookie("csrf_token")
		token := r.Header.Get("X-CSRF-Token")
		if err != nil || token == "" || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
			return "CSRF tokenが必要です", true
		}
	}
	return "", true
}

func (s *Server) localTUI(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message, noStore := localTUIRequestFailure(r)
		if noStore {
			w.Header().Set("Cache-Control", "no-store")
		}
		if message != "" {
			http.Error(w, message, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
func tuiJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("TUI応答失敗", "error", err)
	}
}
func (s *Server) handleTUIConfig(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.ConfigurationSnapshot()
	if err != nil {
		http.Error(w, "設定取得失敗", 500)
		return
	}
	var doc yaml.Node
	raw, err := yaml.Marshal(snapshot.Config)
	if err != nil {
		http.Error(w, "設定変換失敗", 500)
		return
	}
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		http.Error(w, "設定変換失敗", 500)
		return
	}
	redactSettings(doc.Content[0])
	raw, err = yaml.Marshal(&doc)
	if err != nil {
		http.Error(w, "設定変換失敗", 500)
		return
	}
	tuiJSON(w, control.Settings{Revision: snapshot.Revision, YAML: string(raw), CSRF: issueCSRF(w, r)})
}
func protectedKey(key string) bool {
	switch key {
	case "bot_token", "app_token", "webhook_url", "config_revision":
		return true
	}
	return false
}
func redactSettings(n *yaml.Node) {
	if n.Kind == yaml.MappingNode {
		var kept []*yaml.Node
		for i := 0; i < len(n.Content); i += 2 {
			if protectedKey(n.Content[i].Value) {
				continue
			}
			redactSettings(n.Content[i+1])
			kept = append(kept, n.Content[i], n.Content[i+1])
		}
		n.Content = kept
	} else {
		for _, child := range n.Content {
			redactSettings(child)
		}
	}
}
func checkSettingsNode(n *yaml.Node, depth int) error {
	if depth > 40 || n.Kind == yaml.AliasNode {
		return errors.New("YAMLの深さまたは別名参照が不正です")
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if protectedKey(n.Content[i].Value) {
				return errors.New("認証情報・revisionはYAMLから変更できません")
			}
		}
	}
	for _, c := range n.Content {
		if err := checkSettingsNode(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
func validateTUISettings(next, old config.Config) error {
	if next.Evaluator.Sandbox.Enabled != old.Evaluator.Sandbox.Enabled && !next.Evaluator.Sandbox.Enabled {
		return errors.New("AI隔離を無効にできません")
	}
	if next.Slack.BotToken != old.Slack.BotToken || next.Slack.AppToken != old.Slack.AppToken || next.Discord.WebhookURL != old.Discord.WebhookURL {
		return errors.New("認証情報は環境変数で設定してください")
	}
	if next.PollInterval <= 0 {
		return errors.New("監視間隔は正数で指定してください")
	}
	if next.RSS.RefreshInterval < 15*time.Minute || next.RSS.RequestTimeout <= 0 || next.RSS.MaxItemsPerFeed < 1 || next.RSS.MaxItemsPerFeed > 1000 || next.RSS.RetentionDays < 1 || next.RSS.RetentionDays > 3650 {
		return errors.New("RSSの間隔・タイムアウト・件数・保存期間が不正です")
	}
	if next.Evaluator.Sandbox.Timeout <= 0 || next.Evaluator.MaxEvalPerPoll < 0 || next.ActiveMonths < 0 {
		return errors.New("AIタイムアウト・評価上限・活動月数が不正です")
	}
	for _, v := range []string{next.NotifyMinSeverity, next.FetchMinSeverity, next.Evaluator.MinSeverity} {
		if v != "" && v != "low" && v != "medium" && v != "high" && v != "critical" {
			return errors.New("重要度はlow/medium/high/criticalを指定してください")
		}
	}
	if next.GhPath == "" || next.ClaudePath == "" || next.CodexPath == "" || next.DataPath == "" {
		return errors.New("CLIパス・DB保存先は空にできません")
	}
	if next.LogLevel != "debug" && next.LogLevel != "info" && next.LogLevel != "warn" && next.LogLevel != "error" {
		return errors.New("ログレベルが不正です")
	}
	return next.Validate()
}
func restartForSettings(a, b config.Config) bool {
	return a.PollInterval != b.PollInterval || a.Web != b.Web || a.DataPath != b.DataPath || a.GhPath != b.GhPath || a.GitHubAuth != b.GitHubAuth || a.LogLevel != b.LogLevel || !reflect.DeepEqual(a.Slack, b.Slack) || a.Discord != b.Discord || a.Threat != b.Threat
}
func (s *Server) handleTUISave(w http.ResponseWriter, r *http.Request) {
	var request control.Settings
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "設定リクエストが不正です", 400)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "余分なデータがあります", 400)
		return
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(request.YAML), &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		http.Error(w, "設定YAMLはマップで指定してください", 400)
		return
	}
	if err := checkSettingsNode(&doc, 0); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	unlock, err := s.repositoryPolicy.LockUpdate(r.Context())
	if err != nil {
		http.Error(w, "設定変更の待機を中止しました", http.StatusRequestTimeout)
		return
	}
	defer unlock()
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if request.Revision != s.cfg.ConfigRevision {
		http.Error(w, "設定が更新されています。再読込して編集してください", http.StatusConflict)
		return
	}
	next, err := config.Clone(*s.cfg)
	if err != nil {
		http.Error(w, "設定複製失敗", 500)
		return
	}
	yd := yaml.NewDecoder(bytes.NewBufferString(request.YAML))
	yd.KnownFields(true)
	if err := yd.Decode(&next); err != nil {
		http.Error(w, "設定YAMLの項目・型が不正です", 400)
		return
	}
	if err := yd.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "YAMLは1文書だけ指定してください", 400)
		return
	}
	if err := validateTUISettings(next, *s.cfg); err != nil {
		http.Error(w, fmt.Sprintf("設定が不正です: %s", err), 400)
		return
	}
	restart := restartForSettings(*s.cfg, next)
	next.ConfigRevision++
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, &next); err != nil {
			http.Error(w, "設定保存失敗", 500)
			return
		}
	}
	*s.cfg = next
	if s.onEvaluatorConfigChanged != nil {
		s.onEvaluatorConfigChanged(next)
	}
	s.notifyRiskConfigChanged()
	select {
	case s.feedConfigChanged <- struct{}{}:
	default:
	}
	slog.Info("TUIから設定を保存しました", "revision", next.ConfigRevision, "restart_required", restart)
	tuiJSON(w, control.Saved{Revision: next.ConfigRevision, RestartRequired: restart})
}
func (s *Server) handleTUIStatus(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.ConfigurationSnapshot()
	if err != nil {
		http.Error(w, "状態取得失敗", 500)
		return
	}
	s.pollingMu.Lock()
	polling := s.isPolling
	s.pollingMu.Unlock()
	alerts := s.store.List()
	if len(alerts) > 100 {
		alerts = alerts[:100]
	}
	logs := s.store.ListLogs()
	if len(logs) > 50 {
		logs = logs[:50]
	}
	tuiJSON(w, control.Status{Alerts: alerts, Logs: logs, Polling: polling, SlackBot: snapshot.Config.Slack.BotToken != "", SlackApp: snapshot.Config.Slack.AppToken != "", Discord: snapshot.Config.Discord.WebhookURL != ""})
}
