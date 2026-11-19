// Package setup provides terminal-only configuration without starting services.
package setup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

// Run edits the selected configuration interactively and saves only after confirmation.
// Credentials remain environment variables, as with config.Save and the Web UI.
func Run(path string, in io.Reader, out io.Writer) error {
	original, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("既存設定の読み込み: %w", err)
	}
	cfg := config.Defaults()
	cfg.Web.Host = "127.0.0.1"
	if exists {
		cfg, err = config.Load(path)
		if err != nil {
			return fmt.Errorf("既存設定の読み込み: %w", err)
		}
	}
	p := prompt{reader: bufio.NewReader(in), out: out}
	p.print("対話型セットアップ: %s\n実行中のアプリを停止してから設定してください。Enterで現在値を保持、任意項目は - で消去します。\n", path)
	targetNames := []string{}
	for _, t := range cfg.Targets {
		repo := t.Repo
		if repo == "" {
			repo = "*"
		}
		targetNames = append(targetNames, t.Owner+"/"+repo)
	}
	p.ask("監視対象 (owner/repo または owner/*、カンマ区切り、- で対象なし)", strings.Join(targetNames, ","), func(v string) error {
		targets, err := parseTargets(v)
		if err != nil {
			return err
		}
		cfg.Targets = targets
		return nil
	})
	p.ask("監視間隔 (例: 30m, 1h)", cfg.PollInterval.String(), func(v string) error {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return errors.New("正の時間を指定してください")
		}
		cfg.PollInterval = d
		return nil
	})
	for _, field := range []struct {
		label string
		value *string
	}{
		{"GitHub CLIのパス", &cfg.GhPath}, {"Claude CLIのパス", &cfg.ClaudePath}, {"Codex CLIのパス", &cfg.CodexPath}, {"DB保存先 (相対パスは起動時の作業ディレクトリ基準)", &cfg.DataPath},
	} {
		p.ask(field.label, *field.value, func(v string) error {
			if v == "" || v == "-" {
				return errors.New("空にはできません")
			}
			*field.value = v
			return nil
		})
	}
	p.ask("Web待受IP (ローカル接続: 127.0.0.1)", cfg.Web.Host, func(v string) error {
		w := cfg.Web
		w.Host = v
		c := *cfg
		c.Web = w
		if err := c.Validate(); err != nil {
			return err
		}
		cfg.Web = w
		return nil
	})
	p.ask("Webポート", strconv.Itoa(cfg.Web.Port), func(v string) error {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("1〜65535を指定してください")
		}
		cfg.Web.Port = port
		return nil
	})
	p.ask("Slack通知チャンネルID (任意)", cfg.Slack.ChannelID, func(v string) error { cfg.Slack.ChannelID = optional(v); return nil })
	p.ask("Slack承認可能ユーザーID (カンマ区切り、空=全員)", strings.Join(cfg.Slack.AllowedUserIDs, ","), func(v string) error {
		var ids []string
		if v = optional(v); v != "" {
			for _, id := range strings.Split(v, ",") {
				id = strings.TrimSpace(id)
				if id == "" {
					return errors.New("空のユーザーIDがあります")
				}
				ids = append(ids, id)
			}
		}
		cfg.Slack.AllowedUserIDs = ids
		return nil
	})
	p.ask("通知する最低重要度 (low/medium/high/critical)", cfg.NotifyMinSeverity, func(v string) error {
		switch v {
		case "low", "medium", "high", "critical":
			cfg.NotifyMinSeverity = v
			return nil
		}
		return errors.New("low/medium/high/criticalを指定してください")
	})
	p.ask("AI評価プロバイダー (claude/codex/hermes)", cfg.Evaluator.Provider, func(v string) error {
		switch v {
		case "claude", "codex", "hermes":
			cfg.Evaluator.Provider = v
			return nil
		default:
			return errors.New("claude/codex/hermesを指定してください")
		}
	})
	autoEvalPrompt := "AI自動評価を有効にする (隔離用イメージ・CLI認証の準備が必要)"
	if cfg.Evaluator.Provider == "hermes" {
		autoEvalPrompt = "AI自動評価を有効にする (Hermes Proxyを起動してください)"
	}
	p.boolean(autoEvalPrompt, &cfg.Evaluator.AutoEval)
	p.boolean("RSS収集を有効にする", &cfg.RSS.Enabled)
	p.print("\n認証情報は環境変数で設定します（値は表示・保存しません）。\n既存YAML内の認証情報も保存しません。必要な値は環境変数へ移してください。\n")
	for _, key := range []string{"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL"} {
		status := "未設定"
		if os.Getenv(key) != "" {
			status = "設定済み"
		}
		p.print("  %s: %s\n", key, status)
	}
	p.print("GitHub認証は gh auth status で確認してください。\n")
	p.print("\n保存先: %s\n監視対象: %d件 / 間隔: %s / Web: %s\nAI: %s (自動=%t) / RSS: %t (%d件)\n", path, len(cfg.Targets), cfg.PollInterval, cfg.Web.BrowserURL(), cfg.Evaluator.Provider, cfg.Evaluator.AutoEval, cfg.RSS.Enabled, len(cfg.RSS.Feeds))
	save := false
	p.boolean("この内容を保存する", &save)
	if p.err != nil {
		return fmt.Errorf("対話入力: %w", p.err)
	}
	if !save {
		_, err := fmt.Fprintln(out, "保存をキャンセルしました。")
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("設定検証: %w", err)
	}
	// Avoid overwriting a file changed by the running app during this conversation.
	current, readErr := os.ReadFile(path)
	if exists {
		if readErr != nil || !bytes.Equal(current, original) {
			return errors.New("設定ファイルが対話中に変更されました。再実行してください")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return errors.New("設定ファイルが対話中に作成されました。再実行してください")
	}
	cfg.ConfigRevision++
	if err := config.Save(path, cfg); err != nil {
		return fmt.Errorf("設定保存: %w", err)
	}
	_, err = fmt.Fprintln(out, "設定を保存しました。--setupを外し、同じ--configと作業ディレクトリで起動してください。")
	return err
}

func optional(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

func parseTargets(v string) ([]config.Target, error) {
	targets := []config.Target{}
	if optional(v) == "" {
		return targets, nil
	}
	seen := map[string]bool{}
	for _, raw := range strings.Split(v, ",") {
		parts := strings.Split(strings.TrimSpace(raw), "/")
		if len(parts) != 2 || !validName(parts[0]) || (parts[1] != "*" && !validName(parts[1])) {
			return nil, errors.New("owner/repoまたはowner/*をカンマ区切りで指定してください")
		}
		repo := parts[1]
		if repo == "*" {
			repo = ""
		}
		key := strings.ToLower(parts[0] + "/" + repo)
		if seen[key] {
			return nil, errors.New("監視対象が重複しています")
		}
		seen[key] = true
		targets = append(targets, config.Target{Owner: parts[0], Repo: repo})
	}
	return targets, nil
}

func validName(v string) bool {
	if v == "" || v == "." || v == ".." {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

type prompt struct {
	reader *bufio.Reader
	out    io.Writer
	err    error
}

func (p *prompt) print(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.out, format, args...)
	}
}
func (p *prompt) ask(label, current string, apply func(string) error) {
	for p.err == nil {
		p.print("%s [%s]: ", label, current)
		if p.err != nil {
			return
		}
		line, err := p.reader.ReadString('\n')
		if err != nil {
			p.err = err
			return
		}
		v := strings.TrimSpace(line)
		if v == "" {
			return
		}
		if err := apply(v); err != nil {
			p.print("入力エラー: %s\n", err)
			continue
		}
		return
	}
}
func (p *prompt) boolean(label string, value *bool) {
	current := "n"
	if *value {
		current = "y"
	}
	p.ask(label+" (y/n)", current, func(v string) error {
		switch strings.ToLower(v) {
		case "y", "yes":
			*value = true
		case "n", "no":
			*value = false
		default:
			return errors.New("yまたはnを指定してください")
		}
		return nil
	})
}
