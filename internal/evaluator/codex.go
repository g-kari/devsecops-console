package evaluator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type codexCommand struct {
	Name  string
	Args  []string
	Input string
	Dir   string
}

// CodexEvaluator は既存のCodex CLI認証を使ってアラートを評価する。
// Docker隔離が有効な場合はホストのリポジトリをコンテナに渡さない。
type CodexEvaluator struct {
	cfg  config.EvaluatorConfig
	path string
	run  func(context.Context, codexCommand) ([]byte, error)
}

func (e *CodexEvaluator) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	if e.cfg.Sandbox.Runtime == "podman" && !e.cfg.Sandbox.Enabled {
		return nil, fmt.Errorf("Podman隔離が無効です。隔離なしでは評価しません")
	}
	timeout := e.cfg.Sandbox.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	prompt := buildPrompt(alert)
	var spec codexCommand
	if e.cfg.Sandbox.Enabled {
		home := os.Getenv("CODEX_HOME")
		if home == "" {
			userHome, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("codexホーム取得失敗: %w", err)
			}
			home = filepath.Join(userHome, ".codex")
		}
		if _, err := os.Stat(filepath.Join(home, "auth.json")); err != nil {
			return nil, fmt.Errorf("codex認証ファイルがありません。codex login を実行し、認証情報をファイルに保存してください: %w", err)
		}
		spec = e.dockerCommand(prompt, home)
	} else {
		dir, err := os.MkdirTemp("", "security-notice-codex-*")
		if err != nil {
			return nil, fmt.Errorf("codex作業ディレクトリ作成失敗: %w", err)
		}
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				slog.Warn("Codex作業ディレクトリの削除失敗", "error", err)
			}
		}()
		path := e.path
		if path == "" {
			path = "codex"
		}
		spec = codexCommand{Name: path, Args: codexExecArgs(dir, e.cfg.CodexModel), Input: prompt, Dir: dir}
	}
	runner := e.run
	if runner == nil {
		runner = runCodexCommand
	}
	out, err := runner(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("codex AI評価失敗: %w", err)
	}
	return parseCodexOutput(out)
}

func codexExecArgs(dir, model string) []string {
	args := []string{"exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--json", "-C", dir}
	if model != "" {
		args = append(args, "-m", model)
	}
	return append(args, "-")
}

func (e *CodexEvaluator) dockerCommand(prompt, codexHome string) codexCommand {
	image := e.cfg.Sandbox.CodexImage
	if image == "" {
		image = "dependabot-codex-evaluator:latest"
	}
	args := []string{
		"run", "--rm", "-i",
		"-v", codexHome + ":/home/node/.codex:ro",
		"--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
		"--security-opt=no-new-privileges", "--cap-drop=ALL",
		"--network=host", "--user=1000:1000",
	}
	if e.cfg.Sandbox.MemoryLimit != "" {
		args = append(args, "--memory="+e.cfg.Sandbox.MemoryLimit)
	}
	if e.cfg.Sandbox.CPULimit != "" {
		args = append(args, "--cpus="+e.cfg.Sandbox.CPULimit)
	}
	if e.cfg.Sandbox.Runtime == "podman" {
		args = append(args, "--userns=keep-id:uid=1000,gid=1000")
	}
	args = append(args, image)
	args = append(args, codexExecArgs("/tmp", e.cfg.CodexModel)...)
	return codexCommand{Name: containerRuntime(e.cfg.Sandbox.Runtime), Args: args, Input: prompt}
}

func runCodexCommand(ctx context.Context, spec codexCommand) ([]byte, error) {
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Stdin = strings.NewReader(spec.Input)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s実行失敗: %w", spec.Name, err)
	}
	return out, nil
}

func parseCodexOutput(out []byte) (*model.Evaluation, error) {
	var final string
	completed := false
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"item"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("codex結果形式が不正です: %w", err)
		}
		if event.Type == "turn.failed" {
			return nil, fmt.Errorf("Codex評価が失敗しました")
		}
		if event.Type == "item.completed" && event.Item.Type == "agent_message" {
			final = event.Item.Text
		}
		if event.Type == "turn.completed" {
			completed = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("codex結果読込失敗: %w", err)
	}
	if !completed || final == "" {
		return nil, fmt.Errorf("Codex評価結果が完了していません")
	}
	return parseEvaluation([]byte(final))
}
