package evaluator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// AppleEvaluator isolates inference in an Apple container Linux VM on supported Macs.
// It never falls back to a host CLI or mounts a host home/repository.
type AppleEvaluator struct {
	cfg      config.EvaluatorConfig
	run      func(context.Context, codexCommand) ([]byte, error)
	platform func() (string, string)
}

const appleBootstrap = `umask 077
mkdir -p "$HOME/.codex" "$HOME/.claude"
if [ -f /run/security-notice-auth/auth.json ]; then cp /run/security-notice-auth/auth.json "$HOME/.codex/auth.json"; chmod 600 "$HOME/.codex/auth.json"; fi
if [ -f /run/security-notice-auth/.credentials.json ]; then cp /run/security-notice-auth/.credentials.json "$HOME/.claude/.credentials.json"; chmod 600 "$HOME/.claude/.credentials.json"; fi
printf '{"hasCompletedOnboarding":true}' > "$HOME/.claude.json"
exec "$@"`

func (e *AppleEvaluator) Evaluate(parent context.Context, alert model.Alert) (result *model.Evaluation, err error) {
	if !e.cfg.Sandbox.Enabled {
		return nil, errors.New("apple container隔離が無効です。隔離なしでは評価しません")
	}
	osName, arch := runtime.GOOS, runtime.GOARCH
	if e.platform != nil {
		osName, arch = e.platform()
	}
	if osName != "darwin" || arch != "arm64" {
		return nil, errors.New("apple containerはApple SiliconのmacOS 26以降専用です")
	}
	timeout := e.cfg.Sandbox.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	run := e.run
	if run == nil {
		run = runCodexCommand
	}
	version, err := run(ctx, codexCommand{Name: "sw_vers", Args: []string{"-productVersion"}})
	if err != nil {
		return nil, fmt.Errorf("macOSバージョン取得: %w", err)
	}
	major, err := strconv.Atoi(strings.Split(strings.TrimSpace(string(version)), ".")[0])
	if err != nil || major < 26 {
		return nil, errors.New("apple container評価にはmacOS 26以降が必要です")
	}
	memory := e.cfg.Sandbox.MemoryLimit
	if memory == "" {
		memory = "512m"
	}
	if !regexp.MustCompile(`^[1-9][0-9]*[kKmMgG]$`).MatchString(memory) {
		return nil, errors.New("apple containerメモリは512mや1gの形式で指定してください")
	}
	cpus := e.cfg.Sandbox.ContainerCPUs
	if cpus == 0 {
		cpus = 1
	}
	if cpus < 1 || cpus > 64 {
		return nil, errors.New("apple containerのCPU数は1〜64で指定してください")
	}
	work, err := os.MkdirTemp("", "security-notice-apple-auth-*")
	if err != nil {
		return nil, fmt.Errorf("認証用作業フォルダ作成: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(work); removeErr != nil {
			result = nil
			err = errors.Join(err, fmt.Errorf("認証用作業フォルダ削除: %w", removeErr))
		}
	}()
	if strings.ContainsAny(work, ",\r\n") {
		return nil, errors.New("認証用一時パスに利用できない文字があります")
	}
	auth := filepath.Join(work, "auth")
	if err := os.Mkdir(auth, 0755); err != nil {
		return nil, fmt.Errorf("認証ステージ作成: %w", err)
	}
	if err := os.Chmod(auth, 0755); err != nil {
		return nil, fmt.Errorf("認証ステージ権限設定: %w", err)
	}
	secrets, envFile, err := e.stageAuth(work, auth)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("評価ID生成: %w", err)
	}
	name := "security-notice-eval-" + hex.EncodeToString(random)
	path := e.cfg.Sandbox.ContainerPath
	if path == "" {
		path = "container"
	}
	// Delete only this evaluation VM on success, failure, timeout or cancellation.
	// A fresh context ensures killing the CLI does not leave a VM running silently.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, cleanupErr := run(cleanup, codexCommand{Name: path, Args: []string{"delete", "--force", name}}); cleanupErr != nil {
			result = nil
			err = errors.Join(err, fmt.Errorf("評価VMの削除失敗: %w", safeAppleError(cleanupErr, secrets)))
		}
	}()
	image := e.cfg.Sandbox.AppleClaudeImage
	cli := "claude"
	cliArgs := []string{"-p", "--output-format", "json", "--tools", ""}
	if e.cfg.ClaudeModel != "" {
		cliArgs = append(cliArgs, "--model", e.cfg.ClaudeModel)
	}
	if e.cfg.Provider == "codex" {
		image = e.cfg.Sandbox.AppleCodexImage
		cli = "codex"
		cliArgs = codexExecArgs("/tmp", e.cfg.CodexModel)
	}
	if image == "" {
		image = "security-notice-apple-" + cli + ":latest"
	}
	if strings.HasPrefix(image, "-") {
		return nil, errors.New("コンテナイメージ名が不正です")
	}
	args := []string{"run", "--name", name, "-i", "--read-only", "--cap-drop", "ALL", "--user", "1000:1000", "--cpus", strconv.Itoa(cpus), "--memory", memory, "--network", "default", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777", "--workdir", "/tmp", "--env", "HOME=/tmp/home", "--env", "CODEX_HOME=/tmp/home/.codex", "--mount", "type=bind,source=" + auth + ",target=/run/security-notice-auth,readonly", "--entrypoint", "/usr/bin/setpriv"}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, image, "--no-new-privs", "/bin/sh", "-eu", "-c", appleBootstrap, "security-notice-bootstrap", cli)
	args = append(args, cliArgs...)
	out, err := run(ctx, codexCommand{Name: path, Args: args, Input: buildPrompt(alert)})
	if err != nil {
		return nil, fmt.Errorf("apple container AI評価失敗: %w", safeAppleError(err, secrets))
	}
	safe := redactOutput(out, secrets)
	if e.cfg.Provider == "codex" {
		return parseCodexOutput(safe)
	}
	return parseEvaluation(safe)
}

func readCredential(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("認証ファイル取得: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, errors.New("認証ファイルは4MiB以下の通常ファイルを指定してください")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("認証ファイル読み込み: %w", err)
	}
	if !json.Valid(raw) {
		return nil, errors.New("認証ファイルのJSONが不正です")
	}
	return raw, nil
}
func collectSecrets(raw []byte) []string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	var out []string
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				lower := strings.ToLower(key)
				if strings.Contains(lower, "token") || strings.Contains(lower, "key") {
					if s, ok := child.(string); ok && len(s) >= 8 {
						out = append(out, s)
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range x {
				visit(child)
			}
		}
	}
	visit(value)
	return out
}
func (e *AppleEvaluator) stageAuth(work, auth string) ([]string, string, error) {
	var raw []byte
	var err error
	var file string
	var secrets []string
	if e.cfg.Provider == "codex" {
		file = "auth.json"
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			raw, err = json.Marshal(map[string]string{"OPENAI_API_KEY": key})
		} else {
			home := os.Getenv("CODEX_HOME")
			if home == "" {
				user, err := os.UserHomeDir()
				if err != nil {
					return nil, "", fmt.Errorf("codexホーム取得: %w", err)
				}
				home = filepath.Join(user, ".codex")
			}
			raw, err = readCredential(filepath.Join(home, "auth.json"))
		}
	} else {
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			if strings.ContainsAny(key, "\r\n") {
				return nil, "", errors.New("APIキーに改行を含められません")
			}
			path := filepath.Join(work, "api.env")
			if err := os.WriteFile(path, []byte("ANTHROPIC_API_KEY="+key+"\n"), 0600); err != nil {
				return nil, "", fmt.Errorf("API環境ファイル作成: %w", err)
			}
			return []string{key}, path, nil
		}
		file = ".credentials.json"
		home := e.cfg.Sandbox.ClaudeHome
		if home == "" {
			user, err := os.UserHomeDir()
			if err != nil {
				return nil, "", fmt.Errorf("claudeホーム取得: %w", err)
			}
			home = filepath.Join(user, ".claude")
		}
		raw, err = readCredential(filepath.Join(home, file))
	}
	if err != nil {
		return nil, "", fmt.Errorf("apple container用認証準備（APIキーまたはファイル認証が必要）: %w", err)
	}
	secrets = collectSecrets(raw)
	// The private 0700 parent protects the file on the host; guest UID 1000 needs
	// read access through VirtioFS, regardless of the host account's UID.
	if err := os.WriteFile(filepath.Join(auth, file), raw, 0444); err != nil {
		return nil, "", fmt.Errorf("認証ファイルコピー: %w", err)
	}
	if err := os.Chmod(filepath.Join(auth, file), 0444); err != nil {
		return nil, "", fmt.Errorf("認証ファイル権限設定: %w", err)
	}
	return secrets, "", nil
}
func redactOutput(out []byte, secrets []string) []byte {
	s := string(out)
	for _, secret := range secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
		encoded, err := json.Marshal(secret)
		if err == nil && len(encoded) > 2 {
			s = strings.ReplaceAll(s, string(encoded[1:len(encoded)-1]), "[redacted]")
		}
	}
	return []byte(s)
}

// Identity separates Apple VM evaluations from Docker and direct evaluation caches.
func (e *AppleEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	selected := e.cfg.ClaudeModel
	if e.cfg.Provider == "codex" {
		selected = e.cfg.CodexModel
	}
	return identity(alert, e.cfg.Provider, selected, "apple-container", fmt.Sprintf("apple-v1\x00%s\x00%s\x00%s\x00%d\x00%s", e.cfg.Sandbox.AppleClaudeImage, e.cfg.Sandbox.AppleCodexImage, e.cfg.Sandbox.MemoryLimit, e.cfg.Sandbox.ContainerCPUs, e.cfg.Sandbox.ClaudeHome))
}

// appleSafeError preserves the cause while keeping credential values out of logs.
type appleSafeError struct {
	cause   error
	message string
}

func (e appleSafeError) Error() string { return e.message }
func (e appleSafeError) Unwrap() error { return e.cause }
func safeAppleError(err error, secrets []string) error {
	return appleSafeError{cause: err, message: string(redactOutput([]byte(err.Error()), secrets))}
}
