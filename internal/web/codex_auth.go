package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type codexAuthClient interface {
	Status(context.Context, string) toolResult
	StartLogin(context.Context, string) error
}

type cliCodexAuth struct {
	mu      sync.Mutex
	running bool
}

func (a *cliCodexAuth) Status(ctx context.Context, path string) toolResult {
	if path == "" {
		path = "codex"
	}
	out, err := exec.CommandContext(ctx, path, "login", "status").Output()
	if err != nil {
		return toolResult{OK: false, Message: "Codex CLIの認証を確認できません。codex login を実行してください。"}
	}
	method := "Codex CLIで認証済み"
	if strings.Contains(strings.ToLower(string(out)), "chatgpt") {
		method = "ChatGPTで認証済み"
	}
	return toolResult{OK: true, Message: method}
}

func (a *cliCodexAuth) StartLogin(ctx context.Context, path string) error {
	if path == "" {
		path = "codex"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return fmt.Errorf("Codex認証は既に進行中です")
	}
	cmd := exec.CommandContext(ctx, path, "login")
	cmd.Dir = os.TempDir()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("codex認証開始失敗: %w", err)
	}
	a.running = true
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("Codex認証プロセス終了", "error", err)
		}
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()
	return nil
}

func (s *Server) handleCodexAuthStatus(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	path := s.cfg.CodexPath
	s.cfgMu.RUnlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.codexAuth.Status(ctx, path))
}

func (s *Server) handleCodexLogin(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "Codex認証はこのPCからのみ開始できます", http.StatusForbidden)
		return
	}
	s.cfgMu.RLock()
	path := s.cfg.CodexPath
	s.cfgMu.RUnlock()
	ctx := s.appCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.codexAuth.StartLogin(ctx, path); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/settings#ai-evaluation", http.StatusSeeOther)
}
