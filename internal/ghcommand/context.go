// Package ghcommand binds GitHub CLI operations to a frozen authentication
// context. It never logs in, switches accounts, extracts or saves credentials.
package ghcommand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Settings contains only non-secret authentication selection metadata.
type Settings struct {
	Mode          string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Host          string `yaml:"host,omitempty" json:"host,omitempty"`
	TokenEnv      string `yaml:"token_env,omitempty" json:"token_env,omitempty"`
	ExpectedLogin string `yaml:"expected_login,omitempty" json:"expected_login,omitempty"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var loginName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)

// Validate rejects ambiguous sources and unsupported hosts without reading secrets.
func (s Settings) Validate() error {
	if s.Mode == "" || s.Mode == "inherited" {
		if s.Host != "" || s.TokenEnv != "" || s.ExpectedLogin != "" {
			return errors.New("GitHub inherited mode cannot select a host, token source or login")
		}
		return nil
	}
	if s.Mode != "token_env" {
		return errors.New("GitHub authentication mode must be inherited or token_env")
	}
	if s.Host != "" && s.Host != "github.com" {
		return errors.New("explicit GitHub authentication currently supports github.com only")
	}
	if !envName.MatchString(s.TokenEnv) {
		return errors.New("GitHub token environment variable name is invalid")
	}
	if s.ExpectedLogin != "" && !loginName.MatchString(s.ExpectedLogin) {
		return errors.New("GitHub expected login is invalid")
	}
	return nil
}

// ErrIdentity means the expected GitHub login could not be established.
var ErrIdentity = errors.New("GitHub expected login could not be verified")

// ErrRateLimit is a bounded classification of a GitHub CLI rate-limit failure.
var ErrRateLimit = errors.New("GitHub rate limit exceeded")

// ErrAccess is a bounded classification of a denied or unavailable resource.
var ErrAccess = errors.New("GitHub resource unavailable (403/404)")

// ErrCommand does not expose command output, environment, arguments or credentials.
var ErrCommand = errors.New("GitHub command failed; check selected authentication and access")

// Runner is the small command interface used by GitHub integration consumers.
type Runner interface {
	Output(context.Context, ...string) ([]byte, error)
}

type executor func(context.Context, string, []string, []string) ([]byte, []byte, error)

// Context holds a private frozen environment, never serialized into application settings.
type Context struct {
	path        string
	settings    Settings
	environment []string
	secrets     []string
	execute     executor
}

// MarshalJSON pins the JSON representation to an empty object: the context
// holds credentials and must never expose them through serialization.
func (c Context) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

var _ json.Marshaler = Context{}

// New snapshots the application's current environment at an operation boundary.
func New(path string, settings Settings) (*Context, error) {
	return NewWithEnvironment(path, settings, os.Environ())
}

// NewWithEnvironment supports synthetic/offline tests and explicit dependency injection.
// The supplied environment is copied; subsequent changes cannot change this context.
func NewWithEnvironment(path string, settings Settings, environment []string) (*Context, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if path == "" {
		path = "gh"
	}
	c := &Context{path: path, settings: settings}
	if settings.Mode != "token_env" {
		c.environment = append([]string(nil), environment...)
		for _, entry := range environment {
			key, value, ok := strings.Cut(entry, "=")
			if ok && isCredentialKey(key) && value != "" {
				c.secrets = append(c.secrets, value)
			}
		}
		c.execute = func(ctx context.Context, path string, args, env []string) ([]byte, []byte, error) {
			return executeCommand(ctx, path, args, env, false)
		}
		return c, nil
	}
	var token string
	var matches int
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		// Reject case-folded duplicates on every platform, including Windows.
		if strings.EqualFold(key, settings.TokenEnv) {
			token = value
			matches++
			continue
		}
		if safeEnvironmentKey(key) {
			c.environment = append(c.environment, entry)
		}
	}
	if matches != 1 || len(token) == 0 || len(token) > 4096 {
		return nil, errors.New("selected GitHub token environment variable is missing, empty or ambiguous")
	}
	for _, r := range token {
		if r < 33 || r > 126 {
			return nil, errors.New("selected GitHub token contains invalid characters")
		}
	}
	resolved, err := resolveExecutable(path, c.environment)
	if err != nil {
		return nil, err
	}
	c.path = resolved
	c.secrets = []string{token}
	c.environment = append(c.environment, "GH_TOKEN="+token, "GH_HOST=github.com", "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_NO_EXTENSION_UPDATE_NOTIFIER=1", "GH_TELEMETRY=0")
	c.execute = func(ctx context.Context, path string, args, env []string) ([]byte, []byte, error) {
		return executeCommand(ctx, path, args, env, true)
	}
	return c, nil
}

func safeEnvironmentKey(key string) bool {
	switch strings.ToUpper(key) {
	case "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY":
		return true
	}
	return false
}

func isCredentialKey(key string) bool {
	switch strings.ToUpper(key) {
	case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN":
		return true
	}
	return false
}

// Description labels the compatibility mode without disclosing configuration values.
func (c Context) Description() string {
	if c.settings.Mode == "token_env" {
		return "token_env (github.com, application-selected authentication)"
	}
	return "inherited (legacy console authentication; not isolated)"
}

// String prevents ordinary formatted logging from exposing the private environment.
func (c Context) String() string { return c.Description() }

// GoString also protects Go-syntax diagnostic formatting.
func (c Context) GoString() string { return c.Description() }

// Identity verifies a user-token login using the same frozen authentication.
// Installation tokens that cannot call /user must omit expected_login; this
// method reports a bounded failure rather than inferring an installation actor.
func (c *Context) Identity(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("GitHub identity check: %w", err)
	}
	args := []string{"api", "user", "--hostname", "github.com", "--jq", ".login"}
	if c.settings.Mode != "token_env" {
		args = []string{"api", "user", "--jq", ".login"}
	}
	out, err := c.run(ctx, args)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("GitHub identity check: %w", ctxErr)
	}
	if err != nil {
		return "", fmt.Errorf("GitHub identity check: %w", ErrIdentity)
	}
	login := strings.TrimSpace(string(out))
	if !loginName.MatchString(login) || (c.settings.ExpectedLogin != "" && !strings.EqualFold(login, c.settings.ExpectedLogin)) {
		return "", ErrIdentity
	}
	return login, nil
}

// Output runs a supported GitHub command with a frozen environment and bounded errors.
func (c *Context) Output(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.settings.Mode == "token_env" {
		var err error
		args, err = pinGitHub(args)
		if err != nil {
			return nil, err
		}
	}
	if c.settings.ExpectedLogin != "" {
		if _, err := c.Identity(ctx); err != nil {
			return nil, err
		}
	}
	return c.run(ctx, args)
}

func (c *Context) run(ctx context.Context, args []string) ([]byte, error) {
	out, stderr, err := c.execute(ctx, c.path, append([]string(nil), args...), append([]string(nil), c.environment...))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		message := strings.ToLower(string(stderr) + " " + string(out))
		switch {
		case strings.Contains(message, "rate limit"), strings.Contains(message, "secondary rate"):
			return []byte(ErrRateLimit.Error()), ErrRateLimit
		case strings.Contains(message, "403"), strings.Contains(message, "404"), strings.Contains(message, "not found"), strings.Contains(message, "not enabled"), strings.Contains(message, "dependabot alerts are disabled"):
			return []byte(ErrAccess.Error()), ErrAccess
		default:
			return nil, ErrCommand
		}
	}
	for _, secret := range c.secrets {
		out = bytes.ReplaceAll(out, []byte(secret), []byte("[REDACTED]"))
	}
	return out, nil
}

func executeCommand(ctx context.Context, path string, args, environment []string, isolated bool) ([]byte, []byte, error) {
	var dir string
	if isolated {
		var err error
		dir, err = os.MkdirTemp("", "devsecops-gh-")
		if err != nil {
			return nil, nil, ErrCommand
		}
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				// Cleanup failure must not turn a successful remote mutation into a
				// retryable command failure. Do not log paths or external error text.
				slog.Warn("GitHub temporary configuration cleanup failed")
			}
		}()
		environment = append(environment, "GH_CONFIG_DIR="+dir)
		// Release downloads retain their destination when the command runs outside
		// the caller's repository, preventing cwd-based host/config inference.
		for i, arg := range args {
			if arg == "--dir" && i+1 < len(args) {
				args[i+1], err = filepath.Abs(args[i+1])
				if err != nil {
					return nil, nil, ErrCommand
				}
			}
		}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = environment
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
