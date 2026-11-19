package ghcommand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExplicitContextFreezesEnvironmentAndPinsGitHub(t *testing.T) {
	env := []string{"PATH=/fixture/bin", "HOME=/fixture/home", "APP_GITHUB_TOKEN=fixture-token-a", "GH_TOKEN=other-token", "GITHUB_TOKEN=other-token-2", "gh_host=other.invalid", "GH_CONFIG_DIR=/other", "GH_DEBUG=api", "DEBUG=1", "SLACK_BOT_TOKEN=slack-fixture"}
	c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_GITHUB_TOKEN"}, env)
	if err != nil {
		t.Fatal(err)
	}
	env[2] = "APP_GITHUB_TOKEN=changed"
	c.execute = func(_ context.Context, path string, args, child []string) ([]byte, []byte, error) {
		joined := strings.Join(child, "\n")
		for _, forbidden := range []string{"other-token", "other.invalid", "/other", "GH_DEBUG", "DEBUG=", "slack-fixture", "APP_GITHUB_TOKEN=", "changed"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("inherited forbidden entry %q", forbidden)
			}
		}
		if path != fixtureExecutable() || !contains(child, "GH_TOKEN=fixture-token-a") || !contains(child, "GH_HOST=github.com") || !contains(child, "GH_PROMPT_DISABLED=1") {
			t.Fatal("missing explicit execution context")
		}
		if !reflect.DeepEqual(args, []string{"api", "rate_limit", "--hostname", "github.com"}) {
			t.Fatalf("args=%q", args)
		}
		return []byte("fixture-token-a"), nil, nil
	}
	out, err := c.Output(context.Background(), "api", "rate_limit")
	if err != nil || string(out) != "[REDACTED]" {
		t.Fatalf("unexpected sanitized output, err=%v", err)
	}
	serialized, _ := json.Marshal(c)
	if strings.Contains(fmt.Sprintf("%+v %s", c, serialized), "fixture-token-a") {
		t.Fatal("context leaked a token")
	}
}

func TestExplicitContextRejectsMissingEmptyInvalidAndAmbiguousCredentials(t *testing.T) {
	for _, env := range [][]string{nil, {"APP_TOKEN="}, {"APP_TOKEN=has space"}, {"APP_TOKEN=bad\nvalue"}, {"APP_TOKEN=a", "app_token=b"}} {
		if _, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, env); err == nil {
			t.Fatal("expected credential validation failure")
		}
	}
	for _, settings := range []Settings{{Mode: "bad"}, {Mode: "token_env"}, {Mode: "token_env", TokenEnv: "BAD=NAME"}, {Mode: "token_env", TokenEnv: "APP_TOKEN", Host: "elsewhere.invalid"}, {Mode: "inherited", TokenEnv: "APP_TOKEN"}, {Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "bad/login"}} {
		if _, err := NewWithEnvironment(fixtureExecutable(), settings, []string{"APP_TOKEN=fixture"}); err == nil {
			t.Fatalf("expected validation failure for %+v", settings)
		}
	}
}

func TestExpectedLoginGuardsEveryOperationWithoutSwitchingAccounts(t *testing.T) {
	c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "Alice"}, []string{"APP_TOKEN=fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	c.execute = func(_ context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
		calls++
		if !reflect.DeepEqual(args, []string{"api", "user", "--hostname", "github.com", "--jq", ".login"}) {
			t.Fatal("unexpected command before identity confirmation")
		}
		return []byte("bob\n"), nil, nil
	}
	if _, err := c.Output(context.Background(), "pr", "merge", "1", "--repo", "org/repo"); !errors.Is(err, ErrIdentity) {
		t.Fatalf("err=%v", err)
	}
	if calls != 1 {
		t.Fatal("operation executed with the wrong principal")
	}
	c.execute = func(_ context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
		if args[0] == "api" {
			return []byte("alice\n"), nil, nil
		}
		if !contains(args, "github.com/org/repo") {
			t.Fatal("repository host not pinned")
		}
		return []byte("ok"), nil, nil
	}
	if _, err := c.Output(context.Background(), "pr", "merge", "1", "--repo", "org/repo"); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitContextRejectsHostAndCommandShapeOverridesBeforeExecution(t *testing.T) {
	for _, args := range [][]string{
		{"api", "https://other.invalid/user"}, {"api", "//other.invalid/user"}, {"api", "repos/org/repo/../../user"},
		{"api", "user", "--hostname", "other.invalid"}, {"api", "user", "-H", "Authorization: Bearer fixture"},
		{"api", "user", "--hostname=other.invalid"}, {"api", "user", "--input", "/secret"},
		{"pr", "merge", "https://other.invalid/org/repo/pull/1", "--repo", "org/repo"},
		{"pr", "merge", "1", "--repo", "other.invalid/org/repo"},
		{"pr", "merge", "1", "--repo", "org/repo", "-R", "other.invalid/org/repo"},
		{"pr", "merge", "1", "--repo", "org/repo", "--repo", "org/other"},
		{"pr", "merge", "1", "--repo=org/repo"}, {"pr", "create", "--repo", "org/repo"},
		{"repo", "list", "https://other.invalid/org"}, {"repo", "view", "../repo"},
		{"release", "upload", "v1", "--repo", "org/repo"}, {"extension", "exec", "anything"}, {"auth", "switch"},
	} {
		c, _ := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "alice"}, []string{"APP_TOKEN=fixture"})
		called := false
		c.execute = func(context.Context, string, []string, []string) ([]byte, []byte, error) {
			called = true
			return []byte("alice"), nil, nil
		}
		if _, err := c.Output(context.Background(), args...); err == nil {
			t.Errorf("accepted unsafe args %q", args)
		}
		if called {
			t.Errorf("executed a command for unsafe args %q", args)
		}
	}
}

func TestExplicitContextAllowsOnlyExistingCommandShapes(t *testing.T) {
	for _, args := range [][]string{
		{"api", "/repos/org/repo/dependabot/alerts?state=open&per_page=100&severity=critical,high", "--paginate"},
		{"api", "repos/org/repo/contributors?per_page=100"},
		{"api", "/orgs/org/dependabot/alerts?state=open", "--jq", "length"},
		{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery},
		{"pr", "list", "--repo", "org/repo", "--author", "app/dependabot", "--state", "open", "--json", "number,title", "--limit", "100"},
		{"repo", "view", "org/repo", "--json", "homepageUrl", "--jq", ".homepageUrl"},
		{"repo", "list", "org", "--json", "name", "--jq", ".[].name", "--limit", "1000"},
		{"release", "download", "v1", "--repo", "org/repo", "--pattern", "a.tar.gz", "--pattern", "checksums.txt", "--dir", "relative path"},
	} {
		if _, err := pinGitHub(args); err != nil {
			t.Errorf("existing shape %q rejected: %v", args, err)
		}
	}
}

func TestIdentityAndOperationUseSameFrozenEnvironment(t *testing.T) {
	env := []string{"APP_TOKEN=original-synthetic-token"}
	c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "alice"}, env)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.execute = func(_ context.Context, _ string, args, child []string) ([]byte, []byte, error) {
		calls++
		if !contains(child, "GH_TOKEN=original-synthetic-token") {
			t.Fatal("identity/operation environment changed")
		}
		if args[0] == "api" && args[1] == "user" {
			env[0] = "APP_TOKEN=changed-source"
			for i := range child {
				child[i] = "mutated-child"
			}
			return []byte("alice"), nil, nil
		}
		return []byte("ok"), nil, nil
	}
	if _, err := c.Output(context.Background(), "pr", "merge", "1", "--repo", "org/repo", "--squash", "--delete-branch", "--auto"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected identity and operation, calls=%d", calls)
	}
}

func TestExternalFailuresAreBoundedAndDoNotExposeSecrets(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		want   error
	}{{"fixture rate limit", ErrRateLimit}, {"fixture HTTP 403", ErrAccess}, {"fixture unknown problem", ErrCommand}} {
		c, _ := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, []string{"APP_TOKEN=fixture"})
		c.execute = func(context.Context, string, []string, []string) ([]byte, []byte, error) {
			return []byte("fixture"), []byte(tc.stderr), errors.New("fixture leaked error")
		}
		out, err := c.Output(context.Background(), "api", "rate_limit")
		if !errors.Is(err, tc.want) || strings.Contains(string(out)+err.Error(), "fixture") {
			t.Fatalf("unsafe or misclassified failure: %v", err)
		}
	}
}

func TestIdentityAndExpectedLoginPreflightPreserveContextCancellation(t *testing.T) {
	for _, operation := range []string{"explicit identity", "inherited identity", "expected login preflight"} {
		for _, failure := range []string{"canceled", "deadline"} {
			for _, phase := range []string{"before execution", "during execution"} {
				t.Run(operation+"/"+failure+"/"+phase, func(t *testing.T) {
					settings := Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}
					switch operation {
					case "inherited identity":
						settings = Settings{}
					case "expected login preflight":
						settings.ExpectedLogin = "alice"
					}
					c, err := NewWithEnvironment(fixtureExecutable(), settings, []string{"APP_TOKEN=synthetic-token"})
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					want := context.Canceled
					if failure == "deadline" {
						cancel()
						deadline := time.Now().Add(time.Second)
						if phase == "before execution" {
							deadline = time.Now().Add(-time.Second)
						}
						ctx, cancel = context.WithDeadline(context.Background(), deadline)
						want = context.DeadlineExceeded
					} else if phase == "before execution" {
						cancel()
					}
					defer cancel()
					calls := 0
					c.execute = func(callCtx context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
						calls++
						if len(args) < 2 || args[0] != "api" || args[1] != "user" {
							t.Fatalf("target operation executed after failed preflight: %q", args)
						}
						if failure == "canceled" {
							cancel()
						}
						<-callCtx.Done()
						return []byte("synthetic-token"), []byte("synthetic private failure"), errors.New("synthetic raw executor error")
					}
					var out []byte
					if operation == "expected login preflight" {
						out, err = c.Output(ctx, "pr", "merge", "7", "--repo", "org/repo")
					} else {
						var login string
						login, err = c.Identity(ctx)
						out = []byte(login)
					}
					wantCalls := 1
					if phase == "before execution" {
						wantCalls = 0
					}
					if !errors.Is(err, want) || errors.Is(err, ErrIdentity) || len(out) != 0 || calls != wantCalls {
						t.Fatalf("err=%v output=%q executions=%d; want %v, no output, %d executions", err, out, calls, want, wantCalls)
					}
					if strings.Contains(err.Error(), "synthetic") {
						t.Fatalf("raw executor output leaked in cancellation: %v", err)
					}
				})
			}
		}
	}
}

func TestIdentityFailuresRemainBounded(t *testing.T) {
	c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "alice"}, []string{"APP_TOKEN=synthetic-token"})
	if err != nil {
		t.Fatal(err)
	}
	c.execute = func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		return []byte("synthetic-token"), []byte("synthetic private failure"), errors.New("synthetic raw executor error")
	}
	login, err := c.Identity(context.Background())
	if !errors.Is(err, ErrIdentity) || login != "" || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("unbounded identity failure: login=%q err=%v", login, err)
	}
}

func TestParallelContextsRemainIndependent(t *testing.T) {
	var wg sync.WaitGroup
	for _, token := range []string{"fixture-a", "fixture-b"} {
		c, _ := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, []string{"APP_TOKEN=" + token})
		c.execute = func(_ context.Context, _ string, _ []string, env []string) ([]byte, []byte, error) {
			if !contains(env, "GH_TOKEN="+token) {
				t.Error("cross-context token")
			}
			env[0] = "mutated"
			return nil, nil, nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if _, err := c.Output(context.Background(), "api", "rate_limit"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestLegacyContextIsExplicitlyLabeledAndFreezesInheritedEnvironment(t *testing.T) {
	c, err := NewWithEnvironment(fixtureExecutable(), Settings{}, []string{"GH_TOKEN=legacy-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Description(), "inherited") {
		t.Fatal("legacy mode is not labeled")
	}
	c.execute = func(_ context.Context, _ string, args, env []string) ([]byte, []byte, error) {
		if !contains(env, "GH_TOKEN=legacy-fixture") || !reflect.DeepEqual(args, []string{"api", "rate_limit"}) {
			t.Fatal("legacy compatibility changed")
		}
		return []byte("legacy-fixture"), nil, nil
	}
	out, err := c.Output(context.Background(), "api", "rate_limit")
	if err != nil || string(out) != "[REDACTED]" {
		t.Fatal("legacy token was not redacted")
	}
	c.execute = func(_ context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
		if !reflect.DeepEqual(args, []string{"api", "user", "--jq", ".login"}) {
			t.Fatal("legacy host compatibility changed")
		}
		return []byte("alice"), nil, nil
	}
	if _, err := c.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func fixtureExecutable() string { return filepath.Join(os.TempDir(), "never-execute-gh-fixture") }
