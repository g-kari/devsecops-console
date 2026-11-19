package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/evaluator"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/setup"
	"github.com/g-kari/dependabot-alert-notice/internal/slack"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/tui"
	"github.com/g-kari/dependabot-alert-notice/internal/updater"
	"github.com/g-kari/dependabot-alert-notice/internal/web"
)

var version = "dev"

func main() {
	if err := runAndRestart(runApplication, restartProcess, os.Args, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runApplication() string {
	cleanupPreviousBinary()
	configPath := flag.String("config", "config.yaml", "設定ファイルパス")
	interactiveSetup := flag.Bool("setup", false, "ブラウザなしの対話型設定を実行して終了")
	terminalUI := flag.Bool("tui", false, "稼働中アプリに接続し、状態・設定をターミナルで操作")
	terminalURL := flag.String("tui-url", "", "TUIのローカル接続先URL（省略時は--configのWeb設定）")
	once := flag.Bool("once", false, "1回だけ実行して終了")
	logLevel := flag.String("log-level", "", "ログレベル (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "バージョン表示")
	showWebURL := flag.Bool("web-url", false, "設定のWeb UI URLを表示して終了（通信・DB作成なし）")
	checkUpdate := flag.Bool("check-update", false, "公開済み安定版Releaseの更新確認だけを行って終了")
	applyUpdate := flag.Bool("update", false, "新しい安定版Releaseへ更新して終了（Mac/Linux/Windows、次回起動から適用）")
	updateRepo := flag.String("update-repo", "g-kari/dependabot-alert-notice", "更新元GitHubリポジトリ (owner/repo)")
	updateGHPath := flag.String("update-gh-path", "", "Release取得用GitHub CLIパス（省略時: 設定のgh_path）")
	autoUpdate := flag.Bool("auto-update", os.Getenv("SECURITY_NOTICE_AUTO_UPDATE") != "0", "常駐中にReleaseを定期確認し更新後に自動再起動（Mac/Linux/Windowsのリリース版）")
	updateInterval := flag.Duration("update-interval", 6*time.Hour, "常駐中のRelease更新確認間隔")
	flag.Parse()

	if *interactiveSetup {
		if *terminalUI || *once || *showVersion || *showWebURL || *checkUpdate || *applyUpdate {
			slog.Error("--setupは--tui、--once、--version、--web-url、--check-update、--updateと同時に指定できません")
			os.Exit(1)
		}
		if err := setup.Run(*configPath, os.Stdin, os.Stdout); err != nil {
			slog.Error("対話型セットアップ失敗", "error", err)
			os.Exit(1)
		}
		return ""
	}

	if *terminalUI {
		if *once || *showVersion || *showWebURL || *checkUpdate || *applyUpdate {
			slog.Error("--tuiは--once、--version、--web-url、--check-update、--updateと同時に指定できません")
			os.Exit(1)
		}
		base := *terminalURL
		if base == "" {
			cfg, err := config.Load(*configPath)
			if errors.Is(err, os.ErrNotExist) {
				cfg = config.Defaults()
			} else if err != nil {
				slog.Error("TUI用設定読み込み失敗", "error", err)
				os.Exit(1)
			}
			base = cfg.Web.BrowserURL()
		}
		if err := tui.Run(context.Background(), base, os.Stdin, os.Stdout); err != nil {
			slog.Error("TUI終了", "error", err)
			os.Exit(1)
		}
		return ""
	}
	if *terminalURL != "" {
		slog.Error("--tui-urlは--tuiと併せて指定してください")
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("dependabot-alert-notice %s\n", version)
		os.Exit(0)
	}
	if *checkUpdate || *applyUpdate {
		if *checkUpdate && *applyUpdate {
			slog.Error("--check-updateと--updateは同時に指定できません")
			os.Exit(1)
		}
		executable, err := os.Executable()
		if err != nil {
			slog.Error("実行ファイル取得失敗", "error", err)
			os.Exit(1)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		updateConfig, err := loadUpdateConfig(*configPath, !flagWasSet("config"))
		if err != nil {
			slog.Error("更新用設定読み込み失敗", "error", err)
			os.Exit(1)
		}
		source, err := releaseSource(*updateRepo, *updateGHPath, *updateConfig)
		if err != nil {
			slog.Error("更新用GitHub認証設定失敗", "error", err)
			os.Exit(1)
		}
		warnInheritedGitHub(updateConfig.GitHubAuth)
		u := updater.Updater{
			Source:  source,
			Current: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Executable: executable,
		}
		if err := runReleaseUpdate(ctx, u, *applyUpdate, os.Stdout); err != nil {
			slog.Error("Release更新失敗", "error", err)
			os.Exit(1)
		}
		return ""
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("設定読み込み失敗", "error", err)
		os.Exit(1)
	}
	if *showWebURL {
		fmt.Println(cfg.Web.BrowserURL())
		return ""
	}
	if *autoUpdate && *updateInterval <= 0 {
		slog.Error("--update-intervalは正数で指定してください")
		os.Exit(1)
	}

	// ログレベル設定
	level := cfg.LogLevel
	if *logLevel != "" {
		level = *logLevel
	}
	setupLogger(level)
	warnInheritedGitHub(cfg.GitHubAuth)

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	dataPath := cfg.DataPath
	s, err := store.NewWithPath(dataPath)
	if err != nil {
		slog.Error("ストア初期化失敗", "path", dataPath, "error", err)
		os.Exit(1)
	}
	defer func() { _ = s.Close() }()

	// ストア初期化後にslogハンドラを差し替えてWebUIログにも出力
	slog.SetDefault(slog.New(store.NewStoreLogHandler(slog.Default().Handler(), s)))

	ghClient := github.New(cfg)
	initialEvaluatorConfig := *cfg
	eval := evaluator.NewSwitcher(evaluator.New(&initialEvaluatorConfig))
	m := merger.New(cfg, s, ghClient)

	// Slack Socket Mode起動（トークンが設定されている場合のみ）
	var slackClient *slack.SlackClient
	if cfg.Slack.BotToken != "" && cfg.Slack.AppToken != "" {
		slackClient = slack.New(cfg, s, m)
	} else {
		slog.Warn("Slackトークン未設定のためSocket Mode無効")
	}

	// Discord Webhookクライアント初期化（webhook_urlが設定されている場合のみ）
	var discordClient *discord.Client
	if cfg.Discord.WebhookURL != "" {
		discordClient = discord.New(cfg.Discord.WebhookURL)
		slog.Info("Discord通知有効")
	} else {
		slog.Warn("Discord Webhook URL未設定のためDiscord通知無効")
	}

	// JobQueue起動
	q := queue.New(100, 2)

	// WebUIサーバー起動
	webSrv := web.New(cfg, *configPath, s, m)
	notificationSettingsChanged := make(chan struct{}, 1)
	webSrv.SetEvaluatorConfigChanged(func(next config.Config) {
		eval.Set(evaluator.New(&next))
		select {
		case notificationSettingsChanged <- struct{}{}:
		default:
		}
	})
	if slackClient != nil {
		slackClient.SetConfigSource(webSrv.ConfigurationSnapshot)
		slackClient.RefreshApprovalButtons()
	}
	if discordClient != nil {
		discordClient.ConfigureGrouping(s, webSrv.ConfigurationSnapshot)
	}
	webSrv.SetQueue(q)
	guard := webSrv.RepositoryPolicy()
	q.Register(queue.JobFetchAlerts, makeFetchHandler(cfg, ghClient, s, q, slackClient, discordClient, guard))
	q.Register(queue.JobEvaluateAlert, makeEvaluateHandler(cfg, eval, s, slackClient, discordClient, guard))
	q.Start(ctx)
	webSrv.SetPollFn(func() {
		enqueueFetchAll(cfg, q, guard)
	})
	services := []func(context.Context){
		webSrv.RunFeedScheduler,
		webSrv.RunThreatScheduler,
		func(ctx context.Context) {
			if err := webSrv.RunRiskScheduler(ctx); err != nil {
				slog.Error("緊急度ワーカー停止", "error", err)
			}
		},
		func(ctx context.Context) {
			if err := webSrv.Start(ctx); err != nil {
				slog.Error("WebUIサーバー停止", "error", err)
			}
		},
	}
	if slackClient != nil {
		services = append(services, slackClient.Start)
	}
	if slackClient != nil || discordClient != nil {
		services = append(services, func(ctx context.Context) { runNotificationScheduler(ctx, slackClient, discordClient, guard) })
		services = append(services, func(ctx context.Context) {
			refresh := func() {
				if slackClient != nil {
					slackClient.RefreshApprovalButtons()
				}
				seen := map[string]bool{}
				for _, record := range s.List() {
					owner, repo := record.Alert.Owner, record.Alert.Repo
					key := strings.ToLower(owner + "/" + repo)
					if seen[key] {
						continue
					}
					seen[key] = true
					if err := guard.WithAllowed(ctx, owner, repo, func(config.Snapshot) error {
						refreshRepositoryNotifications(slackClient, discordClient, owner, repo)
						return nil
					}); err != nil && !errors.Is(err, policy.ErrNotMonitored) {
						slog.Error("通知設定反映失敗", "error", err)
					}
				}
			}
			refresh()
			for {
				select {
				case <-ctx.Done():
					return
				case <-notificationSettingsChanged:
					refresh()
				}
			}
		})
	}
	restartRequests := make(chan string, 1)
	u := updater.Updater{Current: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if *autoUpdate && !*once && u.SupportsAutomaticUpdates() {
		executable, err := os.Executable()
		if err != nil {
			slog.Warn("定期Release更新無効、実行ファイル取得失敗", "error", err)
		} else {
			u.Executable = executable
			services = append(services, func(ctx context.Context) {
				apply := func(attempt context.Context) (updater.Result, error) {
					snapshot, err := guard.Snapshot()
					if err != nil {
						return updater.Result{}, fmt.Errorf("更新用設定取得: %w", err)
					}
					source, err := releaseSource(*updateRepo, *updateGHPath, snapshot.Config)
					if err != nil {
						return updater.Result{}, fmt.Errorf("更新用GitHub認証設定: %w", err)
					}
					u.Source = source
					return u.Apply(attempt)
				}
				result, err := updater.Schedule(ctx, *updateInterval, 2*time.Minute, apply)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						slog.Warn("定期Release更新停止", "error", err)
					}
					return
				}
				slog.Info("Release更新完了、終了処理後に再起動", "current", result.Current, "latest", result.Latest)
				restartRequests <- executable
				cancel()
			})
			slog.Info("定期Release更新有効", "interval", *updateInterval, "repository", *updateRepo)
		}
	}
	waitSchedulers := startManagedSchedulers(ctx, *once, services...)
	// Stop new services before closing the store, including normal --once exit.
	defer func() { cancel(); waitSchedulers() }()

	// ポーリングループ
	if *once {
		// --once: inputs and queued evaluations finish before persisted scoring.
		if err := runOnceSteps(ctx,
			func(ctx context.Context) error {
				if cfg.RSS.Enabled {
					return webSrv.RefreshFeeds(ctx)
				}
				return nil
			},
			func(ctx context.Context) error {
				if cfg.Threat.Enabled {
					return webSrv.RefreshThreats(ctx)
				}
				return nil
			},
			func(ctx context.Context) error { enqueueFetchAll(cfg, q); q.Wait(); return ctx.Err() },
			webSrv.RecalculateRisks,
			func(ctx context.Context) error {
				return flushNotificationBatches(ctx, time.Now(), slackClient, discordClient, guard)
			},
		); err != nil {
			slog.Warn("一回実行の一部処理に失敗", "error", err)
		}
		q.Stop()
	} else {
		pollLoop(ctx, cfg, q, guard)
		q.Stop()
	}
	cancel()
	waitSchedulers()
	select {
	case executable := <-restartRequests:
		if signalCtx.Err() == nil {
			return executable
		}
	default:
	}
	return ""
}

// enqueueFetchAll は全ターゲットのFetchAlertsジョブをキューに積む
func enqueueFetchAll(cfg *config.Config, q *queue.Queue, guards ...*policy.Guard) {
	if len(guards) > 0 && guards[0] != nil {
		snapshot, err := guards[0].Snapshot()
		if err != nil {
			slog.Error("取得設定読み込み失敗", "error", err)
			return
		}
		cfg = &snapshot.Config
	}
	slog.Info("FetchAlertsジョブ投入", "targets", len(cfg.Targets))
	for _, target := range cfg.Targets {
		q.Enqueue(queue.Job{
			Type:    queue.JobFetchAlerts,
			Payload: target,
		})
	}
}

// makeFetchHandler はFetchAlertsジョブのハンドラを返す
func makeFetchHandler(cfg *config.Config, ghClient github.Client, s *store.Store, q *queue.Queue, slackClient *slack.SlackClient, discordClient *discord.Client, guards ...*policy.Guard) queue.Handler {
	guard := jobPolicy(cfg, guards)
	return func(ctx context.Context, job queue.Job) (handlerErr error) {
		snapshot, err := guard.Snapshot()
		if err != nil {
			return fmt.Errorf("取得ジョブ設定取得失敗: %w", err)
		}
		cfg := &snapshot.Config
		target, ok := job.Payload.(config.Target)
		if !ok {
			return fmt.Errorf("FetchAlertsペイロード型エラー")
		}
		if target.Repo != "" && !policy.IsMonitored(cfg.Targets, target.Owner, target.Repo) {
			slog.Info("監視対象外リポジトリをスキップ", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo))
			return nil
		}
		if target.Repo == "" {
			found := false
			for _, configured := range cfg.Targets {
				if strings.EqualFold(configured.Owner, target.Owner) && configured.Repo == "" {
					target = configured
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		} else {
			target.Excludes = nil
		}

		slog.Info("FetchAlerts開始", "owner", target.Owner, "repo", target.Repo)
		var alerts []model.Alert
		var completeRepos []string
		var skippedRepos []string
		resultAware := false
		client := ghClient
		if configurable, ok := client.(github.ConfigClient); ok {
			client, err = configurable.WithConfig(*cfg)
			if err != nil {
				return err
			}
		}
		scope := target.Owner
		if target.Repo != "" {
			scope += "/" + target.Repo
		}
		run, err := s.StartIngestRun(ctx, "dependabot", scope, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("ingest run開始失敗: %w", err)
		}
		ingestResult, ingestCoverage, ingestCode := model.IngestResultFailed, model.IngestCoverageUnknown, "fetch_failed"
		defer func() {
			if handlerErr != nil && ingestResult != model.IngestResultFailed {
				ingestResult, ingestCoverage, ingestCode = model.IngestResultFailed, model.IngestCoveragePartial, "processing_failed"
			}
			// Cancellation of collection must not leave its ledger running. Bound
			// this independent write so shutdown cannot wait indefinitely either.
			finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := s.FinishIngestRun(finishCtx, run.ID, ingestResult, ingestCoverage, ingestCode, time.Now().UTC()); err != nil {
				handlerErr = errors.Join(handlerErr, fmt.Errorf("ingest run終了失敗: %w", err))
			}
		}()
		if rich, ok := client.(github.ResultClient); ok {
			resultAware = true
			result, fetchErr := rich.FetchAlertsResult(ctx, target)
			alerts, completeRepos, skippedRepos, err = result.Alerts, result.CompleteRepos, result.SkippedRepos, fetchErr
		} else {
			alerts, err = client.FetchAlerts(ctx, target)
		}
		if err != nil {
			var rateLimitErr *github.RateLimitError
			if errors.As(err, &rateLimitErr) {
				ingestCode = "rate_limited"
				slog.Warn("GitHub APIレート制限スキップ",
					"remaining", rateLimitErr.Remaining,
					"resetAt", rateLimitErr.ResetAt.Format("15:04:05"))
				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "warn",
					Message: fmt.Sprintf("GitHub APIレート制限のためスキップ（残り %d、リセット: %s）",
						rateLimitErr.Remaining, rateLimitErr.ResetAt.Format("15:04:05")),
				})
				return nil
			}
			var skipErr *github.SkipError
			if errors.As(err, &skipErr) {
				ingestCode = "source_skipped"
				slog.Warn("Dependabotアラートスキップ", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo))
				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "warn",
					Message:   fmt.Sprintf("Dependabotアラートスキップ (%s/%s): 未有効または権限なし", target.Owner, target.Repo),
				})
				return nil
			}
			if errors.Is(err, context.Canceled) {
				ingestCode = "canceled"
			} else if errors.Is(err, context.DeadlineExceeded) {
				ingestCode = "deadline_exceeded"
			}
			slog.Error("アラート取得失敗", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "error", err)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("アラート取得失敗 (%s/%s): %v", target.Owner, target.Repo, err),
			})
			return fmt.Errorf("FetchAlerts: %w", err)
		}

		ingestResult, ingestCoverage, ingestCode = model.IngestResultPartial, model.IngestCoveragePartial, "incomplete_coverage"
		switch {
		case !resultAware:
			ingestCoverage, ingestCode = model.IngestCoverageUnknown, "coverage_unknown"
		case cfg.FetchMinSeverity != "" && !strings.EqualFold(cfg.FetchMinSeverity, "low"):
			ingestCode = "filtered_scope"
		case len(skippedRepos) > 0:
			ingestCode = "scope_skipped"
		case target.Repo != "":
			for _, repo := range completeRepos {
				if strings.EqualFold(repo, scope) {
					ingestResult, ingestCoverage, ingestCode = model.IngestResultSuccess, model.IngestCoverageFull, ""
					break
				}
			}
		}
		// CompleteRepos proves only individual repositories, not an exhaustive
		// owner-wide inventory. Owner-scoped collection remains partial.
		markPolicyChanged := func() {
			ingestResult, ingestCoverage, ingestCode = model.IngestResultPartial, model.IngestCoveragePartial, "policy_changed"
		}

		newCount := 0
		for _, alert := range alerts {
			if !strings.EqualFold(alert.Owner, target.Owner) || (target.Repo != "" && !strings.EqualFold(alert.Repo, target.Repo)) {
				continue
			}
			err := guard.WithAllowed(ctx, alert.Owner, alert.Repo, func(current config.Snapshot) error {
				if err := s.ObserveDependabot(ctx, alert, run.ID, time.Now().UTC()); err != nil {
					return fmt.Errorf("dependabot観測保存失敗: %w", err)
				}
				cfg := &current.Config
				if s.HasByKey(alert.Owner, alert.Repo, alert.Number) {
					// 既存レコードでも、今回のポーリングでメタデータが取得できた場合のみ更新する。
					// 取得失敗（空/nil）の場合はスキップし、以前の良いデータを上書きしない。
					if alert.DefaultBranch != "" || len(alert.Contributors) > 0 || alert.Homepage != "" {
						if err := s.UpdateAlertJSON(alert.Owner, alert.Repo, alert.Number, alert); err != nil {
							return fmt.Errorf("取得済みアラートmetadata更新失敗: %w", err)
						}
					}
					existing, err := s.GetByKey(alert.Owner, alert.Repo, alert.Number)
					if err != nil {
						return err
					}
					notifyPendingRecord(cfg, s, slackClient, discordClient, existing)
					return nil
				}
				record := &model.AlertRecord{
					Alert:      alert,
					State:      model.AlertStatePending,
					EvalStatus: model.EvalStatusPending,
					NotifiedAt: time.Now(),
				}
				isNew, err := s.SaveObservedWithError(ctx, record)
				if err != nil {
					return fmt.Errorf("取得済みアラート保存失敗: %w", err)
				}
				if !isNew {
					// 既存レコードの更新（別ターゲットから重複取得など）はスキップ
					return nil
				}
				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "info",
					Message:   fmt.Sprintf("新規アラート: %s (%s) in %s/%s", alert.PackageName, alert.Severity, alert.Owner, alert.Repo),
					AlertID:   record.Alert.ID,
				})

				// 重要度フィルタを満たす場合は即通知
				if cfg.ShouldNotify(string(alert.Severity)) {
					if slackClient != nil {
						if ts, err := slackClient.Notify(record); err != nil {
							slog.Error("Slack通知失敗（新規アラート）", "alertID", record.Alert.ID, "error", err)
						} else if ts != "" {
							record.SlackMessageTS = ts
							if err := s.UpdateSlackMessageTS(record.Alert.ID, ts); err != nil {
								slog.Error("SlackMessageTS保存失敗", "alertID", record.Alert.ID, "error", err)
							}
						}
					}
					if discordClient != nil {
						if msgID, err := discordClient.Notify(record); err != nil {
							slog.Error("Discord通知失敗（新規アラート）", "alertID", record.Alert.ID, "error", err)
						} else if msgID != "" {
							record.DiscordMessageID = msgID
							if err := s.UpdateDiscordMessageID(record.Alert.ID, msgID); err != nil {
								slog.Error("DiscordMessageID保存失敗", "alertID", record.Alert.ID, "error", err)
							}
						}
					}
				}

				newCount++
				return nil
			})
			if errors.Is(err, policy.ErrNotMonitored) {
				markPolicyChanged()
			}
			if err != nil && !errors.Is(err, policy.ErrNotMonitored) {
				return fmt.Errorf("アラート保存/通知失敗: %w", err)
			}
		}
		slog.Info("新規アラート登録", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "new", newCount, "total", len(alerts))

		// AI自動評価が有効な場合のみ pending/failed をEvaluateJobとして積む
		if cfg.Evaluator.AutoEval {
			maxEval := cfg.Evaluator.MaxEvalPerPoll
			if maxEval <= 0 {
				maxEval = 10
			}
			current, err := guard.Snapshot()
			if err != nil {
				return err
			}
			pending, err := s.ListPendingForTarget(ctx, current.Config, target, maxEval)
			if err != nil {
				return err
			}
			for _, record := range pending {
				// このターゲットに属するアラートのみ評価（別ターゲットの混入を防ぐ）
				if record.Alert.Owner != target.Owner {
					continue
				}
				if target.Repo != "" && record.Alert.Repo != target.Repo {
					continue
				}
				if !cfg.Evaluator.ShouldEvaluate(string(record.Alert.Severity)) {
					continue
				}
				err := guard.WithAllowed(ctx, record.Alert.Owner, record.Alert.Repo, func(current config.Snapshot) error {
					if !current.Config.Evaluator.AutoEval || !current.Config.Evaluator.ShouldEvaluate(string(record.Alert.Severity)) {
						return nil
					}
					// evaluating にセットしてから積む（別ターゲットの fetch ジョブが二重エンキューするのを防ぐ）
					claimed, err := s.ClaimEvaluation(ctx, record.Alert.ID, false)
					if err != nil {
						slog.Error("eval_status更新失敗（エンキュー前）", "alertID", record.Alert.ID, "error", err)
						return err
					}
					if !claimed {
						return nil
					}
					if !q.TryEnqueue(queue.Job{
						Type:    queue.JobEvaluateAlert,
						Payload: queue.EvaluationRequest{AlertID: record.Alert.ID},
					}) {
						return s.UpdateEvalStatus(record.Alert.ID, model.EvalStatusPending)
					}
					return nil
				})
				if errors.Is(err, policy.ErrNotMonitored) {
					markPolicyChanged()
				}
				if err != nil && !errors.Is(err, policy.ErrNotMonitored) {
					return err
				}
			}
		}

		// 重要度フィルタを使った取得は全件取得ではないため、欠落を解決済みと推定しない。
		if !resultAware || len(completeRepos) == 0 || len(skippedRepos) > 0 || (cfg.FetchMinSeverity != "" && !strings.EqualFold(cfg.FetchMinSeverity, "low")) {
			return nil
		}
		// 対応済みアラートのクリーンアップ: fetch 結果に含まれないものは GitHub 側で close 済み
		openByRepo := make(map[string][]int) // "owner/repo" → [numbers]
		for _, alert := range alerts {
			key := alert.Owner + "/" + alert.Repo
			openByRepo[key] = append(openByRepo[key], alert.Number)
		}
		// target.Repo 指定時は空結果でもそのリポをクリーンアップ対象に含める
		if target.Repo != "" {
			key := target.Owner + "/" + target.Repo
			if _, ok := openByRepo[key]; !ok {
				openByRepo[key] = nil
			}
		} else {
			// org レベルターゲット: DB に存在するすべてのリポを対象に含める（全解決済みリポの漏れ防止）
			for _, repo := range s.ListReposByOwner(target.Owner) {
				key := target.Owner + "/" + repo
				if _, ok := openByRepo[key]; !ok {
					openByRepo[key] = nil
				}
			}
		}
		slog.Debug("クリーンアップ対象リポ", "count", len(openByRepo))
		for key, numbers := range openByRepo {
			parts := strings.SplitN(key, "/", 2)
			if len(parts) != 2 {
				continue
			}
			if !strings.EqualFold(parts[0], target.Owner) || (target.Repo != "" && !strings.EqualFold(parts[1], target.Repo)) {
				continue
			}
			if resultAware {
				complete := false
				for _, candidate := range completeRepos {
					if strings.EqualFold(candidate, key) {
						complete = true
						break
					}
				}
				if !complete {
					continue
				}
			}
			err := guard.WithAllowed(ctx, parts[0], parts[1], func(config.Snapshot) error {
				removed, err := s.ResolveMissingAlerts(ctx, parts[0], parts[1], numbers, time.Now().UTC())
				if err != nil {
					return fmt.Errorf("解決済みアラート保存失敗 (%s): %w", key, err)
				}
				for _, rec := range removed {
					slog.Info("対応済みアラートを履歴として保持", "id", rec.Alert.ID, "package", rec.Alert.PackageName, "repo", key)
					s.AddLog(model.LogEntry{
						Timestamp: time.Now(),
						Level:     "info",
						Message:   fmt.Sprintf("対応済みアラートを履歴として保持: %s in %s（GitHub側で解決済み）", rec.Alert.PackageName, key),
						AlertID:   rec.Alert.ID,
					})
					// Slack通知更新
					if slackClient != nil && rec.SlackMessageTS != "" {
						if err := slackClient.NotifyResolved(rec); err != nil {
							slog.Error("Slack対応済み通知失敗", "alertID", rec.Alert.ID, "error", err)
						}
					}
					// Discord通知更新
					if discordClient != nil && rec.DiscordMessageID != "" {
						if err := discordClient.NotifyResolved(rec); err != nil {
							slog.Error("Discord対応済み通知失敗", "alertID", rec.Alert.ID, "error", err)
						}
					}
				}
				refreshRepositoryNotifications(slackClient, discordClient, parts[0], parts[1])
				return nil
			})
			if errors.Is(err, policy.ErrNotMonitored) {
				markPolicyChanged()
			}
			if err != nil && !errors.Is(err, policy.ErrNotMonitored) {
				return err
			}
		}

		return nil
	}
}

// makeEvaluateHandler はEvaluateAlertジョブのハンドラを返す
func makeEvaluateHandler(cfg *config.Config, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient, discordClient *discord.Client, guards ...*policy.Guard) queue.Handler {
	guard := jobPolicy(cfg, guards)
	return func(ctx context.Context, job queue.Job) error {
		request, ok := job.Payload.(queue.EvaluationRequest)
		if legacyID, legacy := job.Payload.(int); legacy {
			request, ok = queue.EvaluationRequest{AlertID: legacyID}, true
		}
		if !ok || request.AlertID <= 0 {
			return fmt.Errorf("EvaluateAlertペイロード型エラー")
		}
		alertID := request.AlertID
		for attempt := 0; attempt < 3; attempt++ {
			if err := ctx.Err(); err != nil {
				return evaluationFailed(s, alertID, err)
			}

			record, err := s.Get(alertID)
			if err != nil {
				return fmt.Errorf("アラート取得失敗 (id=%d): %w", alertID, err)
			}
			if record.ResolvedAt != nil {
				slog.Info("解決済みのためAI評価をスキップ", "alertID", alertID)
				return nil
			}

			err = guard.WithAllowed(ctx, record.Alert.Owner, record.Alert.Repo, func(config.Snapshot) error { return s.UpdateEvalStatus(alertID, model.EvalStatusEvaluating) })
			if errors.Is(err, policy.ErrNotMonitored) {
				if record.EvalStatus == model.EvalStatusEvaluating {
					return s.UpdateEvalStatus(alertID, model.EvalStatusPending)
				}
				return nil
			}
			if err != nil {
				return err
			}

			alert := record.Alert
			slog.Info("AI評価中", "id", alert.ID, "package", alert.PackageName, "severity", alert.Severity)

			bound := evaluator.Capture(eval, alert)
			evaluation, err := evaluateResult(ctx, bound, s, alert, request.Force)
			if err != nil {
				if currentErr := bound.WithCurrent(func() error { return nil }); errors.Is(currentErr, evaluator.ErrEvaluatorChanged) {
					continue
				}
				return evaluationFailed(s, alertID, err)
			}

			err = guard.WithAllowed(ctx, alert.Owner, alert.Repo, func(current config.Snapshot) error {
				cfg := &current.Config
				var written bool
				err := bound.WithCurrent(func() error {
					var saveErr error
					written, saveErr = s.SaveEvaluationIfCurrent(ctx, record, evaluation)
					return saveErr
				})
				if err != nil {
					return err
				}
				if !written {
					slog.Info("評価中に解決済みとなったため結果・通知を破棄", "alertID", alertID)
					return nil
				}
				// 再評価中の承認・通知先更新などを古いrecordで上書きしない。
				record, err = s.Get(alertID)
				if err != nil {
					return fmt.Errorf("AI評価通知前のレコード取得失敗: %w", err)
				}

				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "info",
					Message:   fmt.Sprintf("AI評価完了 (#%d %s/%s): %s → %s", alert.ID, alert.Owner, alert.Repo, alert.PackageName, evaluation.Recommendation),
					AlertID:   alert.ID,
				})

				// 重要度フィルタ
				if !cfg.ShouldNotify(string(alert.Severity)) {
					slog.Debug("通知スキップ（重要度フィルタ）", "alertID", alert.ID, "severity", alert.Severity, "minSeverity", cfg.NotifyMinSeverity)
					return nil
				}

				// Slack: 既存メッセージがあれば編集、なければ新規送信
				if slackClient != nil {
					if record.SlackMessageTS != "" {
						if err := slackClient.UpdateEvalMessage(record); err != nil {
							slog.Error("SlackメッセージAI評価更新失敗", "alertID", alert.ID, "error", err)
						}
					} else {
						if ts, err := slackClient.Notify(record); err != nil {
							slog.Error("Slack通知失敗（AI評価完了）", "alertID", alert.ID, "error", err)
						} else if ts != "" {
							if err := s.UpdateSlackMessageTS(alert.ID, ts); err != nil {
								slog.Error("SlackMessageTS保存失敗（AI評価後）", "alertID", alert.ID, "error", err)
							}
						}
					}
				}

				// Discord: 既存メッセージがあれば編集、なければ新規投稿
				if discordClient != nil {
					if record.DiscordMessageID != "" {
						if err := discordClient.UpdateEvalMessage(record); err != nil {
							slog.Error("Discordメッセージ更新失敗（AI評価完了）", "alertID", alert.ID, "error", err)
						}
					} else {
						if msgID, err := discordClient.Notify(record); err != nil {
							slog.Error("Discord通知失敗（AI評価完了）", "alertID", alert.ID, "error", err)
						} else if msgID != "" {
							if err := s.UpdateDiscordMessageID(alert.ID, msgID); err != nil {
								slog.Error("DiscordMessageID保存失敗（AI評価後）", "alertID", alert.ID, "error", err)
							}
						}
					}
				}

				return nil
			})
			if errors.Is(err, policy.ErrNotMonitored) {
				return s.UpdateEvalStatus(alertID, model.EvalStatusPending)
			}
			if errors.Is(err, evaluator.ErrEvaluatorChanged) || errors.Is(err, store.ErrEvaluationInputsChanged) {
				slog.Info("AI評価の古い結果を破棄して再試行", "alertID", alertID, "attempt", attempt+1, "error", err)
				continue
			}
			if err != nil {
				return evaluationFailed(s, alertID, err)
			}
			return err
		}
		if err := s.UpdateEvalStatus(alertID, model.EvalStatusPending); err != nil {
			return err
		}
		return fmt.Errorf("AI評価の設定・入力が繰り返し変更されたため中断しました。再評価してください (id=%d)", alertID)
	}
}

func setupLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

func pollLoop(ctx context.Context, cfg *config.Config, q *queue.Queue, guards ...*policy.Guard) {
	if len(guards) > 0 && guards[0] != nil {
		snapshot, err := guards[0].Snapshot()
		if err != nil {
			slog.Error("ポーリング設定取得失敗", "error", err)
			return
		}
		cfg = &snapshot.Config
	}
	slog.Info("ポーリング開始", "interval", cfg.PollInterval)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("シャットダウン")
			return
		case <-ticker.C:
			slog.Debug("ポーリング実行", "interval", cfg.PollInterval)
			enqueueFetchAll(cfg, q, guards...)
		}
	}
}
