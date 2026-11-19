package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/risk"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

type reportData struct {
	Items      []reportItem
	Feeds      []reportFeed
	Refreshing bool
	Error      string
	Days       int
	CSRFToken  string
	Page       int
	Total      int
	CVECount   int
	FeedFilter string
	CVEFilter  string
	RepoFilter string
	PrevURL    string
	NextURL    string
	RSSEnabled bool
}

type reportFeed struct {
	store.FeedStatus
	Name    string
	Enabled bool
}

type reportItem struct {
	Item   feed.Item
	Alerts []reportAlert
}

type reportAlert struct {
	Record *model.AlertRecord
	Score  model.ScoreResult
}

func (s *Server) handleVulnerabilityReport(w http.ResponseWriter, r *http.Request) {
	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	cfg := snapshot.Config
	days, page := 7, 1
	if n, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && n >= 1 && n <= 90 {
		days = n
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n >= 1 && n <= 1000000 {
		page = n
	}
	const pageSize = 25
	filter := store.ReportFilter{
		Days: days, Page: page, PageSize: pageSize,
		Feed: strings.TrimSpace(r.URL.Query().Get("feed")),
		CVE:  strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("cve"))),
		Repo: strings.TrimSpace(r.URL.Query().Get("repo")),
	}
	result, err := s.store.QueryReport(r.Context(), filter)
	if err != nil {
		slog.Error("レポート取得失敗", "error", err)
		http.Error(w, "レポート取得失敗", http.StatusInternalServerError)
		return
	}
	var cves []string
	for _, row := range result.Rows {
		cves = append(cves, row.Item.CVEIDs...)
	}
	records, err := s.store.ListReportAlerts(r.Context(), cves)
	if err != nil {
		slog.Error("レポート関連アラート取得失敗", "error", err)
		http.Error(w, "関連アラート取得失敗", http.StatusInternalServerError)
		return
	}
	records = filterByConfig(records, &cfg)
	if filter.Repo != "" {
		kept := records[:0]
		for _, rec := range records {
			if strings.EqualFold(rec.Alert.Owner+"/"+rec.Alert.Repo, filter.Repo) {
				kept = append(kept, rec)
			}
		}
		records = kept
	}
	var advisoryKeys []string
	for _, rec := range records {
		advisoryKeys = append(advisoryKeys, "cve:"+strings.ToUpper(rec.Alert.CVEID))
	}
	threats, err := s.store.ListThreatSnapshotsFor(r.Context(), advisoryKeys)
	if err != nil {
		slog.Error("レポート脅威情報取得失敗", "error", err)
		http.Error(w, "脅威情報取得失敗", http.StatusInternalServerError)
		return
	}
	byCVE := make(map[string][]*model.AlertRecord)
	for _, rec := range records {
		key := strings.ToUpper(rec.Alert.CVEID)
		byCVE[key] = append(byCVE[key], rec)
	}
	view := make([]reportItem, 0, len(result.Rows))
	scores := make(map[int]model.ScoreResult)
	for _, row := range result.Rows {
		item := row.Item
		if link, err := url.Parse(item.Link); err != nil || (link.Scheme != "http" && link.Scheme != "https") || link.Host == "" {
			item.Link = ""
		}
		var alerts []reportAlert
		seen := map[int]bool{}
		for _, cve := range item.CVEIDs {
			for _, rec := range byCVE[strings.ToUpper(cve)] {
				if seen[rec.Alert.ID] {
					continue
				}
				seen[rec.Alert.ID] = true
				score, ok := scores[rec.Alert.ID]
				if !ok {
					score = scoreAlertWithThreat(cfg.ServiceProfiles, cfg.Assessments, threats, rec)
					scores[rec.Alert.ID] = score
				}
				alerts = append(alerts, reportAlert{Record: rec, Score: score})
			}
		}
		view = append(view, reportItem{Item: item, Alerts: alerts})
	}
	statuses, err := s.store.ListFeedStatuses(r.Context())
	if err != nil {
		slog.Error("レポートフィード状態取得失敗", "error", err)
		http.Error(w, "フィード状態取得失敗", http.StatusInternalServerError)
		return
	}
	byURL := make(map[string]store.FeedStatus, len(statuses))
	for _, status := range statuses {
		byURL[status.FeedURL] = status
	}
	var feeds []reportFeed
	failed, attempted := 0, 0
	for _, configured := range cfg.RSS.Feeds {
		status := byURL[configured.URL]
		status.FeedURL = configured.URL
		feeds = append(feeds, reportFeed{Name: configured.Name, Enabled: configured.Enabled, FeedStatus: status})
		if configured.Enabled && status.LastAttemptAt != nil {
			attempted++
			if status.LastError != "" {
				failed++
			}
		}
	}
	warning := ""
	if failed > 0 {
		warning = "一部のフィードの取得に失敗しています。前回取得した記事は保持されています。"
		if failed == attempted {
			warning = "取得を試みた全フィードで失敗しています。前回取得した記事は保持されています。"
		}
	}
	s.feedMu.Lock()
	refreshing := s.feedRefreshing
	s.feedMu.Unlock()
	pageURL := func(n int) string {
		q := url.Values{"page": {strconv.Itoa(n)}, "days": {strconv.Itoa(days)}}
		for key, value := range map[string]string{"feed": filter.Feed, "cve": filter.CVE, "repo": filter.Repo} {
			if value != "" {
				q.Set(key, value)
			}
		}
		return "/reports/vulnerabilities?" + q.Encode()
	}
	prevURL, nextURL := "", ""
	if page > 1 {
		prevURL = pageURL(page - 1)
	}
	if page*pageSize < result.Total {
		nextURL = pageURL(page + 1)
	}
	s.render(w, "vulnerability_report.html", reportData{
		Items: view, Feeds: feeds, Refreshing: refreshing, RSSEnabled: cfg.RSS.Enabled,
		Error: warning, Days: days, Page: page, Total: result.Total, CVECount: result.CVECount,
		FeedFilter: filter.Feed, CVEFilter: filter.CVE, RepoFilter: filter.Repo,
		PrevURL: prevURL, NextURL: nextURL, CSRFToken: issueCSRF(w, r),
	})
}

func scoreAlertWithThreat(profiles []model.ServiceProfile, assessments []model.CVEAssessment, threats map[string]model.ThreatSnapshot, rec *model.AlertRecord) model.ScoreResult {
	profile := model.ServiceProfile{ID: "unconfigured:" + rec.Alert.Owner + "/" + rec.Alert.Repo, Exposure: model.ExposureUnknown, Environment: model.EnvironmentUnknown, Authentication: model.AuthUnknown, BusinessCriticality: model.RiskUnknown, DataClassification: model.RiskUnknown, IntegrityImpact: model.RiskUnknown, PrivilegeScope: model.PrivilegeUnknown}
	var matching []model.ServiceProfile
	resolver := config.Config{ServiceProfiles: profiles}
	for _, p := range profiles {
		resolved, err := resolver.ResolveProfile(p.ID)
		if err != nil {
			return model.ScoreResult{Upper: 100, Status: "provisional", Priority: "immediate", Confidence: "insufficient", MissingFacts: []string{err.Error()}, ModelVersion: scoring.ModelVersion()}
		}
		p = resolved
		if strings.EqualFold(p.Owner, rec.Alert.Owner) && (strings.TrimSpace(p.Repo) == "" || strings.EqualFold(p.Repo, rec.Alert.Repo)) {
			matching = append(matching, p)
		}
	}
	if len(matching) == 0 {
		matching = append(matching, profile)
	}
	at := time.Now().UTC()
	var best model.ScoreResult
	for i, profile := range matching {
		candidate := scoreProfileWithThreat(profile, assessments, threats, rec, at)
		if i == 0 || worseRisk(candidate, best) {
			best = candidate
		}
	}
	return best
}

func worseRisk(candidate, previous model.ScoreResult) bool {
	active := func(score model.ScoreResult) bool {
		return score.Status != "not_affected" && score.Status != "mitigated"
	}
	if active(candidate) != active(previous) {
		return active(candidate)
	}
	if candidate.Upper != previous.Upper {
		return candidate.Upper > previous.Upper
	}
	return candidate.Priority == "incident" && previous.Priority != "incident"
}

func scoreProfileWithThreat(profile model.ServiceProfile, assessments []model.CVEAssessment, threats map[string]model.ThreatSnapshot, rec *model.AlertRecord, at time.Time) model.ScoreResult {
	result, err := scoring.Calculate(risk.InputForAlert(profile, assessments, threats, rec, at))
	if err != nil {
		return model.ScoreResult{ProfileID: profile.ID, Upper: 100, Status: "provisional", Priority: "immediate", Confidence: "insufficient", MissingFacts: []string{err.Error()}, ModelVersion: scoring.ModelVersion()}
	}
	return result
}

func (s *Server) handleVulnerabilityRefresh(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	enabled := s.cfg.RSS.Enabled
	s.cfgMu.RUnlock()
	if !enabled {
		http.Error(w, "RSS収集は無効です", http.StatusUnprocessableEntity)
		return
	}
	s.feedMu.Lock()
	if s.feedRefreshing {
		s.feedMu.Unlock()
		http.Error(w, "RSS更新実行中です", http.StatusConflict)
		return
	}
	s.feedRefreshing = true
	s.feedMu.Unlock()
	jobCtx := s.appCtx
	if jobCtx == nil {
		jobCtx = context.Background()
	}
	go func() {
		defer func() { s.feedMu.Lock(); s.feedRefreshing = false; s.feedMu.Unlock() }()
		if err := s.refreshFeedsOnce(jobCtx); err != nil {
			slog.Error("RSS手動更新失敗", "error", err)
		}
	}()
	http.Redirect(w, r, "/reports/vulnerabilities", http.StatusSeeOther)
}

// RunFeedScheduler は設定変更を監視し、有効なRSSフィードを定期更新する。
func (s *Server) RunFeedScheduler(ctx context.Context) {
	for {
		s.cfgMu.RLock()
		enabled := s.cfg.RSS.Enabled
		interval := s.cfg.RSS.RefreshInterval
		s.cfgMu.RUnlock()
		if !enabled {
			select {
			case <-ctx.Done():
				return
			case <-s.feedConfigChanged:
				continue
			}
		}
		if interval < 15*time.Minute {
			interval = 15 * time.Minute
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.feedConfigChanged:
			timer.Stop()
			continue
		case <-timer.C:
			if err := s.refreshFeeds(ctx); err != nil {
				slog.Error("RSS定期更新失敗", "error", err)
			}
		}
	}
}

func (s *Server) refreshFeeds(ctx context.Context) error {
	s.feedMu.Lock()
	if s.feedRefreshing {
		s.feedMu.Unlock()
		return fmt.Errorf("RSS更新実行中です")
	}
	s.feedRefreshing = true
	s.feedMu.Unlock()
	defer func() { s.feedMu.Lock(); s.feedRefreshing = false; s.feedMu.Unlock() }()
	return s.refreshFeedsOnce(ctx)
}

func (s *Server) refreshFeedsOnce(ctx context.Context) error {
	s.cfgMu.RLock()
	cfg := *s.cfg
	s.cfgMu.RUnlock()
	if !cfg.RSS.Enabled {
		return fmt.Errorf("RSS収集は無効です")
	}
	statuses, err := s.store.ListFeedStatuses(ctx)
	if err != nil {
		return err
	}
	previous := make(map[string]store.FeedStatus, len(statuses))
	for _, status := range statuses {
		previous[status.FeedURL] = status
	}
	var failures []string
	for _, f := range cfg.RSS.Feeds {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !f.Enabled {
			continue
		}
		now := time.Now().UTC()
		prior := previous[f.URL]
		if prior.NextAttemptAt != nil && now.Before(*prior.NextAttemptAt) {
			continue
		}
		response, fetchErr := s.fetchFeed(ctx, f.URL, feed.FetchOptions{
			Timeout: cfg.RSS.RequestTimeout, MaxItems: cfg.RSS.MaxItemsPerFeed,
			ETag: prior.ETag, LastModified: prior.LastModified,
		})
		status := store.FeedStatus{FeedURL: f.URL, LastAttemptAt: &now}
		if fetchErr == nil && response.NotModified {
			status.LastSuccessAt = &now
			status.ItemCount = prior.ItemCount
			status.ETag, status.LastModified = response.ETag, response.LastModified
			if status.ETag == "" {
				status.ETag = prior.ETag
			}
			if status.LastModified == "" {
				status.LastModified = prior.LastModified
			}
			fetchErr = s.store.SaveFeedStatus(ctx, status)
		} else if fetchErr == nil {
			retention := time.Duration(cfg.RSS.RetentionDays) * 24 * time.Hour
			fetchErr = s.store.CommitFeed(ctx, store.FeedBatch{
				FeedURL: f.URL, Items: response.Items, FetchedAt: now, Retention: retention,
				ETag: response.ETag, LastModified: response.LastModified,
			})
		}
		if fetchErr == nil {
			continue
		}
		status.LastSuccessAt = nil
		status.LastError = fetchErr.Error()
		var limited *feed.HTTPStatusError
		if errors.As(fetchErr, &limited) && limited.StatusCode == http.StatusTooManyRequests {
			due := limited.RetryAt
			if due.IsZero() {
				due = now.Add(15 * time.Minute)
			}
			status.NextAttemptAt = &due
		}
		failures = append(failures, fmt.Sprintf("%s: %v", f.Name, fetchErr))
		if err := s.store.RecordFeedFailure(ctx, status); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", f.Name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("一部のRSS更新に失敗しました: %s", strings.Join(failures, "; "))
	}
	return nil
}

// RefreshFeeds performs one synchronous feed refresh for command-line --once
// and integration tests.
func (s *Server) RefreshFeeds(ctx context.Context) error { return s.refreshFeeds(ctx) }

// RefreshThreats downloads KEV/EPSS fixtures through the threat adapter and
// stores the last successful snapshots. A failed source never clears prior
// positive observations.
func (s *Server) RefreshThreats(ctx context.Context) error {
	s.cfgMu.RLock()
	cfg := *s.cfg
	s.cfgMu.RUnlock()
	if !cfg.Threat.Enabled {
		return fmt.Errorf("脅威情報収集は無効です")
	}
	client := threat.Service{Timeout: cfg.Threat.Timeout}
	if client.Timeout <= 0 {
		client.Timeout = 10 * time.Second
	}
	at := time.Now().UTC()
	var failures []string
	kevURL := cfg.Threat.KEVURL
	if kevURL == "" {
		kevURL = threat.DefaultKEVURL
	}
	if snapshots, err := client.FetchKEV(ctx, kevURL, at); err != nil {
		failures = append(failures, "KEV: "+err.Error())
	} else {
		values := make([]model.ThreatSnapshot, 0, len(snapshots))
		for _, snap := range snapshots {
			values = append(values, snap)
		}
		if err := s.store.UpsertThreat(ctx, "kev", values); err != nil {
			failures = append(failures, err.Error())
		}
	}
	epssURL := cfg.Threat.EPSSURL
	if epssURL == "" {
		epssURL = threat.DefaultEPSSURL
	}
	if snapshots, err := client.FetchEPSS(ctx, epssURL, at); err != nil {
		failures = append(failures, "EPSS: "+err.Error())
	} else {
		values := make([]model.ThreatSnapshot, 0, len(snapshots))
		for _, snap := range snapshots {
			values = append(values, snap)
		}
		if err := s.store.UpsertThreat(ctx, "epss", values); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("一部の脅威情報更新に失敗しました: %s", strings.Join(failures, "; "))
	}
	return nil
}

// RunThreatScheduler periodically refreshes structured threat feeds.
func (s *Server) RunThreatScheduler(ctx context.Context) {
	s.cfgMu.RLock()
	enabled, interval := s.cfg.Threat.Enabled, s.cfg.Threat.Interval
	s.cfgMu.RUnlock()
	if !enabled {
		return
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.RefreshThreats(ctx); err != nil {
				slog.Error("脅威情報更新失敗", "error", err)
			}
		}
	}
}
