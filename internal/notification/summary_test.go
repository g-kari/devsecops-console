package notification

import (
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestSummaryCountsFilteringOrderingAndLimits(t *testing.T) {
	cfg := config.Defaults()
	cfg.Targets = []config.Target{{Owner: "org", Repo: "repo"}}
	cfg.NotifyMinSeverity = "high"
	var records []*model.AlertRecord
	for i := 0; i < 75; i++ {
		records = append(records, &model.AlertRecord{Alert: model.Alert{ID: i + 1, Number: i + 1, Owner: "org", Repo: "repo", Severity: model.SeverityHigh, PackageName: strings.Repeat("😀", 500)}, EvalStatus: model.EvalStatusPending})
	}
	records = append(records, &model.AlertRecord{Alert: model.Alert{Number: 99, Owner: "org", Repo: "repo", Severity: model.SeverityCritical, PackageName: "first"}, EvalStatus: model.EvalStatusDone, Evaluation: &model.Evaluation{}})
	records = append(records, []*model.AlertRecord{
		{Alert: model.Alert{Owner: "other", Repo: "repo", Severity: model.SeverityCritical}},
		{Alert: model.Alert{Owner: "org", Repo: "repo", Severity: model.SeverityLow}},
		{Alert: model.Alert{Owner: "org", Repo: "repo", Severity: model.SeverityCritical}, ResolvedAt: new(time.Time)},
	}...)
	s := Build(records, *cfg, "ORG", "REPO")
	if s.Total != 76 || s.Done != 1 || s.Pending != 75 || s.Severities[model.SeverityHigh] != 75 {
		t.Fatalf("wrong counts: %+v", s)
	}
	if s.Records[0].Alert.PackageName != "first" {
		t.Fatal("not severity ordered")
	}
	text := s.Text()
	if len([]rune(text)) > 2400 || !strings.Contains(text, "76") || !strings.Contains(text, "省略") {
		t.Fatalf("invalid summary %q", text)
	}
	cfg.Targets = nil
	if got := Build(records, *cfg, "org", "repo"); got.Total != 0 {
		t.Fatal("unmonitored included")
	}
	if got := Limit(strings.Repeat("😀", 100), 11); len([]rune(got)) > 6 || !strings.HasSuffix(got, "…") {
		t.Fatal(got)
	}
}
