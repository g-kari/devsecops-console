package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestPersistedOfflineCoverageCannotBecomeComparable(t *testing.T) {
	s, err := NewWithPath(filepath.Join(t.TempDir(), "comparison.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close comparison test store: %v", err)
		}
	})
	ctx := context.Background()
	run, item := importFixture()
	item.Finding.PackageEcosystem = "npm"
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err != nil {
		t.Fatalf("import synthetic Trivy evidence: %v", err)
	}
	detail, err := s.GetFindingDetail(ctx, item.Finding.ID)
	if err != nil || len(detail.Observations) != 1 {
		t.Fatalf("read persisted finding: observations=%d err=%v", len(detail.Observations), err)
	}
	if detail.Finding.FilePath != "" {
		t.Fatal("offline import unexpectedly produced an authenticated package location")
	}
	obs := detail.Observations[0]
	runs, err := s.QueryIngestRuns(ctx)
	if err != nil || len(runs) != 1 {
		t.Fatalf("read persisted run: count=%d err=%v", len(runs), err)
	}
	persisted := runs[0]
	if persisted.ID != obs.IngestRunID || persisted.Connector != obs.Source || persisted.Coverage != model.IngestCoveragePartial {
		t.Fatal("offline coverage or evidence binding was not preserved")
	}

	// A hypothetical shared snapshot and fully covered counterpart cannot fill
	// in the missing package location or upgrade the persisted run coverage.
	scan := model.ComparisonEvidence{
		SecurityFinding: model.SecurityFinding{Asset: detail.Asset, Finding: detail.Finding.Finding, Observation: obs},
		Run:             persisted,
		SnapshotID:      "synthetic-immutable-snapshot",
	}
	counterpart := scan
	counterpart.Finding.ID = "synthetic-dependabot-finding"
	counterpart.Observation.ID = "synthetic-dependabot-observation"
	counterpart.Observation.FindingID = counterpart.Finding.ID
	counterpart.Observation.Source = "dependabot"
	counterpart.Observation.SourceFindingID = "synthetic-dependabot-native"
	counterpart.Run.ID = "synthetic-dependabot-run"
	counterpart.Run.Connector = "dependabot"
	counterpart.Run.Coverage = model.IngestCoverageFull
	counterpart.Observation.IngestRunID = counterpart.Run.ID

	for _, tc := range []struct {
		name  string
		left  model.ComparisonEvidence
		right model.ComparisonEvidence
		want  string
	}{
		{"trivy left", scan, counterpart, "left_incomplete_coverage"},
		{"trivy right", counterpart, scan, "right_incomplete_coverage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := model.CompareFindingEvidence(tc.left, tc.right, run.StartedAt, time.Hour)
			want := []string{"package_location_missing_or_different", tc.want}
			if !result.SameCVE || result.Comparable || !slices.Equal(result.Reasons, want) {
				t.Fatalf("comparison=%+v; want same CVE, incomparable, reasons=%v", result, want)
			}
		})
	}
}
