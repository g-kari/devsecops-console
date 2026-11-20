package model

import (
	"reflect"
	"testing"
	"time"
)

func TestCompareFindingEvidenceConservativeClassification(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	fixture := func(source string) ComparisonEvidence {
		finished := at.Add(-time.Minute)
		return ComparisonEvidence{
			SecurityFinding: SecurityFinding{
				Asset:       Asset{ID: "synthetic-asset", Type: "repository", Provider: "github", Account: "example", NativeID: "example/demo"},
				Finding:     Finding{ID: source+"-finding", AssetID: "synthetic-asset", Category: "vulnerability", VulnerabilityID: "CVE-2099-0001", PackageName: "example-package", PackageEcosystem: "npm", InstalledVersion: "1.0.0", FilePath: "app/package-lock.json", SourceStatus: SourceStatusActive},
				Observation: Observation{ID: source+"-observation", Source: source, SourceFindingID: source+"-native", FindingID: source+"-finding", IngestRunID: source+"-run", Fingerprint: "synthetic-fingerprint", ObservedAt: at.Add(-2*time.Minute)},
			},
			Run:        IngestRun{ID: source+"-run", Connector: source, Scope: source+"-scope", StartedAt: at.Add(-3*time.Minute), FinishedAt: &finished, Result: IngestResultSuccess, Coverage: IngestCoverageFull},
			SnapshotID: "explicit-synthetic-revision",
		}
	}
	tests := []struct {
		name                string
		change              func(*ComparisonEvidence)
		sameCVE, comparable bool
		reason              string
	}{
		{"explicit_matching_evidence", func(*ComparisonEvidence) {}, true, true, ""},
		{"different_cve", func(e *ComparisonEvidence) { e.Finding.VulnerabilityID = "CVE-2099-0002" }, false, false, "not_same_cve"},
		{"noncanonical_cve", func(e *ComparisonEvidence) { e.Finding.VulnerabilityID = "cve-2099-0001" }, false, false, "not_same_cve"},
		{"different_asset", func(e *ComparisonEvidence) {
			e.Asset.ID = "another"
			e.Finding.AssetID = "another"
		}, true, false, "asset_missing_or_different"},
		{"different_asset_context", func(e *ComparisonEvidence) { e.Asset.Environment = "production" }, true, false, "asset_missing_or_different"},
		{"different_package", func(e *ComparisonEvidence) { e.Finding.PackageName = "other" }, true, false, "package_missing_or_different"},
		{"different_ecosystem", func(e *ComparisonEvidence) { e.Finding.PackageEcosystem = "pip" }, true, false, "package_missing_or_different"},
		{"missing_package", func(e *ComparisonEvidence) { e.Finding.PackageName = "" }, true, false, "package_missing_or_different"},
		{"different_location", func(e *ComparisonEvidence) { e.Finding.FilePath = "other/package-lock.json" }, true, false, "package_location_missing_or_different"},
		{"missing_location", func(e *ComparisonEvidence) { e.Finding.FilePath = "" }, true, false, "package_location_missing_or_different"},
		{"fix_available_not_resolution", func(e *ComparisonEvidence) { e.Finding.FixedVersion = "2.0.0" }, true, true, ""},
		{"approval_not_resolution", func(e *ComparisonEvidence) { e.Finding.TriageStatus = TriageStatusClosed }, true, true, ""},
		{"different_version", func(e *ComparisonEvidence) { e.Finding.InstalledVersion = "1.0.1" }, true, false, "installed_version_missing_or_different"},
		{"missing_version", func(e *ComparisonEvidence) { e.Finding.InstalledVersion = "" }, true, false, "installed_version_missing_or_different"},
		{"missing_snapshot", func(e *ComparisonEvidence) { e.SnapshotID = "" }, true, false, "snapshot_missing_or_different"},
		{"different_snapshot", func(e *ComparisonEvidence) { e.SnapshotID = "other" }, true, false, "snapshot_missing_or_different"},
		{"wrong_observation_binding", func(e *ComparisonEvidence) { e.Observation.FindingID = "other" }, true, false, "right_unbound_evidence"},
		{"wrong_run_binding", func(e *ComparisonEvidence) { e.Observation.IngestRunID = "other" }, true, false, "right_unbound_evidence"},
		{"missing_native_identity", func(e *ComparisonEvidence) { e.Observation.SourceFindingID = "" }, true, false, "right_unbound_evidence"},
		{"missing_scope", func(e *ComparisonEvidence) { e.Run.Scope = "" }, true, false, "right_unbound_evidence"},
		{"partial_coverage", func(e *ComparisonEvidence) { e.Run.Coverage = IngestCoveragePartial }, true, false, "right_incomplete_coverage"},
		{"unknown_coverage", func(e *ComparisonEvidence) { e.Run.Coverage = IngestCoverageUnknown }, true, false, "right_incomplete_coverage"},
		{"partial_run", func(e *ComparisonEvidence) { e.Run.Result = IngestResultPartial }, true, false, "right_incomplete_coverage"},
		{"failed_run", func(e *ComparisonEvidence) { e.Run.Result = IngestResultFailed }, true, false, "right_incomplete_coverage"},
		{"stale_observation", func(e *ComparisonEvidence) { e.Observation.ObservedAt = at.Add(-48*time.Hour) }, true, false, "right_invalid_or_stale_observation"},
		{"future_observation", func(e *ComparisonEvidence) { e.Observation.ObservedAt = at.Add(time.Hour) }, true, false, "right_invalid_or_stale_observation"},
		{"missing_observation", func(e *ComparisonEvidence) { e.Observation = Observation{} }, true, false, "unsupported_source_pair"},
		{"unfinished_run", func(e *ComparisonEvidence) { e.Run.FinishedAt = nil }, true, false, "right_invalid_or_stale_observation"},
		{"unknown_status", func(e *ComparisonEvidence) { e.Finding.SourceStatus = SourceStatusUnknown }, true, false, "right_not_active_evidence"},
		{"resolved_is_not_shared_resolution", func(e *ComparisonEvidence) { e.Finding.SourceStatus = SourceStatusResolved }, true, false, "right_not_active_evidence"},
		{"suppressed_is_not_fixed", func(e *ComparisonEvidence) { e.Finding.SourceStatus = SourceStatusSuppressed }, true, false, "right_not_active_evidence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := fixture("dependabot"), fixture("trivy")
			tt.change(&b)
			beforeA, beforeB := copyComparisonEvidence(a), copyComparisonEvidence(b)
			got := CompareFindingEvidence(a, b, at, 24*time.Hour)
			if got.SameCVE != tt.sameCVE || got.Comparable != tt.comparable {
				t.Fatalf("input=(%+v, %+v), got=%+v, want sameCVE=%v comparable=%v", a, b, got, tt.sameCVE, tt.comparable)
			}
			if tt.reason != "" {
				found := false
				for _, reason := range got.Reasons {
					if reason == tt.reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("input=%+v, reasons=%v, want %s", b, got.Reasons, tt.reason)
				}
			}
			if !reflect.DeepEqual(a, beforeA) || !reflect.DeepEqual(b, beforeB) {
				t.Fatal("comparison mutated evidence")
			}
			if swapped := CompareFindingEvidence(b, a, at, 24*time.Hour); swapped.SameCVE != got.SameCVE || swapped.Comparable != got.Comparable {
				t.Fatalf("asymmetric classification: %+v vs %+v", got, swapped)
			}
		})
	}
	for _, policy := range []struct {
		at  time.Time
		age time.Duration
	}{{time.Time{}, time.Hour}, {at, 0}, {at, -time.Hour}} {
		got := CompareFindingEvidence(fixture("dependabot"), fixture("trivy"), policy.at, policy.age)
		if got.Comparable {
			t.Fatalf("invalid policy %+v accepted: %+v", policy, got)
		}
	}
}

func TestCompareFindingEvidenceRejectsBlankMetadata(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	same := ComparisonEvidence{
		SecurityFinding: SecurityFinding{
			Finding: Finding{Category: "vulnerability", VulnerabilityID: "CVE-2099-0001", InstalledVersion: " ", FilePath: "\t"},
		},
		SnapshotID: " ",
	}
	got := CompareFindingEvidence(same, same, at, time.Hour)
	for _, want := range []string{"snapshot_missing_or_different", "installed_version_missing_or_different", "package_location_missing_or_different"} {
		found := false
		for _, reason := range got.Reasons {
			if reason == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing reason %q in %+v", want, got)
		}
	}
}

func copyComparisonEvidence(e ComparisonEvidence) ComparisonEvidence {
	if e.Run.FinishedAt != nil {
		at := *e.Run.FinishedAt
		e.Run.FinishedAt = &at
	}
	return e
}
