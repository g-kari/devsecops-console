package model

import (
	"regexp"
	"strings"
	"time"
)

// ComparisonEvidence binds a caller-selected snapshot to its recorded run.
// SnapshotID must explicitly identify the same immutable deployment/revision
// on both sides. It must never be inferred from a CVE, timestamp or repository.
type ComparisonEvidence struct {
	SecurityFinding
	Run        IngestRun
	SnapshotID string
}

// FindingComparison separates advisory association from evidence comparability.
// Even comparable evidence never establishes duplicate identity or remediation.
type FindingComparison struct {
	SameCVE    bool
	Comparable bool
	Reasons    []string
}

var comparisonCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// CompareFindingEvidence compares Dependabot and Trivy snapshots without I/O,
// mutation, record merging, version interpretation or resolution inference.
// At and maxAge are explicit caller policy, not an implicit system clock.
// Reasons are stable codes and never contain raw evidence or source payloads.
func CompareFindingEvidence(a, b ComparisonEvidence, at time.Time, maxAge time.Duration) FindingComparison {
	out := FindingComparison{}
	af, bf := a.Finding, b.Finding
	out.SameCVE = len(af.VulnerabilityID) <= 64 &&
		comparisonCVE.MatchString(af.VulnerabilityID) &&
		af.VulnerabilityID == bf.VulnerabilityID &&
		af.Category == "vulnerability" &&
		bf.Category == "vulnerability"
	if !out.SameCVE {
		out.Reasons = append(out.Reasons, "not_same_cve")
	}
	aSource, bSource := a.Observation.Source, b.Observation.Source
	supported := (aSource == "dependabot" && bSource == "trivy") ||
		(aSource == "trivy" && bSource == "dependabot")
	if !supported {
		out.Reasons = append(out.Reasons, "unsupported_source_pair")
	}
	if at.IsZero() || maxAge <= 0 {
		out.Reasons = append(out.Reasons, "invalid_time_policy")
	}
	if comparisonBlank(a.Asset.ID) ||
		comparisonBlank(b.Asset.ID) ||
		comparisonBlank(a.Asset.NativeID) ||
		comparisonBlank(b.Asset.NativeID) ||
		comparisonBlank(a.Asset.Type) ||
		comparisonBlank(a.Asset.Provider) ||
		a.Asset.ID != b.Asset.ID ||
		a.Asset.Type != b.Asset.Type ||
		a.Asset.Provider != b.Asset.Provider ||
		a.Asset.Account != b.Asset.Account ||
		a.Asset.NativeID != b.Asset.NativeID ||
		a.Asset.Region != b.Asset.Region ||
		a.Asset.Environment != b.Asset.Environment {
		out.Reasons = append(out.Reasons, "asset_missing_or_different")
	}
	if comparisonBlank(af.PackageName) ||
		comparisonBlank(af.PackageEcosystem) ||
		comparisonBlank(bf.PackageName) ||
		comparisonBlank(bf.PackageEcosystem) ||
		af.PackageName != bf.PackageName ||
		af.PackageEcosystem != bf.PackageEcosystem {
		out.Reasons = append(out.Reasons, "package_missing_or_different")
	}
	if comparisonBlank(af.InstalledVersion) || comparisonBlank(bf.InstalledVersion) || af.InstalledVersion != bf.InstalledVersion {
		out.Reasons = append(out.Reasons, "installed_version_missing_or_different")
	}
	if comparisonBlank(af.FilePath) || comparisonBlank(bf.FilePath) || af.FilePath != bf.FilePath {
		out.Reasons = append(out.Reasons, "package_location_missing_or_different")
	}
	if comparisonBlank(a.SnapshotID) || comparisonBlank(b.SnapshotID) || a.SnapshotID != b.SnapshotID {
		out.Reasons = append(out.Reasons, "snapshot_missing_or_different")
	}
	for _, side := range []struct {
		name     string
		evidence ComparisonEvidence
	}{{"left", a}, {"right", b}} {
		e := side.evidence
		f, o, r := e.Finding, e.Observation, e.Run
		if comparisonBlank(f.ID) ||
			comparisonBlank(e.Asset.ID) ||
			f.AssetID != e.Asset.ID ||
			comparisonBlank(o.ID) ||
			o.FindingID != f.ID ||
			comparisonBlank(o.SourceFindingID) ||
			comparisonBlank(o.Fingerprint) ||
			comparisonBlank(r.ID) ||
			o.IngestRunID != r.ID ||
			r.Connector != o.Source ||
			comparisonBlank(r.Scope) {
			out.Reasons = append(out.Reasons, side.name+"_unbound_evidence")
		}
		if r.Result != IngestResultSuccess || r.Coverage != IngestCoverageFull {
			out.Reasons = append(out.Reasons, side.name+"_incomplete_coverage")
		}
		if o.ObservedAt.IsZero() ||
			o.ObservedAt.After(at) ||
			at.Sub(o.ObservedAt) > maxAge ||
			r.StartedAt.IsZero() ||
			r.FinishedAt == nil ||
			r.FinishedAt.Before(r.StartedAt) ||
			r.FinishedAt.After(at) ||
			o.ObservedAt.Before(r.StartedAt) ||
			o.ObservedAt.After(*r.FinishedAt) {
			out.Reasons = append(out.Reasons, side.name+"_invalid_or_stale_observation")
		}
		if f.SourceStatus != SourceStatusActive {
			out.Reasons = append(out.Reasons, side.name+"_not_active_evidence")
		}
	}
	out.Comparable = len(out.Reasons) == 0
	return out
}

func comparisonBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}
