package findingpreviewwire

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func assessmentFixture() map[string]any {
	m := profileFixture()
	m["schema_version"] = AssessmentSchemaVersion
	m["assessment"] = map[string]any{"profile_id": "profile-a", "repo": "synthetic/repo", "advisory_key": "cve:CVE-2099-0001", "applicability": "affected", "reachability": "reachable", "evidence": map[string]any{"id": "claim-a", "source": "synthetic-source", "observed_at": "2026-11-07T00:00:00Z", "expires_at": "2026-11-09T00:00:00Z"}}
	return m
}
func assessmentDirect() findingpreview.Input {
	in := profileDirect()
	in.Assessment = &model.CVEAssessment{ProfileID: "profile-a", Repo: "synthetic/repo", AdvisoryKey: "cve:CVE-2099-0001", Applicability: "affected", Reachability: "reachable", Facts: map[string]string{}, Evidence: []model.Evidence{{ID: "claim-a", Source: "synthetic-source", ObservedAt: in.At.Add(-24 * time.Hour), ExpiresAt: in.At.Add(24 * time.Hour)}}}
	return in
}
func assessmentSame(t *testing.T, m map[string]any, in findingpreview.Input) findingpreview.Result {
	t.Helper()
	r, err := DecodeAssessment(encoded(t, m))
	want, we := findingpreview.Calculate(in)
	if err != nil || we != nil || !reflect.DeepEqual(r, want) {
		t.Fatalf("assessment full adapter parity failed: wire error %v, adapter error %v", err, we)
	}
	return r
}
func assessmentReject(t *testing.T, b []byte) Error {
	t.Helper()
	r, err := DecodeAssessment(b)
	e, ok := err.(Error)
	if !ok || !reflect.DeepEqual(r, findingpreview.Result{}) {
		t.Fatalf("expected fixed error and zero result; error type %T", err)
	}
	if !oneOf(string(e), "size", "encoding", "syntax", "null", "type", "depth", "duplicate", "required", "string", "time", "number", "field", "version", "enum", "binding", "positive", "adapter") {
		t.Fatal("unexpected diagnostic")
	}
	return e
}
func assessmentObject(m map[string]any) map[string]any { return m["assessment"].(map[string]any) }
func assessmentEvidence(m map[string]any) map[string]any {
	return assessmentObject(m)["evidence"].(map[string]any)
}

func TestA01FullResultParity(t *testing.T) {
	r := assessmentSame(t, assessmentFixture(), assessmentDirect())
	if !r.PreviewOnly || r.InputOrigins["assessment.evidence"].Source != "bound_assessment" || r.ScoreResult == nil {
		t.Fatal("lost preview or origin")
	}
}
func TestA02EveryNewFieldRequiredAndTyped(t *testing.T) {
	for _, group := range []string{"root", "assessment", "evidence"} {
		keys := []string{"assessment", "profile", "binding"}
		if group == "assessment" {
			keys = []string{"profile_id", "repo", "advisory_key", "applicability", "reachability", "evidence"}
		}
		if group == "evidence" {
			keys = []string{"id", "source", "observed_at", "expires_at"}
		}
		for _, key := range keys {
			for _, mode := range []string{"missing", "null", "number", "bool", "array", "wrong-shape"} {
				t.Run(group+"/"+key+"/"+mode, func(t *testing.T) {
					m := assessmentFixture()
					obj := m
					if group == "assessment" {
						obj = assessmentObject(m)
					}
					if group == "evidence" {
						obj = assessmentEvidence(m)
					}
					switch mode {
					case "missing":
						delete(obj, key)
					case "null":
						obj[key] = nil
					case "number":
						obj[key] = 7
					case "bool":
						obj[key] = false
					case "array":
						obj[key] = []any{}
					case "wrong-shape":
						if group == "root" || key == "evidence" {
							obj[key] = "object required"
						} else {
							obj[key] = map[string]any{}
						}
					}
					_ = assessmentReject(t, encoded(t, m))
				})
			}
		}
	}
}
func TestA03AxisVocabularyIsClosedAndExplicit(t *testing.T) {
	for _, a := range []string{"", "unknown", "affected", "not_affected"} {
		for _, r := range []string{"", "unknown", "reachable", "unreachable"} {
			m := assessmentFixture()
			in := assessmentDirect()
			assessmentObject(m)["applicability"] = a
			assessmentObject(m)["reachability"] = r
			in.Assessment.Applicability = a
			in.Assessment.Reachability = r
			got := assessmentSame(t, m, in)
			if slices.Contains(got.MissingInputs, "assessment") {
				t.Fatal("explicit assessment treated as absent")
			}
		}
	}
	for _, axis := range []string{"applicability", "reachability"} {
		bad := []string{"UNKNOWN", " unknown", "unknown ", "mitigated", "arbitrary"}
		if axis == "applicability" {
			bad = append(bad, "reachable", "unreachable")
		} else {
			bad = append(bad, "affected", "not_affected")
		}
		for _, v := range bad {
			m := assessmentFixture()
			assessmentObject(m)[axis] = v
			if assessmentReject(t, encoded(t, m)) != Error("enum") {
				t.Fatalf("%s invalid vocabulary", axis)
			}
		}
	}
}
func TestA04EveryIdentityBindingAndNoReuse(t *testing.T) {
	for _, group := range []string{"binding", "assessment"} {
		keys := []string{"finding_id", "asset_id", "cve", "profile_id", "repo"}
		if group == "assessment" {
			keys = []string{"profile_id", "repo", "advisory_key"}
		}
		for _, key := range keys {
			m := assessmentFixture()
			m[group].(map[string]any)[key] = "other"
			if assessmentReject(t, encoded(t, m)) != Error("binding") {
				t.Fatalf("binding %s.%s", group, key)
			}
		}
	}
	for _, change := range []string{"finding", "asset", "profile", "repo", "advisory-case", "advisory-space"} {
		m := assessmentFixture()
		switch change {
		case "finding":
			m["finding"].(map[string]any)["id"] = "finding-b"
		case "asset":
			m["finding"].(map[string]any)["asset_id"] = "asset-b"
			m["asset"].(map[string]any)["id"] = "asset-b"
		case "profile":
			m["profile"].(map[string]any)["id"] = "profile-b"
			m["binding"].(map[string]any)["profile_id"] = "profile-b"
		case "repo":
			m["profile"].(map[string]any)["repo"] = "synthetic/other"
			m["binding"].(map[string]any)["repo"] = "synthetic/other"
		case "advisory-case":
			assessmentObject(m)["advisory_key"] = "CVE:CVE-2099-0001"
		case "advisory-space":
			assessmentObject(m)["advisory_key"] = "cve:CVE-2099-0001 "
		}
		_ = assessmentReject(t, encoded(t, m))
	}
}
func TestA05ExpiryBoundaryAndStrictClocks(t *testing.T) {
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		m := assessmentFixture()
		in := assessmentDirect()
		in.Assessment.Evidence[0].ExpiresAt = in.At.Add(delta)
		assessmentEvidence(m)["expires_at"] = in.At.Add(delta).Format(time.RFC3339Nano)
		assessmentSame(t, m, in)
	}
	for _, key := range []string{"observed_at", "expires_at"} {
		for _, bad := range []string{"", "0001-01-01T00:00:00Z", "2026-11-07T0:00:00Z", "2026-11-07T00:00:00,1Z", "2026-11-07T00:00:00+24:00", "2026-11-07T00:00:00+00:60", "2026-11-07T00:00:00.1234567891Z", "not-time", "10000-01-01T00:00:00Z"} {
			m := assessmentFixture()
			assessmentEvidence(m)[key] = bad
			_ = assessmentReject(t, encoded(t, m))
		}
	}
	for _, c := range []struct{ observed, expires string }{{"2026-11-08T00:00:00.000000001Z", "2026-11-09T00:00:00Z"}, {"2026-11-07T00:00:00Z", "2026-11-07T00:00:00Z"}, {"2026-11-07T00:00:00Z", "2026-11-06T00:00:00Z"}} {
		m := assessmentFixture()
		e := assessmentEvidence(m)
		e["observed_at"] = c.observed
		e["expires_at"] = c.expires
		if assessmentReject(t, encoded(t, m)) != Error("time") {
			t.Fatal("clock order")
		}
	}
	// Equal instants across offsets must be compared as instants, without rewriting supplied times.
	m := assessmentFixture()
	in := assessmentDirect()
	e := assessmentEvidence(m)
	e["observed_at"] = "2026-11-08T09:00:00+09:00"
	e["expires_at"] = "2026-11-08T09:00:00.000000001+09:00"
	in.Assessment.Evidence[0].ObservedAt, _ = time.ParseInLocation(time.RFC3339Nano, e["observed_at"].(string), time.UTC)
	in.Assessment.Evidence[0].ExpiresAt, _ = time.ParseInLocation(time.RFC3339Nano, e["expires_at"].(string), time.UTC)
	assessmentSame(t, m, in)
}
func TestA06NotAffectedIsOnlyASuppliedClaim(t *testing.T) {
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		m := assessmentFixture()
		in := assessmentDirect()
		assessmentObject(m)["applicability"] = "not_affected"
		in.Assessment.Applicability = "not_affected"
		in.Assessment.Evidence[0].ExpiresAt = in.At.Add(delta)
		assessmentEvidence(m)["expires_at"] = in.At.Add(delta).Format(time.RFC3339Nano)
		r := assessmentSame(t, m, in)
		if delta > 0 {
			if r.ScoreResult.Status != "not_affected" || r.ScoreResult.Confidence != "verified" || r.ScoreResult.Priority != "planned" {
				t.Fatal("existing supplied claim result changed")
			}
		} else if r.ScoreResult.Status != "provisional" || r.ScoreResult.Confidence != "insufficient" {
			t.Fatal("expiry equality must be expired")
		}
	}
}
func TestA07MissingInputsAndUnexposedFieldsRemain(t *testing.T) {
	r := assessmentSame(t, assessmentFixture(), assessmentDirect())
	a := r.InputSnapshot.Assessment
	if a.Facts == nil || len(a.Facts) != 0 || a.EvidenceByFact != nil || a.Mitigation != "" || a.LocalActivity != "" || a.DeploymentRevision != "" || r.InputSnapshot.CVSSKnown {
		t.Fatal("invented inputs")
	}
	e := a.Evidence[0]
	if len(a.Evidence) != 1 || e.Reference != "" || e.Reviewer != "" || e.DeploymentRevision != "" {
		t.Fatal("invented evidence metadata")
	}
	for _, key := range []string{"cvss", "assessment.facts", "assessment.local_activity", "technical.confidentiality", "technical.integrity", "technical.availability", "technical.privilege"} {
		if !slices.Contains(r.MissingInputs, key) {
			t.Fatalf("missing %s", key)
		}
	}
	if slices.Contains(r.MissingInputs, "assessment") {
		t.Fatal("supplied assessment marked absent")
	}
}
func TestA08UnsupportedStillValidatesAllStructure(t *testing.T) {
	for _, category := range []string{"secret", "vulnerability"} {
		build := func() map[string]any {
			m := assessmentFixture()
			m["finding"].(map[string]any)["category"] = category
			if category == "vulnerability" {
				m["finding"].(map[string]any)["vulnerability_id"] = "GHSA-fictional"
				m["binding"].(map[string]any)["cve"] = "GHSA-fictional"
				assessmentObject(m)["advisory_key"] = "cve:GHSA-fictional"
			}
			return m
		}
		m := build()
		r, err := DecodeAssessment(encoded(t, m))
		if err != nil || r.AdapterState != "unsupported" || r.ScoreResult != nil || r.InputSnapshot != nil {
			t.Fatal("valid unsupported changed")
		}
		for _, bad := range []string{"field", "binding", "time", "enum"} {
			m = build()
			switch bad {
			case "field":
				assessmentObject(m)["facts"] = map[string]any{}
			case "binding":
				assessmentObject(m)["profile_id"] = "other"
			case "time":
				assessmentEvidence(m)["observed_at"] = "2026-11-10T00:00:00Z"
			case "enum":
				assessmentObject(m)["reachability"] = "affected"
			}
			_ = assessmentReject(t, encoded(t, m))
		}
	}
}
func TestA09ForbiddenExtensionsAtEveryLevel(t *testing.T) {
	for _, key := range []string{"facts", "evidence_by_fact", "mitigation", "local_activity", "cvss", "metadata", "reference", "reviewer", "deployment_revision", "extends"} {
		for _, level := range []string{"root", "assessment", "evidence", "profile", "binding"} {
			m := assessmentFixture()
			obj := m
			switch level {
			case "assessment":
				obj = assessmentObject(m)
			case "evidence":
				obj = assessmentEvidence(m)
			case "profile", "binding":
				obj = m[level].(map[string]any)
			}
			obj[key] = "sentinel-private-reference"
			_ = assessmentReject(t, encoded(t, m))
		}
	}
	for _, level := range []string{"assessment", "evidence"} {
		m := assessmentFixture()
		if level == "assessment" {
			m[level] = []any{assessmentObject(m)}
		} else {
			assessmentObject(m)[level] = []any{assessmentEvidence(m)}
		}
		_ = assessmentReject(t, encoded(t, m))
	}
}
func TestA10VersionIsolation(t *testing.T) {
	b := encoded(t, assessmentFixture())
	_ = reject(t, b)
	_ = profileReject(t, b)
	for _, version := range []string{SchemaVersion, ProfileSchemaVersion, "finding-preview-assessment-core-v0.2"} {
		m := assessmentFixture()
		m["schema_version"] = version
		_ = assessmentReject(t, encoded(t, m))
	}
	_ = assessmentReject(t, encoded(t, fixture()))
	_ = assessmentReject(t, encoded(t, profileFixture()))
	m := assessmentFixture()
	m["schema_version"] = SchemaVersion
	_ = reject(t, encoded(t, m))
	m["schema_version"] = ProfileSchemaVersion
	_ = profileReject(t, encoded(t, m))
	sameAdapter(t, fixture(), direct())
	profileSame(t, profileFixture(), profileDirect())
}
func TestA11NoInferenceAndIndependentFeedClocks(t *testing.T) {
	for _, hours := range []time.Duration{72, 73} {
		m := assessmentFixture()
		in := assessmentDirect()
		assessmentObject(m)["applicability"] = "unknown"
		assessmentObject(m)["reachability"] = ""
		in.Assessment.Applicability = "unknown"
		in.Assessment.Reachability = ""
		m["asset"].(map[string]any)["environment"] = "production"
		m["asset"].(map[string]any)["criticality"] = "critical"
		in.Asset.Environment = "production"
		in.Asset.Criticality = "critical"
		f := m["finding"].(map[string]any)
		f["severity"] = "critical"
		f["source_status"] = "resolved"
		f["triage_status"] = "risk_accepted"
		in.Finding.Severity = model.SeverityCritical
		in.Finding.SourceStatus = "resolved"
		in.Finding.TriageStatus = "risk_accepted"
		epss := addEvidence(m, "epss")
		kev := addEvidence(m, "kev")
		ep := in.At.Add(-hours * time.Hour)
		kp := in.At.Add(-74 * time.Hour)
		kd := kp.Add(-time.Hour)
		epss["published_at"] = ep.Format(time.RFC3339Nano)
		epss["observed_at"] = ep.Format(time.RFC3339Nano)
		epss["reported_fresh"] = true
		kev["published_at"] = kp.Format(time.RFC3339Nano)
		kev["observed_at"] = kp.Format(time.RFC3339Nano)
		kev["date_added"] = kd.Format(time.RFC3339Nano)
		kev["reported_fresh"] = true
		p := 0.0
		in.Enrichment = &model.FindingEnrichment{CVEID: "CVE-2099-0001", EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: ep, ObservedAt: ep, Fresh: true, EPSS: &p}, KEV: &model.SecurityEnrichmentEvidence{Source: "kev", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: kp, ObservedAt: kp, Fresh: true, KEV: true, KEVDateAdded: &kd}}
		r := assessmentSame(t, m, in)
		if r.EPSS.Fresh != (hours == 72) || !r.KEV.HistoricalPositive || r.KEV.Fresh || r.InputSnapshot.Assessment.Applicability != "unknown" || r.InputSnapshot.Assessment.Reachability != "" {
			t.Fatal("clock or inference changed")
		}
	}
}
func TestA12PrivacyBoundsAndIsolation(t *testing.T) {
	base := string(encoded(t, assessmentFixture()))
	for _, raw := range []string{
		strings.Replace(base, `"id":"claim-a"`, `"id":"claim-a","id":"sentinel-secret"`, 1),
		strings.Replace(base, `"id":"claim-a"`, `"id":"claim-a","\u0069d":"sentinel-secret"`, 1),
		strings.Replace(base, `"applicability"`, `"Applicability"`, 1),
		strings.Replace(base, `"claim-a"`, `"\ud800"`, 1),
		strings.Replace(base, `"claim-a"`, `"\u0000"`, 1),
		base + " true", `[]`, `null`, strings.Repeat(" ", MaxBytes+1),
	} {
		_ = assessmentReject(t, []byte(raw))
	}
	_ = assessmentReject(t, append([]byte(base), 0xff))
	m := assessmentFixture()
	var deep any = "sentinel-secret"
	for i := 0; i < MaxDepth; i++ {
		deep = map[string]any{"x": deep}
	}
	m["extra"] = deep
	_ = assessmentReject(t, encoded(t, m))
	for _, group := range []string{"assessment", "evidence"} {
		keys := []string{"profile_id", "repo", "advisory_key"}
		if group == "evidence" {
			keys = []string{"id", "source"}
		}
		for _, key := range keys {
			for _, bad := range []string{"", "   ", strings.Repeat("é", 129), "sentinel-secret\n"} {
				m := assessmentFixture()
				obj := assessmentObject(m)
				if group == "evidence" {
					obj = assessmentEvidence(m)
				}
				obj[key] = bad
				e := assessmentReject(t, encoded(t, m))
				if strings.Contains(e.Error(), "sentinel") {
					t.Fatal("input leaked")
				}
			}
		}
	}
	// Inclusive document bound and UTF-8 byte bound, not rune count.
	m = assessmentFixture()
	assessmentEvidence(m)["id"] = strings.Repeat("é", 128)
	in := assessmentDirect()
	in.Assessment.Evidence[0].ID = strings.Repeat("é", 128)
	assessmentSame(t, m, in)
	b := encoded(t, m)
	b = append(b, []byte(strings.Repeat(" ", MaxBytes-len(b)))...)
	if _, err := DecodeAssessment(b); err != nil {
		t.Fatal("inclusive size rejected")
	}
	_ = assessmentReject(t, append(b, ' '))
	r := assessmentSame(t, assessmentFixture(), assessmentDirect())
	r.InputSnapshot.Assessment.Evidence[0].ID = "mutated"
	r.InputSnapshot.Assessment.Facts["invented"] = "yes"
	r.InputOrigins["assessment.evidence"] = findingpreview.InputOrigin{Source: "mutated"}
	assessmentSame(t, assessmentFixture(), assessmentDirect())
}
func FuzzAssessmentDecode(f *testing.F) {
	b, err := json.Marshal(assessmentFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"assessment":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeAssessment(b)
		if err != nil {
			_ = assessmentReject(t, b)
			return
		}
		if !r.PreviewOnly || r.ScoreResult == nil && r.AdapterState != "unsupported" {
			t.Fatalf("invalid successful state: %s", r.AdapterState)
		}
	})
}
