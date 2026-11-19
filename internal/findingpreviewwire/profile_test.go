package findingpreviewwire

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func profileFixture() map[string]any {
	m := fixture()
	m["schema_version"] = ProfileSchemaVersion
	m["profile"] = map[string]any{"id": "profile-a", "repo": "synthetic/repo", "environment": "production", "exposure": "internet", "authentication": "customer", "business_criticality": "critical", "max_outage_minutes": 60, "data_classification": "restricted", "integrity_impact": "high", "privilege_scope": "service_only"}
	m["binding"] = map[string]any{"finding_id": "finding-a", "asset_id": "asset-a", "cve": "CVE-2099-0001", "profile_id": "profile-a", "repo": "synthetic/repo"}
	return m
}
func profileDirect() findingpreview.Input {
	in := direct()
	in.Binding = findingpreview.Binding{FindingID: "finding-a", AssetID: "asset-a", CVE: "CVE-2099-0001", ProfileID: "profile-a", Repo: "synthetic/repo"}
	in.Profile = &model.EffectiveProfile{ID: "profile-a", Repo: "synthetic/repo", Environment: model.EnvironmentProduction, Exposure: model.ExposureInternet, Authentication: model.AuthCustomer, BusinessCriticality: model.RiskCritical, MaxOutageMinutes: 60, DataClassification: model.RiskRestricted, IntegrityImpact: model.RiskHigh, PrivilegeScope: model.PrivilegeServiceOnly}
	return in
}
func profileSame(t *testing.T, m map[string]any, in findingpreview.Input) findingpreview.Result {
	t.Helper()
	r, err := DecodeProfile(encoded(t, m))
	want, we := findingpreview.Calculate(in)
	if err != nil || we != nil || !reflect.DeepEqual(r, want) {
		t.Fatal("profile wire differs from independently constructed adapter input")
	}
	return r
}
func profileReject(t *testing.T, b []byte) Error {
	t.Helper()
	r, err := DecodeProfile(b)
	e, ok := err.(Error)
	if !ok || !reflect.DeepEqual(r, findingpreview.Result{}) {
		t.Fatalf("expected fixed error and zero result; got error type %T", err)
	}
	if !oneOf(string(e), "size", "encoding", "syntax", "null", "type", "depth", "duplicate", "required", "string", "time", "number", "field", "version", "enum", "binding", "positive", "adapter") {
		t.Fatal("unexpected diagnostic code")
	}
	return e
}
func TestR01ExplicitProfileMatchesFullAdapter(t *testing.T) {
	r := profileSame(t, profileFixture(), profileDirect())
	if r.InputSnapshot == nil || r.ScoreResult == nil || !r.PreviewOnly || r.InputOrigins["profile.exposure"].Source != "bound_resolved_profile" {
		t.Fatal("missing bound profile")
	}
	if r.InputSnapshot.Profile.Owner != "" || r.InputSnapshot.Profile.ReviewedAt != nil || r.InputSnapshot.Profile.Extends != "" {
		t.Fatal("metadata invented")
	}
}
func TestR02ExplicitUnknownIsNotAbsent(t *testing.T) {
	m := profileFixture()
	p := m["profile"].(map[string]any)
	in := profileDirect()
	for _, key := range []string{"environment", "exposure", "authentication", "business_criticality", "data_classification", "integrity_impact", "privilege_scope"} {
		p[key] = "unknown"
	}
	p["max_outage_minutes"] = 0
	in.Profile = &model.EffectiveProfile{ID: "profile-a", Repo: "synthetic/repo", Environment: model.EnvironmentUnknown, Exposure: model.ExposureUnknown, Authentication: model.AuthUnknown, BusinessCriticality: model.RiskUnknown, DataClassification: model.RiskUnknown, IntegrityImpact: model.RiskUnknown, PrivilegeScope: model.PrivilegeUnknown}
	r := profileSame(t, m, in)
	if slices.Contains(r.MissingInputs, "profile") || r.ScoreResult.Status != "provisional" {
		t.Fatal("unknown confused with absent or confirmed")
	}
	for _, key := range []string{"profile.exposure", "profile.max_outage_minutes", "assessment", "cvss"} {
		if !slices.Contains(r.MissingInputs, key) {
			t.Fatalf("missing %s", key)
		}
	}
}
func TestR03ExactVocabularyAndRequiredFields(t *testing.T) {
	risk := []string{"", "unknown", "low", "standard", "high", "critical", "restricted", "confidential", "internal", "public"}
	cases := []struct {
		key    string
		values []string
		set    func(*model.EffectiveProfile, string)
	}{
		{"environment", []string{"", "production", "staging", "development", "ci", "unknown"}, func(p *model.EffectiveProfile, v string) { p.Environment = model.ServiceEnvironment(v) }},
		{"exposure", []string{"", "internet", "partner", "internal", "isolated", "unknown"}, func(p *model.EffectiveProfile, v string) { p.Exposure = model.ExposurePath(v) }},
		{"authentication", []string{"", "none", "customer", "employee", "privileged", "unknown"}, func(p *model.EffectiveProfile, v string) { p.Authentication = model.AuthenticationBoundary(v) }},
		{"business_criticality", risk, func(p *model.EffectiveProfile, v string) { p.BusinessCriticality = model.RiskLevel(v) }},
		{"data_classification", risk, func(p *model.EffectiveProfile, v string) { p.DataClassification = model.RiskLevel(v) }},
		{"integrity_impact", risk, func(p *model.EffectiveProfile, v string) { p.IntegrityImpact = model.RiskLevel(v) }},
		{"privilege_scope", []string{"", "shared_control", "production_write", "service_only", "sandbox", "unknown"}, func(p *model.EffectiveProfile, v string) { p.PrivilegeScope = model.PrivilegeScope(v) }},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			for _, v := range c.values {
				m := profileFixture()
				m["profile"].(map[string]any)[c.key] = v
				in := profileDirect()
				c.set(in.Profile, v)
				profileSame(t, m, in)
			}
			for _, v := range []any{"typo", "UNKNOWN", "unknown ", " customer", 1, true, map[string]any{}, []any{}} {
				m := profileFixture()
				m["profile"].(map[string]any)[c.key] = v
				_ = profileReject(t, encoded(t, m))
			}
		})
	}
	for _, object := range []string{"profile", "binding"} {
		for key := range profileFixture()[object].(map[string]any) {
			m := profileFixture()
			delete(m[object].(map[string]any), key)
			if profileReject(t, encoded(t, m)) != Error("required") {
				t.Fatalf("missing %s.%s must be required", object, key)
			}
		}
	}
	for _, obj := range []string{"profile", "binding"} {
		m := profileFixture()
		delete(m, obj)
		_ = profileReject(t, encoded(t, m))
	}
}
func TestR04CanonicalIntegerBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 60, 61, 240, 241, 1440, 1441, 2147483647} {
		m := profileFixture()
		m["profile"].(map[string]any)["max_outage_minutes"] = n
		in := profileDirect()
		in.Profile.MaxOutageMinutes = n
		profileSame(t, m, in)
	}
	for _, n := range []string{`-1`, `-0`, `2147483648`, `1.5`, `"1"`, `1e2`, `0e0`, `1.0`, `+1`, `01`, `true`, `1e99999999999999999999999`, strings.Repeat("9", 256)} {
		raw := strings.Replace(string(encoded(t, profileFixture())), `"max_outage_minutes":60`, `"max_outage_minutes":`+n, 1)
		_ = profileReject(t, []byte(raw))
	}
}
func TestR05AllBindingsMustMatch(t *testing.T) {
	for _, key := range []string{"finding_id", "asset_id", "cve", "profile_id", "repo"} {
		m := profileFixture()
		m["binding"].(map[string]any)[key] = "other"
		if profileReject(t, encoded(t, m)) != Error("binding") {
			t.Fatal("binding mismatch not rejected")
		}
	}
	m := profileFixture()
	m["finding"].(map[string]any)["asset_id"] = "asset-b"
	m["asset"].(map[string]any)["id"] = "asset-b"
	_ = profileReject(t, encoded(t, m))
	m = profileFixture()
	m["profile"].(map[string]any)["repo"] = "different/repo"
	_ = profileReject(t, encoded(t, m))
	for _, key := range []string{"id", "repo"} {
		m := profileFixture()
		m["profile"].(map[string]any)[key] = " "
		_ = profileReject(t, encoded(t, m))
	}
}
func TestR06UnsupportedOnlyAfterFullValidation(t *testing.T) {
	for _, tc := range []struct{ category, cve string }{{"secret", ""}, {"code_scanning", "rule-a"}, {"vulnerability", "GHSA-xxxx-xxxx-xxxx"}, {"vulnerability", "cve-2099-0001"}, {"vulnerability", ""}} {
		m := profileFixture()
		f := m["finding"].(map[string]any)
		f["category"] = tc.category
		f["vulnerability_id"] = tc.cve
		m["binding"].(map[string]any)["cve"] = tc.cve
		in := profileDirect()
		in.Finding.Category = tc.category
		in.Finding.VulnerabilityID = tc.cve
		in.Binding.CVE = tc.cve
		r := profileSame(t, m, in)
		if r.AdapterState != "unsupported" || r.ScoreResult != nil || r.InputSnapshot != nil {
			t.Fatal("unsupported gained score")
		}
		m["profile"].(map[string]any)["exposure"] = "invalid"
		_ = profileReject(t, encoded(t, m))
		m["profile"].(map[string]any)["exposure"] = "internet"
		m["binding"].(map[string]any)["profile_id"] = "other"
		_ = profileReject(t, encoded(t, m))
		m["binding"].(map[string]any)["profile_id"] = "profile-a"
		addEvidence(m, "epss")["probability"] = -1
		_ = profileReject(t, encoded(t, m))
	}
}
func TestR07BaseContractRemainsClosed(t *testing.T) {
	m := profileFixture()
	_ = reject(t, encoded(t, m))
	m["schema_version"] = SchemaVersion
	_ = reject(t, encoded(t, m))
	_ = profileReject(t, encoded(t, m))
	for _, key := range []string{"profile", "binding"} {
		m := fixture()
		m[key] = profileFixture()[key]
		_ = reject(t, encoded(t, m))
	}
	m = fixture()
	m["schema_version"] = ProfileSchemaVersion
	_ = reject(t, encoded(t, m))
	_ = profileReject(t, encoded(t, m))
	sameAdapter(t, fixture(), direct())
}
func TestR08NoContextInference(t *testing.T) {
	m := profileFixture()
	in := profileDirect()
	before := profileSame(t, m, in)
	f := m["finding"].(map[string]any)
	f["severity"] = "critical"
	f["source_status"] = "resolved"
	f["triage_status"] = "closed"
	m["asset"].(map[string]any)["environment"] = "development"
	m["asset"].(map[string]any)["criticality"] = "public"
	in.Finding.Severity = model.Severity("critical")
	in.Finding.SourceStatus = model.SourceStatusResolved
	in.Finding.TriageStatus = model.TriageStatusClosed
	in.Asset.Environment = "development"
	in.Asset.Criticality = "public"
	after := profileSame(t, m, in)
	if !reflect.DeepEqual(before.InputSnapshot, after.InputSnapshot) || !reflect.DeepEqual(before.ScoreResult, after.ScoreResult) {
		t.Fatal("context altered scoring inputs")
	}
	m["profile"].(map[string]any)["exposure"] = "isolated"
	in.Profile.Exposure = model.ExposureIsolated
	profileSame(t, m, in)
	if after.InputSnapshot.CVSSKnown || after.InputSnapshot.Assessment.Applicability != "unknown" {
		t.Fatal("missing inputs inferred")
	}
}
func TestR09EvidenceParityWithProfile(t *testing.T) {
	for _, age := range []time.Duration{24 * time.Hour, 72 * time.Hour, 72*time.Hour + time.Nanosecond} {
		for _, kevAge := range []time.Duration{24 * time.Hour, 74 * time.Hour} {
			for _, reported := range []bool{false, true} {
				m := profileFixture()
				in := profileDirect()
				e := addEvidence(m, "epss")
				k := addEvidence(m, "kev")
				p := in.At.Add(-age)
				o := p
				kp := in.At.Add(-kevAge)
				ko := kp
				ka := kp.Add(-time.Hour)
				zero := 0.0
				e["published_at"] = p.Format(time.RFC3339Nano)
				e["observed_at"] = o.Format(time.RFC3339Nano)
				e["reported_fresh"] = reported
				k["published_at"] = kp.Format(time.RFC3339Nano)
				k["observed_at"] = ko.Format(time.RFC3339Nano)
				k["date_added"] = ka.Format(time.RFC3339Nano)
				k["reported_fresh"] = reported
				in.Enrichment = &model.FindingEnrichment{CVEID: in.Finding.VulnerabilityID, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: p, ObservedAt: o, Fresh: reported, EPSS: &zero}, KEV: &model.SecurityEnrichmentEvidence{Source: "kev", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: kp, ObservedAt: ko, Fresh: reported, KEV: true, KEVDateAdded: &ka}}
				r := profileSame(t, m, in)
				if r.EPSS.Fresh != (age <= 72*time.Hour) || r.KEV.HistoricalPositive != (kevAge > 72*time.Hour) {
					t.Fatal("changed evidence semantics")
				}
			}
		}
	}
	r := profileSame(t, profileFixture(), profileDirect())
	if r.InputSnapshot.Threat.EPSS != nil || r.InputSnapshot.Threat.KEVKnown {
		t.Fatal("missing evidence became known")
	}
}
func TestR10StructurePrivacyAndBounds(t *testing.T) {
	const sentinel = "PRIVATE_SENTINEL"
	for _, obj := range []string{"profile", "binding"} {
		for _, key := range []string{"extends", "owner", "owner_team", "reviewed_by", "reviewed_at", "review_due_at", "assessment", "cvss", "raw_ref", "secret", sentinel} {
			m := profileFixture()
			m[obj].(map[string]any)[key] = sentinel
			err := profileReject(t, encoded(t, m))
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("payload leak")
			}
		}
		for key := range profileFixture()[obj].(map[string]any) {
			m := profileFixture()
			m[obj].(map[string]any)[key] = nil
			_ = profileReject(t, encoded(t, m))
			m = profileFixture()
			target := m[obj].(map[string]any)
			value := target[key]
			delete(target, key)
			target[strings.ToUpper(key)] = value
			_ = profileReject(t, encoded(t, m))
		}
		for _, bad := range []any{nil, []any{}, 1, "text"} {
			m := profileFixture()
			m[obj] = bad
			_ = profileReject(t, encoded(t, m))
		}
		for _, dupe := range []string{`"repo":"other",`, `"\u0072epo":"other",`} {
			b := strings.Replace(string(encoded(t, profileFixture())), `"`+obj+`":{`, `"`+obj+`":{`+dupe, 1)
			if profileReject(t, []byte(b)) != Error("duplicate") {
				t.Fatal("decoded duplicate accepted")
			}
		}
	}
	for _, key := range []string{"assessment", "cvss", "raw_ref", "secret"} {
		m := profileFixture()
		m[key] = sentinel
		_ = profileReject(t, encoded(t, m))
	}
	for _, obj := range []string{"profile", "binding"} {
		for key, value := range profileFixture()[obj].(map[string]any) {
			if _, ok := value.(string); !ok {
				continue
			}
			m := profileFixture()
			limit := 256
			if key == "cve" {
				limit = 64
			}
			m[obj].(map[string]any)[key] = strings.Repeat("x", limit+1)
			if profileReject(t, encoded(t, m)) != Error("string") {
				t.Fatalf("length boundary not enforced for %s.%s", obj, key)
			}
		}
	}
	for _, key := range []string{"id", "repo"} {
		m := profileFixture()
		in := profileDirect()
		s := strings.Repeat("界", 85) + "x"
		m["profile"].(map[string]any)[key] = s
		if key == "id" {
			m["binding"].(map[string]any)["profile_id"] = s
			in.Profile.ID = s
			in.Binding.ProfileID = s
		} else {
			m["binding"].(map[string]any)["repo"] = s
			in.Profile.Repo = s
			in.Binding.Repo = s
		}
		profileSame(t, m, in)
	}
	for _, obj := range []string{"profile", "binding"} {
		m := profileFixture()
		key := "repo"
		m[obj].(map[string]any)[key] = "bad\x00"
		_ = profileReject(t, encoded(t, m))
	}
	b := encoded(t, profileFixture())
	padded := append(append([]byte{}, b...), []byte(strings.Repeat(" ", MaxBytes-len(b)))...)
	if _, err := DecodeProfile(padded); err != nil {
		t.Fatal("inclusive size rejected")
	}
	if profileReject(t, append(padded, ' ')) != Error("size") {
		t.Fatal("size limit changed")
	}
	deep := `{"profile":` + strings.Repeat(`{"x":`, MaxDepth) + `0` + strings.Repeat(`}`, MaxDepth) + `}`
	if profileReject(t, []byte(deep)) != Error("depth") {
		t.Fatal("depth limit weakened")
	}
	for _, raw := range [][]byte{append(append([]byte{}, b...), 0xff), append(append([]byte{}, b...), []byte(" {}")...), []byte(`[]`), []byte(`{"profile":"\ud800"}`)} {
		_ = profileReject(t, raw)
	}
}
func TestR11DeterministicNonSharedResults(t *testing.T) {
	m := profileFixture()
	addEvidence(m, "epss")
	raw := encoded(t, m)
	copyRaw := append([]byte{}, raw...)
	a, ae := DecodeProfile(raw)
	b, be := DecodeProfile(raw)
	if ae != nil || be != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("not deterministic")
	}
	a.InputSnapshot.Profile.ID = "changed"
	a.InputSnapshot.Assessment.Facts["changed"] = "yes"
	*a.InputSnapshot.Threat.EPSS = .9
	a.InputOrigins["profile.exposure"] = findingpreview.InputOrigin{}
	a.MissingInputs[0] = "changed"
	c, ce := DecodeProfile(raw)
	if ce != nil || !reflect.DeepEqual(b, c) || !reflect.DeepEqual(raw, copyRaw) {
		t.Fatal("shared result or mutated input")
	}
}
func FuzzR12ProfileFixedDiagnostics(f *testing.F) {
	for _, m := range []map[string]any{profileFixture(), fixture()} {
		b, err := json.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	m := profileFixture()
	addEvidence(m, "epss")
	b, err := json.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"profile":{"id":1,"id":2}}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, e := DecodeProfile(b)
		if e != nil {
			_ = profileReject(t, b)
			if strings.Contains(fmt.Sprint(r), "PRIVATE_SENTINEL") {
				t.Fatal("partial payload")
			}
		}
	})
}
