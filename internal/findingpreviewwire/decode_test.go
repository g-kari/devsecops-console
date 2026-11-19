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

func fixture() map[string]any {
	return map[string]any{"schema_version": SchemaVersion, "as_of": "2026-11-08T00:00:00Z", "finding": map[string]any{"id": "finding-a", "asset_id": "asset-a", "category": "vulnerability", "vulnerability_id": "CVE-2099-0001"}, "asset": map[string]any{"id": "asset-a"}}
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func accept(t *testing.T, m map[string]any) findingpreview.Result {
	t.Helper()
	r, e := Decode(encoded(t, m))
	if e != nil || r.ScoreResult == nil || r.AdapterState != "eligible" {
		t.Fatalf("expected eligible: %v %s", e, r.AdapterState)
	}
	return r
}
func reject(t *testing.T, b []byte) Error {
	t.Helper()
	r, e := Decode(b)
	code, ok := e.(Error)
	if !ok || !reflect.DeepEqual(r, findingpreview.Result{}) {
		t.Fatalf("expected fixed error and zero result; error type %T", e)
	}
	return code
}
func evidenceFixture() map[string]any {
	return map[string]any{"version": "fixture-v1", "run_id": "fixture-run", "published_at": "2026-11-07T00:00:00Z", "observed_at": "2026-11-07T01:00:00Z"}
}
func addEvidence(m map[string]any, source string) map[string]any {
	e := evidenceFixture()
	if source == "epss" {
		e["probability"] = 0.0
	} else {
		e["positive"] = true
		e["date_added"] = "2026-11-06T00:00:00Z"
	}
	enrichment, ok := m["enrichment"].(map[string]any)
	if !ok {
		enrichment = map[string]any{"cve_id": "CVE-2099-0001"}
		m["enrichment"] = enrichment
	}
	enrichment[source] = e
	return e
}
func direct() findingpreview.Input {
	return findingpreview.Input{At: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), Finding: model.Finding{ID: "finding-a", AssetID: "asset-a", Category: "vulnerability", VulnerabilityID: "CVE-2099-0001"}, Asset: model.Asset{ID: "asset-a"}}
}
func sameAdapter(t *testing.T, m map[string]any, in findingpreview.Input) findingpreview.Result {
	t.Helper()
	r, e := Decode(encoded(t, m))
	want, we := findingpreview.Calculate(in)
	if e != nil || we != nil || !reflect.DeepEqual(r, want) {
		t.Fatal("wire result differs from independently constructed adapter input")
	}
	return r
}

func TestW01MinimalMatchesAdapter(t *testing.T) {
	r := sameAdapter(t, fixture(), direct())
	for _, key := range []string{"profile", "assessment", "cvss", "epss", "kev"} {
		if !slices.Contains(r.MissingInputs, key) {
			t.Fatalf("missing %s", key)
		}
	}
	if !r.PreviewOnly || r.InputSnapshot.Technical.Confidentiality != (model.Interval{Low: 0, High: 1}) {
		t.Fatal("lost unknown intervals")
	}
}
func TestW02ZeroIsNotMissing(t *testing.T) {
	m := fixture()
	addEvidence(m, "epss")
	r := accept(t, m)
	if r.InputSnapshot.Threat.EPSS == nil || *r.InputSnapshot.Threat.EPSS != 0 || slices.Contains(r.MissingInputs, "epss") {
		t.Fatal("zero lost")
	}
	if accept(t, fixture()).InputSnapshot.Threat.EPSS != nil {
		t.Fatal("missing became zero")
	}
}
func TestW03IndependentClocksAndFullAdapterParity(t *testing.T) {
	for _, hours := range []time.Duration{24, 72, 73} {
		for _, kevHours := range []time.Duration{24, 74} {
			t.Run(fmt.Sprintf("epss_%d_kev_%d", hours, kevHours), func(t *testing.T) {
				m := fixture()
				e := addEvidence(m, "epss")
				k := addEvidence(m, "kev")
				in := direct()
				zero := 0.0
				pub := in.At.Add(-hours * time.Hour)
				obs := pub
				kp := in.At.Add(-kevHours * time.Hour)
				ko := kp
				ka := kp.Add(-time.Hour)
				e["published_at"] = pub.Format(time.RFC3339Nano)
				e["observed_at"] = obs.Format(time.RFC3339Nano)
				e["reported_fresh"] = true
				e["percentile"] = 0.0
				k["published_at"] = kp.Format(time.RFC3339Nano)
				k["observed_at"] = ko.Format(time.RFC3339Nano)
				k["date_added"] = ka.Format(time.RFC3339Nano)
				in.Enrichment = &model.FindingEnrichment{CVEID: in.Finding.VulnerabilityID, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: pub, ObservedAt: obs, Fresh: true, EPSS: &zero, Percentile: &zero}, KEV: &model.SecurityEnrichmentEvidence{Source: "kev", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: kp, ObservedAt: ko, KEV: true, KEVDateAdded: &ka}}
				r := sameAdapter(t, m, in)
				if r.EPSS.Fresh != (hours <= 72) || r.KEV.Fresh != (kevHours <= 72) || r.KEV.HistoricalPositive != (kevHours > 72) {
					t.Fatal("freshness changed")
				}
			})
		}
	}
	m := fixture()
	e := addEvidence(m, "epss")
	e["published_at"] = "2026-11-04T23:59:59.999999999Z"
	if accept(t, m).EPSS.Fresh {
		t.Fatal("72h plus nanosecond must be stale")
	}
}
func TestW04UnsupportedIsNotZero(t *testing.T) {
	for _, c := range []struct{ category, cve string }{{"secret", ""}, {"code_scanning", "rule-a"}, {"vulnerability", "GHSA-xxxx-xxxx-xxxx"}, {"vulnerability", "cve-2099-0001"}, {"vulnerability", "CVE-2099-001"}} {
		m := fixture()
		f := m["finding"].(map[string]any)
		f["category"] = c.category
		f["vulnerability_id"] = c.cve
		in := direct()
		in.Finding.Category = c.category
		in.Finding.VulnerabilityID = c.cve
		r := sameAdapter(t, m, in)
		if r.AdapterState != "unsupported" || r.ScoreResult != nil || r.InputSnapshot != nil {
			t.Fatal("unsupported gained score")
		}
	}
}
func TestW05SemanticRejection(t *testing.T) {
	cases := map[string]func(map[string]any){
		"asset_binding": func(m map[string]any) { m["asset"].(map[string]any)["id"] = "other" },
		"provenance_binding": func(m map[string]any) {
			m["provenance"] = map[string]any{"finding_id": "other", "source": "fixture", "source_native_id": "fixture"}
		},
		"cve_binding": func(m map[string]any) {
			addEvidence(m, "epss")
			m["enrichment"].(map[string]any)["cve_id"] = "CVE-2099-0002"
		},
		"future":              func(m map[string]any) { addEvidence(m, "epss")["observed_at"] = "2026-11-09T00:00:00Z" },
		"reversed":            func(m map[string]any) { addEvidence(m, "epss")["published_at"] = "2026-11-07T02:00:00Z" },
		"missing_time":        func(m map[string]any) { delete(addEvidence(m, "epss"), "observed_at") },
		"missing_probability": func(m map[string]any) { delete(addEvidence(m, "epss"), "probability") },
		"false_kev":           func(m map[string]any) { addEvidence(m, "kev")["positive"] = false },
		"future_added":        func(m map[string]any) { addEvidence(m, "kev")["date_added"] = "2026-11-08T00:00:00Z" },
		"bad_severity":        func(m map[string]any) { m["finding"].(map[string]any)["severity"] = "CRITICAL" },
		"bad_status":          func(m map[string]any) { m["finding"].(map[string]any)["source_status"] = "closed" },
		"bad_triage":          func(m map[string]any) { m["finding"].(map[string]any)["triage_status"] = "safe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			mutate(m)
			_ = reject(t, encoded(t, m))
			m["finding"].(map[string]any)["category"] = "secret"
			_ = reject(t, encoded(t, m))
		})
	}
	for _, n := range []json.Number{"-0.1", "1.1", "1.00000000000000000000000000000000001", "1e999999", "1e-999999", "NaN", "Infinity"} {
		m := fixture()
		e := addEvidence(m, "epss")
		e["probability"] = 0
		b := strings.Replace(string(encoded(t, m)), `"probability":0`, `"probability":`+string(n), 1)
		_ = reject(t, []byte(b))
	}
	for _, s := range []string{"", "0001-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "2026-11-08T0:00:00Z", "2026-11-08T00:00:00", "2026-11-08T00:00:00+24:00", "2026-11-08T00:00:00+00:60", "2026-11-08T00:00:00,1Z", "2026-11-08T00:00:00.1234567890Z", "9999-12-31T23:59:59-23:59"} {
		m := fixture()
		m["as_of"] = s
		_ = reject(t, encoded(t, m))
	}
}
func TestW06StructuralFailClosedAndNoPayloadInErrors(t *testing.T) {
	const secret = "SENTINEL_PRIVATE_PAYLOAD"
	for _, key := range []string{"profile", "assessment", "binding", "cvss", "raw_ref", "secret", secret, "Schema_Version"} {
		m := fixture()
		m[key] = secret
		r := reject(t, encoded(t, m))
		if strings.Contains(r.Error(), secret) {
			t.Fatal("payload in error")
		}
	}
	for _, path := range []string{"finding", "asset", "provenance", "enrichment", "epss", "kev"} {
		m := fixture()
		m["provenance"] = map[string]any{"finding_id": "finding-a", "source": "fixture", "source_native_id": "fixture"}
		e := addEvidence(m, "epss")
		k := addEvidence(m, "kev")
		var target map[string]any
		switch path {
		case "epss":
			target = e
		case "kev":
			target = k
		default:
			target = m[path].(map[string]any)
		}
		target["raw_ref"] = secret
		_ = reject(t, encoded(t, m))
	}
	base := string(encoded(t, fixture()))
	cases := []string{"", "[]", "null", base + " {}", base + "x", `{"schema_version":"x","schema_version":"y"}`, `{"id":"x","\u0069d":"y"}`, `{"a":{"b":1,"b":2}}`, strings.Replace(base, `"finding":{`, `"finding":{"id":"duplicate",`, 1), strings.Replace(base, `"id":"asset-a"`, `"ID":"asset-a"`, 1), strings.Replace(base, `"id":"asset-a"`, `"id":null`, 1), strings.Replace(base, `"id":"asset-a"`, `"id":123`, 1), strings.Replace(base, `"id":"asset-a"`, `"id":[]`, 1), strings.Replace(base, `"id":"asset-a"`, `"id":"\ud800"`, 1), strings.Replace(base, `"id":"asset-a"`, `"id":"\udc00"`, 1)}
	for _, b := range cases {
		_ = reject(t, []byte(b))
	}
	_ = reject(t, append([]byte(base), 0xff))
	for _, field := range []string{"schema_version", "as_of", "finding", "asset", "provenance", "enrichment"} {
		m := fixture()
		m[field] = nil
		_ = reject(t, encoded(t, m))
	}
	for _, field := range []string{"probability", "percentile", "reported_fresh", "version", "run_id", "published_at", "observed_at"} {
		for _, bad := range []any{nil, []any{}, map[string]any{}} {
			m := fixture()
			addEvidence(m, "epss")[field] = bad
			_ = reject(t, encoded(t, m))
		}
	}
	m := fixture()
	addEvidence(m, "epss")["probability"] = "0"
	_ = reject(t, encoded(t, m))
}
func TestW07ExactResourceBounds(t *testing.T) {
	b := encoded(t, fixture())
	padded := append(append([]byte{}, b...), []byte(strings.Repeat(" ", MaxBytes-len(b)))...)
	if _, e := Decode(padded); e != nil {
		t.Fatal("inclusive size bound rejected")
	}
	if reject(t, append(padded, ' ')) != Error("size") {
		t.Fatal("wrong size error")
	}
	for _, depth := range []int{MaxDepth, MaxDepth + 1} {
		raw := strings.Repeat(`{"x":`, depth) + `0` + strings.Repeat(`}`, depth)
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		_, e := readValue(d, 0)
		if depth == MaxDepth && e != nil || depth > MaxDepth && e != Error("depth") {
			t.Fatalf("depth %d got %v", depth, e)
		}
		_ = reject(t, []byte(raw)) // Parser depth acceptance does not bypass the closed schema.
	}
	for _, c := range []struct {
		field string
		max   int
	}{{"id", 256}, {"environment", 64}, {"criticality", 64}} {
		for _, extra := range []int{0, 1} {
			m := fixture()
			s := strings.Repeat("a", c.max+extra)
			m["asset"].(map[string]any)[c.field] = s
			if c.field == "id" {
				m["finding"].(map[string]any)["asset_id"] = s
			}
			if extra == 0 {
				accept(t, m)
			} else {
				_ = reject(t, encoded(t, m))
			}
		}
	}
	m := fixture()
	m["finding"].(map[string]any)["vulnerability_id"] = "CVE-2099-" + strings.Repeat("1", 55)
	accept(t, m)
	m["finding"].(map[string]any)["vulnerability_id"] = "CVE-2099-" + strings.Repeat("1", 56)
	_ = reject(t, encoded(t, m))
	for _, s := range []string{"", "  ", "a\x00b", "a\nb", "a\u007fb"} {
		m := fixture()
		m["finding"].(map[string]any)["id"] = s
		_ = reject(t, encoded(t, m))
	}
	m = fixture()
	m["finding"].(map[string]any)["id"] = strings.Repeat("界", 85) + "x"
	accept(t, m)
	m["finding"].(map[string]any)["id"] = strings.Repeat("界", 86)
	_ = reject(t, encoded(t, m))
}
func TestW08DeterministicNonSharedContextOnly(t *testing.T) {
	m := fixture()
	addEvidence(m, "epss")
	addEvidence(m, "kev")
	raw := encoded(t, m)
	before := append([]byte{}, raw...)
	a := accept(t, m)
	b := accept(t, m)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic")
	}
	*a.InputSnapshot.Threat.EPSS = .9
	a.InputOrigins["profile.exposure"] = findingpreview.InputOrigin{}
	a.MissingInputs[0] = "mutated"
	a.EPSS.RunID = "mutated"
	if !reflect.DeepEqual(b, accept(t, m)) {
		t.Fatal("shared output")
	}
	_, _ = Decode(raw)
	if !reflect.DeepEqual(raw, before) {
		t.Fatal("input mutated")
	}
	f := m["finding"].(map[string]any)
	f["severity"] = "critical"
	f["source_status"] = "resolved"
	f["triage_status"] = "closed"
	m["asset"].(map[string]any)["criticality"] = "critical"
	m["asset"].(map[string]any)["environment"] = "production"
	c := accept(t, m)
	if !reflect.DeepEqual(b.InputSnapshot, c.InputSnapshot) || !reflect.DeepEqual(b.ScoreResult, c.ScoreResult) {
		t.Fatal("context changed score")
	}
}
func TestProvenanceAndOffsetClockProjection(t *testing.T) {
	m := fixture()
	m["as_of"] = "2026-11-08T09:00:00+09:00"
	m["provenance"] = map[string]any{"finding_id": "finding-a", "source": "fixture-source", "source_native_id": "fixture-native"}
	in := direct()
	in.At = time.Date(2026, 11, 8, 9, 0, 0, 0, time.FixedZone("", 9*3600))
	in.Observation = &model.Observation{FindingID: "finding-a", Source: "fixture-source", SourceFindingID: "fixture-native"}
	sameAdapter(t, m, in)
}
func TestDecimalRangeWithoutRoundingBypass(t *testing.T) {
	for _, s := range []string{"0", "-0", "1", "1.0", "0.0001", "1e-2", "10e-1", "0.1e1", "0e99999999999999999999"} {
		if !unitDecimal(s) {
			t.Fatalf("rejected %s", s)
		}
	}
	for _, s := range []string{"-0.1", "1.00000000000000000001", "10", "1e99999999", "9e1"} {
		if unitDecimal(s) {
			t.Fatalf("accepted %s", s)
		}
	}
}
func FuzzDecodeNoPartialResults(f *testing.F) {
	f.Add([]byte(`{"schema_version":"finding-preview-base-v0.1"}`))
	f.Add([]byte(`{"a":{"a":1,"a":2}}`))
	f.Add([]byte{0xff})
	f.Add([]byte(`{"schema_version":"finding-preview-base-v0.1","as_of":"2026-11-08T00:00:00Z","finding":{"id":"f","asset_id":"a","category":"vulnerability","vulnerability_id":"CVE-2099-0001"},"asset":{"id":"a"}}`))
	f.Add([]byte(`{"schema_version":"finding-preview-base-v0.1","as_of":"2026-11-08T00:00:00Z","finding":{"id":"f","asset_id":"a","category":"vulnerability","vulnerability_id":"CVE-2099-0001"},"asset":{"id":"a"},"enrichment":{"cve_id":"CVE-2099-0001","epss":{"version":"v","run_id":"r","published_at":"2026-11-07T00:00:00Z","observed_at":"2026-11-07T01:00:00Z","probability":0.125}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, e := Decode(b)
		if e != nil {
			if _, ok := e.(Error); !ok || !reflect.DeepEqual(r, findingpreview.Result{}) {
				t.Fatal("nonconstant error or partial result")
			}
		}
	})
}

func TestEscapedUnicodeAndBackslashRemainExact(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`"\ud83d\ude00"`, "😀"}, {`"path\\uD800"`, `path\uD800`}, {`"literal�"`, "literal�"},
	} {
		base := string(encoded(t, fixture()))
		b := strings.Replace(base, `"finding-a"`, tc.raw, 1)
		r, err := Decode([]byte(b))
		if err != nil || r.FindingID != tc.want {
			t.Fatal("escaped Unicode projection changed")
		}
	}
}
func TestNonzeroProbabilitiesAndEvidenceOffsetsMatchAdapter(t *testing.T) {
	for _, offset := range []int{-9, 9} {
		in := direct()
		p := 0.125
		percentile := 0.875
		zone := time.FixedZone("", offset*3600)
		pub := in.At.Add(-24 * time.Hour).In(zone)
		obs := in.At.Add(-23 * time.Hour).In(zone)
		in.Enrichment = &model.FindingEnrichment{CVEID: in.Finding.VulnerabilityID, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "fixture-v1", RunID: "fixture-run", PublishedAt: pub, ObservedAt: obs, EPSS: &p, Percentile: &percentile}}
		m := fixture()
		e := addEvidence(m, "epss")
		e["probability"] = p
		e["percentile"] = percentile
		e["published_at"] = pub.Format(time.RFC3339Nano)
		e["observed_at"] = obs.Format(time.RFC3339Nano)
		sameAdapter(t, m, in)
	}
}
