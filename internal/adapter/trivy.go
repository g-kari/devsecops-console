package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const (
	trivyMaxInputBytes     = 10 << 20
	trivyMaxResults        = 2048
	trivyMaxFindings       = 20000
	trivyMaxFieldBytes     = 4096
	trivyMaxOptionBytes    = 256
	trivyMaxCanonicalBytes = 20000
)

// TrivyOptions identifies the trusted import scope and observation run. Scope
// must distinguish the CI/project/machine owning the artifact. Neither the
// report's timestamps nor a filesystem path alone establish a trusted scope.
type TrivyOptions struct {
	Scope      string
	RunID      string
	ObservedAt time.Time
}

// These deliberately projected types do not retain ImageConfig, secret matches,
// misconfiguration code, licenses, descriptions, references or arbitrary custom
// payloads. The imported schema is Trivy's SchemaVersion 2 report, not its cache
// or database schema: https://github.com/aquasecurity/trivy/blob/v0.68.1/pkg/types/report.go
// and https://github.com/aquasecurity/trivy/blob/v0.68.1/pkg/types/vulnerability.go.
type trivyReport struct {
	SchemaVersion int
	ArtifactName  string
	ArtifactType  string
	Metadata      struct {
		ImageID     string
		RepoDigests []string
	}
	Results trivyResults
}

type trivyResult struct {
	Target          string
	Class           string
	Type            string
	Vulnerabilities trivyVulnerabilities
}

type trivyVulnerability struct {
	VulnerabilityID string
	PkgID           string
	PkgName         string
	PkgPath         string
	PkgIdentifier   struct {
		PURL string
		UID  string
	}
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
	PrimaryURL       string
}

type trivyResults []*trivyResult
type trivyVulnerabilities []*trivyVulnerability

func (r *trivyResults) UnmarshalJSON(data []byte) error {
	values, err := decodeTrivyArray[*trivyResult](data, trivyMaxResults)
	if err != nil {
		return fmt.Errorf("decode trivy results: %w", err)
	}
	*r = values
	return nil
}

func (v *trivyVulnerabilities) UnmarshalJSON(data []byte) error {
	values, err := decodeTrivyArray[*trivyVulnerability](data, trivyMaxFindings)
	if err != nil {
		return fmt.Errorf("decode trivy vulnerabilities: %w", err)
	}
	*v = values
	return nil
}

func decodeTrivyArray[T any](data []byte, limit int) ([]T, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errors.New("expected an array")
	}
	var values []T
	for decoder.More() {
		if len(values) >= limit {
			return nil, errors.New("array entry limit exceeded")
		}
		var value T
		if err := decoder.Decode(&value); err != nil {
			// JSON errors can contain an attacker-controlled field value. Do not
			// propagate those errors into import logs or the CLI response.
			return nil, errors.New("invalid array entry")
		}
		values = append(values, value)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, errors.New("invalid array ending")
	}
	return values, nil
}

// ParseTrivyJSON normalizes one bounded offline Trivy SchemaVersion 2 JSON
// report. Only container_image and explicitly scoped filesystem vulnerability
// results are supported. It performs no scanner execution, network requests or
// persistence. Secret, configuration, license and experimental suppressed
// findings are intentionally ignored, including their raw values.
//
// Returned data is partial coverage, even for an empty report. Callers must not
// resolve absent findings from this import. Trivy's vulnerability Status means
// fix availability, so imported detections always remain source-active.
// Errors are sanitized and return no partial findings.
func ParseTrivyJSON(reader io.Reader, options TrivyOptions) ([]model.SecurityFinding, error) {
	options.Scope = strings.TrimSpace(options.Scope)
	options.RunID = strings.TrimSpace(options.RunID)
	options.ObservedAt = options.ObservedAt.UTC()
	if !safeTrivyField(options.Scope, true, trivyMaxOptionBytes) || !safeTrivyField(options.RunID, true, trivyMaxOptionBytes) || options.ObservedAt.IsZero() || options.ObservedAt.Year() < 1 || options.ObservedAt.Year() > 9999 {
		return nil, errors.New("parse trivy JSON: safe scope, run ID and observation time are required")
	}
	if reader == nil {
		return nil, errors.New("parse trivy JSON: report reader is required")
	}
	body, err := io.ReadAll(io.LimitReader(reader, trivyMaxInputBytes+1))
	if err != nil {
		// Reader failures can also contain attacker-controlled payloads.
		return nil, errors.New("parse trivy JSON: unable to read report")
	}
	if len(body) > trivyMaxInputBytes {
		return nil, errors.New("parse trivy JSON: report exceeds 10 MiB")
	}
	if !utf8.Valid(body) {
		return nil, errors.New("parse trivy JSON: report is not valid UTF-8")
	}
	var report *trivyReport
	// Unmarshal, unlike a single Decoder.Decode call, rejects additional JSON
	// documents or non-whitespace after the report.
	if err := json.Unmarshal(body, &report); err != nil || report == nil {
		return nil, errors.New("parse trivy JSON: invalid report document")
	}
	if report.SchemaVersion != 2 {
		return nil, errors.New("parse trivy JSON: SchemaVersion 2 is required")
	}
	artifactID, err := trivyArtifactIdentity(report)
	if err != nil {
		return nil, fmt.Errorf("parse trivy JSON artifact: %w", err)
	}
	asset := model.Asset{
		ID:   stableSecurityID("asset", "trivy", options.Scope, report.ArtifactType, artifactID),
		Type: report.ArtifactType, Provider: "trivy", Account: options.Scope, NativeID: artifactID,
	}
	var findings []model.SecurityFinding
	seen := make(map[string]string)
	entryCount := 0
	for resultIndex, result := range report.Results {
		if result == nil {
			return nil, fmt.Errorf("parse trivy JSON: result %d is null", resultIndex)
		}
		if !safeTrivyField(result.Target, true, trivyMaxFieldBytes) {
			return nil, fmt.Errorf("parse trivy JSON: result %d has an invalid or missing target", resultIndex)
		}
		entryCount += len(result.Vulnerabilities)
		if entryCount > trivyMaxFindings {
			return nil, errors.New("parse trivy JSON: vulnerability entry limit exceeded")
		}
		if len(result.Vulnerabilities) == 0 {
			// Other scanner categories are not interpreted as vulnerability
			// evidence, nor as proof of complete/clean vulnerability coverage.
			continue
		}
		if (result.Class != "os-pkgs" && result.Class != "lang-pkgs") || !safeTrivyField(result.Target, true, trivyMaxFieldBytes) || !safeTrivyField(result.Type, true, trivyMaxFieldBytes) {
			return nil, fmt.Errorf("parse trivy JSON: result %d has invalid vulnerability target, class or type", resultIndex)
		}
		for vulnerabilityIndex, vulnerability := range result.Vulnerabilities {
			normalized, err := normalizeTrivyVulnerability(asset, result, vulnerability, options)
			if err != nil {
				return nil, fmt.Errorf("parse trivy JSON result %d vulnerability %d: %w", resultIndex, vulnerabilityIndex, err)
			}
			if fingerprint, exists := seen[normalized.Finding.ID]; exists {
				if fingerprint != normalized.Observation.Fingerprint {
					return nil, errors.New("parse trivy JSON: conflicting duplicate vulnerability identity")
				}
				continue
			}
			seen[normalized.Finding.ID] = normalized.Observation.Fingerprint
			findings = append(findings, normalized)
		}
	}
	return findings, nil
}

func trivyArtifactIdentity(report *trivyReport) (string, error) {
	if !safeTrivyField(report.ArtifactName, false, trivyMaxFieldBytes) {
		return "", errors.New("invalid artifact name")
	}
	switch report.ArtifactType {
	case "filesystem":
		if !safeTrivyField(report.ArtifactName, true, trivyMaxFieldBytes) {
			return "", errors.New("filesystem artifact name is required")
		}
		return report.ArtifactName, nil
	case "container_image":
		if report.Metadata.ImageID != "" {
			if !validTrivyDigest(report.Metadata.ImageID) {
				return "", errors.New("invalid immutable image ID")
			}
			return strings.ToLower(report.Metadata.ImageID), nil
		}
		if len(report.Metadata.RepoDigests) == 0 || len(report.Metadata.RepoDigests) > 128 {
			return "", errors.New("immutable image ID or repository digest is required")
		}
		var imageDigest string
		for _, reference := range report.Metadata.RepoDigests {
			if !safeTrivyField(reference, true, trivyMaxFieldBytes) {
				return "", errors.New("invalid repository digest")
			}
			repository, digest, found := strings.Cut(reference, "@")
			if !found || repository == "" || !validTrivyDigest(digest) {
				return "", errors.New("invalid repository digest")
			}
			digest = strings.ToLower(digest)
			if imageDigest != "" && imageDigest != digest {
				return "", errors.New("ambiguous immutable image digests")
			}
			imageDigest = digest
		}
		// Registry aliases and report ordering do not change artifact identity.
		return imageDigest, nil
	default:
		return "", errors.New("unsupported artifact type")
	}
}

func validTrivyDigest(value string) bool {
	algorithm, digest, ok := strings.Cut(value, ":")
	if !ok || (algorithm != "sha256" || len(digest) != 64) && (algorithm != "sha512" || len(digest) != 128) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func normalizeTrivyVulnerability(asset model.Asset, result *trivyResult, vulnerability *trivyVulnerability, options TrivyOptions) (model.SecurityFinding, error) {
	if vulnerability == nil {
		return model.SecurityFinding{}, errors.New("null vulnerability")
	}
	for _, field := range []struct {
		value    string
		required bool
	}{
		{vulnerability.VulnerabilityID, true}, {vulnerability.PkgName, true},
		{vulnerability.InstalledVersion, true}, {vulnerability.Severity, true},
		{vulnerability.PkgID, false}, {vulnerability.PkgPath, false},
		{vulnerability.PkgIdentifier.PURL, false}, {vulnerability.PkgIdentifier.UID, false},
		{vulnerability.FixedVersion, false}, {vulnerability.Title, false}, {vulnerability.PrimaryURL, false},
	} {
		if !safeTrivyField(field.value, field.required, trivyMaxFieldBytes) {
			return model.SecurityFinding{}, errors.New("invalid or missing vulnerability field")
		}
	}
	var severity model.Severity
	switch vulnerability.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
		severity = model.Severity(strings.ToLower(vulnerability.Severity))
	default:
		return model.SecurityFinding{}, errors.New("unsupported vulnerability severity")
	}
	nativeID := stableSecurityID("trivy-native", options.Scope, asset.Type, asset.NativeID,
		result.Target, result.Class, result.Type, vulnerability.PkgID, vulnerability.PkgName,
		vulnerability.PkgPath, vulnerability.PkgIdentifier.PURL, vulnerability.PkgIdentifier.UID,
		vulnerability.VulnerabilityID, vulnerability.InstalledVersion)
	findingID := stableSecurityID("finding", "trivy", options.Scope, nativeID)
	ecosystem := trivyEcosystem(result.Type)
	packagePath := vulnerability.PkgPath
	if packagePath == "" {
		packagePath = result.Target
	}
	canonical, err := json.Marshal([4]string{strings.ToUpper(vulnerability.VulnerabilityID), ecosystem, vulnerability.PkgName, packagePath})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode correlation tuple: %w", err)
	}
	if len(canonical) > trivyMaxCanonicalBytes {
		return model.SecurityFinding{}, errors.New("encoded correlation key exceeds field limit")
	}
	rawRef := safeTrivyURL(vulnerability.PrimaryURL)
	// Stable, selected evidence excludes local run/time, raw input, secret
	// categories and arbitrary report fields. A new run retains its own
	// Observation while repeated evidence has the same fingerprint.
	evidence, err := json.Marshal(struct {
		NativeID, Title, VulnerabilityID, PackageName, Ecosystem string
		InstalledVersion, FixedVersion, Severity, RawRef         string
	}{nativeID, vulnerability.Title, vulnerability.VulnerabilityID, vulnerability.PkgName,
		ecosystem, vulnerability.InstalledVersion, vulnerability.FixedVersion, string(severity), rawRef})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode selected evidence: %w", err)
	}
	digest := sha256.Sum256(evidence)
	fingerprint := hex.EncodeToString(digest[:])
	return model.SecurityFinding{
		Asset: asset,
		Finding: model.Finding{
			ID: findingID, Category: "vulnerability", AssetID: asset.ID, CanonicalKey: string(canonical),
			Severity: severity, TriageStatus: model.TriageStatusNew, SourceStatus: model.SourceStatusActive,
			FirstSeen: options.ObservedAt, LastSeen: options.ObservedAt,
			Title: vulnerability.Title, VulnerabilityID: vulnerability.VulnerabilityID,
			PackageName: vulnerability.PkgName, PackageEcosystem: ecosystem,
			InstalledVersion: vulnerability.InstalledVersion, FixedVersion: vulnerability.FixedVersion,
		},
		Observation: model.Observation{
			ID:     stableSecurityID("observation", findingID, options.RunID, fingerprint),
			Source: "trivy", Account: options.Scope, SourceFindingID: nativeID,
			FindingID: findingID, IngestRunID: options.RunID, RawRef: rawRef,
			Fingerprint: fingerprint, ObservedAt: options.ObservedAt,
		},
	}, nil
}

func safeTrivyField(value string, required bool, maxBytes int) bool {
	return (!required || strings.TrimSpace(value) != "") && len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool {
		return r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}

func safeTrivyURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(value, "#") || !safeTrivyField(parsed.Path, false, trivyMaxFieldBytes) {
		return ""
	}
	encoded := parsed.String()
	if len(encoded) > trivyMaxFieldBytes {
		return ""
	}
	return encoded
}

func trivyEcosystem(targetType string) string {
	// Trivy target types describe analyzers; these familiar ecosystem names
	// align obvious aliases with Dependabot for correlation hints only.
	switch targetType {
	case "npm", "node-pkg", "yarn", "pnpm", "bun":
		return "npm"
	case "gomod", "gobinary":
		return "go"
	case "pip", "pipenv", "poetry", "uv", "python-pkg":
		return "pip"
	case "bundler", "gemspec":
		return "rubygems"
	case "cargo", "rustbinary":
		return "rust"
	case "jar", "pom", "gradle", "sbt":
		return "maven"
	case "nuget", "dotnet-core", "packages-props":
		return "nuget"
	case "composer-vendor":
		return "composer"
	default:
		return strings.ToLower(targetType)
	}
}
