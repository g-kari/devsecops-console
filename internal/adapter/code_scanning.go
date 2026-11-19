package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// CodeScanningOptions supplies the trusted GitHub.com repository and observation
// context. Offline response bodies do not establish their own repository scope.
type CodeScanningOptions struct {
	Repository string
	RunID      string
	ObservedAt time.Time
}

// Only selected alert metadata is decoded. Source snippets, messages, rule
// descriptions, dismissal actors/comments, refs and arbitrary report URLs are
// deliberately excluded. Input follows the GitHub REST repository alert list:
// https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository
// SARIF, organization lists and nested/paginated arrays are not this format.
type codeScanningAlert struct {
	Number  int64  `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Rule    struct {
		ID               string `json:"id"`
		Severity         string `json:"severity"`
		SecuritySeverity string `json:"security_severity_level"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
		GUID string `json:"guid"`
	} `json:"tool"`
	MostRecentInstance struct {
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// CodeScanningRepository validates and normalizes an explicit GitHub.com
// owner/repository identifier, without accepting URLs, traversal or API paths.
func CodeScanningRepository(value string) (string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || len(parts[0]) > 39 || len(parts[1]) > 100 {
		return "", errors.New("code scanning: explicit owner/repository is required")
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("code scanning: invalid repository identifier")
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && (i != 1 || (r != '_' && r != '.')) {
				return "", errors.New("code scanning: invalid repository identifier")
			}
		}
	}
	if strings.HasPrefix(parts[0], "-") || strings.HasSuffix(parts[0], "-") {
		return "", errors.New("code scanning: invalid owner identifier")
	}
	return strings.ToLower(value), nil
}

// ParseCodeScanningJSON projects a bounded flat GitHub REST code-scanning alert
// array. It performs no network access, scanner execution or persistence. The
// caller must record partial coverage: absent alerts never imply resolution.
// Only explicit open/fixed/dismissed source states are interpreted. Errors are
// sanitized and never return partial results or source-controlled error text.
func ParseCodeScanningJSON(reader io.Reader, options CodeScanningOptions) ([]model.SecurityFinding, error) {
	repository, err := CodeScanningRepository(options.Repository)
	if err != nil {
		return nil, err
	}
	options.Repository = repository
	options.ObservedAt = options.ObservedAt.UTC()
	if !safeTrivyField(options.RunID, true, 256) || options.ObservedAt.IsZero() || options.ObservedAt.Year() < 1 || options.ObservedAt.Year() > 9999 || reader == nil {
		return nil, errors.New("parse code scanning: run ID, observation time and reader are required")
	}
	body, err := io.ReadAll(io.LimitReader(reader, trivyMaxInputBytes+1))
	if err != nil {
		return nil, errors.New("parse code scanning: cannot read input")
	}
	if len(body) > trivyMaxInputBytes || !utf8.Valid(body) || !json.Valid(body) || strings.TrimSpace(string(body)) == "null" {
		return nil, errors.New("parse code scanning: invalid or oversized JSON")
	}
	alerts, err := decodeTrivyArray[*codeScanningAlert](body, trivyMaxFindings)
	if err != nil {
		return nil, errors.New("parse code scanning: bounded flat alert array is required")
	}
	owner, _, _ := strings.Cut(repository, "/")
	asset := model.Asset{ID: stableSecurityID("asset", "github", "repository", owner, repository), Type: "repository", Provider: "github", Account: owner, NativeID: repository}
	items := make([]model.SecurityFinding, 0, len(alerts))
	seen := make(map[string]string, len(alerts))
	for _, alert := range alerts {
		item, err := normalizeCodeScanningAlert(alert, asset, options)
		if err != nil {
			return nil, fmt.Errorf("parse code scanning alert: %w", err)
		}
		if prior, ok := seen[item.Finding.ID]; ok {
			if prior != item.Observation.Fingerprint {
				return nil, errors.New("parse code scanning: conflicting duplicate alert identity")
			}
			continue
		}
		seen[item.Finding.ID] = item.Observation.Fingerprint
		items = append(items, item)
	}
	return items, nil
}

func normalizeCodeScanningAlert(alert *codeScanningAlert, asset model.Asset, options CodeScanningOptions) (model.SecurityFinding, error) {
	if alert == nil || alert.Number <= 0 {
		return model.SecurityFinding{}, errors.New("positive alert number is required")
	}
	for _, field := range []struct {
		value    string
		required bool
	}{{alert.Rule.ID, true}, {alert.Tool.Name, true}, {alert.Tool.GUID, false}, {alert.MostRecentInstance.Location.Path, false}} {
		if !safeTrivyField(field.value, field.required, 4096) {
			return model.SecurityFinding{}, errors.New("invalid selected metadata")
		}
	}
	location := alert.MostRecentInstance.Location
	if location.StartLine < 0 || location.StartLine > 2147483647 || location.Path == "" && location.StartLine != 0 || location.Path != "" && (path.IsAbs(location.Path) || path.Clean(location.Path) != location.Path || strings.ContainsAny(location.Path, ":\\") || strings.HasPrefix(location.Path, "../") || location.Path == ".." || location.Path == ".") {
		return model.SecurityFinding{}, errors.New("invalid repository-relative location")
	}
	var status model.SourceStatus
	switch alert.State {
	case "open":
		status = model.SourceStatusActive
	case "fixed":
		status = model.SourceStatusResolved
	case "dismissed":
		status = model.SourceStatusSuppressed
	default:
		return model.SecurityFinding{}, errors.New("unsupported alert state")
	}
	var severity model.Severity
	switch alert.Rule.SecuritySeverity {
	case "critical", "high", "medium", "low":
		severity = model.Severity(alert.Rule.SecuritySeverity)
	case "":
		severity = "unknown"
	default:
		return model.SecurityFinding{}, errors.New("unsupported security severity")
	}
	// Rule severity is diagnostic importance, not security severity. An ordinary
	// error or warning without security_severity_level must stay unknown.
	switch alert.Rule.Severity {
	case "", "none", "note", "warning", "error":
	default:
		return model.SecurityFinding{}, errors.New("unsupported rule severity")
	}
	nativeID := options.Repository + ":" + strconv.FormatInt(alert.Number, 10)
	findingID := stableSecurityID("finding", "github_code_scanning", asset.Account, nativeID)
	toolID := alert.Tool.GUID
	if toolID == "" {
		toolID = alert.Tool.Name
	}
	canonical, err := json.Marshal([3]string{"github_code_scanning", toolID, alert.Rule.ID})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode rule correlation: %w", err)
	}
	if len(canonical) > 20000 || len(alert.Tool.Name+": "+alert.Rule.ID) > 4096 {
		return model.SecurityFinding{}, errors.New("encoded selected metadata exceeds field limits")
	}
	finding := model.Finding{ID: findingID, Category: "code_scanning", AssetID: asset.ID, CanonicalKey: string(canonical), Severity: severity, TriageStatus: model.TriageStatusNew, SourceStatus: status, FirstSeen: options.ObservedAt, LastSeen: options.ObservedAt, Title: alert.Tool.Name + ": " + alert.Rule.ID, RuleID: alert.Rule.ID, ToolName: alert.Tool.Name, FilePath: location.Path, StartLine: location.StartLine}
	// Derive the source URL from trusted scope and a numeric native ID, rather
	// than retaining an untrusted html_url (which may contain tokens or redirects).
	rawRef := "https://github.com/" + options.Repository + "/code-scanning/" + strconv.FormatInt(alert.Number, 10)
	// A URL never establishes scope. When supplied by a native export, require
	// agreement with explicit scope to catch accidental cross-repository input.
	securityURL := "https://github.com/" + options.Repository + "/security/code-scanning/" + strconv.FormatInt(alert.Number, 10)
	if alert.HTMLURL != "" && !strings.EqualFold(alert.HTMLURL, rawRef) && !strings.EqualFold(alert.HTMLURL, securityURL) {
		return model.SecurityFinding{}, errors.New("alert URL does not match the selected repository and number")
	}
	// Observation time/run identity must not change the selected source evidence.
	fingerprintFinding := finding
	fingerprintFinding.FirstSeen = time.Time{}
	fingerprintFinding.LastSeen = time.Time{}
	evidence, err := json.Marshal(struct {
		NativeID, ToolID, RuleSeverity string
		Finding                        model.Finding
	}{nativeID, toolID, alert.Rule.Severity, fingerprintFinding})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode source fingerprint: %w", err)
	}
	digest := sha256.Sum256(evidence)
	fingerprint := hex.EncodeToString(digest[:])
	return model.SecurityFinding{Asset: asset, Finding: finding, Observation: model.Observation{ID: stableSecurityID("observation", findingID, options.RunID, fingerprint), Source: "github_code_scanning", Account: asset.Account, SourceFindingID: nativeID, FindingID: findingID, IngestRunID: options.RunID, RawRef: rawRef, Fingerprint: fingerprint, ObservedAt: options.ObservedAt}}, nil
}
