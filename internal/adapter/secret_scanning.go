package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SecretScanningOptions supplies explicit GitHub.com repository and observation
// context. Offline metadata never establishes its own trusted scope.
type SecretScanningOptions struct {
	Repository string
	RunID      string
	ObservedAt time.Time
}

// absentSecret rejects every literal secret, including a masking placeholder.
// The source must omit secret or supply null/empty string. Repeated JSON members
// are each checked, so a later null cannot erase an earlier forbidden value.
type absentSecret struct{}

func (*absentSecret) UnmarshalJSON(body []byte) error {
	if string(body) != "null" && string(body) != `""` {
		return errors.New("literal secret fields are not accepted")
	}
	return nil
}

// Only selected identifiers/lifecycle are decoded. Secret values, locations,
// snippets, display names, comments, actors, owners, provider metadata and
// validity claims are not projected. This is a secret-free subset of the REST
// repository alert list, not the locations endpoint or an organization list.
type secretScanningAlert struct {
	Number     int64        `json:"number"`
	HTMLURL    string       `json:"html_url"`
	State      string       `json:"state"`
	Resolution string       `json:"resolution"`
	SecretType string       `json:"secret_type"`
	Secret     absentSecret `json:"secret"`
}

// SecretScanningRepository validates an explicit GitHub.com owner/repository.
func SecretScanningRepository(value string) (string, error) {
	repository, err := CodeScanningRepository(value)
	if err != nil {
		return "", errors.New("secret scanning: explicit valid owner/repository is required")
	}
	return repository, nil
}

// ParseSecretScanningJSON projects a bounded, secret-free repository alert
// metadata array. It never fetches alerts/locations, verifies credentials, or
// returns source-controlled error text. Errors return no partial results.
// Offline snapshots are partial coverage; absence never resolves a finding.
func ParseSecretScanningJSON(reader io.Reader, options SecretScanningOptions) ([]model.SecurityFinding, error) {
	repository, err := SecretScanningRepository(options.Repository)
	if err != nil {
		return nil, err
	}
	options.Repository = repository
	options.ObservedAt = options.ObservedAt.UTC()
	if !safeTrivyField(options.RunID, true, 256) || options.ObservedAt.IsZero() || options.ObservedAt.Year() < 1 || options.ObservedAt.Year() > 9999 || reader == nil {
		return nil, errors.New("parse secret scanning: run ID, observation time and reader are required")
	}
	body, err := io.ReadAll(io.LimitReader(reader, trivyMaxInputBytes+1))
	if err != nil {
		return nil, errors.New("parse secret scanning: cannot read input")
	}
	if len(body) > trivyMaxInputBytes || !utf8.Valid(body) || !json.Valid(body) || strings.TrimSpace(string(body)) == "null" {
		return nil, errors.New("parse secret scanning: invalid or oversized JSON")
	}
	alerts, err := decodeTrivyArray[*secretScanningAlert](body, trivyMaxFindings)
	if err != nil {
		return nil, errors.New("parse secret scanning: bounded secret-free flat alert metadata array is required")
	}
	owner, _, _ := strings.Cut(repository, "/")
	asset := model.Asset{ID: stableSecurityID("asset", "github", "repository", owner, repository), Type: "repository", Provider: "github", Account: owner, NativeID: repository}
	items := make([]model.SecurityFinding, 0, len(alerts))
	seen := make(map[string]string, len(alerts))
	for _, alert := range alerts {
		item, err := normalizeSecretScanningAlert(alert, asset, options)
		if err != nil {
			return nil, fmt.Errorf("parse secret scanning alert: %w", err)
		}
		if prior, ok := seen[item.Finding.ID]; ok {
			if prior != item.Observation.Fingerprint {
				return nil, errors.New("parse secret scanning: conflicting duplicate alert identity")
			}
			continue
		}
		seen[item.Finding.ID] = item.Observation.Fingerprint
		items = append(items, item)
	}
	return items, nil
}

func normalizeSecretScanningAlert(alert *secretScanningAlert, asset model.Asset, options SecretScanningOptions) (model.SecurityFinding, error) {
	if alert == nil || alert.Number <= 0 {
		return model.SecurityFinding{}, errors.New("positive alert number is required")
	}
	if !secretScanningType(alert.SecretType) {
		return model.SecurityFinding{}, errors.New("invalid secret type identifier")
	}
	var status model.SourceStatus
	switch alert.State {
	case "open":
		if alert.Resolution != "" {
			return model.SecurityFinding{}, errors.New("open alert has a resolution")
		}
		status = model.SourceStatusActive
	case "resolved":
		switch alert.Resolution {
		case "revoked":
			status = model.SourceStatusResolved
		case "false_positive", "wont_fix", "used_in_tests", "pattern_edited", "pattern_deleted":
			status = model.SourceStatusSuppressed
		default:
			return model.SecurityFinding{}, errors.New("unsupported or missing source resolution")
		}
	default:
		return model.SecurityFinding{}, errors.New("unsupported alert state")
	}
	number := strconv.FormatInt(alert.Number, 10)
	nativeID := options.Repository + ":" + number
	findingID := stableSecurityID("finding", "github_secret_scanning", asset.Account, nativeID)
	canonical, err := json.Marshal([2]string{"github_secret_scanning", alert.SecretType})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode secret type correlation: %w", err)
	}
	finding := model.Finding{ID: findingID, Category: "secret_scanning", AssetID: asset.ID, CanonicalKey: string(canonical), Severity: "unknown", TriageStatus: model.TriageStatusNew, SourceStatus: status, FirstSeen: options.ObservedAt, LastSeen: options.ObservedAt, Title: "Secret Scanning: " + alert.SecretType, SecretType: alert.SecretType, SecretResolution: alert.Resolution}
	rawRef := "https://github.com/" + options.Repository + "/security/secret-scanning/" + number
	if alert.HTMLURL != "" && !strings.EqualFold(alert.HTMLURL, rawRef) {
		return model.SecurityFinding{}, errors.New("alert URL does not match the selected repository and number")
	}
	selected := finding
	selected.FirstSeen = time.Time{}
	selected.LastSeen = time.Time{}
	evidence, err := json.Marshal(struct {
		NativeID string
		Finding  model.Finding
	}{nativeID, selected})
	if err != nil {
		return model.SecurityFinding{}, fmt.Errorf("encode selected metadata fingerprint: %w", err)
	}
	digest := sha256.Sum256(evidence)
	fingerprint := hex.EncodeToString(digest[:])
	return model.SecurityFinding{Asset: asset, Finding: finding, Observation: model.Observation{ID: stableSecurityID("observation", findingID, options.RunID, fingerprint), Source: "github_secret_scanning", Account: asset.Account, SourceFindingID: nativeID, FindingID: findingID, IngestRunID: options.RunID, RawRef: rawRef, Fingerprint: fingerprint, ObservedAt: options.ObservedAt}}, nil
}

func secretScanningType(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}
