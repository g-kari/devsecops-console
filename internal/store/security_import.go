package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrIngestConflict means a run ID already belongs to a different import.
var ErrIngestConflict = errors.New("ingest run identity conflict")

// ImportResult describes an atomically committed report or an unchanged replay.
type ImportResult struct {
	Findings     int  `json:"findings"`
	Observations int  `json:"observations"`
	Replay       bool `json:"replay"`
}

// ValidateSecurityImport validates an offline batch without opening or changing
// a database. Callers should use it before selecting an import destination.
func ValidateSecurityImport(run model.IngestRun, items []model.SecurityFinding) error {
	_, _, err := validateSecurityImport(run, items)
	return err
}

// ImportSecurityFindings atomically imports a bounded, offline security report.
// Cursor must be sha256:<original input digest>. A versioned receipt binds that
// digest, normalized entities and timestamps; reused IDs cannot silently replace
// evidence. Imports are partial coverage and never close absent findings or
// change the legacy approval/evaluation/notification workflow.
func (s *Store) ImportSecurityFindings(ctx context.Context, run model.IngestRun, items []model.SecurityFinding) (ImportResult, error) {
	var result ImportResult
	normalized, receipt, err := validateSecurityImport(run, items)
	if err != nil {
		return result, fmt.Errorf("security import検証失敗: %w", err)
	}
	result.Findings, result.Observations = len(normalized), len(normalized)
	run.Cursor = receipt
	run.StartedAt = run.StartedAt.UTC()
	finished := run.FinishedAt.UTC()
	run.FinishedAt = &finished
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportResult{}, fmt.Errorf("security import開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var storedCursor, connector, scope string
	err = tx.QueryRowContext(ctx, `SELECT cursor,connector,scope FROM ingest_runs WHERE id=?`, run.ID).Scan(&storedCursor, &connector, &scope)
	if err == nil {
		if storedCursor != receipt || connector != run.Connector || scope != run.Scope {
			return ImportResult{}, ErrIngestConflict
		}
		result.Replay = true
		return result, nil
	}
	if err != sql.ErrNoRows {
		return ImportResult{}, fmt.Errorf("security import既存run確認失敗: %w", err)
	}
	if err := insertIngestRun(ctx, tx, run); err != nil {
		return ImportResult{}, err
	}
	for _, item := range normalized {
		if err := projectSecurityFinding(ctx, tx, item); err != nil {
			return ImportResult{}, fmt.Errorf("security import保存失敗: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return ImportResult{}, fmt.Errorf("security import確定失敗: %w", err)
	}
	return result, nil
}

func validateSecurityImport(run model.IngestRun, items []model.SecurityFinding) ([]model.SecurityFinding, string, error) {
	if !securityUUID(run.ID) || (run.Connector != "trivy" && run.Connector != "github_code_scanning" && run.Connector != "github_secret_scanning") || !securityField(run.Scope, true, 256) || strings.TrimSpace(run.Scope) != run.Scope || !securityTime(run.StartedAt) || run.FinishedAt == nil || !securityTime(*run.FinishedAt) || run.FinishedAt.Before(run.StartedAt) || run.Result != model.IngestResultSuccess || run.Coverage != model.IngestCoveragePartial || run.Error != "" || !strings.HasPrefix(run.Cursor, "sha256:") || !securityDigest(strings.TrimPrefix(run.Cursor, "sha256:")) {
		return nil, "", errors.New("invalid offline run metadata")
	}
	if run.Connector == "github_code_scanning" || run.Connector == "github_secret_scanning" {
		repository, err := adapter.CodeScanningRepository(run.Scope)
		if err != nil || repository != run.Scope {
			return nil, "", errors.New("invalid offline repository scope")
		}
	}
	if len(items) > 20000 {
		return nil, "", errors.New("import item limit exceeded")
	}
	unique := make(map[string]model.SecurityFinding, len(items))
	encoded := make(map[string]string, len(items))
	for _, item := range items {
		a, f, o := item.Asset, item.Finding, item.Observation
		if !securityUUID(a.ID) || !securityUUID(f.ID) || !securityUUID(o.ID) || !securityField(a.NativeID, true, 4096) || f.AssetID != a.ID || !validOfflineSource(run, item) || o.FindingID != f.ID || o.IngestRunID != run.ID || !securityField(o.SourceFindingID, true, 4096) || !securityDigest(o.Fingerprint) || !o.ObservedAt.Equal(run.StartedAt) || !f.LastSeen.Equal(o.ObservedAt) || !f.FirstSeen.Equal(o.ObservedAt) || f.TriageStatus != model.TriageStatusNew {
			return nil, "", errors.New("invalid normalized entity identity, scope or lifecycle")
		}
		if f.Severity != model.SeverityCritical && f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium && f.Severity != model.SeverityLow && f.Severity != "unknown" {
			return nil, "", errors.New("invalid normalized severity")
		}
		for _, value := range []string{a.Region, a.Environment, a.Criticality, f.Title, f.VulnerabilityID, f.PackageName, f.PackageEcosystem, f.InstalledVersion, f.FixedVersion, f.RuleID, f.ToolName, f.FilePath, f.SecretType, f.SecretResolution, o.RawRef} {
			if !securityField(value, false, 4096) {
				return nil, "", errors.New("invalid normalized field")
			}
		}
		if f.StartLine < 0 || f.StartLine > 2147483647 || !securityField(f.CanonicalKey, false, 20000) || !securityRawRef(o.RawRef) {
			return nil, "", errors.New("invalid normalized correlation or reference")
		}
		item.Finding.FirstSeen = item.Finding.FirstSeen.UTC()
		item.Finding.LastSeen = item.Finding.LastSeen.UTC()
		item.Observation.ObservedAt = item.Observation.ObservedAt.UTC()
		body, err := json.Marshal(item)
		if err != nil {
			return nil, "", fmt.Errorf("encode normalized import: %w", err)
		}
		if prior, ok := encoded[f.ID]; ok && prior != string(body) {
			return nil, "", errors.New("conflicting duplicate finding identity")
		}
		unique[f.ID], encoded[f.ID] = item, string(body)
	}
	normalized := make([]model.SecurityFinding, 0, len(unique))
	for _, item := range unique {
		normalized = append(normalized, item)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Finding.ID < normalized[j].Finding.ID })
	run.StartedAt = run.StartedAt.UTC()
	finished := run.FinishedAt.UTC()
	run.FinishedAt = &finished
	body, err := json.Marshal(struct {
		Run   model.IngestRun
		Items []model.SecurityFinding
	}{run, normalized})
	if err != nil {
		return nil, "", fmt.Errorf("encode import receipt: %w", err)
	}
	digest := sha256.Sum256(body)
	return normalized, run.Connector + "-v1:" + run.Cursor + ":" + hex.EncodeToString(digest[:]), nil
}

func securityField(value string, required bool, limit int) bool {
	return (!required || strings.TrimSpace(value) != "") && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
func securityTime(at time.Time) bool { return !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999 }
func securityDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func securityUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}
func securityRawRef(value string) bool {
	if value == "" {
		return true
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.Opaque == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(value, "#")
}

// Source-specific validation keeps each offline adapter inside its own scope
// and lifecycle contract. Enabling one source does not weaken Trivy validation.
func validOfflineSource(run model.IngestRun, item model.SecurityFinding) bool {
	a, f, o := item.Asset, item.Finding, item.Observation
	if o.Source != run.Connector {
		return false
	}
	switch run.Connector {
	case "trivy":
		if f.SecretType != "" || f.SecretResolution != "" {
			return false
		}
		return a.Provider == "trivy" && (a.Type == "filesystem" || a.Type == "container_image") && a.Account == run.Scope && o.Account == run.Scope && f.Category == "vulnerability" && f.SourceStatus == model.SourceStatusActive && f.RuleID == "" && f.ToolName == "" && f.FilePath == "" && f.StartLine == 0
	case "github_code_scanning":
		if f.SecretType != "" || f.SecretResolution != "" {
			return false
		}
		repository, err := adapter.CodeScanningRepository(run.Scope)
		owner, _, _ := strings.Cut(repository, "/")
		numberText, hasNumber := strings.CutPrefix(o.SourceFindingID, repository+":")
		number, numberErr := strconv.ParseInt(numberText, 10, 64)
		if !hasNumber || numberErr != nil || number <= 0 || strconv.FormatInt(number, 10) != numberText || o.RawRef != "https://github.com/"+repository+"/code-scanning/"+numberText {
			return false
		}
		return err == nil && repository == run.Scope && a.Provider == "github" && a.Type == "repository" && a.NativeID == repository && a.Account == owner && o.Account == owner && f.Category == "code_scanning" && securityField(f.RuleID, true, 4096) && securityField(f.ToolName, true, 4096) && (f.SourceStatus == model.SourceStatusActive || f.SourceStatus == model.SourceStatusResolved || f.SourceStatus == model.SourceStatusSuppressed)
	case "github_secret_scanning":
		repository, err := adapter.SecretScanningRepository(run.Scope)
		owner, _, _ := strings.Cut(repository, "/")
		numberText, hasNumber := strings.CutPrefix(o.SourceFindingID, repository+":")
		number, numberErr := strconv.ParseInt(numberText, 10, 64)
		if !hasNumber || numberErr != nil || number <= 0 || strconv.FormatInt(number, 10) != numberText || o.RawRef != "https://github.com/"+repository+"/security/secret-scanning/"+numberText {
			return false
		}
		if len(f.SecretType) == 0 || len(f.SecretType) > 128 || strings.IndexFunc(f.SecretType, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' }) >= 0 {
			return false
		}
		expectedStatus := model.SourceStatusActive
		switch f.SecretResolution {
		case "":
		case "revoked":
			expectedStatus = model.SourceStatusResolved
		case "false_positive", "wont_fix", "used_in_tests", "pattern_edited", "pattern_deleted":
			expectedStatus = model.SourceStatusSuppressed
		default:
			return false
		}
		canonical, marshalErr := json.Marshal([2]string{"github_secret_scanning", f.SecretType})
		return err == nil && marshalErr == nil && repository == run.Scope && a.Provider == "github" && a.Type == "repository" && a.NativeID == repository && a.Account == owner && o.Account == owner && f.Category == "secret_scanning" && f.SourceStatus == expectedStatus && f.Severity == "unknown" && f.Title == "Secret Scanning: "+f.SecretType && f.CanonicalKey == string(canonical) && f.RuleID == "" && f.ToolName == "" && f.FilePath == "" && f.StartLine == 0 && f.VulnerabilityID == "" && f.PackageName == "" && f.PackageEcosystem == "" && f.InstalledVersion == "" && f.FixedVersion == ""
	default:
		return false
	}
}
