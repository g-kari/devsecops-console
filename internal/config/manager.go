package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"gopkg.in/yaml.v3"
)

// Snapshot is an immutable configuration view. Config is deep-copied when it
// is returned and can therefore safely be retained by a worker.
type Snapshot struct {
	Revision uint64
	Config   Config
}

// Manager serializes validated configuration updates and persists them using
// an atomic same-directory replacement.
type Manager struct {
	mu       sync.RWMutex
	path     string
	cfg      Config
	revision uint64
}

// NewManager creates a manager from a configuration value. The value is
// cloned before being retained.
func NewManager(path string, cfg *Config) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	clone, err := cloneConfig(*cfg)
	if err != nil {
		return nil, err
	}
	if err := clone.Validate(); err != nil {
		return nil, err
	}
	return &Manager{path: path, cfg: clone, revision: clone.ConfigRevision}, nil
}

// Snapshot returns a detached configuration snapshot.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clone, _ := cloneConfig(m.cfg)
	return Snapshot{Revision: m.revision, Config: clone}
}

// Update applies mutate only when expected is the current revision.
func (m *Manager) Update(expected uint64, mutate func(*Config) error) error {
	if mutate == nil {
		return errors.New("mutate is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if expected != m.revision {
		return fmt.Errorf("config revision conflict: expected %d, current %d", expected, m.revision)
	}
	next, err := cloneConfig(m.cfg)
	if err != nil {
		return err
	}
	if err := mutate(&next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	next.ConfigRevision = m.revision + 1
	if m.path != "" {
		if err := atomicSave(m.path, &next); err != nil {
			return err
		}
	}
	m.cfg = next
	m.revision = next.ConfigRevision
	return nil
}

func cloneConfig(in Config) (Config, error) {
	b, err := yaml.Marshal(in)
	if err != nil {
		return Config{}, err
	}
	var out Config
	if err := yaml.Unmarshal(b, &out); err != nil {
		return Config{}, err
	}
	out.CredentialsRevision = in.CredentialsRevision
	return out, nil
}

// Clone returns a deep copy suitable for preparing an atomic update.
func Clone(in Config) (Config, error) { return cloneConfig(in) }

func atomicSave(path string, cfg *Config) error {
	// Tokens are runtime-only overlays and must never be written by the
	// configuration manager. Users configure them through environment variables.
	persisted, err := cloneConfig(*cfg)
	if err != nil {
		return fmt.Errorf("config clone: %w", err)
	}
	persisted.Slack.BotToken = ""
	persisted.Slack.AppToken = ""
	persisted.Discord.WebhookURL = ""
	b, err := yaml.Marshal(&persisted)
	if err != nil {
		return fmt.Errorf("config serialize: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("config temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("config replace: %w", err)
	}
	return nil
}

// Validate checks values that would make scoring or monitoring ambiguous.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := c.GitHubAuth.Validate(); err != nil {
		return fmt.Errorf("GitHub authentication: %w", err)
	}
	if c.NotificationInterval < 0 {
		return errors.New("notification_intervalは0以上で指定してください")
	}
	if err := c.Web.validate(); err != nil {
		return err
	}
	if c.Evaluator.Provider != "" && c.Evaluator.Provider != "claude" && c.Evaluator.Provider != "codex" && c.Evaluator.Provider != "hermes" {
		return fmt.Errorf("unknown evaluator provider: %s", c.Evaluator.Provider)
	}
	if len(c.Evaluator.HermesModel) > 128 || strings.ContainsAny(c.Evaluator.HermesModel, "\r\n") {
		return errors.New("evaluator.hermes_model must be at most 128 characters without newlines")
	}
	if c.Evaluator.Provider == "hermes" && c.Evaluator.HermesBaseURL != "" {
		if err := validateHermesBaseURL(c.Evaluator.HermesBaseURL); err != nil {
			return err
		}
	}
	switch c.Evaluator.Sandbox.Runtime {
	case "", "auto", "docker", "apple", "podman":
	default:
		return errors.New("sandbox.runtime must be auto/docker/apple/podman")
	}
	if c.Evaluator.Sandbox.Runtime == "podman" && !c.Evaluator.Sandbox.Enabled {
		return errors.New("Podman実行にはAI隔離の有効化が必要です")
	}
	if c.Evaluator.Sandbox.ContainerCPUs < 0 || c.Evaluator.Sandbox.ContainerCPUs > 64 {
		return errors.New("container_cpus must be 1-64 (0 inherits default)")
	}
	seenTargets := map[string]bool{}
	for _, t := range c.Targets {
		key := strings.ToLower(strings.TrimSpace(t.Owner)) + "/" + strings.ToLower(strings.TrimSpace(t.Repo))
		if t.Owner == "" {
			return errors.New("target owner is required")
		}
		if seenTargets[key] {
			return fmt.Errorf("duplicate target: %s", key)
		}
		seenTargets[key] = true
	}
	seenProfiles := map[string]bool{}
	for i, p := range c.ServiceProfiles {
		if p.ID == "" {
			return fmt.Errorf("service_profiles[%d].id is required", i)
		}
		if seenProfiles[p.ID] {
			return fmt.Errorf("duplicate service profile: %s", p.ID)
		}
		seenProfiles[p.ID] = true
		if p.ReviewDueAt != nil && p.ReviewedAt != nil && p.ReviewDueAt.Before(*p.ReviewedAt) {
			return fmt.Errorf("service profile %s review_due_at precedes reviewed_at", p.ID)
		}
		if err := validateProfile(p); err != nil {
			return err
		}
	}
	for _, p := range c.ServiceProfiles {
		seen := map[string]bool{}
		for parent := p.Extends; parent != ""; {
			if seen[parent] {
				return fmt.Errorf("service profile inheritance cycle at %s", parent)
			}
			seen[parent] = true
			found := false
			for _, candidate := range c.ServiceProfiles {
				if candidate.ID == parent {
					parent = candidate.Extends
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("service profile %s extends unknown profile %s", p.ID, parent)
			}
		}
	}
	seenAssessments := map[string]bool{}
	for _, a := range c.Assessments {
		if a.ProfileID == "" || a.AdvisoryKey == "" {
			return errors.New("assessment profile_id and advisory_key are required")
		}
		key := a.ProfileID + "\x00" + strings.ToLower(a.AdvisoryKey)
		if seenAssessments[key] {
			return fmt.Errorf("duplicate assessment: %s", a.AdvisoryKey)
		}
		seenAssessments[key] = true
		for name, value := range map[string]string{"applicability": a.Applicability, "reachability": a.Reachability} {
			if value != "" && value != "unknown" && value != "affected" && value != "not_affected" && value != "reachable" && value != "unreachable" && value != "mitigated" {
				return fmt.Errorf("assessment %s has unknown %s %q", a.AdvisoryKey, name, value)
			}
		}
	}
	if c.RSS.MaxItemsPerFeed < 0 || c.RSS.RetentionDays < 0 {
		return errors.New("rss limits must be non-negative")
	}
	for _, f := range c.RSS.Feeds {
		if strings.TrimSpace(f.URL) == "" {
			return errors.New("rss feed url is required")
		}
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("rss feed must use an https URL: %s", f.URL)
		}
	}
	for name, raw := range map[string]string{"kev_url": c.Threat.KEVURL, "epss_url": c.Threat.EPSSURL} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("%s must use an https URL", name)
		}
	}
	return nil
}

func validateHermesBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || (u.EscapedPath() != "/v1" && u.EscapedPath() != "/v1/") {
		return errors.New("evaluator.hermes_base_url must be a local HTTP /v1 endpoint")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("evaluator.hermes_base_url must use a loopback host")
	}
	if u.Port() != "8645" {
		return errors.New("evaluator.hermes_base_url must use the Hermes proxy port 8645")
	}
	return nil
}

func validateProfile(p model.ServiceProfile) error {
	validExposure := map[model.ExposurePath]bool{model.ExposureInternet: true, model.ExposurePartner: true, model.ExposureInternal: true, model.ExposureIsolated: true, model.ExposureUnknown: true, "": true}
	if !validExposure[p.Exposure] {
		return fmt.Errorf("service profile %s has unknown exposure %q", p.ID, p.Exposure)
	}
	validEnv := map[model.ServiceEnvironment]bool{model.EnvironmentProduction: true, model.EnvironmentStaging: true, model.EnvironmentDevelopment: true, model.EnvironmentCI: true, model.EnvironmentUnknown: true, "": true}
	if !validEnv[p.Environment] {
		return fmt.Errorf("service profile %s has unknown environment %q", p.ID, p.Environment)
	}
	validRisk := map[model.RiskLevel]bool{model.RiskUnknown: true, model.RiskLow: true, model.RiskStandard: true, model.RiskHigh: true, model.RiskCritical: true, model.RiskRestricted: true, model.RiskConfidential: true, model.RiskInternal: true, model.RiskPublic: true, "": true}
	for name, value := range map[string]model.RiskLevel{"business_criticality": p.BusinessCriticality, "data_classification": p.DataClassification, "integrity_impact": p.IntegrityImpact} {
		if !validRisk[value] {
			return fmt.Errorf("service profile %s has unknown %s %q", p.ID, name, value)
		}
	}
	validPriv := map[model.PrivilegeScope]bool{model.PrivilegeUnknown: true, model.PrivilegeSharedControl: true, model.PrivilegeProductionWrite: true, model.PrivilegeServiceOnly: true, model.PrivilegeSandbox: true, "": true}
	if !validPriv[p.PrivilegeScope] {
		return fmt.Errorf("service profile %s has unknown privilege_scope %q", p.ID, p.PrivilegeScope)
	}
	validAuth := map[model.AuthenticationBoundary]bool{model.AuthUnknown: true, model.AuthNone: true, model.AuthCustomer: true, model.AuthEmployee: true, model.AuthPrivileged: true, "": true}
	if !validAuth[p.Authentication] {
		return fmt.Errorf("service profile %s has unknown authentication %q", p.ID, p.Authentication)
	}
	return nil
}

// ResolveProfile returns a profile with its extends chain applied from the
// root to the requested child. Zero-valued child fields inherit the parent.
func (c *Config) ResolveProfile(id string) (model.ServiceProfile, error) {
	byID := make(map[string]model.ServiceProfile, len(c.ServiceProfiles))
	for _, p := range c.ServiceProfiles {
		byID[p.ID] = p
	}
	cur, ok := byID[id]
	if !ok {
		return model.ServiceProfile{}, fmt.Errorf("service profile not found: %s", id)
	}
	chain := []model.ServiceProfile{}
	seen := map[string]bool{}
	for {
		if seen[cur.ID] {
			return model.ServiceProfile{}, fmt.Errorf("service profile inheritance cycle at %s", cur.ID)
		}
		seen[cur.ID] = true
		chain = append(chain, cur)
		if cur.Extends == "" {
			break
		}
		var found bool
		cur, found = byID[cur.Extends]
		if !found {
			return model.ServiceProfile{}, fmt.Errorf("service profile parent not found: %s", chain[len(chain)-1].Extends)
		}
	}
	result := chain[len(chain)-1]
	for i := len(chain) - 2; i >= 0; i-- {
		result = inheritProfile(chain[i], result)
	}
	return result, nil
}

func inheritProfile(child, parent model.ServiceProfile) model.ServiceProfile {
	if child.Owner == "" {
		child.Owner = parent.Owner
	}
	if child.Repo == "" {
		child.Repo = parent.Repo
	}
	if child.Environment == "" {
		child.Environment = parent.Environment
	}
	if child.Exposure == "" {
		child.Exposure = parent.Exposure
	}
	if child.Authentication == "" {
		child.Authentication = parent.Authentication
	}
	if child.BusinessCriticality == "" {
		child.BusinessCriticality = parent.BusinessCriticality
	}
	if child.MaxOutageMinutes == 0 {
		child.MaxOutageMinutes = parent.MaxOutageMinutes
	}
	if child.DataClassification == "" {
		child.DataClassification = parent.DataClassification
	}
	if child.IntegrityImpact == "" {
		child.IntegrityImpact = parent.IntegrityImpact
	}
	if child.PrivilegeScope == "" {
		child.PrivilegeScope = parent.PrivilegeScope
	}
	if child.OwnerTeam == "" {
		child.OwnerTeam = parent.OwnerTeam
	}
	if child.ReviewedBy == "" {
		child.ReviewedBy = parent.ReviewedBy
	}
	if child.ReviewedAt == nil {
		child.ReviewedAt = parent.ReviewedAt
	}
	if child.ReviewDueAt == nil {
		child.ReviewDueAt = parent.ReviewDueAt
	}
	return child
}
