package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

//go:embed migrations/002_security.sql
var securitySchema string

//go:embed migrations/003_security_enrichment.sql
var securityEnrichmentSchema string

//go:embed migrations/004_security_enrichment_journal.sql
var securityEnrichmentJournalSchema string

//go:embed migrations/005_security_enrichment_reservation.sql
var securityEnrichmentReservationSchema string

//go:embed migrations/006_security_enrichment_release.sql
var securityEnrichmentReleaseSchema string

func securityID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("security ID生成失敗: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (s *Store) migrateSecurity() error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("security migration開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, securitySchema); err != nil {
		return fmt.Errorf("security schema作成失敗: %w", err)
	}
	var applied int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_migrations WHERE version=2`).Scan(&applied); err != nil {
		return fmt.Errorf("security migration確認失敗: %w", err)
	}
	if applied == 0 {
		rows, err := tx.QueryContext(ctx, `SELECT owner,repo,number,alert_json,resolved_at,notified_at FROM alert_records ORDER BY id`)
		if err != nil {
			return fmt.Errorf("legacy alert読込失敗: %w", err)
		}
		var records []model.AlertRecord
		for rows.Next() {
			var rec model.AlertRecord
			var body string
			var resolved sql.NullString
			if err := rows.Scan(&rec.Alert.Owner, &rec.Alert.Repo, &rec.Alert.Number, &body, &resolved, &rec.NotifiedAt); err != nil {
				_ = rows.Close()
				return fmt.Errorf("legacy alert走査失敗: %w", err)
			}
			owner, repo, number := rec.Alert.Owner, rec.Alert.Repo, rec.Alert.Number
			if err := json.Unmarshal([]byte(body), &rec.Alert); err != nil {
				_ = rows.Close()
				return fmt.Errorf("legacy alert解析失敗（既存行は保持）: %w", err)
			}
			rec.Alert.Owner, rec.Alert.Repo, rec.Alert.Number = owner, repo, number
			if resolved.Valid {
				at, err := time.Parse(time.RFC3339Nano, resolved.String)
				if err != nil {
					_ = rows.Close()
					return fmt.Errorf("legacy resolved日時解析失敗: %w", err)
				}
				rec.ResolvedAt = &at
			}
			records = append(records, rec)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("legacy alert読込失敗: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("legacy alert読込終了失敗: %w", err)
		}
		for _, rec := range records {
			at := rec.Alert.UpdatedAt
			if at.IsZero() {
				at = rec.NotifiedAt
			}
			if at.IsZero() {
				at = rec.Alert.CreatedAt
			}
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if rec.ResolvedAt != nil {
				at = *rec.ResolvedAt
			}
			if err := projectDependabot(ctx, tx, rec, "", at, false); err != nil {
				return fmt.Errorf("legacy security backfill失敗（既存行は保持）: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_migrations(version,applied_at) VALUES(2,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("security migration記録失敗: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, securityEnrichmentSchema); err != nil {
		return fmt.Errorf("security enrichment migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, securityEnrichmentJournalSchema); err != nil {
		return fmt.Errorf("security operation journal migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, securityEnrichmentReservationSchema); err != nil {
		return fmt.Errorf("security operation reservation migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, securityEnrichmentReleaseSchema); err != nil {
		return fmt.Errorf("security operation release migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("security migration確定失敗: %w", err)
	}
	return nil
}

func insertIngestRun(ctx context.Context, tx *sql.Tx, run model.IngestRun) error {
	body, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("ingest run変換失敗: %w", err)
	}
	var finished any
	if run.FinishedAt != nil {
		finished = run.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ingest_runs(id,connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, run.ID, run.Connector, run.Scope, run.StartedAt.UTC().Format(time.RFC3339Nano), finished, run.Result, run.Coverage, run.Cursor, run.Error, string(body))
	if err != nil {
		return fmt.Errorf("ingest run保存失敗: %w", err)
	}
	return nil
}

// StartIngestRun records an attempt before contacting a source. No credentials
// or source error bodies are persisted in this ledger.
func (s *Store) StartIngestRun(ctx context.Context, connector, scope string, at time.Time) (model.IngestRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var run model.IngestRun
	if strings.TrimSpace(connector) == "" || strings.TrimSpace(scope) == "" || at.IsZero() {
		return run, fmt.Errorf("ingest runのsource/scope/時刻が未設定です")
	}
	if connector == "epss_feed" || connector == "kev_feed" {
		return startGuardedFeedIngestRun(ctx, s.db, connector, scope, at)
	}
	id, err := securityID()
	if err != nil {
		return run, err
	}
	run = model.IngestRun{ID: id, Connector: connector, Scope: scope, StartedAt: at.UTC(), Result: "running", Coverage: "unknown"}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return run, fmt.Errorf("ingest run開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertIngestRun(ctx, tx, run); err != nil {
		return run, err
	}
	if err := tx.Commit(); err != nil {
		return run, fmt.Errorf("ingest run開始確定失敗: %w", err)
	}
	return run, nil
}

// FinishIngestRun records coverage explicitly. It never resolves findings.
func (s *Store) FinishIngestRun(ctx context.Context, id, result, coverage, errorCode string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (result != "success" && result != "partial" && result != "failed") || (coverage != "full" && coverage != "partial" && coverage != "unknown") || at.IsZero() {
		return fmt.Errorf("ingest runの完了状態が不正です")
	}
	// Only bounded machine codes, never arbitrary API errors, may enter this field.
	if len(errorCode) > 64 || strings.IndexFunc(errorCode, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' }) >= 0 {
		return fmt.Errorf("ingest error codeが不正です")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ingest run終了開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardLegacyIngestFinishTx(ctx, tx, id); err != nil {
		return err
	}
	var body string
	if err := tx.QueryRowContext(ctx, `SELECT body_json FROM ingest_runs WHERE id=? AND result='running'`, id).Scan(&body); err != nil {
		return fmt.Errorf("ingest run読込失敗: %w", err)
	}
	var run model.IngestRun
	if err := json.Unmarshal([]byte(body), &run); err != nil {
		return fmt.Errorf("ingest run解析失敗: %w", err)
	}
	if at.Before(run.StartedAt) {
		return fmt.Errorf("ingest run終了が開始より前です")
	}
	closed := at.UTC()
	run.FinishedAt = &closed
	run.Result = result
	run.Coverage = coverage
	run.Error = errorCode
	encoded, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("ingest run変換失敗: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ingest_runs SET finished_at=?,result=?,coverage=?,error=?,body_json=? WHERE id=? AND result='running'`, closed.Format(time.RFC3339Nano), result, coverage, errorCode, string(encoded), id); err != nil {
		return fmt.Errorf("ingest run終了失敗: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ingest run終了確定失敗: %w", err)
	}
	return nil
}

// ObserveDependabot writes a source observation without changing the existing
// approval, evaluation or notification workflow. Replaying one run is idempotent.
func (s *Store) ObserveDependabot(ctx context.Context, alert model.Alert, runID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("dependabot観測開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var source, scope, result string
	if err := tx.QueryRowContext(ctx, `SELECT connector,scope,result FROM ingest_runs WHERE id=?`, runID).Scan(&source, &scope, &result); err != nil {
		return fmt.Errorf("dependabot ingest run確認失敗: %w", err)
	}
	repo := alert.Owner + "/" + alert.Repo
	if source != "dependabot" || result != "running" || (!strings.EqualFold(scope, alert.Owner) && !strings.EqualFold(scope, repo)) {
		return fmt.Errorf("dependabot観測がingest scope外です")
	}
	if err := projectDependabot(ctx, tx, model.AlertRecord{Alert: alert}, runID, at, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("dependabot観測確定失敗: %w", err)
	}
	return nil
}

func projectDependabot(ctx context.Context, tx *sql.Tx, rec model.AlertRecord, runID string, at time.Time, alwaysObserve bool) error {
	normalizedRun := runID
	if normalizedRun == "" {
		normalizedRun = "legacy-projection"
	}
	value, err := adapter.NormalizeDependabot(rec, normalizedRun, at.UTC())
	if err != nil {
		return fmt.Errorf("dependabot正規化失敗: %w", err)
	}
	if runID == "" {
		var fingerprint, status string
		err := tx.QueryRowContext(ctx, `SELECT fingerprint,source_status FROM findings WHERE id=?`, value.Finding.ID).Scan(&fingerprint, &status)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("既存Finding確認失敗: %w", err)
		}
		if err == nil && fingerprint == value.Observation.Fingerprint && status == string(value.Finding.SourceStatus) && !alwaysObserve {
			return nil
		}
		id, err := securityID()
		if err != nil {
			return err
		}
		finished := at.UTC()
		run := model.IngestRun{ID: id, Connector: "dependabot", Scope: rec.Alert.Owner + "/" + rec.Alert.Repo, StartedAt: at.UTC(), FinishedAt: &finished, Result: "success", Coverage: "partial"}
		if err := insertIngestRun(ctx, tx, run); err != nil {
			return err
		}
		value, err = adapter.NormalizeDependabot(rec, id, at.UTC())
		if err != nil {
			return fmt.Errorf("dependabot正規化失敗: %w", err)
		}
	}
	return projectSecurityFinding(ctx, tx, model.SecurityFinding{Asset: value.Asset, Finding: value.Finding, Observation: value.Observation})
}

func projectSecurityFinding(ctx context.Context, tx *sql.Tx, value model.SecurityFinding) error {
	var previous model.Finding
	var previousBody, previousFingerprint string
	existingErr := tx.QueryRowContext(ctx, `SELECT body_json,fingerprint FROM findings WHERE id=?`, value.Finding.ID).Scan(&previousBody, &previousFingerprint)
	if existingErr != nil && existingErr != sql.ErrNoRows {
		return fmt.Errorf("既存Finding確認失敗: %w", existingErr)
	}
	if existingErr == nil {
		if err := json.Unmarshal([]byte(previousBody), &previous); err != nil {
			return fmt.Errorf("既存Finding解析失敗: %w", err)
		}
		if previous.AssetID != value.Finding.AssetID || previous.Category != value.Finding.Category {
			return fmt.Errorf("finding identity conflict")
		}
		value.Finding.FirstSeen = previous.FirstSeen
		value.Finding.TriageStatus = previous.TriageStatus
	}
	changed := existingErr == sql.ErrNoRows || previousFingerprint != value.Observation.Fingerprint || previous.SourceStatus != value.Finding.SourceStatus
	var priorAssetBody string
	assetErr := tx.QueryRowContext(ctx, `SELECT body_json FROM assets WHERE id=?`, value.Asset.ID).Scan(&priorAssetBody)
	if assetErr != nil && assetErr != sql.ErrNoRows {
		return fmt.Errorf("既存Asset確認失敗: %w", assetErr)
	}
	if assetErr == nil {
		var prior model.Asset
		if err := json.Unmarshal([]byte(priorAssetBody), &prior); err != nil {
			return fmt.Errorf("既存Asset解析失敗: %w", err)
		}
		if prior.Type != value.Asset.Type || prior.Provider != value.Asset.Provider || prior.Account != value.Asset.Account || prior.Region != value.Asset.Region || prior.NativeID != value.Asset.NativeID {
			return fmt.Errorf("asset identity conflict")
		}
	}

	stale := existingErr == nil && value.Observation.ObservedAt.Before(previous.LastSeen)
	assetJSON, err := json.Marshal(value.Asset)
	if err != nil {
		return fmt.Errorf("asset変換失敗: %w", err)
	}
	a := value.Asset
	if _, err := tx.ExecContext(ctx, `INSERT INTO assets(id,type,provider,account,region,native_id,environment,criticality,body_json) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, a.ID, a.Type, a.Provider, a.Account, a.Region, a.NativeID, a.Environment, a.Criticality, string(assetJSON)); err != nil {
		return fmt.Errorf("asset保存失敗: %w", err)
	}
	if !stale {
		findingJSON, err := json.Marshal(value.Finding)
		if err != nil {
			return fmt.Errorf("finding変換失敗: %w", err)
		}
		f := value.Finding
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings(id,category,asset_id,canonical_key,severity,triage_status,source_status,first_seen,last_seen,fingerprint,body_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET canonical_key=excluded.canonical_key,severity=excluded.severity,source_status=excluded.source_status,last_seen=excluded.last_seen,fingerprint=excluded.fingerprint,body_json=excluded.body_json`, f.ID, f.Category, f.AssetID, f.CanonicalKey, f.Severity, f.TriageStatus, f.SourceStatus, f.FirstSeen.UTC().Format(time.RFC3339Nano), f.LastSeen.UTC().Format(time.RFC3339Nano), value.Observation.Fingerprint, string(findingJSON)); err != nil {
			return fmt.Errorf("finding保存失敗: %w", err)
		}
	}
	observationJSON, err := json.Marshal(value.Observation)
	if err != nil {
		return fmt.Errorf("observation変換失敗: %w", err)
	}
	o := value.Observation
	result, err := tx.ExecContext(ctx, `INSERT INTO observations(id,source,account,source_finding_id,finding_id,ingest_run_id,raw_ref,observed_at,fingerprint,body_json) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source,account,source_finding_id,ingest_run_id,fingerprint) DO NOTHING`, o.ID, o.Source, o.Account, o.SourceFindingID, o.FindingID, o.IngestRunID, o.RawRef, o.ObservedAt.UTC().Format(time.RFC3339Nano), o.Fingerprint, string(observationJSON))
	if err != nil {
		return fmt.Errorf("observation保存失敗: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("observation保存件数確認失敗: %w", err)
	}
	if changed && !stale && n > 0 {
		id, err := securityID()
		if err != nil {
			return err
		}
		kind := "finding.updated"
		if existingErr == sql.ErrNoRows {
			kind = "finding.created"
		} else if previous.SourceStatus != value.Finding.SourceStatus {
			kind = "finding.source_status_changed"
		}
		event := model.Event{ID: id, EntityID: value.Finding.ID, EventType: kind, Actor: value.Observation.Source, Timestamp: value.Observation.ObservedAt.UTC(), BeforeRef: previousFingerprint, AfterRef: value.Observation.Fingerprint}
		body, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("event変換失敗: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(id,entity_id,event_type,actor,timestamp,before_ref,after_ref,body_json) VALUES(?,?,?,?,?,?,?,?)`, event.ID, event.EntityID, event.EventType, event.Actor, event.Timestamp.Format(time.RFC3339Nano), event.BeforeRef, event.AfterRef, string(body)); err != nil {
			return fmt.Errorf("event保存失敗: %w", err)
		}
	}
	return nil
}

func querySecurity[T any](ctx context.Context, db *sql.DB, query string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("security記録取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	values := make([]T, 0)
	for rows.Next() {
		var body string
		var value T
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("security記録読込失敗: %w", err)
		}
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			return nil, fmt.Errorf("security記録解析失敗: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("security記録走査失敗: %w", err)
	}
	return values, nil
}

// QueryAssets returns normalized assets without changing source workflow state.
func (s *Store) QueryAssets(ctx context.Context) ([]model.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return querySecurity[model.Asset](ctx, s.db, `SELECT body_json FROM assets ORDER BY id`)
}

// QueryFindings returns normalized findings, including retained resolved history.
func (s *Store) QueryFindings(ctx context.Context) ([]model.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return querySecurity[model.Finding](ctx, s.db, `SELECT body_json FROM findings ORDER BY id`)
}

// QueryObservations returns immutable source observations for one finding.
func (s *Store) QueryObservations(ctx context.Context, id string) ([]model.Observation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return querySecurity[model.Observation](ctx, s.db, `SELECT body_json FROM observations WHERE finding_id=? ORDER BY rowid`, id)
}

// QueryEvents returns the append-only audit trail for one entity.
func (s *Store) QueryEvents(ctx context.Context, id string) ([]model.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return querySecurity[model.Event](ctx, s.db, `SELECT body_json FROM events WHERE entity_id=? ORDER BY rowid`, id)
}

// QueryIngestRuns returns persisted attempts and their explicit coverage.
func (s *Store) QueryIngestRuns(ctx context.Context) ([]model.IngestRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return querySecurity[model.IngestRun](ctx, s.db, `SELECT body_json FROM ingest_runs ORDER BY rowid`)
}
