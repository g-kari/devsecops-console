package enrichmentrefresh

import (
	"bytes"
	"context"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// RecoverableJournalRepository adds one read-only, full-history and business
// inspection to the checkpoint boundary. Implementations must honor context.
type RecoverableJournalRepository interface {
	JournalRepository
	InspectSecurityEnrichmentOperation(context.Context, string) (store.SecurityEnrichmentOperationInspection, error)
}

type journalTerminalRecovery struct {
	adapter    *journalAdapter
	repository RecoverableJournalRepository
}

// NewRecoverableJournalManualController explicitly enables terminal acknowledgement
// recovery in this controller lifetime only. It does not restore records, acquire
// durable generation ownership, release reservations or wire a runtime caller.
func NewRecoverableJournalManualController(service Service, repository RecoverableJournalRepository) (*ManualController, error) {
	if missing(repository) {
		return nil, ErrManualInvalid
	}
	adapter := &journalAdapter{repository: repository, records: make(map[string]*journalAdapterRecord)}
	c, err := NewPreservingManualController(service, adapter)
	if err != nil {
		return nil, err
	}
	c.recovery = &journalTerminalRecovery{adapter: adapter, repository: repository}
	return c, nil
}

func terminalRecoveryPayload(checkpoint *PreservationCheckpoint) ([]byte, bool) {
	if checkpoint == nil || checkpoint.Stage != PreserveReturned || checkpoint.Result.Pending != nil || checkpoint.Prepared == nil {
		return nil, false
	}
	p := checkpoint.Prepared
	switch checkpoint.Result.Outcome {
	case "success":
		if p.Completion == nil || p.ExpectedFailure != nil {
			return nil, false
		}
	case "failed":
		if p.ExpectedFailure == nil || p.Completion != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	converted, err := convertJournalCheckpoint(*checkpoint)
	if err != nil {
		return nil, false
	}
	payload, err := enrichmentjournal.Encode(converted)
	return payload, err == nil
}

// ReconcileJournalTerminal explicitly checks one retained terminal checkpoint.
// Both private unknown gates clear together only after exact read-only proof.
// Unsupported/uncertain states retain their evidence and may be checked later;
// there is no append, business retry, fresh fetch or automatic recovery loop.
func (c *ManualController) ReconcileJournalTerminal(ctx context.Context, operationID string) (ManualOperation, error) {
	if c == nil || c.operations == nil || c.recovery == nil || ctx == nil || !uuid(operationID) {
		return ManualOperation{}, ErrManualInvalid
	}
	if ctx.Err() != nil {
		return ManualOperation{}, manualContextError(ctx)
	}
	c.mu.Lock()
	record, ok := c.operations[operationID]
	if !ok {
		c.mu.Unlock()
		return ManualOperation{}, ErrManualNotFound
	}
	snapshot := cloneManualOperation(record.operation)
	if record.operation.State == "resolved" {
		err := record.err
		c.mu.Unlock()
		return snapshot, err
	}
	if c.busy {
		c.mu.Unlock()
		return snapshot, ErrManualBusy
	}
	payload, eligible := terminalRecoveryPayload(record.checkpoint)
	if !record.preservationUnknown || record.operation.State != "pending" || !eligible {
		c.mu.Unlock()
		return snapshot, ErrPending
	}
	a := c.recovery.adapter
	// Whenever both locks are needed the order is controller, then adapter.
	// Preserve never holds its adapter lock while entering the controller.
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		c.mu.Unlock()
		return snapshot, ErrManualBusy
	}
	journal := a.records[operationID]
	if journal == nil || !journal.reservedConfirmed ||
		journal.request != record.operation.Request || !bytes.Equal(journal.payload, payload) || journal.digest != adapterDigest(payload) {
		a.mu.Unlock()
		c.mu.Unlock()
		return snapshot, ErrPending
	}
	checkpoint := record.checkpoint
	original := clonePreservationCheckpoint(*checkpoint)
	sequence, digest := journal.current.Sequence, journal.digest
	c.busy, a.busy = true, true
	a.mu.Unlock()
	c.mu.Unlock()

	readCtx, stop := context.WithTimeout(ctx, cleanupBudget)
	defer stop()
	verified := false
	if readCtx.Err() == nil {
		inspection, err := c.recovery.repository.InspectSecurityEnrichmentOperation(readCtx, operationID)
		if err == nil && readCtx.Err() == nil && inspection.State == "valid" && inspection.OperationID == operationID &&
			inspection.HeadSequence == sequence && inspection.HeadDigest == digest && inspection.Checkpoint != nil {
			observed, encodeErr := enrichmentjournal.Encode(*inspection.Checkpoint)
			if encodeErr == nil && bytes.Equal(observed, payload) {
				verified = (original.Result.Outcome == "success" && inspection.Business.State == "success" && inspection.Business.Receipt != "") ||
					(original.Result.Outcome == "failed" && inspection.Business.State == "failed" && inspection.Business.Receipt == "")
			}
		}
	}

	c.mu.Lock()
	a.mu.Lock()
	// Recheck identities and both copies of the retained bytes at publication.
	currentPayload, currentEligible := terminalRecoveryPayload(record.checkpoint)
	if verified && ctx.Err() == nil && readCtx.Err() == nil && c.operations[operationID] == record &&
		record.checkpoint == checkpoint && record.preservationUnknown && record.operation.State == "pending" &&
		currentEligible && bytes.Equal(currentPayload, payload) && a.records[operationID] == journal &&
		journal.reservedConfirmed && journal.current.Sequence == sequence &&
		journal.digest == digest && bytes.Equal(journal.payload, payload) {
		record.operation.Result = cloneManualResult(original.Result)
		record.operation.State, record.err, record.preservationUnknown = "resolved", nil, false
		journal.acknowledged, journal.unknown = true, false
	}
	c.busy, a.busy = false, false
	snapshot, err := cloneManualOperation(record.operation), record.err
	if record.operation.State == "pending" {
		err = ErrPending
	}
	if ctx.Err() != nil {
		err = manualContextError(ctx)
	}
	a.mu.Unlock()
	c.mu.Unlock()
	return snapshot, err
}
