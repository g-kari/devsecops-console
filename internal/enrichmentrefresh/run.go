package enrichmentrefresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

// ErrPending means this in-process operation must retain its original envelope.
// It never authorizes a new UUID, refetch, automatic retry or cursor advance.
var ErrPending = errors.New("enrichment refresh: pending receipt")

const maxInputBytes = 32 << 20
const cleanupBudget = 2 * time.Second

var errInvalid = errors.New("enrichment refresh: invalid input")
var errUnavailable = errors.New("enrichment refresh: unavailable")

func (s Service) run(ctx context.Context, request Request) (Result, error) {
	return s.runPrepared(ctx, request, nil)
}

func (s Service) runPrepared(ctx context.Context, request Request, preserve preservationBeforeWrite) (out Result, runErr error) {
	out = Result{NextAfter: request.After}
	if ctx == nil {
		return reject(out, "invalid_context")
	}
	var cleanupCtx context.Context
	var cleanupCancel context.CancelFunc
	cleanup := func() context.Context {
		if cleanupCtx == nil {
			cleanupCtx, cleanupCancel = context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
		}
		return cleanupCtx
	}
	defer func() {
		if cleanupCancel != nil {
			cleanupCancel()
		}
	}()
	var work *Pending
	preservationStopped := false
	acknowledge := func(checkpointCtx context.Context, stage PreservationStage, candidate Result) error {
		if preserve == nil {
			return nil
		}
		if err := preserve(checkpointCtx, stage, candidate); err != nil {
			preservationStopped = true
			return ErrPending
		}
		return nil
	}
	if preserve != nil {
		// Run before cleanup cancellation so Fail/readback/result preservation
		// share the one existing two-second cleanup deadline without renewal.
		defer func() {
			if preservationStopped {
				return
			}
			checkpointCtx := ctx
			if cleanupCtx != nil || ctx.Err() != nil {
				checkpointCtx = cleanup()
			}
			if err := acknowledge(checkpointCtx, PreserveReturned, out); err != nil {
				out.Pending = work
				out, runErr = preservationUnknown(out, request.After)
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return canceled(out, err)
	}
	if missing(s.Store) || missing(s.Fetcher) || s.Clock == nil || s.NewUUID == nil {
		return reject(out, "missing_dependency")
	}
	domain := ""
	switch request.Connector {
	case "epss_feed":
		domain = "epss"
	case "kev_feed":
		domain = "kev"
	default:
		return reject(out, "invalid_source")
	}
	if request.Limit < 1 || request.Limit > 200 || !cursor(request.After) {
		return reject(out, "invalid_query")
	}
	page, err := s.Store.QuerySecurityEnrichmentRefreshTargets(ctx, request.After, request.Limit)
	if err := ctx.Err(); err != nil {
		return canceled(out, err)
	}
	if err != nil {
		out.Outcome, out.Code = "error", "scan_failed"
		return out, fmt.Errorf("scan refresh targets: %w", errUnavailable)
	}
	cves, err := pageCVEs(page, request)
	if err != nil {
		return reject(out, "invalid_page")
	}
	out.Scanned, out.Targets, out.ScanAfter = page.Scanned, len(page.Targets), page.After
	if err := ctx.Err(); err != nil {
		return canceled(out, err)
	}
	if page.Scanned == 0 {
		out.Outcome, out.Exhausted = "exhausted", true
		return out, nil
	}
	if len(page.Targets) == 0 {
		out.Outcome, out.Advance, out.NextAfter = "no_targets", true, page.After
		return out, nil
	}
	scope, err := threat.OfflineSelectionScope(cves)
	if err != nil {
		return reject(out, "invalid_page")
	}
	start := s.Clock()
	if !clockTime(start) {
		return reject(out, "invalid_clock")
	}
	start = start.UTC()
	if err := ctx.Err(); err != nil {
		return canceled(out, err)
	}
	id, err := s.NewUUID()
	if err := ctx.Err(); err != nil {
		return canceled(out, err)
	}
	if err != nil || !uuid(id) {
		return reject(out, "invalid_uuid")
	}
	// Prepare and retain before Begin. No error path regenerates this envelope.
	work = &Pending{Attempt: store.SecurityEnrichmentRefreshAttempt{
		RunID: id, Connector: request.Connector, Scope: scope, StartedAt: start,
		Targets: append([]store.SecurityEnrichmentRefreshTarget(nil), page.Targets...),
	}}
	out.RunID, out.Pending = id, work
	if err := acknowledge(ctx, PreserveBegin, out); err != nil {
		return preservationUnknown(out, request.After)
	}
	replay, beginErr := s.Store.BeginSecurityEnrichmentRefresh(ctx, work.Attempt)
	if beginErr != nil || replay {
		state, readErr := s.Store.ReadSecurityEnrichmentRefreshAttempt(cleanup(), work.Attempt, nil)
		code := "begin_unknown"
		if replay && beginErr == nil {
			code = "begin_replay"
		}
		if readErr != nil || (state.State != "running" && state.State != "missing" && state.State != "unknown") {
			code = "begin_readback_unknown"
		}
		// A recorded running row is not an ownership grant. Never fetch or Fail.
		return pending(out, code)
	}
	latestClock := start
	fail := func(code string, finish time.Time) (Result, error) {
		if !clockTime(finish) || finish.Before(latestClock) {
			return pending(out, "invalid_clock")
		}
		// Capture this exact expected write before Fail, including its clock.
		work.ExpectedFailure = &store.SecurityEnrichmentRefreshFailure{Code: code, FinishedAt: finish.UTC()}
		if err := acknowledge(cleanup(), PreserveFail, out); err != nil {
			return preservationUnknown(out, request.After)
		}
		_, failErr := s.Store.FailSecurityEnrichmentRefresh(cleanup(), work.Attempt, code, work.ExpectedFailure.FinishedAt)
		if failErr == nil {
			out.Outcome, out.Code, out.Pending = "failed", code, nil
			return out, nil
		}
		state, readErr := s.Store.ReadSecurityEnrichmentRefreshAttempt(cleanup(), work.Attempt, work.ExpectedFailure)
		if readErr == nil && state.State == "failed" && state.Receipt == "" {
			out.Outcome, out.Code, out.Pending = "failed", code, nil
			return out, nil
		}
		return pending(out, "failure_unknown")
	}
	if err := ctx.Err(); err != nil {
		return fail("canceled", s.Clock())
	}
	data, fetchErr := s.Fetcher.Fetch(ctx, domain)
	if err := ctx.Err(); err != nil {
		return fail("canceled", s.Clock())
	}
	if fetchErr != nil {
		code := "fetch_failed"
		if errors.Is(fetchErr, context.Canceled) || errors.Is(fetchErr, context.DeadlineExceeded) {
			code = "canceled"
		}
		return fail(code, s.Clock())
	}
	// This is a cap on returned synthetic input, not transport allocation or
	// compressed-wire bytes. Check length before hashing and strict parsing.
	if len(data) > maxInputBytes {
		return fail("parse_failed", s.Clock())
	}
	digest := sha256.Sum256(data)
	if err := ctx.Err(); err != nil {
		return fail("canceled", s.Clock())
	}
	observed := s.Clock()
	if !clockTime(observed) || observed.Before(start) {
		return fail("invalid_metadata", s.Clock())
	}
	observed = observed.UTC()
	latestClock = observed
	if err := ctx.Err(); err != nil {
		return fail("canceled", s.Clock())
	}
	feed, parseErr := threat.ParseOfflineThreat(bytes.NewReader(data), domain, threat.OfflineOptions{CVEs: cves, ObservedAt: observed})
	finish := s.Clock()
	if !clockTime(finish) || finish.Before(latestClock) {
		return pending(out, "invalid_clock")
	}
	finish = finish.UTC()
	if err := ctx.Err(); err != nil {
		return fail("canceled", finish)
	}
	if parseErr != nil {
		return fail("parse_failed", finish)
	}
	// Retain the full completion before Complete; the digest is exactly the
	// delivered uncompressed CSV/catalog JSON bytes, not compressed-wire provenance.
	work.Completion = &store.SecurityEnrichmentRefreshCompletion{
		Attempt: work.Attempt, Feed: feed, OriginalDigest: "sha256:" + hex.EncodeToString(digest[:]), FinishedAt: finish,
	}
	if err := acknowledge(ctx, PreserveComplete, out); err != nil {
		return preservationUnknown(out, request.After)
	}
	result, completeErr := s.Store.CompleteSecurityEnrichmentRefresh(ctx, *work.Completion)
	if completeErr == nil && result.Entries == len(feed.Entries) {
		return succeeded(out)
	}
	state, readErr := s.Store.ReconcileSecurityEnrichmentRefresh(cleanup(), *work.Completion)
	if readErr == nil && state.State == "success" && state.Receipt != "" {
		return succeeded(out)
	}
	// No Fail, retry, refetch, rehash or second clock follows an uncertain Complete.
	return pending(out, "completion_unknown")
}

func succeeded(out Result) (Result, error) {
	out.Outcome, out.Code, out.Pending = "success", "", nil
	out.Advance, out.NextAfter = true, out.ScanAfter
	return out, nil
}

func pending(out Result, code string) (Result, error) {
	out.Outcome, out.Code, out.Advance = "pending", code, false
	return out, ErrPending
}

func reject(out Result, code string) (Result, error) {
	out.Outcome, out.Code = "invalid", code
	return out, fmt.Errorf("refresh %s: %w", code, errInvalid)
}

func canceled(out Result, err error) (Result, error) {
	out.Outcome, out.Code, out.Advance = "canceled", "canceled", false
	return out, fmt.Errorf("refresh canceled: %w", err)
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func cursor(value string) bool {
	return len(value) <= 128 && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

func clockTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999 && at.UTC().Year() >= 1 && at.UTC().Year() <= 9999
}

func uuid(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func pageCVEs(page store.SecurityEnrichmentRefreshTargetPage, request Request) ([]string, error) {
	if page.Scanned < 0 || page.Scanned > request.Limit || len(page.Targets) > page.Scanned || len(page.Targets) > 200 {
		return nil, errInvalid
	}
	if page.Scanned == 0 {
		if page.After != "" || len(page.Targets) != 0 {
			return nil, errInvalid
		}
		return nil, nil
	}
	if page.After == "" || !cursor(page.After) || strings.Compare(page.After, request.After) <= 0 {
		return nil, errInvalid
	}
	var selected []string
	previous := request.After
	for _, target := range page.Targets {
		if target.FindingID == "" || !cursor(target.FindingID) || strings.Compare(target.FindingID, previous) <= 0 || strings.Compare(target.FindingID, page.After) > 0 || len(target.Revision) != 64 || strings.ToLower(target.Revision) != target.Revision {
			return nil, errInvalid
		}
		if _, err := hex.DecodeString(target.Revision); err != nil {
			return nil, errInvalid
		}
		canonical, err := threat.NormalizeOfflineCVEs([]string{target.CVEID})
		if err != nil || canonical[0] != target.CVEID {
			return nil, errInvalid
		}
		selected = append(selected, target.CVEID)
		previous = target.FindingID
	}
	if len(page.Targets) > 0 && len(page.Targets) == page.Scanned && page.After != previous {
		return nil, errInvalid
	}
	if len(selected) == 0 {
		return nil, nil
	}
	return threat.NormalizeOfflineCVEs(selected)
}
