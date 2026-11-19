package enrichmentjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var cvePattern = regexp.MustCompile("^CVE-([0-9]{4})-[0-9]{4,19}$")
var versionPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

func validText(s string, max int, empty bool) bool {
	return (empty || s != "") && len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validHex(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && validHex(strings.TrimPrefix(s, "sha256:"))
}

func validClock(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999 && at.UTC().Year() >= 1 && at.UTC().Year() <= 9999
}

func validCVE(s string) bool {
	m := cvePattern.FindStringSubmatch(s)
	return m != nil && m[1] >= "1999"
}

func failureCode(code string) bool {
	switch code {
	case "fetch_failed", "parse_failed", "invalid_metadata", "target_changed", "store_failed", "canceled":
		return true
	}
	return false
}

func pendingCode(code string) bool {
	switch code {
	case "begin_unknown", "begin_replay", "begin_readback_unknown", "invalid_clock", "failure_unknown", "completion_unknown", "preservation_unknown":
		return true
	}
	return false
}

func rejectedCode(code string) bool {
	switch code {
	case "invalid_context", "missing_dependency", "invalid_source", "invalid_query", "invalid_page", "invalid_clock", "invalid_uuid":
		return true
	}
	return false
}

func validProbability(p *float64) bool {
	return p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= 1
}

func validateCheckpoint(c Checkpoint) error {
	if c.Version != Version || !validUUID(c.OperationID) || (c.Request.Connector != "epss_feed" && c.Request.Connector != "kev_feed") || !validText(c.Request.After, 128, true) || c.Request.Limit < 1 || c.Request.Limit > 200 {
		return invalid("binding")
	}
	p := c.Progress
	if p.Scanned < 0 || p.Scanned > c.Request.Limit || p.Targets < 0 || p.Targets > p.Scanned || !validText(p.ScanAfter, 128, true) || !validText(p.NextAfter, 128, true) {
		return invalid("progress bounds")
	}
	if p.Scanned == 0 {
		if p.ScanAfter != "" || p.Targets != 0 {
			return invalid("empty progress")
		}
	} else if p.ScanAfter == "" || strings.Compare(p.ScanAfter, c.Request.After) <= 0 {
		return invalid("scan cursor")
	}
	if c.Stage == Reserved {
		want := Progress{NextAfter: c.Request.After}
		if p != want || c.Prepared != nil {
			return invalid("reservation")
		}
		return nil
	}
	if c.Prepared != nil {
		if err := validatePrepared(c); err != nil {
			return err
		}
	} else if p.RunID != "" || p.Pending {
		return invalid("missing preparation")
	}
	if c.Stage == Begin || c.Stage == Fail || c.Stage == Complete {
		if c.Prepared == nil || !p.Pending || p.Outcome != "" || p.Code != "" || p.Advance || p.Exhausted || p.NextAfter != c.Request.After {
			return invalid("write progress")
		}
		switch c.Stage {
		case Begin:
			if c.Prepared.Failure != nil || c.Prepared.Completion != nil {
				return invalid("begin preparation")
			}
		case Fail:
			if c.Prepared.Failure == nil || c.Prepared.Completion != nil {
				return invalid("failure preparation")
			}
		case Complete:
			if c.Prepared.Completion == nil || c.Prepared.Failure != nil {
				return invalid("completion preparation")
			}
		}
		return nil
	}
	if c.Stage != Returned {
		return invalid("stage")
	}
	switch p.Outcome {
	case "success":
		if c.Prepared == nil || c.Prepared.Completion == nil || p.Pending || !p.Advance || p.NextAfter != p.ScanAfter || p.Code != "" || p.Exhausted {
			return invalid("successful result")
		}
	case "failed":
		if c.Prepared == nil || c.Prepared.Failure == nil || p.Pending || p.Advance || p.NextAfter != c.Request.After || p.Code != c.Prepared.Failure.Code || p.Exhausted {
			return invalid("failed result")
		}
	case "pending":
		if c.Prepared == nil || !p.Pending || p.Advance || p.NextAfter != c.Request.After || !pendingCode(p.Code) || p.Exhausted {
			return invalid("pending result")
		}
	case "no_targets":
		if c.Prepared != nil || p.Scanned == 0 || p.Targets != 0 || !p.Advance || p.NextAfter != p.ScanAfter || p.Pending || p.Exhausted || p.Code != "" {
			return invalid("no-target result")
		}
	case "exhausted":
		if c.Prepared != nil || p.Scanned != 0 || p.Targets != 0 || p.Advance || p.NextAfter != c.Request.After || p.Pending || !p.Exhausted || p.Code != "" {
			return invalid("exhausted result")
		}
	case "invalid", "error", "canceled":
		validCode := p.Outcome == "invalid" && rejectedCode(p.Code) || p.Outcome == "error" && p.Code == "scan_failed" || p.Outcome == "canceled" && p.Code == "canceled"
		if c.Prepared != nil || p.Advance || p.NextAfter != c.Request.After || p.Exhausted || !validCode {
			return invalid("rejected result")
		}
	default:
		return invalid("outcome")
	}
	return nil
}

func validatePrepared(c Checkpoint) error {
	a := c.Prepared.Attempt
	p := c.Progress
	if !validUUID(a.RunID) || a.RunID != p.RunID || a.Connector != c.Request.Connector || !validClock(a.StartedAt) || len(a.Targets) == 0 || len(a.Targets) > 200 || len(a.Targets) != p.Targets || p.Scanned == 0 {
		return invalid("attempt")
	}
	seen := make(map[string]bool, len(a.Targets))
	selected := make(map[string]bool, len(a.Targets))
	maxID := ""
	for _, target := range a.Targets {
		if !validText(target.FindingID, 128, false) || !validCVE(target.CVEID) || !validHex(target.Revision) || seen[target.FindingID] || strings.Compare(target.FindingID, c.Request.After) <= 0 || strings.Compare(target.FindingID, p.ScanAfter) > 0 {
			return invalid("target")
		}
		seen[target.FindingID], selected[target.CVEID] = true, true
		if target.FindingID > maxID {
			maxID = target.FindingID
		}
	}
	if len(a.Targets) == p.Scanned && maxID != p.ScanAfter {
		return invalid("last scan")
	}
	cves := make([]string, 0, len(selected))
	for cve := range selected {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	selectionJSON, err := json.Marshal(cves)
	if err != nil || a.Scope != fmt.Sprintf("cves-sha256:%x", sha256.Sum256(selectionJSON)) {
		return invalid("scope")
	}
	if c.Prepared.Failure != nil && c.Prepared.Completion != nil {
		return invalid("exclusive write")
	}
	if f := c.Prepared.Failure; f != nil {
		if !failureCode(f.Code) || !validClock(f.FinishedAt) || f.FinishedAt.Before(a.StartedAt) {
			return invalid("expected failure")
		}
	}
	if completion := c.Prepared.Completion; completion != nil {
		f := completion.Feed
		if !validDigest(completion.OriginalDigest) || !validClock(completion.FinishedAt) || f.Source != strings.TrimSuffix(a.Connector, "_feed") || !versionPattern.MatchString(f.Version) || !validClock(f.PublishedAt) || !validClock(f.ObservedAt) || f.PublishedAt.After(f.ObservedAt) || f.ObservedAt.Before(a.StartedAt) || completion.FinishedAt.Before(f.ObservedAt) || len(f.SelectedCVEs) != len(cves) || len(f.Entries) > 200 {
			return invalid("completion metadata")
		}
		for i, cve := range cves {
			if f.SelectedCVEs[i] != cve {
				return invalid("selection")
			}
		}
		entries := make(map[string]bool, len(f.Entries))
		for _, entry := range f.Entries {
			if !validCVE(entry.CVEID) || !selected[entry.CVEID] || entries[entry.CVEID] {
				return invalid("entry")
			}
			entries[entry.CVEID] = true
			if f.Source == "epss" {
				if !validProbability(entry.EPSS) || !validProbability(entry.Percentile) || entry.KEV || entry.KEVDateAdded != nil {
					return invalid("EPSS entry")
				}
			} else if !entry.KEV || entry.KEVDateAdded == nil || !validClock(*entry.KEVDateAdded) || entry.KEVDateAdded.After(f.PublishedAt) || entry.EPSS != nil || entry.Percentile != nil {
				return invalid("KEV entry")
			}
		}
	}
	return nil
}
