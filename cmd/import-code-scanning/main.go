// Command import-code-scanning imports an explicitly selected local Code Scanning JSON report.
// It does not run a scanner, load application configuration, or start services.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const maxInputBytes = 10 * 1024 * 1024

const usage = `Usage: import-code-scanning --input PATH|- --repository OWNER/REPO --observed-at RFC3339 [--db PATH | --dry-run] [--run-id UUID]

Offline import only. Reads at most 10 MiB of local Code Scanning JSON.
--input and --repository must be explicit; --observed-at has no default.
--db explicitly selects a SQLite file that may be created or migrated; back it up first.
--dry-run validates and normalizes without opening any database.
--run-id is optional; otherwise a stable UUID is derived from the repository and original report bytes.
`

type options struct {
	input      string
	repository string
	database   string
	runID      string
	observedAt time.Time
	dryRun     bool
}

type summary struct {
	RunID        string `json:"run_id"`
	Findings     int    `json:"findings"`
	Observations int    `json:"observations"`
	Replay       bool   `json:"replay"`
	DryRun       bool   `json:"dry_run"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(stdout, usage); err != nil {
			_, _ = io.WriteString(stderr, "cannot write command help\n")
			return 1
		}
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	report, err := readReport(opts.input, stdin)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if opts.runID == "" {
		opts.runID = reportRunID(opts.repository, report)
	}
	items, err := adapter.ParseCodeScanningJSON(bytes.NewReader(report), adapter.CodeScanningOptions{
		Repository: opts.repository, RunID: opts.runID, ObservedAt: opts.observedAt,
	})
	if err != nil {
		// Source-controlled strings and reader errors never enter command output.
		_, _ = io.WriteString(stderr, "input validation failed: invalid or unsupported Code Scanning JSON\n")
		return 1
	}

	at := opts.observedAt
	digest := sha256.Sum256(report)
	ingestRun := model.IngestRun{
		ID: opts.runID, Connector: "github_code_scanning", Scope: opts.repository,
		StartedAt: at, FinishedAt: &at, Result: model.IngestResultSuccess,
		Coverage: model.IngestCoveragePartial, Cursor: "sha256:" + hex.EncodeToString(digest[:]),
	}
	if err := store.ValidateSecurityImport(ingestRun, items); err != nil {
		_, _ = io.WriteString(stderr, "normalized report validation failed\n")
		return 1
	}

	out := summary{RunID: opts.runID, DryRun: opts.dryRun}
	if opts.dryRun {
		findings, observations := make(map[string]struct{}), make(map[string]struct{})
		for _, item := range items {
			findings[item.Finding.ID] = struct{}{}
			observations[item.Observation.ID] = struct{}{}
		}
		out.Findings, out.Observations = len(findings), len(observations)
	} else {
		// The parser must finish before this call: opening a Store can migrate
		// the explicitly selected file, even when the import later conflicts.
		s, err := store.NewWithPath(opts.database)
		if err != nil {
			_, _ = io.WriteString(stderr, "cannot open or migrate the explicitly selected database\n")
			return 1
		}
		result, importErr := s.ImportSecurityFindings(context.Background(), ingestRun, items)
		closeErr := s.Close()
		if importErr != nil {
			_, _ = io.WriteString(stderr, "cannot import report: validation, database operation, or run ID conflict failed\n")
			return 1
		}
		if closeErr != nil {
			_, _ = io.WriteString(stderr, "import committed, but database close failed; verify the run ID before retrying\n")
			return 1
		}
		out.Findings, out.Observations, out.Replay = result.Findings, result.Observations, result.Replay
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		_, _ = io.WriteString(stderr, "cannot write result summary; verify the run ID before retrying an import\n")
		return 1
	}
	return 0
}

func parseOptions(args []string) (options, error) {
	var opts options
	var observedAt string
	flags := flag.NewFlagSet("import-code-scanning", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.input, "input", "", "explicit local JSON file, or - for stdin")
	flags.StringVar(&opts.repository, "repository", "", "explicit GitHub owner/repository")
	flags.StringVar(&observedAt, "observed-at", "", "explicit RFC3339 observation timestamp")
	flags.StringVar(&opts.database, "db", "", "explicit SQLite file path")
	flags.StringVar(&opts.runID, "run-id", "", "optional stable UUID")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "validate without opening a database")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, flag.ErrHelp
		}
		return opts, errors.New("invalid flags; use --help for command usage")
	}
	if flags.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments; use --help for command usage")
	}
	if opts.input == "" || (opts.input != "-" && !localPath(opts.input)) {
		return opts, errors.New("--input requires an explicit local file path or - for stdin")
	}
	repository, err := adapter.CodeScanningRepository(opts.repository)
	if err != nil {
		return opts, errors.New("--repository requires an explicit GitHub owner/repository identifier")
	}
	opts.repository = repository
	at, err := time.Parse(time.RFC3339, observedAt)
	if err != nil || at.IsZero() {
		return opts, errors.New("--observed-at requires an explicit, nonzero RFC3339 timestamp")
	}
	opts.observedAt = at.UTC()
	runIDSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "run-id" {
			runIDSet = true
		}
	})
	if runIDSet {
		if !validUUID(opts.runID) {
			return opts, errors.New("--run-id requires a canonical UUID")
		}
		opts.runID = strings.ToLower(opts.runID)
	}
	if !opts.dryRun {
		if opts.database == "" || !localPath(opts.database) || opts.database == ":memory:" || strings.ContainsAny(opts.database, "?#") {
			return opts, errors.New("--db requires an explicit local SQLite file path unless --dry-run is used")
		}
		absolute, err := filepath.Abs(opts.database)
		if err != nil {
			return opts, errors.New("cannot resolve explicitly selected database path")
		}
		opts.database = absolute
	}
	return opts, nil
}

func localPath(path string) bool {
	// Windows treats either slash as a separator. Reject UNC, mixed-separator
	// and device namespace paths before Stat/Open can initiate SMB access.
	if len(path) >= 2 && strings.ContainsRune("/\\", rune(path[0])) && strings.ContainsRune("/\\", rune(path[1])) {
		return false
	}
	if strings.IndexByte(path, 0) >= 0 {
		return false
	}
	colon := strings.IndexByte(path, ':')
	if colon < 0 {
		return true
	}
	// Preserve Windows drive paths without accepting URI or SQLite DSN input.
	if colon == 1 && len(path) > 2 && (path[2] == '/' || path[2] == '\\') && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) {
		return true
	}
	for _, c := range path[:colon] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return true
		}
	}
	return false
}

func validUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func readReport(path string, stdin io.Reader) ([]byte, error) {
	reader := stdin
	var file *os.File
	if path != "-" {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("cannot read input: expected an accessible regular local file")
		}
		file, err = os.Open(path)
		if err != nil {
			return nil, errors.New("cannot open explicitly selected input file")
		}
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, errors.New("cannot read input: expected an accessible regular local file")
		}
		reader = file
	}
	if reader == nil {
		return nil, errors.New("cannot read input: stdin is unavailable")
	}
	report, readErr := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var closeErr error
	if file != nil {
		closeErr = file.Close()
	}
	if readErr != nil {
		return nil, errors.New("cannot read input report")
	}
	if closeErr != nil {
		return nil, errors.New("cannot close input file after reading")
	}
	if len(report) > maxInputBytes {
		return nil, errors.New("input report exceeds the 10 MiB limit")
	}
	return report, nil
}

func reportRunID(repository string, report []byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "github_code_scanning-v1\x00")
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(repository)))
	_, _ = h.Write(length[:])
	_, _ = io.WriteString(h, repository)
	_, _ = h.Write(report)
	id := h.Sum(nil)[:16]
	// Version 8 identifies this application's deterministic SHA-256 UUID.
	id[6] = (id[6] & 0x0f) | 0x80
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}
