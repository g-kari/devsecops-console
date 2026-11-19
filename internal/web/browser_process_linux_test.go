//go:build linux

package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type browserQAProc struct {
	pid, parent, group int
	start              string
	state              string
}

func browserQAParseProc(pid int, raw string) (browserQAProc, error) {
	end := strings.LastIndex(raw, ") ")
	if end < 0 || len(raw) > 4096 {
		return browserQAProc{}, fmt.Errorf("parse process %d: invalid stat", pid)
	}
	fields := strings.Fields(raw[end+2:])
	if len(fields) < 20 {
		return browserQAProc{}, fmt.Errorf("parse process %d: truncated stat", pid)
	}
	parent, pErr := strconv.Atoi(fields[1])
	group, gErr := strconv.Atoi(fields[2])
	_, sErr := strconv.ParseUint(fields[19], 10, 64)
	if pErr != nil || gErr != nil || sErr != nil {
		return browserQAProc{}, fmt.Errorf("parse process %d: invalid identity", pid)
	}
	return browserQAProc{pid: pid, parent: parent, group: group, start: fields[19], state: fields[0]}, nil
}

func browserQAReadProcs() (map[int]browserQAProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read owned-process snapshot: %w", err)
	}
	if len(entries) > 8192 {
		return nil, fmt.Errorf("read owned-process snapshot: /proc entry bound exceeded")
	}
	result := map[int]browserQAProc{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue // Process exited during the snapshot, not an unknown live PID.
		}
		if err != nil {
			return nil, fmt.Errorf("read process %d identity: %w", pid, err)
		}
		p, err := browserQAParseProc(pid, string(raw))
		if err != nil {
			return nil, err
		}
		result[pid] = p
	}
	return result, nil
}

func browserQASubreaper(get bool, value *int32) error {
	var errno syscall.Errno
	if get {
		// Keep the pointer conversion in the syscall expression so the runtime
		// retains its lifetime/address across the syscall (not a stored uintptr).
		_, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, 37, uintptr(unsafe.Pointer(value)), 0, 0, 0, 0) // PR_GET_CHILD_SUBREAPER.
	} else {
		_, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, 36, uintptr(*value), 0, 0, 0, 0) // PR_SET_CHILD_SUBREAPER.
	}
	if errno != 0 {
		return fmt.Errorf("configure test-process child supervision: %w", errno)
	}
	return nil
}

// Use a Linux pidfd, not numeric kill: a PID can be reused between a proc
// snapshot and signal. Open the handle first, then verify its current PID/start
// identity; the handle continues to refer to that process if it exits/recycles.
// Trap numbers match this project's Go 1.26 internal/syscall/unix definitions.
func browserQASignalOwned(p browserQAProc, signal syscall.Signal) error {
	openTrap, signalTrap := uintptr(434), uintptr(424)
	switch runtime.GOARCH {
	case "mips", "mipsle":
		openTrap, signalTrap = 4434, 4424
	case "mips64", "mips64le":
		openTrap, signalTrap = 5434, 5424
	case "386", "amd64", "arm", "arm64", "loong64", "ppc64", "ppc64le", "riscv64", "s390x":
	default:
		return fmt.Errorf("owned-process pidfd signaling unsupported on %s", runtime.GOARCH)
	}
	fd, _, errno := syscall.Syscall(openTrap, uintptr(p.pid), 0, 0)
	if errno == syscall.ESRCH {
		return nil
	}
	if errno != 0 {
		return fmt.Errorf("open exact owned-process pidfd: %w", errno)
	}
	defer func() { _ = syscall.Close(int(fd)) }()
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.pid), "stat"))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify exact owned-process pidfd identity: %w", err)
	}
	current, err := browserQAParseProc(p.pid, string(raw))
	if err != nil {
		return err
	}
	if current.start != p.start {
		return fmt.Errorf("owned-process identity changed before signal; no signal sent")
	}
	_, _, errno = syscall.Syscall(signalTrap, fd, uintptr(signal), 0)
	if errno != 0 && errno != syscall.ESRCH {
		return fmt.Errorf("signal exact owned-process pidfd: %w", errno)
	}
	return nil
}

// browserQADiscoverOwned never treats a process-group number as ownership.
// A PID is newly owned only through a currently present, same-start-time known
// parent, or fresh adoption by this same supervisor process. The caller has
// already proved there were no existing direct children/other child launchers.
// Unknown/reused identities are reported and are not inserted into known.
func browserQADiscoverOwned(current, known map[int]browserQAProc, supervisor browserQAProc, root int, adopted map[string]bool) error {
	actualSelf, ok := current[supervisor.pid]
	if !ok || actualSelf.start != supervisor.start {
		return fmt.Errorf("supervisor identity unavailable; no new process ownership accepted")
	}
	var firstErr error
	uncertain := func(message string) {
		if firstErr == nil {
			firstErr = errors.New(message)
		}
	}
	for pass := 0; pass <= len(current); pass++ {
		changed := false
		for _, p := range current {
			if p.pid == supervisor.pid {
				continue
			}
			if old, exists := known[p.pid]; exists {
				if old.start != p.start {
					uncertain("owned PID identity changed; replacement is not owned")
				} else if p.parent == supervisor.pid && p.pid != root {
					adopted[fmt.Sprintf("%d:%s", p.pid, p.start)] = true
				}
				continue
			}
			parent, parentKnown := known[p.parent]
			actualParent, parentAlive := current[p.parent]
			ownedParent := parentKnown && parentAlive && parent.start == actualParent.start
			newAdoptee := p.parent == supervisor.pid && p.pid != root
			if parentKnown && !ownedParent {
				uncertain("known parent identity unavailable; child remains unowned")
			}
			if !ownedParent && !newAdoptee {
				continue
			}
			known[p.pid] = p
			if newAdoptee {
				adopted[fmt.Sprintf("%d:%s", p.pid, p.start)] = true
			}
			changed = true
		}
		if !changed {
			break
		}
	}
	// A matching group can reveal an unresolved identity, never authorize it.
	// This also catches disappearance/recreation entirely between two polls.
	for _, p := range current {
		old, exists := known[p.pid]
		if p.group == root && (!exists || old.start != p.start) {
			uncertain("unattributed process in former Node group; no ownership/signal allowed")
		}
	}
	return firstErr
}

// browserQARunOwnedProcess owns one fresh process group. Becoming a temporary
// child subreaper prevents double-fork/setsid Chrome descendants from disappearing
// into PID 1 after Node exits. This opt-in test launches no other children and
// requires an empty initial direct-child set. Only that group's descendants and
// newly adopted direct children are signalled/reaped, with PID start-time checks.
// A failed/unknown snapshot, remaining child or cleanup deadline is never a pass.
func browserQARunOwnedProcess(ctx context.Context, cmd *exec.Cmd) (map[string]any, error) {
	report := map[string]any{"cleanup_complete": false, "scope": "verified Node identity plus current known-parent ancestry and subreaper adoption; group numbers never authorize ownership", "node_reaped": false, "signal_method": "Linux pidfd plus start-time identity; no numeric/global kill", "snapshot_verified": false, "forced_cleanup": false}
	previous := int32(0)
	if err := browserQASubreaper(true, &previous); err != nil {
		return report, err
	}
	enabled := int32(1)
	if err := browserQASubreaper(false, &enabled); err != nil {
		return report, err
	}
	restored := false
	defer func() {
		if !restored {
			_ = browserQASubreaper(false, &previous) // Result is explicitly unknown/failed below on this early-error path.
		}
	}()
	initial, err := browserQAReadProcs()
	if err != nil {
		return report, err
	}
	self := os.Getpid()
	supervisor, ok := initial[self]
	if !ok {
		return report, fmt.Errorf("capture supervisor identity: process absent from initial snapshot")
	}
	for _, p := range initial {
		if p.parent == self {
			return report, fmt.Errorf("start owned-process supervisor: existing direct child prevents unambiguous adoption ownership")
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return report, fmt.Errorf("start owned Node process: %w", err)
	}
	root := cmd.Process.Pid
	report["node_pid"] = root
	known := map[int]browserQAProc{}
	var auditErr error
	rememberError := func(e error) {
		if e != nil && auditErr == nil {
			auditErr = e
		}
	}
	// Capture Node before enumerating all /proc entries: a short test fixture
	// may already have exited by the end of a whole-system read-only snapshot.
	rawRoot, rootErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(root), "stat"))
	if rootErr != nil {
		rememberError(fmt.Errorf("capture initial Node identity: %w", rootErr))
	} else {
		p, err := browserQAParseProc(root, string(rawRoot))
		if err != nil || p.parent != self || p.group != root {
			rememberError(fmt.Errorf("initial Node group/identity could not be verified"))
		} else {
			known[root] = p
		}
	}
	adopted, reaped := map[string]bool{}, map[string]bool{}
	identity := func(p browserQAProc) string { return fmt.Sprintf("%d:%s", p.pid, p.start) }
	refresh := func() map[int]browserQAProc {
		current, err := browserQAReadProcs()
		if err != nil {
			rememberError(err)
			return nil
		}
		rememberError(browserQADiscoverOwned(current, known, supervisor, root, adopted))
		if len(known) > 512 {
			rememberError(fmt.Errorf("owned process count exceeded reviewed 512-PID bound"))
		}
		// Reap only our known adopted children. os/exec exclusively reaps Node.
		for pid, old := range known {
			p, live := current[pid]
			if !live || p.start != old.start || p.parent != self || pid == root {
				continue
			}
			var status syscall.WaitStatus
			got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			if err != nil && !errors.Is(err, syscall.ECHILD) {
				rememberError(fmt.Errorf("reap owned child: %w", err))
			}
			if got == pid {
				reaped[identity(p)] = true
				delete(current, pid)
			}
		}
		return current
	}
	_ = refresh() // initial discovery/reaping pass; the snapshot is superseded below
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	var commandErr error
running:
	for {
		select {
		case commandErr = <-wait:
			report["node_reaped"] = true
			break running
		case <-ticker.C:
			refresh()
		}
	}
	remaining := func(current map[int]browserQAProc) []browserQAProc {
		result := []browserQAProc{}
		for pid, old := range known {
			if p, ok := current[pid]; ok && p.start == old.start {
				result = append(result, p)
			}
		}
		return result
	}
	current := refresh()
	left := remaining(current)
	naturalDeadline := time.Now().Add(500 * time.Millisecond)
	for len(left) > 0 && time.Now().Before(naturalDeadline) {
		time.Sleep(20 * time.Millisecond)
		current = refresh()
		left = remaining(current)
	}
	if len(left) > 0 {
		report["forced_cleanup"] = true
	}
	// Bounded TERM then KILL of exact known identities only. No pkill/global
	// cleanup and no signal to a reused PID or an unrelated process group.
	for _, stage := range []struct {
		signal syscall.Signal
		budget time.Duration
	}{{syscall.SIGTERM, 2 * time.Second}, {syscall.SIGKILL, 2 * time.Second}} {
		deadline := time.Now().Add(stage.budget)
		sent := map[string]bool{}
		for len(left) > 0 && time.Now().Before(deadline) {
			for _, p := range left {
				if !sent[identity(p)] {
					if err := browserQASignalOwned(p, stage.signal); err != nil && !errors.Is(err, syscall.ESRCH) {
						rememberError(fmt.Errorf("signal exact owned child: %w", err))
					}
					sent[identity(p)] = true
				}
			}
			time.Sleep(20 * time.Millisecond)
			current = refresh()
			left = remaining(current)
		}
	}
	current = refresh()
	left = remaining(current)
	report["observed_owned_pids"] = len(known)
	report["adopted_pids"] = len(adopted)
	report["adopted_reaped"] = len(reaped)
	report["remaining_owned_pids"] = len(left)
	if current == nil {
		report["remaining_owned_pids"] = nil // Unknown is not an empty verified set.
	}
	report["context_cancelled"] = ctx.Err() != nil
	report["configured_deadlines_ms"] = map[string]int{"snapshot_poll": 40, "natural_descendant_drain": 500, "descendant_term": 2000, "descendant_kill": 2000}
	if len(left) != 0 {
		rememberError(fmt.Errorf("owned descendants remain after bounded cleanup: %d", len(left)))
	}
	if current == nil {
		rememberError(fmt.Errorf("final owned-process snapshot unknown"))
	}
	if err := browserQASubreaper(false, &previous); err != nil {
		rememberError(err)
	} else {
		restored = true
	}
	report["subreaper_restored"] = restored
	report["snapshot_verified"] = auditErr == nil
	report["cleanup_complete"] = auditErr == nil && len(left) == 0
	if auditErr != nil {
		report["error"] = auditErr.Error()
		return report, fmt.Errorf("owned browser-process supervision failed: %w", auditErr)
	}
	if commandErr != nil {
		return report, fmt.Errorf("owned Node command failed: %w", commandErr)
	}
	if report["forced_cleanup"] == true {
		return report, fmt.Errorf("Node returned before owned descendants exited; bounded cleanup recovered them")
	}
	return report, nil
}

func TestBrowserQAParseProcIdentity(t *testing.T) {
	fields := []string{"S", "42", "43"}
	for len(fields) < 20 {
		fields = append(fields, "0")
	}
	fields[19] = "123456"
	p, err := browserQAParseProc(44, "44 (name ) with spaces) "+strings.Join(fields, " "))
	if err != nil || p.parent != 42 || p.group != 43 || p.start != "123456" {
		t.Fatalf("parse actual proc field positions: %+v, %v", p, err)
	}
	for _, raw := range []string{"invalid", "1 (x) S 1", strings.Repeat("x", 4097)} {
		if _, err := browserQAParseProc(1, raw); err == nil {
			t.Errorf("invalid process identity accepted: %q", raw[:min(len(raw), 32)])
		}
	}
}

func TestBrowserQAOwnedSignalRejectsChangedIdentity(t *testing.T) {
	if os.Getenv("DEVSECOPS_BROWSER_QA") != "1" {
		t.Skip("owned-process runtime QA not requested")
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	p, err := browserQAParseProc(os.Getpid(), string(raw))
	if err != nil {
		t.Fatal(err)
	}
	p.start = "0" // Deliberately wrong; even a harmless signal 0 must be refused.
	if err := browserQASignalOwned(p, 0); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("changed owned-process identity not specifically refused: %v", err)
	}
}

// This child-only test fixture contains no browser, server, credentials or network.
func TestBrowserQAProcessFixture(t *testing.T) {
	role := os.Getenv("DEVSECOPS_QA_PROCESS_FIXTURE")
	if role == "" {
		return
	}
	if role == "leaf" {
		signal.Ignore(syscall.SIGTERM, os.Interrupt)
		if _, err := fmt.Fprintln(os.Stdout, "synthetic owned child ready"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Second)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestBrowserQAProcessFixture$", "-test.timeout=20s")
	child.Env = []string{"DEVSECOPS_QA_PROCESS_FIXTURE=leaf"}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readyRead.Close() }()
	defer func() { _ = readyWrite.Close() }()
	child.Stdout = readyWrite
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // Deliberately escape the root group.
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(readyRead).ReadString('\n')
	if err != nil || line != "synthetic owned child ready\n" {
		t.Fatalf("synthetic child readiness: %q %v", line, err)
	}
	if role == "timeout" {
		signal.Ignore(os.Interrupt)
		time.Sleep(15 * time.Second)
	}
	os.Exit(0) // Deliberately orphan leaf; the owning subreaper must recover/reap it.
}

func TestBrowserQAOwnedProcessRecoversOrphanAndNodeTimeout(t *testing.T) {
	if os.Getenv("DEVSECOPS_BROWSER_QA") != "1" {
		t.Skip("owned-process runtime QA not requested")
	}
	for _, role := range []string{"orphan", "timeout"} {
		t.Run(role, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestBrowserQAProcessFixture$", "-test.timeout=20s")
			cmd.Env = []string{"DEVSECOPS_QA_PROCESS_FIXTURE=" + role}
			cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
			cmd.WaitDelay = 100 * time.Millisecond
			report, err := browserQARunOwnedProcess(ctx, cmd)
			if err == nil || report["cleanup_complete"] != true || report["node_reaped"] != true || report["forced_cleanup"] != true || report["remaining_owned_pids"] != 0 || report["adopted_pids"].(int) < 1 {
				t.Fatalf("orphan/timeout must fail command but verify recovered descendants: report=%+v err=%v", report, err)
			}
		})
	}
}

func TestBrowserQAOwnedDiscoveryRejectsUnobservedGroupReuse(t *testing.T) {
	self := browserQAProc{pid: 100, start: "supervisor"}
	oldRoot := browserQAProc{pid: 200, parent: 100, group: 200, start: "old-root"}
	for _, tc := range []struct {
		name    string
		current map[int]browserQAProc
	}{
		{"group-and-leader-replaced-between-polls", map[int]browserQAProc{
			100: self,
			200: {pid: 200, parent: 900, group: 200, start: "replacement-root"},
			201: {pid: 201, parent: 200, group: 200, start: "replacement-child"},
		}},
		{"same-group-parent-not-present", map[int]browserQAProc{
			100: self,
			201: {pid: 201, parent: 200, group: 200, start: "unproven-child"},
		}},
		{"new-group-parent-not-present", map[int]browserQAProc{
			100: self,
			201: {pid: 201, parent: 200, group: 201, start: "unproven-setsid-child"},
		}},
		{"same-group-unrelated-parent", map[int]browserQAProc{
			100: self,
			201: {pid: 201, parent: 900, group: 200, start: "unrelated-child"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known := map[int]browserQAProc{200: oldRoot}
			if err := browserQADiscoverOwned(tc.current, known, self, 200, map[string]bool{}); err == nil {
				t.Fatal("unproven process/group ownership was not rejected")
			}
			if len(known) != 1 || known[200].start != oldRoot.start {
				t.Fatalf("replacement identity admitted to signal candidates: %+v", known)
			}
			for pid, p := range tc.current {
				if candidate, exists := known[pid]; exists && candidate.start == p.start {
					t.Fatalf("unproven current identity became a signal candidate: %+v", p)
				}
			}
		})
	}
}

func TestBrowserQAOwnedDiscoveryRequiresLiveKnownParentOrSupervisorAdoption(t *testing.T) {
	self := browserQAProc{pid: 100, start: "supervisor"}
	root := browserQAProc{pid: 200, parent: 100, group: 200, start: "root"}
	current := map[int]browserQAProc{
		100: self, 200: root,
		201: {pid: 201, parent: 200, group: 200, start: "child"},
		202: {pid: 202, parent: 201, group: 202, start: "setsid-grandchild"},
		203: {pid: 203, parent: 100, group: 203, start: "adopted-orphan"},
	}
	known, adopted := map[int]browserQAProc{200: root}, map[string]bool{}
	if err := browserQADiscoverOwned(current, known, self, 200, adopted); err != nil || len(known) != 4 || !adopted["203:adopted-orphan"] {
		t.Fatalf("verified ancestry/adoption not preserved: known=%+v adopted=%+v err=%v", known, adopted, err)
	}
	// A missing/replaced supervisor cannot authorize an apparent new adoption.
	for _, supervisor := range []browserQAProc{{pid: 999, start: "missing"}, {pid: 100, start: "old-supervisor"}} {
		known = map[int]browserQAProc{200: root}
		if err := browserQADiscoverOwned(current, known, supervisor, 200, map[string]bool{}); err == nil || len(known) != 1 {
			t.Fatalf("unknown supervisor admitted new ownership: known=%+v err=%v", known, err)
		}
	}
}
