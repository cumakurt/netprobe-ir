package ebpfattr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Kind                           string
	Proto, LocalIP, RemoteIP, Comm string
	Path                           string
	LocalPort, RemotePort          uint16
	PID, PPID, UID                 int
	Success                        bool
	Time                           time.Time
}

type Runner struct {
	Path    string
	mu      sync.RWMutex
	active  bool
	lastErr string
}

func (r *Runner) Active() bool      { r.mu.RLock(); defer r.mu.RUnlock(); return r.active }
func (r *Runner) LastError() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.lastErr }
func (r *Runner) Available() bool {
	p := r.Path
	if p == "" {
		p = "bpftrace"
	}
	_, e := exec.LookPath(p)
	return e == nil
}

// Runtime probes are assembled from tracepoints actually exposed by the host.
// This avoids making one missing syscall tracepoint disable all eBPF attribution.
const connectProgram = `
kprobe:tcp_v4_connect
{
  $sk = (struct sock *)arg0;
  $dp = bswap($sk->__sk_common.skc_dport);
  printf("NPBPF|connect|%d|%d|%s|TCP|%s|%d|%s|%d\\n", pid, uid, comm,
    ntop($sk->__sk_common.skc_rcv_saddr), $sk->__sk_common.skc_num,
    ntop($sk->__sk_common.skc_daddr), $dp);
}
`

var runtimeFragments = map[string]string{
	"execve":       `tracepoint:syscalls:sys_enter_execve { printf("NPBPF|runtime|execve|%d|%d|%s|%s\\n", pid, uid, comm, str(args->filename)); }`,
	"openat":       `tracepoint:syscalls:sys_enter_openat { printf("NPBPF|runtime|openat|%d|%d|%s|%s\\n", pid, uid, comm, str(args->filename)); }`,
	"unlinkat":     `tracepoint:syscalls:sys_enter_unlinkat { printf("NPBPF|runtime|unlinkat|%d|%d|%s|%s\\n", pid, uid, comm, str(args->pathname)); }`,
	"renameat2":    `tracepoint:syscalls:sys_enter_renameat2 { printf("NPBPF|runtime|renameat2|%d|%d|%s|%s\\n", pid, uid, comm, str(args->oldname)); }`,
	"chmod":        `tracepoint:syscalls:sys_enter_chmod { printf("NPBPF|runtime|chmod|%d|%d|%s|%s\\n", pid, uid, comm, str(args->filename)); }`,
	"fchmodat":     `tracepoint:syscalls:sys_enter_fchmodat { printf("NPBPF|runtime|fchmodat|%d|%d|%s|%s\\n", pid, uid, comm, str(args->filename)); }`,
	"chown":        `tracepoint:syscalls:sys_enter_chown { printf("NPBPF|runtime|chown|%d|%d|%s|%s\\n", pid, uid, comm, str(args->filename)); }`,
	"memfd_create": `tracepoint:syscalls:sys_enter_memfd_create { printf("NPBPF|runtime|memfd_create|%d|%d|%s|%s\\n", pid, uid, comm, str(args->uname)); }`,
	"ptrace":       `tracepoint:syscalls:sys_enter_ptrace { printf("NPBPF|runtime|ptrace|%d|%d|%s|request=%d\\n", pid, uid, comm, args->request); }`,
	"setuid":       `tracepoint:syscalls:sys_enter_setuid { printf("NPBPF|runtime|setuid|%d|%d|%s|target_uid=%d\\n", pid, uid, comm, args->uid); }`,
	"setgid":       `tracepoint:syscalls:sys_enter_setgid { printf("NPBPF|runtime|setgid|%d|%d|%s|target_gid=%d\\n", pid, uid, comm, args->gid); }`,
	"mount":        `tracepoint:syscalls:sys_enter_mount { printf("NPBPF|runtime|mount|%d|%d|%s|%s\\n", pid, uid, comm, str(args->dir_name)); }`,
	"setns":        `tracepoint:syscalls:sys_enter_setns { printf("NPBPF|runtime|setns|%d|%d|%s|nstype=%d\\n", pid, uid, comm, args->nstype); }`,
	"clone":        `tracepoint:syscalls:sys_enter_clone { printf("NPBPF|runtime|clone|%d|%d|%s|flags=%d\\n", pid, uid, comm, args->clone_flags); }`,
	"bind":         `tracepoint:syscalls:sys_enter_bind { printf("NPBPF|runtime|bind|%d|%d|%s|fd=%d\\n", pid, uid, comm, args->fd); }`,
	"listen":       `tracepoint:syscalls:sys_enter_listen { printf("NPBPF|runtime|listen|%d|%d|%s|fd=%d\\n", pid, uid, comm, args->fd); }`,
	"accept4":      `tracepoint:syscalls:sys_enter_accept4 { printf("NPBPF|runtime|accept4|%d|%d|%s|fd=%d\\n", pid, uid, comm, args->fd); }`,
}

func Capabilities() []string {
	out := []string{"connect"}
	for k := range runtimeFragments {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func BuildProgram(available string) string {
	program := connectProgram
	for _, kind := range Capabilities() {
		if kind == "connect" {
			continue
		}
		probe := "tracepoint:syscalls:sys_enter_" + kind
		if strings.Contains(available, probe) {
			program += "\n" + runtimeFragments[kind] + "\n"
		}
	}
	return program
}

func (r *Runner) discoverProgram(p string) string {
	cmd := exec.Command(p, "-l", "tracepoint:syscalls:sys_enter_*")
	b, err := cmd.Output()
	if err != nil {
		return connectProgram
	}
	return BuildProgram(string(b))
}

func (r *Runner) Run(ctx context.Context, cb func(Event)) error {
	p := r.Path
	if p == "" {
		p = "bpftrace"
	}
	if _, e := exec.LookPath(p); e != nil {
		return fmt.Errorf("bpftrace unavailable: %w", e)
	}
	program := r.discoverProgram(p)
	cmd := exec.CommandContext(ctx, p, "-q", "-e", program)
	out, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	errout, e := cmd.StderrPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return e
	}
	r.mu.Lock()
	r.active = true
	r.lastErr = ""
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.active = false; r.mu.Unlock() }()
	errCh := make(chan string, 1)
	go func() { b, _ := io.ReadAll(io.LimitReader(errout, 64<<10)); errCh <- strings.TrimSpace(string(b)) }()
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		ev, ok := ParseLine(sc.Text())
		if ok && cb != nil {
			cb(ev)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	msg := <-errCh
	if ctx.Err() != nil {
		return nil
	}
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		if msg != "" {
			r.mu.Lock()
			r.lastErr = msg
			r.mu.Unlock()
			return fmt.Errorf("bpftrace: %s", msg)
		}
		return waitErr
	}
	return nil
}

func ParseLine(line string) (Event, bool) {
	fs := strings.Split(strings.TrimSpace(line), "|")
	if len(fs) < 2 || fs[0] != "NPBPF" {
		return Event{}, false
	}
	now := time.Now()
	switch fs[1] {
	case "connect":
		if len(fs) != 10 {
			return Event{}, false
		}
		pid, e1 := strconv.Atoi(fs[2])
		uid, e2 := strconv.Atoi(fs[3])
		lp, e3 := strconv.ParseUint(fs[7], 10, 16)
		rp, e4 := strconv.ParseUint(fs[9], 10, 16)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			return Event{}, false
		}
		return Event{Kind: "connect", PID: pid, UID: uid, Comm: fs[4], Proto: fs[5], LocalIP: fs[6], LocalPort: uint16(lp), RemoteIP: fs[8], RemotePort: uint16(rp), Success: true, Time: now}, true
	case "runtime":
		if len(fs) < 7 {
			return Event{}, false
		}
		pid, e1 := strconv.Atoi(fs[3])
		uid, e2 := strconv.Atoi(fs[4])
		if e1 != nil || e2 != nil {
			return Event{}, false
		}
		path := strings.Join(fs[6:], "|")
		return Event{Kind: fs[2], PID: pid, UID: uid, Comm: fs[5], Path: path, Success: true, Time: now}, true
	default:
		return Event{}, false
	}
}
