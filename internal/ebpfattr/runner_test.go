package ebpfattr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	e, ok := ParseLine("NPBPF|connect|4321|1000|curl|TCP|10.0.0.2|51515|203.0.113.9|443")
	if !ok || e.Kind != "connect" || e.PID != 4321 || e.LocalIP != "10.0.0.2" || e.LocalPort != 51515 || e.RemoteIP != "203.0.113.9" || e.RemotePort != 443 {
		t.Fatalf("bad %+v %v", e, ok)
	}
	r, ok := ParseLine("NPBPF|runtime|execve|77|1000|bash|/tmp/payload")
	if !ok || r.Kind != "execve" || r.PID != 77 || r.Path != "/tmp/payload" {
		t.Fatalf("runtime=%+v %v", r, ok)
	}
}

func TestRunnerProviderLifecycleWithCompatibleEmitter(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "bpftrace")
	script := "#!/bin/sh\nprintf '%s\\n' 'NPBPF|connect|77|1000|curl|TCP|10.0.0.2|51000|203.0.113.9|443'\nprintf '%s\\n' 'NPBPF|runtime|execve|77|1000|curl|/tmp/x'\n"
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Path: p}
	var got []Event
	if err := r.Run(context.Background(), func(e Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RemotePort != 443 || got[1].Kind != "execve" {
		t.Fatalf("callbacks: %+v", got)
	}
	if r.Active() {
		t.Fatal("runner remained active after exit")
	}
}

func TestBuildProgramUsesOnlyAvailableRuntimeTracepoints(t *testing.T) {
	p := BuildProgram("tracepoint:syscalls:sys_enter_execve\ntracepoint:syscalls:sys_enter_setuid\n")
	if !strings.Contains(p, "sys_enter_execve") || !strings.Contains(p, "sys_enter_setuid") || strings.Contains(p, "sys_enter_ptrace") {
		t.Fatalf("program=%s", p)
	}
}
