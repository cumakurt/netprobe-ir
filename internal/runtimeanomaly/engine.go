package runtimeanomaly

import (
	"fmt"
	"netprobe-ir/internal/model"
	"strings"
	"time"
)

type Engine struct{}

func New() *Engine { return &Engine{} }
func (e *Engine) Observe(ev model.RuntimeEvent) (model.SecurityFinding, bool) {
	kind := strings.ToLower(ev.Kind)
	path := strings.ToLower(ev.Path)
	sev, conf, rule, title := "", 0, "", ""
	evidence := map[string]any{"runtime_kind": ev.Kind, "path": ev.Path, "source": ev.Source}
	switch {
	case kind == "memfd_create":
		sev = "high"
		conf = 90
		rule = "NP-RUNTIME-1001"
		title = "Anonymous memfd object created"
	case kind == "ptrace":
		sev = "medium"
		conf = 75
		rule = "NP-RUNTIME-1002"
		title = "Process tracing activity observed"
	case kind == "execve" && (strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.Contains(path, "(deleted)")):
		sev = "high"
		conf = 92
		rule = "NP-RUNTIME-1003"
		title = "Executable launched from transient/deleted path"
	case kind == "setns" || kind == "mount" || kind == "capset":
		sev = "medium"
		conf = 72
		rule = "NP-RUNTIME-1004"
		title = "Sensitive namespace or capability operation"
	default:
		return model.SecurityFinding{}, false
	}
	f := model.SecurityFinding{ID: fmt.Sprintf("runtime-%d-%d", ev.PID, time.Now().UnixNano()), Time: ev.Time, Severity: sev, Confidence: conf, Verdict: "behavioral", RuleID: rule, Title: title, Description: "Runtime security event crossed a deterministic NetProbe policy rule.", Category: "runtime_security", Tactic: "Execution", PID: ev.PID, Process: ev.Comm, Source: ev.Local, Destination: ev.Remote, Protocol: ev.Proto, Evidence: evidence, Tags: []string{"runtime", "ebpf"}}
	return f, true
}
