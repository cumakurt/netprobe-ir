package runtimeanomaly

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestTransientExec(t *testing.T) {
	f, ok := New().Observe(model.RuntimeEvent{Time: time.Now(), Kind: "execve", PID: 5, Comm: "x", Path: "/tmp/a", Source: "ebpf"})
	if !ok || f.RuleID != "NP-RUNTIME-1003" || f.Confidence < 90 {
		t.Fatalf("bad %#v", f)
	}
}
