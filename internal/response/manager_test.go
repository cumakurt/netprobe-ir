package response

import (
	"context"
	"testing"
)

func TestDryRunGuardrails(t *testing.T) {
	m := New(Config{Enabled: true, DryRun: true, AllowedActions: []string{"block_ip", "kill_process"}, Allowlist: []string{"192.0.2.0/24"}})
	r, e := m.Execute(context.Background(), Request{Action: "block_ip", IP: "203.0.113.5", TTLSeconds: 60})
	if e != nil || !r.OK || !r.DryRun {
		t.Fatal(r, e)
	}
	if _, e = m.Execute(context.Background(), Request{Action: "block_ip", IP: "127.0.0.1"}); e == nil {
		t.Fatal("loopback accepted")
	}
	if _, e = m.Execute(context.Background(), Request{Action: "block_ip", IP: "192.0.2.5"}); e == nil {
		t.Fatal("allowlisted accepted")
	}
	if _, e = m.Execute(context.Background(), Request{Action: "kill_process", PID: 1}); e == nil {
		t.Fatal("pid1 accepted")
	}
}
func TestLiveNeedsConfirm(t *testing.T) {
	m := New(Config{Enabled: true, DryRun: false, AllowedActions: []string{"kill_process"}})
	if _, e := m.Execute(context.Background(), Request{Action: "kill_process", PID: 99999}); e == nil {
		t.Fatal("missing confirmation accepted")
	}
}
