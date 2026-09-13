package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditChainAndTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, e := New(p)
	if e != nil {
		t.Fatal(e)
	}
	_ = l.Append(Event{Username: "admin", Action: "login", Success: true})
	_ = l.Append(Event{Username: "admin", Action: "capture.stop", Success: true})
	if e = l.Verify(); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	_ = os.WriteFile(p, b, 0600)
	if e = l.Verify(); e == nil {
		t.Fatal("tamper not detected")
	}
}
