package approvals

import (
	"netprobe-ir/internal/response"
	"path/filepath"
	"testing"
)

func TestTwoPerson(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "a.json"))
	r, e := s.Create("alice", response.Request{Action: "block_ip", IP: "1.2.3.4"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Approve(r.ID, "alice", response.Result{}, nil); e == nil {
		t.Fatal("self approval allowed")
	}
	if x, e := s.Approve(r.ID, "bob", response.Result{}, nil); e != nil || x.Status != "approved" {
		t.Fatal(e)
	}
}
