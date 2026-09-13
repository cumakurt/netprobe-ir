package tuning

import (
	"netprobe-ir/internal/model"
	"path/filepath"
	"testing"
)

func TestSuppression(t *testing.T) {
	s, _ := New(filepath.Join(t.TempDir(), "tuning.json"))
	r, e := s.Add(Rule{Kind: "rule", Value: "NP-1"})
	if e != nil || r.ID == "" {
		t.Fatal(e)
	}
	if !s.Suppressed(model.SecurityFinding{RuleID: "NP-1"}) {
		t.Fatal("not suppressed")
	}
	if e = s.Delete(r.ID); e != nil {
		t.Fatal(e)
	}
	if s.Suppressed(model.SecurityFinding{RuleID: "NP-1"}) {
		t.Fatal("still suppressed")
	}
}
