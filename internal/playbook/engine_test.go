package playbook

import (
	"netprobe-ir/internal/model"
	"path/filepath"
	"testing"
)

func TestStoreEvaluate(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "p.json"))
	if e != nil {
		t.Fatal(e)
	}
	p := Playbook{ID: "x", Name: "confirmed", Enabled: true, Mode: ApprovalRequired, Condition: Condition{MinSeverity: "high", MinConfidence: 90, Verdicts: []string{"confirmed_ioc"}}, Actions: []Action{{Type: "block_ip", TTLSeconds: 900}}}
	if e = s.Upsert(p); e != nil {
		t.Fatal(e)
	}
	ms := s.Evaluate(model.SecurityFinding{ID: "f", Severity: "critical", Confidence: 95, Verdict: "confirmed_ioc"})
	if len(ms) != 1 || !ms[0].RequiresApproval {
		t.Fatalf("bad %#v", ms)
	}
}
func TestAutomaticExplicit(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "p.json"))
	_ = s.Upsert(Playbook{ID: "a", Name: "auto", Enabled: true, Mode: Automatic, Condition: Condition{MinSeverity: "critical"}, Actions: []Action{{Type: "create_case"}}})
	m := s.Evaluate(model.SecurityFinding{ID: "f", Severity: "critical"})
	if len(m) != 1 || !m[0].Automatic {
		t.Fatal("expected automatic")
	}
}
