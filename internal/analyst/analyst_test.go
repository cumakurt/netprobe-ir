package analyst

import (
	"context"
	"netprobe-ir/internal/model"
	"strings"
	"testing"
)

func TestLocalEvidence(t *testing.T) {
	a := New(Config{Enabled: true})
	x, e := a.Ask(context.Background(), EvidencePack{Query: "why critical", Findings: []model.SecurityFinding{{ID: "1", RuleID: "R1", Severity: "critical", Confidence: 99, Description: "IOC matched"}}})
	if e != nil || !strings.Contains(x.Text, "R1") || len(x.EvidenceIDs) != 1 {
		t.Fatalf("%v %#v", e, x)
	}
}
