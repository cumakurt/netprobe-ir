package scripting

import (
	"netprobe-ir/internal/model"
	"testing"
)

func TestParseAndEvaluate(t *testing.T) {
	r, e := Parse("rule py\ntitle Python TLS\nseverity high\nconfidence 90\nmitre T1071.001\nwhen process ~ python AND app ~ TLS AND direction = outbound\nend\n")
	if e != nil || len(r) != 1 {
		t.Fatalf("parse: %v %#v", e, r)
	}
	eng := New()
	eng.rules = r
	f := model.Flow{ID: "x", Direction: model.DirectionOutbound, Process: &model.ProcessInfo{Comm: "python3"}, DPI: model.DPIInfo{Application: "HTTPS/TLS"}}
	got := eng.Evaluate(Context{Flow: f})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("got %#v", got)
	}
}
