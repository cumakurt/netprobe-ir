package smartpcap

import (
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
	"testing"
)

func TestHeadersAndMatch(t *testing.T) {
	p := &decode.Packet{Interface: "eth0", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", Raw: make([]byte, 100), Payload: make([]byte, 20)}
	f := model.Flow{Direction: model.DirectionOutbound, Process: &model.ProcessInfo{Comm: "curl"}, DPI: model.DPIInfo{Application: "HTTP"}}
	pol := Policy{Mode: "smart", DefaultAction: "headers", Rules: []Rule{{Name: "curl", Process: "curl", Action: "full"}}}
	if d := pol.Decide(p, f); d.Action != "full" {
		t.Fatal(d)
	}
	pol.Rules = nil
	fr, ok := Apply(pol.Decide(p, f), p, capture.Frame{Data: make([]byte, 100)})
	if !ok || len(fr.Data) != 80 {
		t.Fatalf("%v %d", ok, len(fr.Data))
	}
}
