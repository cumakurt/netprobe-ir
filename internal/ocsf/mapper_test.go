package ocsf

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestFindingMapping(t *testing.T) {
	f := model.SecurityFinding{ID: "f1", Time: time.Now(), Severity: "critical", Confidence: 97, Verdict: "signature_match", RuleID: "R1", Title: "x", Description: "y", Source: model.Endpoint{IP: "1.2.3.4", Port: 1}, Destination: model.Endpoint{IP: "5.6.7.8", Port: 443}, Protocol: "tcp", Application: "tls"}
	e := Finding(f)
	if e.ClassUID != 2004 || e.SeverityID != 6 || e.Dst.IP != "5.6.7.8" {
		t.Fatalf("bad map %#v", e)
	}
}
func TestFlowMapping(t *testing.T) {
	f := model.Flow{ID: "x", LastSeen: time.Now(), NetworkProtocol: "TCP", Local: model.Endpoint{IP: "10.0.0.1", Port: 1}, Remote: model.Endpoint{IP: "8.8.8.8", Port: 53}, Direction: model.DirectionOutbound, BytesTX: 10, BytesRX: 20, PacketsTX: 1, PacketsRX: 2, Risk: 80}
	e := Flow(f)
	if e.Network.Bytes != 30 || e.Severity != "high" {
		t.Fatalf("bad %#v", e)
	}
}
