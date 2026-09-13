package stories

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestCorrelatesProcessFindings(t *testing.T) {
	now := time.Now()
	fs := []model.SecurityFinding{{ID: "1", Time: now, Severity: "high", Confidence: 80, RuleID: "A", Title: "one", PID: 42, Process: "python", MITRE: []string{"T1071"}}, {ID: "2", Time: now.Add(time.Second), Severity: "critical", Confidence: 95, RuleID: "B", Title: "two", PID: 42, Process: "python", MITRE: []string{"T1041"}}}
	s := Build(fs, nil, 10)
	if len(s) != 1 || s[0].Findings != 2 || s[0].Severity != "critical" || len(s[0].MITRE) != 2 {
		t.Fatalf("%#v", s)
	}
}

func TestBuildExtendedAddsRootCauseRiskAndRuntime(t *testing.T) {
	now := time.Now()
	findings := []model.SecurityFinding{{ID: "f1", Time: now.Add(2 * time.Second), Severity: "high", Confidence: 90, RuleID: "R1", Title: "exploit", PID: 42, Process: "svc", Destination: model.Endpoint{IP: "203.0.113.1"}}}
	flows := []model.Flow{{ID: "fl1", FirstSeen: now.Add(time.Second), LastSeen: now.Add(3 * time.Second), Remote: model.Endpoint{IP: "203.0.113.1", Port: 443}, Direction: model.DirectionOutbound, Process: &model.ProcessInfo{PID: 42, Comm: "svc"}, DPI: model.DPIInfo{Application: "TLS"}}}
	files := []model.FileArtifact{{ID: "file1", Time: now.Add(1500 * time.Millisecond), FlowID: "fl1", Name: "payload", Yara: []model.YaraMatch{{Rule: "bad"}}}}
	runtime := []model.RuntimeEvent{{Time: now, Kind: "execve", PID: 42, Comm: "svc", Path: "/tmp/payload", Source: "ebpf", Confidence: 95}}
	x := BuildExtended(findings, flows, files, runtime, 10)
	if len(x) != 1 || x[0].RootCause == nil || !x[0].RootCause.Inference || x[0].Runtime != 1 || x[0].Files != 1 || len(x[0].RiskTimeline) == 0 {
		t.Fatalf("story=%#v", x)
	}
	if x[0].RootCause.Kind != "runtime" {
		t.Fatalf("root=%#v", x[0].RootCause)
	}
}
