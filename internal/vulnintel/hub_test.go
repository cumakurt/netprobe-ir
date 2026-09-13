package vulnintel

import (
	"testing"
	"time"

	"netprobe-ir/internal/model"
)

func TestKEVContext(t *testing.T) {
	h := New()
	j := []byte(`{"vulnerabilities":[{"cveID":"CVE-1","vendorProject":"Acme","product":"Widget","vulnerabilityName":"x","dateAdded":"2026-01-01","dueDate":"2026-02-01","knownRansomwareCampaignUse":"Unknown","notes":"n"}]}`)
	if e := h.LoadKEV(j); e != nil {
		t.Fatal(e)
	}
	h.SetPackages([]Package{{Name: "acme-widget", Version: "1.0"}})
	x := h.Exposures()
	if len(x) != 1 || x[0].ProvenVulnerable {
		t.Fatalf("%#v", x)
	}
}

func TestCorrelateRuntimePreservesVersionProofBoundary(t *testing.T) {
	h := New()
	_ = h.LoadKEV([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1","vendorProject":"Acme","product":"apache","vulnerabilityName":"x"}]}`))
	h.SetPackages([]Package{{Name: "apache", Version: "2.4", Source: "dpkg"}})
	now := time.Now()
	findings := []model.SecurityFinding{{ID: "f1", Time: now, Severity: "critical", Confidence: 95, Verdict: "signature_match", RuleID: "EXP", Title: "apache exploit", Category: "exploit", PID: 44, Process: "apache"}}
	runtime := []model.RuntimeEvent{{Time: now.Add(time.Second), Kind: "execve", PID: 44, Comm: "apache", Path: "/bin/sh", Source: "ebpf", Confidence: 95}}
	x := h.CorrelateRuntime(findings, runtime)
	if len(x) != 1 || x[0].Score < 70 || !x[0].RuntimeCorrelated || x[0].VersionProven {
		t.Fatalf("chains=%#v", x)
	}
}
