package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/playbook"
)

func v09Server(t *testing.T) (*httptest.Server, *pipeline.Engine) {
	t.Helper()
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Auth.Enabled = false
	e := pipeline.New(c)
	return httptest.NewServer(New(e, "").Handler()), e
}
func TestV09ReadAPIs(t *testing.T) {
	s, e := v09Server(t)
	defer s.Close()
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFrame()})
	for _, p := range []string{"/api/v1/executive-overview", "/api/v1/ocsf?kind=flows", "/api/v1/analytics", "/api/v1/asset-intelligence", "/api/v1/tls-intelligence", "/api/v1/dns-graph", "/api/v1/core-ebpf", "/api/v1/profiles"} {
		r, err := s.Client().Get(s.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s=%d", p, r.StatusCode)
		}
	}
}
func TestV09RuleTranslationAndPlaybook(t *testing.T) {
	s, _ := v09Server(t)
	defer s.Close()
	post := func(path string, v any) map[string]any {
		b, _ := json.Marshal(v)
		r, err := s.Client().Post(s.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s=%d", path, r.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return out
	}
	x := post("/api/v1/rules/import", map[string]string{"rule": `alert tcp any any -> 1.2.3.4 443 (msg:"x"; content:"evil"; sid:1;)`})
	if x["translated"] == nil {
		t.Fatal("missing translation")
	}
	c := post("/api/v1/sigma/correlation", map[string]string{"rule": "title: x\ncorrelation:\n  type: event_count\n  rules:\n    - r1\n  gte: 3\n"})
	if c["plan"] == nil {
		t.Fatal("missing plan")
	}
	post("/api/v1/playbooks", map[string]any{"name": "p", "enabled": true, "mode": "dry_run", "condition": map[string]any{"min_severity": "high"}, "actions": []map[string]any{{"type": "create_case"}}})
	r, err := s.Client().Get(s.URL + "/api/v1/playbooks")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
}
func TestV09BenchmarkAPI(t *testing.T) {
	s, _ := v09Server(t)
	defer s.Close()
	r, err := s.Client().Post(s.URL+"/api/v1/benchmark", "application/json", strings.NewReader(`{"iterations":1000}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("status=%d", r.StatusCode)
	}
}
func TestOverviewNoInterfaceAcquisitionAndClickableKPI(t *testing.T) {
	b, err := webFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	a := strings.Index(src, "function renderOverview(){")
	z := strings.Index(src, "function renderSecurity(){")
	if a < 0 || z < a {
		t.Fatal("overview not found")
	}
	overview := src[a:z]
	if strings.Contains(overview, "Interface acquisition") {
		t.Fatal("overview still shows Interface acquisition")
	}
	for _, want := range []string{"Active flows", "#/traffic", "Critical findings", "clickable-kpi", "Executive security overview"} {
		if !strings.Contains(src, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestPlaybookApprovalBridgesToExistingApprovalStore(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Auth.Enabled = false
	e := pipeline.New(c)
	srv := NewSecure(e, "", nil, nil, nil)
	if e.PlaybookApproval == nil {
		t.Fatal("playbook approval bridge missing")
	}
	f := model.SecurityFinding{ID: "F-test", Severity: "high", Confidence: 99, PID: 4242, Destination: model.Endpoint{IP: "203.0.113.44"}}
	m := playbook.Match{PlaybookID: "pb-test", PlaybookName: "approval test", RequiresApproval: true, Actions: []playbook.Action{{Type: "block_ip", TTLSeconds: 60}, {Type: "create_case"}}}
	e.PlaybookApproval(f, m)
	xs := srv.Approvals.List()
	if len(xs) != 1 {
		t.Fatalf("approvals=%d want 1: %#v", len(xs), xs)
	}
	if xs[0].RequestedBy != "automation:pb-test" || xs[0].Action.IP != "203.0.113.44" || xs[0].Action.Action != "block_ip" {
		t.Fatalf("unexpected approval: %#v", xs[0])
	}
}
