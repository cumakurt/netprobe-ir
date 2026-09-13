package pipeline

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
)

func v07TCPFrame(srcPort, dstPort uint16, payload string) []byte {
	p := []byte(payload)
	n := 20 + 20 + len(p)
	b := make([]byte, 14+n)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	o := 14
	b[o] = 0x45
	binary.BigEndian.PutUint16(b[o+2:o+4], uint16(n))
	b[o+8] = 64
	b[o+9] = 6
	copy(b[o+12:o+16], []byte{10, 10, 0, 10})
	copy(b[o+16:o+20], []byte{198, 51, 100, 20})
	q := o + 20
	binary.BigEndian.PutUint16(b[q:q+2], srcPort)
	binary.BigEndian.PutUint16(b[q+2:q+4], dstPort)
	b[q+12] = 0x50
	b[q+13] = 0x18
	copy(b[q+20:], p)
	return b
}

func TestV07PipelineFileExtractionAndNPDL(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules.npdl")
	if err := os.WriteFile(rules, []byte(`rule suspicious_http
 title Suspicious HTTP target
 severity high
 confidence 91
 mitre T1071.001
 when http_host = target.example AND application ~ HTTP
 end
`), 0600); err != nil {
		t.Fatal(err)
	}

	c := config.Default()
	c.DataDir = filepath.Join(root, "data")
	c.Recorder.Enabled = false
	c.Scripting.Enabled = true
	c.Scripting.RulesFile = rules
	c.FileExtraction.Enabled = true
	c.FileExtraction.StorePayload = false
	e := New(c)

	e.ProcessReplayFrame(capture.Frame{Time: time.Now().UTC(), Interface: "replay0", Direction: model.DirectionOutbound, Data: v07TCPFrame(51000, 80, "GET /x HTTP/1.1\r\nHost: target.example\r\n\r\n")})
	foundScript := false
	for _, f := range e.Findings(100) {
		if f.RuleID == "NPDL-suspicious_http" {
			foundScript = true
		}
	}
	if !foundScript {
		t.Fatalf("NPDL finding missing: %#v", e.Findings(100))
	}

	// A server-to-client HTTP response with Content-Disposition should be reconstructed.
	body := "MZ-network-artifact"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 19\r\nContent-Disposition: attachment; filename=payload.exe\r\n\r\n" + body
	e.ProcessReplayFrame(capture.Frame{Time: time.Now().UTC(), Interface: "replay0", Direction: model.DirectionInbound, Data: v07TCPFrame(80, 51001, resp)})
	files := e.FilesList(20)
	if len(files) == 0 {
		t.Fatal("expected reconstructed file artifact")
	}
	if files[0].Name != "payload.exe" || files[0].SHA256 == "" || files[0].Entropy <= 0 {
		t.Fatalf("unexpected artifact: %+v", files[0])
	}
}

func TestV07ProtocolPackClassificationThroughPipeline(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	// Redis RESP signature on the standard port exercises the database protocol pack.
	e.ProcessReplayFrame(capture.Frame{Time: time.Now().UTC(), Interface: "replay0", Direction: model.DirectionOutbound, Data: v07TCPFrame(52000, 6379, "PING\r\n")})
	flows := e.Flows(10)
	if len(flows) == 0 {
		t.Fatal("expected flow")
	}
	if flows[0].DPI.Application != "Redis" || flows[0].DPI.ProtocolPack != "database" {
		t.Fatalf("unexpected classification: %+v", flows[0].DPI)
	}
}

func TestV07SmartPCAPMetadataModePreventsFileRetention(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.FileExtraction.Enabled = true
	c.FileExtraction.StorePayload = true
	c.SmartPCAP.Mode = "metadata"
	c.SmartPCAP.DefaultAction = "metadata"
	e := New(c)
	body := "MZ-private-artifact"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 19\r\nContent-Disposition: attachment; filename=private.exe\r\n\r\n" + body
	e.ProcessReplayFrame(capture.Frame{Time: time.Now().UTC(), Interface: "replay0", Direction: model.DirectionInbound, Data: v07TCPFrame(80, 51002, resp)})
	if got := e.FilesList(20); len(got) != 0 {
		t.Fatalf("metadata-only retention created file artifacts: %+v", got)
	}
}
