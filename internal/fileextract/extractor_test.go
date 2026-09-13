package fileextract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type fakeScanner struct{}

func (fakeScanner) Available() bool { return true }
func (fakeScanner) Scan(path string) ([]model.YaraMatch, error) {
	return []model.YaraMatch{{Rule: "TEST_MALWARE", Namespace: "default", Tags: []string{"test"}}}, nil
}

func pkt(payload string, sp, dp uint16) *decode.Packet {
	return &decode.Packet{Time: time.Now().UTC(), Interface: "lo", Direction: model.DirectionOutbound, Protocol: "TCP", SrcIP: "127.0.0.1", DstIP: "127.0.0.2", SrcPort: sp, DstPort: dp, Payload: []byte(payload)}
}
func flow(id string) model.Flow {
	return model.Flow{ID: id, Direction: model.DirectionOutbound, Process: &model.ProcessInfo{PID: 42, Comm: "curl"}}
}

func TestHTTPExtractionHashesAndYaraAsync(t *testing.T) {
	dir := t.TempDir()
	e := New(dir, Config{Enabled: true, StorePayload: true, MaxFileBytes: 1 << 20, MaxArtifacts: 50}, fakeScanner{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	body := "MZ-test-payload"
	req := "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nContent-Disposition: attachment; filename=evil.exe\r\n\r\n" + body
	out := e.Observe(pkt(req, 80, 50000), flow("f1"), model.DPIInfo{Protocol: "HTTP", Application: "HTTP"})
	if len(out) != 1 {
		t.Fatalf("artifacts=%d", len(out))
	}
	want := sha256.Sum256([]byte(body))
	if out[0].SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 mismatch")
	}
	if out[0].Name != "evil.exe" || out[0].StoredPath == "" {
		t.Fatalf("bad artifact: %+v", out[0])
	}
	select {
	case u := <-e.Updates():
		if len(u.Yara) != 1 || u.Yara[0].Rule != "TEST_MALWARE" {
			t.Fatalf("bad yara update %+v", u)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan update timeout")
	}
}

func TestSMTPAttachmentExtraction(t *testing.T) {
	e := New(t.TempDir(), Config{Enabled: true, StorePayload: false, MaxFileBytes: 1 << 20}, nil)
	msg := "DATA\r\nFrom: a@example.test\r\nTo: b@example.test\r\nSubject: sample\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\n--xyz\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=sample.bin\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--xyz--\r\n\r\n.\r\n"
	out := e.Observe(pkt(msg, 25, 40000), flow("smtp"), model.DPIInfo{Protocol: "SMTP", Application: "SMTP"})
	if len(out) != 1 || out[0].Name != "sample.bin" || out[0].Size != 5 {
		t.Fatalf("unexpected %+v", out)
	}
}

func TestYaraXScannerNDJSON(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "yr")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"path\":\"x\",\"rules\":[{\"namespace\":\"default\",\"identifier\":\"EICAR_TEST\",\"tags\":[\"malware\"],\"metadata\":{\"score\":100}}]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sample")
	_ = os.WriteFile(target, []byte("x"), 0600)
	s := &YaraXScanner{Binary: bin, Rules: filepath.Join(dir, "rules.yar")}
	m, err := s.Scan(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "EICAR_TEST" {
		t.Fatalf("unexpected %+v", m)
	}
}
