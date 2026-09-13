package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/auth"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/pipeline"
)

func exportTestEngine(t *testing.T) *pipeline.Engine {
	t.Helper()
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Interfaces = []string{"lo"}
	if err := c.Prepare(); err != nil {
		t.Fatal(err)
	}
	return pipeline.New(c)
}
func doJSON(t *testing.T, h http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &b)
	r.RemoteAddr = "127.0.0.1:12345"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestExportAPISyslogFlowAndPersistence(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	sport := udp.LocalAddr().(*net.UDPAddr).Port
	flow, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	fport := flow.LocalAddr().(*net.UDPAddr).Port
	e := exportTestEngine(t)
	h := New(e, "").Handler()
	w := doJSON(t, h, http.MethodPost, "/api/v1/export/syslog", map[string]any{"name": "siem", "enabled": false, "host": "127.0.0.1", "port": sport, "transport": "udp", "format": "rfc5424", "facility": 16, "severity": 6, "categories": []string{"security", "system"}}, "")
	if w.Code != 200 {
		t.Fatalf("syslog create %d %s", w.Code, w.Body.String())
	}
	var sd struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &sd)
	if sd.ID == "" {
		t.Fatal("missing syslog id")
	}
	w = doJSON(t, h, http.MethodPost, "/api/v1/export/syslog/"+sd.ID+"/test", nil, "")
	if w.Code != 200 {
		t.Fatalf("syslog test %d %s", w.Code, w.Body.String())
	}
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8192)
	n, _, err := udp.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], []byte("syslog_test")) {
		t.Fatalf("syslog=%q", buf[:n])
	}
	w = doJSON(t, h, http.MethodPost, "/api/v1/export/flow", map[string]any{"name": "ipfix", "enabled": false, "host": "127.0.0.1", "port": fport, "protocol": "ipfix", "observation_domain": 99, "active_timeout_seconds": 60, "inactive_timeout_seconds": 15, "template_refresh_seconds": 30, "sampling_rate": 1, "agent_address": "127.0.0.1"}, "")
	if w.Code != 200 {
		t.Fatalf("flow create %d %s", w.Code, w.Body.String())
	}
	var fc struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &fc)
	if fc.ID == "" {
		t.Fatal("missing collector id")
	}
	w = doJSON(t, h, http.MethodPost, "/api/v1/export/flow/"+fc.ID+"/test", nil, "")
	if w.Code != 200 {
		t.Fatalf("flow test %d %s", w.Code, w.Body.String())
	}
	_ = flow.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 2; i++ {
		n, _, err = flow.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n < 16 || buf[0] != 0 || buf[1] != 10 {
			t.Fatalf("not IPFIX: %x", buf[:n])
		}
	}
	// Managers use persistent JSON under the data directory.
	e2 := pipeline.New(e.Config)
	if len(e2.SyslogExport.List()) != 1 || len(e2.FlowExport.List()) != 1 {
		t.Fatal("export config did not persist")
	}
}

func TestExportAPIAuthorizationAndValidation(t *testing.T) {
	e := exportTestEngine(t)
	ac := auth.DefaultConfig()
	ac.PasswordIterations = 50000
	am, err := auth.New(filepath.Join(e.Config.DataDir, "auth", "users.json"), ac)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := am.CreateToken("admin", "viewer", "viewer", []string{"read:integrations"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSecure(e, "", am, nil, nil)
	h := s.Handler()
	good := map[string]any{"name": "bad", "host": "bad host", "port": 514, "transport": "udp", "format": "rfc5424", "facility": 16, "severity": 6}
	w := doJSON(t, h, http.MethodPost, "/api/v1/export/syslog", good, secret)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer mutation code=%d body=%s", w.Code, w.Body.String())
	}
	// Local admin path validates malformed destination fields at the backend.
	h2 := New(e, "").Handler()
	w = doJSON(t, h2, http.MethodPost, "/api/v1/export/syslog", good, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid host code=%d", w.Code)
	}
	w = doJSON(t, h2, http.MethodPost, "/api/v1/export/flow", map[string]any{"name": "x", "host": "127.0.0.1", "port": 70000, "protocol": "ipfix"}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid port code=%d", w.Code)
	}
}

func TestSyslogPrivateKeyRedactedFromAPI(t *testing.T) {
	e := exportTestEngine(t)
	h := New(e, "").Handler()
	body := map[string]any{"name": "mtls", "enabled": false, "host": "127.0.0.1", "port": 6514, "transport": "tls", "format": "rfc5424", "framing": "octet-counting", "facility": 16, "severity": 6, "categories": []string{"security"}, "tls": map[string]any{"client_cert_file": "/etc/netprobe-ir/client.crt", "client_key_file": "/etc/netprobe-ir/client.key"}}
	w := doJSON(t, h, http.MethodPost, "/api/v1/export/syslog", body, "")
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("client.key")) {
		t.Fatalf("private key path leaked: %s", w.Body.String())
	}
	var d map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d["has_client_key"] != true {
		t.Fatalf("expected redacted key marker: %#v", d)
	}
	id, _ := d["id"].(string)
	w = doJSON(t, h, http.MethodGet, "/api/v1/export/syslog/"+id, nil, "")
	if bytes.Contains(w.Body.Bytes(), []byte("client.key")) {
		t.Fatalf("GET leaked key path: %s", w.Body.String())
	}
}

func TestExportAPIReadScopeCanListButNotMutate(t *testing.T) {
	e := exportTestEngine(t)
	ac := auth.DefaultConfig()
	ac.PasswordIterations = 50000
	am, err := auth.New(filepath.Join(e.Config.DataDir, "auth", "users.json"), ac)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := am.CreateToken("admin", "viewer", "viewer", []string{"read:integrations"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := NewSecure(e, "", am, nil, nil).Handler()
	w := doJSON(t, h, http.MethodGet, "/api/v1/export/syslog", nil, secret)
	if w.Code != 200 {
		t.Fatalf("read scope list=%d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, h, http.MethodPost, "/api/v1/export/flow", map[string]any{"name": "x", "host": "127.0.0.1", "port": 2055, "protocol": "netflow5", "active_timeout_seconds": 60, "inactive_timeout_seconds": 15, "template_refresh_seconds": 30, "sampling_rate": 1, "agent_address": "127.0.0.1"}, secret)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read token mutated settings: %d", w.Code)
	}
}
