package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/audit"
	"netprobe-ir/internal/auth"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/oidc"
	"netprobe-ir/internal/pipeline"
)

func secureServer(t *testing.T) (*httptest.Server, *auth.Manager, *http.Client, string) {
	t.Helper()
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Auth.PasswordIterations = 50000
	eng := pipeline.New(c)
	ac := auth.DefaultConfig()
	ac.PasswordIterations = 50000
	am, e := auth.New(filepath.Join(c.DataDir, "auth", "users.json"), ac)
	if e != nil {
		t.Fatal(e)
	}
	pw := am.InitialPassword()
	al, e := audit.New(filepath.Join(c.DataDir, "audit", "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(NewSecure(eng, "", am, al, oidc.New(oidc.Config{})).Handler())
	jar, _ := cookiejar.New(nil)
	cl := s.Client()
	cl.Jar = jar
	return s, am, cl, pw
}
func loginClient(t *testing.T, cl *http.Client, url, user, pw, mfa string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"Username": user, "Password": pw, "TOTP": mfa})
	r, e := cl.Post(url+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	var v map[string]any
	_ = json.NewDecoder(r.Body).Decode(&v)
	return r.StatusCode, v
}
func TestSecureLoginPasswordChangeRBAC(t *testing.T) {
	s, am, cl, pw := secureServer(t)
	defer s.Close()
	r, e := cl.Get(s.URL + "/api/v1/flows")
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 401 {
		t.Fatalf("expected 401 got %d", r.StatusCode)
	}
	r.Body.Close()
	code, v := loginClient(t, cl, s.URL, "admin", pw, "")
	if code != 200 || v["must_change_password"] != true {
		t.Fatalf("login %d %#v", code, v)
	}
	r, _ = cl.Get(s.URL + "/api/v1/flows")
	if r.StatusCode != 403 {
		t.Fatalf("must-change expected 403 got %d", r.StatusCode)
	}
	r.Body.Close()
	body, _ := json.Marshal(map[string]string{"current_password": pw, "new_password": "NetProbe!Secure2026"})
	r, e = cl.Post(s.URL+"/api/v1/auth/change-password", "application/json", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 200 {
		t.Fatalf("change=%d", r.StatusCode)
	}
	r.Body.Close()
	jar, _ := cookiejar.New(nil)
	cl.Jar = jar
	code, _ = loginClient(t, cl, s.URL, "admin", "NetProbe!Secure2026", "")
	if code != 200 {
		t.Fatalf("relogin %d", code)
	}
	r, _ = cl.Get(s.URL + "/api/v1/flows")
	if r.StatusCode != 200 {
		t.Fatalf("flows %d", r.StatusCode)
	}
	r.Body.Close()
	_, e = am.CreateUser("view", "Viewer", "viewer", "Viewer!Secure2026", false)
	if e != nil {
		t.Fatal(e)
	}
	vjar, _ := cookiejar.New(nil)
	vc := s.Client()
	vc.Jar = vjar
	code, _ = loginClient(t, vc, s.URL, "view", "Viewer!Secure2026", "")
	if code != 200 {
		t.Fatalf("viewer login %d", code)
	}
	r, _ = vc.Get(s.URL + "/api/v1/flows")
	if r.StatusCode != 200 {
		t.Fatalf("viewer read %d", r.StatusCode)
	}
	r.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/control/stop", bytes.NewReader([]byte("{}")))
	r, _ = vc.Do(req)
	if r.StatusCode != 403 {
		t.Fatalf("viewer control=%d", r.StatusCode)
	}
	r.Body.Close()
}
func TestSecureAPITokenScopes(t *testing.T) {
	s, am, _, _ := secureServer(t)
	defer s.Close()
	tok, raw, e := am.CreateToken("automation", "ro", "viewer", []string{"read:flows"}, time.Hour)
	if e != nil || tok.ID == "" {
		t.Fatal(e)
	}
	req, _ := http.NewRequest("GET", s.URL+"/api/v1/flows", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	r, e := s.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 200 {
		t.Fatalf("read=%d", r.StatusCode)
	}
	r.Body.Close()
	req, _ = http.NewRequest("GET", s.URL+"/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	r, _ = s.Client().Do(req)
	if r.StatusCode != 403 {
		t.Fatalf("scope leak=%d", r.StatusCode)
	}
	r.Body.Close()
}
func TestV050OperationalEndpoints(t *testing.T) {
	s, _, cl, pw := secureServer(t)
	defer s.Close()
	code, _ := loginClient(t, cl, s.URL, "admin", pw, "")
	if code != 200 {
		t.Fatal(code)
	}
	body, _ := json.Marshal(map[string]string{"current_password": pw, "new_password": "NetProbe!Secure2026"})
	r, _ := cl.Post(s.URL+"/api/v1/auth/change-password", "application/json", bytes.NewReader(body))
	r.Body.Close()
	jar, _ := cookiejar.New(nil)
	cl.Jar = jar
	loginClient(t, cl, s.URL, "admin", "NetProbe!Secure2026", "")
	for _, p := range []string{"/api/v1/stories", "/api/v1/tuning", "/api/v1/timeline", "/api/v1/time-machine", "/api/v1/mitre", "/api/v1/assets", "/api/v1/health", "/api/v1/integrations", "/api/v1/baseline-diff", "/api/v1/admin/users", "/api/v1/admin/audit", "/api/v1/admin/backup"} {
		r, e := cl.Get(s.URL + p)
		if e != nil {
			t.Fatal(e)
		}
		if r.StatusCode != 200 {
			t.Fatalf("%s=%d", p, r.StatusCode)
		}
		r.Body.Close()
	}
}

func authenticatedAdmin(t *testing.T, s *httptest.Server, cl *http.Client, pw string) {
	t.Helper()
	code, _ := loginClient(t, cl, s.URL, "admin", pw, "")
	if code != 200 {
		t.Fatalf("bootstrap login=%d", code)
	}
	b, _ := json.Marshal(map[string]string{"current_password": pw, "new_password": "NetProbe!Secure2026"})
	r, e := cl.Post(s.URL+"/api/v1/auth/change-password", "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("password change=%d", r.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	cl.Jar = jar
	code, _ = loginClient(t, cl, s.URL, "admin", "NetProbe!Secure2026", "")
	if code != 200 {
		t.Fatalf("admin relogin=%d", code)
	}
}

func TestSessionMutationRejectsCrossOrigin(t *testing.T) {
	s, _, cl, pw := secureServer(t)
	defer s.Close()
	authenticatedAdmin(t, s, cl, pw)
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/control/stop", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Origin", "https://evil.example")
	r, e := cl.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin mutation=%d", r.StatusCode)
	}
}

func TestTwoPersonApprovalRejectsSelfBeforeExecution(t *testing.T) {
	s, _, cl, pw := secureServer(t)
	defer s.Close()
	authenticatedAdmin(t, s, cl, pw)
	b, _ := json.Marshal(map[string]any{"action": "block_ip", "ip": "203.0.113.90", "ttl_seconds": 60, "reason": "test"})
	r, e := cl.Post(s.URL+"/api/v1/approvals", "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	var a map[string]any
	_ = json.NewDecoder(r.Body).Decode(&a)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("create=%d %#v", r.StatusCode, a)
	}
	id, _ := a["id"].(string)
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/v1/approvals/"+id, bytes.NewReader([]byte(`{}`)))
	r, e = cl.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("self approval=%d", r.StatusCode)
	}
	r, e = cl.Get(s.URL + "/api/v1/approvals")
	if e != nil {
		t.Fatal(e)
	}
	var items []map[string]any
	_ = json.NewDecoder(r.Body).Decode(&items)
	r.Body.Close()
	if len(items) != 1 || items[0]["status"] != "pending" || items[0]["result"] != nil {
		t.Fatalf("action changed before valid approval: %#v", items)
	}
}

func TestStaticV050SecurityConsoleAssets(t *testing.T) {
	s, _, _, _ := secureServer(t)
	defer s.Close()
	for path, need := range map[string][]string{"/": {"authGate", "loginForm", "Attack Stories", "MITRE ATT&amp;CK", "My Account", "v1.0.0"}, "/app.js": {"bootstrapAuth", "renderStories", "renderTimeMachine", "renderOperations", "mfaEnable", "backup-restore", "renderSyslogSettings", "renderFlowSettings", "syslog-save", "flow-save"}} {
		r, e := http.Get(s.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s=%d", path, r.StatusCode)
		}
		for _, x := range need {
			if !bytes.Contains(b.Bytes(), []byte(x)) {
				t.Fatalf("%s missing %q", path, x)
			}
		}
	}
}
