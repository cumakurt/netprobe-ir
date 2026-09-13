package auth

import (
	"encoding/base32"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	c := DefaultConfig()
	c.PasswordIterations = 50000
	m, e := New(filepath.Join(t.TempDir(), "auth.json"), c)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestBootstrapLoginPasswordChangeAndSession(t *testing.T) {
	m := testManager(t)
	pw := m.InitialPassword()
	if pw == "" {
		t.Fatal("missing initial password")
	}
	sid, p, must, e := m.Login("admin", pw, "", "127.0.0.1", "test")
	if e != nil || sid == "" || p.Role != "admin" || !must {
		t.Fatalf("login=%s %#v %v %v", sid, p, must, e)
	}
	if e = m.ChangePassword("admin", pw, "Changed!Password2026"); e != nil {
		t.Fatal(e)
	}
	if len(m.Sessions("admin")) != 0 {
		t.Fatal("password change must revoke sessions")
	}
	_, _, must, e = m.Login("admin", "Changed!Password2026", "", "127.0.0.1", "test")
	if e != nil || must {
		t.Fatalf("relogin must=%v err=%v", must, e)
	}
}
func TestRBACAndTokens(t *testing.T) {
	m := testManager(t)
	_, e := m.CreateUser("alice", "Alice", "analyst", "Alice!Password2026", false)
	if e != nil {
		t.Fatal(e)
	}
	if !Can(Principal{Role: "analyst"}, "case:write") || Can(Principal{Role: "analyst"}, "response:execute") {
		t.Fatal("role map")
	}
	tok, raw, e := m.CreateToken("alice", "automation", "analyst", []string{"read:findings", "case:write"}, time.Hour)
	if e != nil || raw == "" || tok.Hash != "" {
		t.Fatalf("token %#v %v", tok, e)
	}
	r := httptest.NewRequest("GET", "http://x/api", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	p, e := m.AuthenticateRequest(r, "")
	if e != nil || p.TokenID == "" || !Can(p, "read:findings") || Can(p, "response:execute") {
		t.Fatalf("principal %#v %v", p, e)
	}
}
func TestTOTPAndRecovery(t *testing.T) {
	m := testManager(t)
	pw := m.InitialPassword()
	_, _, _, e := m.Login("admin", pw, "", "127.0.0.1", "test")
	if e != nil {
		t.Fatal(e)
	}
	secret, uri, e := m.SetupTOTP("admin", "NetProbe IR")
	if e != nil || secret == "" || uri == "" {
		t.Fatal(e)
	}
	code := totpCode(mustDecode(secret), time.Now())
	codes, e := m.EnableTOTP("admin", code)
	if e != nil || len(codes) != 10 {
		t.Fatalf("enable %v %v", e, codes)
	}
	if _, _, _, e = m.Login("admin", pw, "000000", "127.0.0.2", "test"); e == nil {
		t.Fatal("bad mfa accepted")
	}
	if _, _, _, e = m.Login("admin", pw, codes[0], "127.0.0.3", "test"); e != nil {
		t.Fatalf("recovery rejected: %v", e)
	}
}
func mustDecode(s string) []byte { b, _ := base32NoPad(s); return b }
func base32NoPad(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func TestCannotRemoveLastEnabledAdmin(t *testing.T) {
	m := testManager(t)
	if err := m.SetRole("admin", "viewer"); err == nil {
		t.Fatal("expected last-admin role guard")
	}
	if err := m.SetDisabled("admin", true); err == nil {
		t.Fatal("expected last-admin disable guard")
	}
	if _, err := m.CreateUser("admin2", "Second Admin", "admin", "Strong!Password123", false); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRole("admin", "viewer"); err != nil {
		t.Fatal(err)
	}
}

func TestLoginBruteForceLockout(t *testing.T) {
	c := DefaultConfig()
	c.PasswordIterations = 50000
	c.MaxFailures = 2
	c.Lockout = 10 * time.Minute
	m, e := New(filepath.Join(t.TempDir(), "auth.json"), c)
	if e != nil {
		t.Fatal(e)
	}
	pw := m.InitialPassword()
	if _, _, _, e = m.Login("admin", "wrong", "", "10.0.0.1", "test"); e == nil {
		t.Fatal("bad password accepted")
	}
	if _, _, _, e = m.Login("admin", "wrong", "", "10.0.0.1", "test"); e == nil {
		t.Fatal("second bad password accepted")
	}
	if _, _, _, e = m.Login("admin", pw, "", "10.0.0.1", "test"); e == nil || !strings.Contains(e.Error(), "temporarily locked") {
		t.Fatalf("expected lockout, got %v", e)
	}
	// Expire the lock deterministically instead of relying on wall-clock sleeps;
	// PBKDF2 is intentionally expensive and race instrumentation can stretch
	// a millisecond-scale test lockout past its deadline.
	m.mu.Lock()
	if fs := m.failures["admin|10.0.0.1"]; fs != nil {
		fs.LockedUntil = time.Now().Add(-time.Second)
	}
	m.mu.Unlock()
	if _, _, _, e = m.Login("admin", pw, "", "10.0.0.1", "test"); e != nil {
		t.Fatalf("login after lockout: %v", e)
	}
}

func TestRevalidatePrincipalRejectsRevokedLongLivedCredentials(t *testing.T) {
	m := testManager(t)
	pw := m.InitialPassword()
	sid, p, _, err := m.Login("admin", pw, "", "127.0.0.1", "ws-test")
	if err != nil || sid == "" {
		t.Fatalf("login sid=%q err=%v", sid, err)
	}
	if _, err = m.RevalidatePrincipal(p); err != nil {
		t.Fatalf("live session rejected: %v", err)
	}
	m.Logout(sid)
	if _, err = m.RevalidatePrincipal(p); err == nil {
		t.Fatal("revoked session remained valid for long-lived connection")
	}

	tok, _, err := m.CreateToken("admin", "ws-token", "admin", []string{"read:telemetry"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tp := Principal{Username: tok.Username, Role: tok.Role, Scopes: tok.Scopes, TokenID: tok.ID}
	if _, err = m.RevalidatePrincipal(tp); err != nil {
		t.Fatalf("live token rejected: %v", err)
	}
	if err = m.RevokeToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.RevalidatePrincipal(tp); err == nil {
		t.Fatal("revoked API token remained valid for long-lived connection")
	}
}
