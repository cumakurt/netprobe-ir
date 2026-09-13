package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netprobe-ir/internal/audit"
	"netprobe-ir/internal/auth"
	"netprobe-ir/internal/backup"
	"netprobe-ir/internal/response"
	"netprobe-ir/internal/tuning"
)

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"enabled": s.Auth != nil && s.Auth.Enabled(), "oidc_enabled": s.OIDC != nil && s.OIDC.Enabled(), "default_username": s.Engine.Config.Auth.DefaultUsername})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		jsonError(w, "cross-origin login rejected", 403)
		return
	}
	if s.Auth == nil || !s.Auth.Enabled() {
		jsonError(w, "local authentication is disabled", 400)
		return
	}
	var q struct{ Username, Password, TOTP string }
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		jsonError(w, "bad JSON", 400)
		return
	}
	sid, p, must, e := s.Auth.Login(q.Username, q.Password, q.TOTP, auth.ClientIP(r), r.UserAgent())
	if e != nil {
		if s.Audit != nil {
			_ = s.Audit.Append(audit.Event{Username: q.Username, SourceIP: auth.ClientIP(r), Action: "auth.login", Success: false, Detail: e.Error()})
		}
		jsonError(w, e.Error(), 401)
		return
	}
	auth.SetSessionCookie(w, r, sid, int((12 * time.Hour).Seconds()))
	if s.Audit != nil {
		_ = s.Audit.Append(audit.Event{Username: p.Username, Role: p.Role, SourceIP: auth.ClientIP(r), Action: "auth.login", Success: true})
	}
	jsonOut(w, map[string]any{"ok": true, "user": p, "must_change_password": must})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var u any = p
	if s.Auth != nil && !p.External {
		if x, ok := s.Auth.User(p.Username); ok {
			u = x
		}
	}
	jsonOut(w, map[string]any{"principal": p, "user": u, "permissions": permissionsFor(p)})
}
func permissionsFor(p auth.Principal) []string {
	all := []string{"read:*", "case:write", "hunt:run", "lab:run", "tuning:write", "response:request", "capture:control", "response:execute", "admin:*"}
	var out []string
	for _, x := range all {
		probe := x
		if x == "read:*" {
			probe = "read:flows"
		}
		if x == "admin:*" {
			probe = "admin:users"
		}
		if auth.Can(p, probe) {
			out = append(out, x)
		}
	}
	return out
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	p := principal(r)
	if s.Auth != nil {
		s.Auth.Logout(p.SessionID)
	}
	auth.ClearSessionCookie(w, r)
	s.auditEvent(r, "auth.logout", "session", "", true)
	jsonOut(w, map[string]any{"ok": true})
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		jsonError(w, "cross-origin mutation rejected", 403)
		return
	}
	p := principal(r)
	if p.External {
		jsonError(w, "external OIDC password is managed by the identity provider", 400)
		return
	}
	var q struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		jsonError(w, "bad JSON", 400)
		return
	}
	e := s.Auth.ChangePassword(p.Username, q.Current, q.New)
	s.auditEvent(r, "auth.password_change", p.Username, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	auth.ClearSessionCookie(w, r)
	jsonOut(w, map[string]any{"ok": true, "reauthenticate": true})
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if s.Auth == nil {
		jsonOut(w, []any{})
		return
	}
	if r.Method == http.MethodGet {
		jsonOut(w, s.Auth.Sessions(p.Username))
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var q struct {
		RevokeID     string `json:"revoke_id"`
		RevokeOthers bool   `json:"revoke_others"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q)
	if q.RevokeOthers {
		s.Auth.RevokeOtherSessions(p.Username, p.SessionID)
		s.auditEvent(r, "auth.sessions.revoke_others", p.Username, "", true)
		jsonOut(w, map[string]any{"ok": true})
		return
	}
	e := s.Auth.RevokeSession(p.Username, q.RevokeID, p.Role == "admin")
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "auth.session.revoke", q.RevokeID, "", true)
	jsonOut(w, map[string]any{"ok": true})
}
func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	p := principal(r)
	if p.External {
		jsonError(w, "MFA is managed by OIDC provider", 400)
		return
	}
	secret, uri, e := s.Auth.SetupTOTP(p.Username, "NetProbe IR")
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "auth.mfa.setup", p.Username, "", true)
	jsonOut(w, map[string]any{"secret": secret, "otpauth_uri": uri})
}
func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	p := principal(r)
	var q struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q)
	codes, e := s.Auth.EnableTOTP(p.Username, q.Code)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "auth.mfa.enable", p.Username, "", true)
	jsonOut(w, map[string]any{"ok": true, "recovery_codes": codes, "warning": "Recovery codes are shown once; store them securely."})
}
func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	p := principal(r)
	var q struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q)
	e := s.Auth.DisableTOTP(p.Username, q.Password, q.Code)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "auth.mfa.disable", p.Username, "", true)
	jsonOut(w, map[string]any{"ok": true})
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || !s.OIDC.Enabled() {
		http.NotFound(w, r)
		return
	}
	u, e := s.OIDC.Begin(r.Context())
	if e != nil {
		jsonError(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || s.Auth == nil {
		http.NotFound(w, r)
		return
	}
	_, username, e := s.OIDC.Callback(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if e != nil {
		jsonError(w, e.Error(), 401)
		return
	}
	sid, p, e := s.Auth.CreateExternalSession(username, s.OIDC.DefaultRole(), auth.ClientIP(r), r.UserAgent())
	if e != nil {
		jsonError(w, e.Error(), 500)
		return
	}
	auth.SetSessionCookie(w, r, sid, int((12 * time.Hour).Seconds()))
	if s.Audit != nil {
		_ = s.Audit.Append(audit.Event{Username: p.Username, Role: p.Role, SourceIP: auth.ClientIP(r), Action: "auth.oidc_login", Success: true})
	}
	http.Redirect(w, r, "/#/overview", http.StatusFound)
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		jsonError(w, "authentication unavailable", 400)
		return
	}
	if r.Method == http.MethodGet {
		jsonOut(w, s.Auth.Users())
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var q struct {
		Username, DisplayName, Role, Password string
		MustChange                            bool `json:"must_change_password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		jsonError(w, "bad JSON", 400)
		return
	}
	u, e := s.Auth.CreateUser(q.Username, q.DisplayName, q.Role, q.Password, q.MustChange)
	s.auditEvent(r, "admin.user.create", q.Username, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	jsonOut(w, u)
}
func (s *Server) adminUserAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	name, action := parts[0], parts[1]
	var e error
	var q map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q)
	switch action {
	case "role":
		e = s.Auth.SetRole(name, fmt.Sprint(q["role"]))
	case "disable":
		v, _ := q["disabled"].(bool)
		e = s.Auth.SetDisabled(name, v)
	case "reset-password":
		must, _ := q["must_change_password"].(bool)
		e = s.Auth.AdminResetPassword(name, fmt.Sprint(q["password"]), must)
	default:
		http.NotFound(w, r)
		return
	}
	s.auditEvent(r, "admin.user."+action, name, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func (s *Server) adminTokens(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		jsonError(w, "authentication unavailable", 400)
		return
	}
	if r.Method == http.MethodGet {
		jsonOut(w, s.Auth.Tokens())
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var q struct {
		Name, Username, Role, TTL string
		Scopes                    []string
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		jsonError(w, "bad JSON", 400)
		return
	}
	t, raw, e := s.Auth.CreateToken(q.Username, q.Name, q.Role, q.Scopes, auth.ParseTTL(q.TTL))
	s.auditEvent(r, "admin.token.create", q.Name, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"token": t, "secret": raw, "warning": "The token secret is shown only once."})
}
func (s *Server) adminTokenAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/tokens/"), "/")
	e := s.Auth.RevokeToken(id)
	s.auditEvent(r, "admin.token.revoke", id, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if s.Audit == nil {
		jsonOut(w, []any{})
		return
	}
	jsonOut(w, s.Audit.List(limit(r, 1000)))
}
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	if s.Audit == nil {
		jsonError(w, "audit unavailable", 400)
		return
	}
	e := s.Audit.Verify()
	jsonOut(w, map[string]any{"ok": e == nil, "error": errString(e)})
}

func (s *Server) stories(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Stories(limit(r, 200)))
}
func (s *Server) tuning(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonOut(w, s.Engine.Suppressions())
		return
	}
	if e := s.require(r, "tuning:write"); e != nil {
		jsonError(w, e.Error(), 403)
		return
	}
	if r.Method == http.MethodPost {
		var q tuning.Rule
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
			jsonError(w, "bad JSON", 400)
			return
		}
		p := principal(r)
		q.CreatedBy = p.Username
		v, e := s.Engine.AddSuppression(q)
		s.auditEvent(r, "tuning.create", q.Kind+":"+q.Value, errString(e), e == nil)
		if e != nil {
			jsonError(w, e.Error(), 400)
			return
		}
		jsonOut(w, v)
		return
	}
	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		e := s.Engine.DeleteSuppression(id)
		s.auditEvent(r, "tuning.delete", id, errString(e), e == nil)
		if e != nil {
			jsonError(w, e.Error(), 400)
			return
		}
		jsonOut(w, map[string]any{"ok": true})
		return
	}
	jsonError(w, "method not allowed", 405)
}
func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, e := time.Parse(time.RFC3339, v); e == nil {
		return t
	}
	if n, e := strconv.ParseInt(v, 10, 64); e == nil {
		return time.Unix(n, 0)
	}
	return time.Time{}
}
func (s *Server) timeline(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.TimelineRange(parseTime(r.URL.Query().Get("from")), parseTime(r.URL.Query().Get("to")), limit(r, 1000)))
}
func (s *Server) timeMachine(w http.ResponseWriter, r *http.Request) {
	at := parseTime(r.URL.Query().Get("at"))
	if at.IsZero() {
		at = time.Now()
	}
	jsonOut(w, s.Engine.TimeMachine(at))
}
func (s *Server) mitreMatrix(w http.ResponseWriter, r *http.Request) {
	m := map[string]int{}
	for _, f := range s.Engine.Findings(5000) {
		for _, x := range f.MITRE {
			m[x]++
		}
	}
	jsonOut(w, m)
}
func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, s.collectAssets())
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	st := s.Engine.Status()
	var fs syscall.Statfs_t
	disk := map[string]any{}
	if syscall.Statfs(s.Engine.Config.DataDir, &fs) == nil {
		disk["free_bytes"] = fs.Bavail * uint64(fs.Bsize)
		disk["total_bytes"] = fs.Blocks * uint64(fs.Bsize)
	}
	auditOK := true
	if s.Audit != nil {
		auditOK = s.Audit.Verify() == nil
	}
	jsonOut(w, map[string]any{"capture_health": s.Engine.CaptureHealth(), "status": st, "audit_chain_ok": auditOK,
		"runtime_security": map[string]any{
			"file_artifacts":             len(s.Engine.FilesList(1000000)),
			"beacon_groups":              len(s.Engine.BeaconGroups()),
			"encrypted_dns_observations": len(s.Engine.EncryptedDNS(1000000)),
			"identity_profiles":          len(s.Engine.IdentityProfiles()),
			"vulnerability":              s.Engine.VulnerabilityContext(),
			"streaming":                  s.Engine.StreamingStatus(),
			"wasm_plugins":               s.Engine.WASMStatus(),
			"self_protection":            s.Engine.SelfProtectionHealth(),
			"detection_quality":          s.Engine.DetectionQuality(),
			"runtime_events_retained":    len(s.Engine.RuntimeEvents(1000000)),
			"exploit_correlations":       len(s.Engine.ExploitCorrelations()),
			"fleet_health":               s.Engine.Federation.FleetHealth(time.Now().UTC()),
		}, "syslog_export": func() any {
			if s.Engine.SyslogExport != nil {
				return s.Engine.SyslogExport.Stats()
			}
			return []any{}
		}(), "flow_export": func() any {
			if s.Engine.FlowExport != nil {
				return s.Engine.FlowExport.Stats()
			}
			return []any{}
		}(), "notifications": func() any {
			if s.Engine.Notifications != nil {
				n := s.Engine.Notifications.Public()
				return map[string]any{
					"email":    map[string]any{"enabled": n.Email.Enabled, "stats": n.EmailStats},
					"telegram": map[string]any{"enabled": n.Telegram.Enabled, "stats": n.TelegramStats},
				}
			}
			return map[string]any{}
		}(), "traffic_live": func() any {
			if s.Engine.TrafficSeries != nil {
				return s.Engine.TrafficSeries.Current()
			}
			return map[string]any{}
		}(), "threat_intel_errors": s.Engine.ThreatIntelErrors(), "ids_load_errors": func() []string {
			if s.Engine.IDS != nil {
				return s.Engine.IDS.LoadErrors()
			}
			return nil
		}(), "disk": disk, "integration_deliveries": func() any {
			if s.Engine.Integrations != nil {
				return s.Engine.Integrations.Deliveries()
			}
			return []any{}
		}()})
}
func (s *Server) baselineDiff(w http.ResponseWriter, r *http.Request) {
	recent := time.Hour
	historical := 7 * 24 * time.Hour
	if v := r.URL.Query().Get("recent"); v != "" {
		if d, e := time.ParseDuration(v); e == nil {
			recent = d
		}
	}
	if v := r.URL.Query().Get("historical"); v != "" {
		if d, e := time.ParseDuration(v); e == nil {
			historical = d
		}
	}
	d, e := s.Engine.NetworkBaselineDiff(time.Now().UTC(), recent, historical)
	if e != nil {
		jsonError(w, e.Error(), 500)
		return
	}
	jsonOut(w, d)
}
func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	if s.Engine.Integrations == nil {
		jsonOut(w, map[string]any{})
		return
	}
	cfg := s.Engine.Integrations.Config()
	for i := range cfg.Webhooks {
		if cfg.Webhooks[i].Token != "" {
			cfg.Webhooks[i].Token = "***"
		}
	}
	jsonOut(w, map[string]any{"config": cfg, "deliveries": s.Engine.Integrations.Deliveries()})
}

func (s *Server) approvalListCreate(w http.ResponseWriter, r *http.Request) {
	if s.Approvals == nil {
		jsonOut(w, []any{})
		return
	}
	if r.Method == http.MethodGet {
		jsonOut(w, s.Approvals.List())
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	if e := s.require(r, "response:request"); e != nil {
		jsonError(w, e.Error(), 403)
		return
	}
	var q response.Request
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		jsonError(w, "bad JSON", 400)
		return
	}
	p := principal(r)
	a, e := s.Approvals.Create(p.Username, q)
	s.auditEvent(r, "response.approval.request", q.Action, errString(e), e == nil)
	if e != nil {
		jsonError(w, e.Error(), 400)
		return
	}
	jsonOut(w, a)
}
func (s *Server) approvalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/"), "/")
	a, ok := s.Approvals.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p := principal(r)
	if a.Status != "pending" {
		jsonError(w, "approval is not pending", 400)
		return
	}
	if a.RequestedBy == p.Username {
		jsonError(w, "two-person approval requires a different user", 400)
		return
	}
	q := a.Action
	q.Confirm = "APPLY"
	res, e := s.Engine.Response.Execute(r.Context(), q)
	updated, ue := s.Approvals.Approve(id, p.Username, res, e)
	if ue != nil {
		jsonError(w, ue.Error(), 400)
		return
	}
	s.auditEvent(r, "response.approval.execute", id, errString(e), e == nil)
	jsonOut(w, updated)
}

func (s *Server) backupAPI(w http.ResponseWriter, r *http.Request) {
	base := filepath.Join(s.Engine.Config.DataDir, "backups")
	_ = os.MkdirAll(base, 0750)
	if r.Method == http.MethodGet {
		ents, _ := os.ReadDir(base)
		var out []map[string]any
		for _, e := range ents {
			if e.IsDir() || (!strings.HasSuffix(e.Name(), ".zip") && !strings.HasSuffix(e.Name(), ".npbackup")) {
				continue
			}
			st, _ := e.Info()
			out = append(out, map[string]any{"name": e.Name(), "size": st.Size(), "modified": st.ModTime()})
		}
		jsonOut(w, out)
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var q struct{ Action, Path, Confirm, Passphrase string }
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q)
	switch q.Action {
	case "create":
		if len(q.Passphrase) < 12 {
			jsonError(w, "backup passphrase must be at least 12 characters", 400)
			return
		}
		p := filepath.Join(base, "netprobe-backup-"+time.Now().UTC().Format("20060102-150405")+".npbackup")
		out, e := backup.CreateEncrypted(s.Engine.Config.DataDir, p, q.Passphrase)
		s.auditEvent(r, "backup.create", filepath.Base(p), errString(e), e == nil)
		if e != nil {
			jsonError(w, e.Error(), 500)
			return
		}
		jsonOut(w, map[string]any{"ok": true, "path": out})
	case "verify":
		p, e := s.allowedFile(q.Path, false)
		if e == nil {
			if backup.IsEncrypted(p) {
				e = backup.VerifyEncrypted(p, q.Passphrase)
			} else {
				e = backup.Verify(p)
			}
		}
		if e != nil {
			jsonError(w, e.Error(), 400)
			return
		}
		jsonOut(w, map[string]any{"ok": true})
	case "restore":
		if q.Confirm != "RESTORE" {
			jsonError(w, "confirm must be RESTORE", 400)
			return
		}
		p, e := s.allowedFile(q.Path, false)
		if e == nil {
			if backup.IsEncrypted(p) {
				e = backup.RestoreEncrypted(p, s.Engine.Config.DataDir, q.Passphrase)
			} else {
				e = backup.Restore(p, s.Engine.Config.DataDir)
			}
		}
		s.auditEvent(r, "backup.restore", q.Path, errString(e), e == nil)
		if e != nil {
			jsonError(w, e.Error(), 400)
			return
		}
		jsonOut(w, map[string]any{"ok": true, "restart_required": true})
	default:
		jsonError(w, "unknown backup action", 400)
	}
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
