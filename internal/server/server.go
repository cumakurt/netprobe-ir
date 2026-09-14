package server

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netprobe-ir/internal/approvals"
	"netprobe-ir/internal/audit"
	"netprobe-ir/internal/auth"
	"netprobe-ir/internal/detectionlab"
	"netprobe-ir/internal/detectionquality"
	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/federation"
	"netprobe-ir/internal/flowexport"
	"netprobe-ir/internal/investigation"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/notifications"
	"netprobe-ir/internal/oidc"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/playbook"
	"netprobe-ir/internal/report"
	"netprobe-ir/internal/response"
	"netprobe-ir/internal/syslogexport"
	"netprobe-ir/internal/trafficseries"
)

//go:embed static/*
var webFS embed.FS

type Server struct {
	Engine    *pipeline.Engine
	Token     string
	Auth      *auth.Manager
	Audit     *audit.Log
	OIDC      *oidc.Client
	Approvals *approvals.Store
}

type principalKey struct{}

func New(e *pipeline.Engine, token string) *Server { return &Server{Engine: e, Token: token} }
func NewSecure(e *pipeline.Engine, token string, am *auth.Manager, al *audit.Log, oc *oidc.Client) *Server {
	s := &Server{Engine: e, Token: token, Auth: am, Audit: al, OIDC: oc, Approvals: approvals.New(filepath.Join(e.Config.DataDir, "audit", "approvals.json"))}
	if e != nil {
		e.PlaybookApproval = func(f model.SecurityFinding, m playbook.Match) {
			for _, a := range m.Actions {
				q := response.Request{Action: a.Type, TTLSeconds: a.TTLSeconds, Reason: firstNonEmpty(a.Reason, "playbook approval: "+m.PlaybookName)}
				switch a.Type {
				case "block_ip", "unblock_ip":
					q.IP = f.Destination.IP
				case "kill_process":
					q.PID = f.PID
				default:
					continue
				}
				_, _ = s.Approvals.Create("automation:"+m.PlaybookID, q)
			}
		}
	}
	return s
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/access/", s.guard("read:packets", s.accessAPI))
	// Public authentication/bootstrap routes. Static assets are public so the login shell can render.
	mux.HandleFunc("/api/v1/auth/status", s.authStatus)
	mux.HandleFunc("/api/v1/auth/login", s.login)
	mux.HandleFunc("/api/v1/auth/oidc/login", s.oidcLogin)
	mux.HandleFunc("/api/v1/auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("/api/v1/status", s.guard("read:status", s.status))
	mux.HandleFunc("/api/v1/flows", s.guard("read:flows", s.flows))
	mux.HandleFunc("/api/v1/flows/", s.guard("read:flows", s.flowDetail))
	mux.HandleFunc("/api/v1/processes", s.guard("read:processes", s.processes))
	mux.HandleFunc("/api/v1/processes/", s.guard("read:processes", s.processDetail))
	mux.HandleFunc("/api/v1/packets", s.guard("read:packets", s.packets))
	mux.HandleFunc("/api/v1/packets/", s.guard("read:packets", s.packetDetail))
	mux.HandleFunc("/api/v1/control/", s.guard("capture:control", s.control))
	mux.HandleFunc("/api/v1/alerts", s.guard("read:alerts", s.alerts))
	mux.HandleFunc("/api/v1/findings", s.guard("read:findings", s.findings))
	mux.HandleFunc("/api/v1/findings/", s.guard("read:findings", s.findingDetail))
	mux.HandleFunc("/api/v1/hunt", s.guard("read:hunt", s.hunt))
	mux.HandleFunc("/api/v1/report.json", s.guard("read:reports", s.reportJSON))
	mux.HandleFunc("/api/v1/report.html", s.guard("read:reports", s.reportHTML))
	mux.HandleFunc("/api/v1/graph", s.guard("read:graph", s.graph))
	mux.HandleFunc("/api/v1/telemetry", s.guard("read:telemetry", s.telemetryAPI))
	mux.HandleFunc("/api/v1/telemetry/stream", s.guard("read:telemetry", s.telemetryAPI))
	mux.HandleFunc("/api/v1/traffic/live", s.guard("read:status", s.trafficLive))
	mux.HandleFunc("/api/v1/traffic/history", s.guard("read:status", s.trafficHistory))
	mux.HandleFunc("/api/v1/notifications", s.guard("admin:settings", s.notificationsAPI))
	mux.HandleFunc("/api/v1/notifications/test/email", s.guard("admin:settings", s.notificationTestEmail))
	mux.HandleFunc("/api/v1/notifications/test/telegram", s.guard("admin:settings", s.notificationTestTelegram))
	mux.HandleFunc("/api/v1/threat-intel", s.guard("read:threat-intel", s.threatIntel))
	mux.HandleFunc("/api/v1/baseline", s.guard("read:baseline", s.baseline))
	mux.HandleFunc("/api/v1/baseline-diff", s.guard("read:baseline", s.baselineDiff))
	mux.HandleFunc("/api/v1/cases", s.guard("read:cases", s.cases))
	mux.HandleFunc("/api/v1/cases/", s.guard("read:cases", s.caseDetail))
	mux.HandleFunc("/api/v1/response", s.guard("response:execute", s.activeResponse))
	mux.HandleFunc("/api/v1/replay", s.guard("lab:run", s.replay))
	mux.HandleFunc("/api/v1/lab/run", s.guard("lab:run", s.detectionLab))
	mux.HandleFunc("/api/v1/detection-quality", s.guard("read:findings", s.detectionQualityAPI))
	mux.HandleFunc("/api/v1/runtime-events", s.guard("read:processes", s.runtimeEventsAPI))
	mux.HandleFunc("/api/v1/exploit-correlations", s.guard("read:findings", s.exploitCorrelationsAPI))
	mux.HandleFunc("/api/v1/fleet/health", s.guard("read:sensors", s.fleetHealthAPI))
	mux.HandleFunc("/api/v1/sigma/translate", s.guard("lab:run", s.sigmaTranslateAPI))
	mux.HandleFunc("/api/v1/sigma/correlation", s.guard("lab:run", s.sigmaCorrelationAPI))
	mux.HandleFunc("/api/v1/rules/import", s.guard("lab:run", s.ruleImportAPI))
	mux.HandleFunc("/api/v1/ocsf", s.guard("read:findings", s.ocsfAPI))
	mux.HandleFunc("/api/v1/playbooks", s.guard("admin:settings", s.playbooksAPI))
	mux.HandleFunc("/api/v1/analytics", s.guard("read:hunt", s.analyticsAPI))
	mux.HandleFunc("/api/v1/asset-intelligence", s.guard("read:assets", s.assetIntelligenceAPI))
	mux.HandleFunc("/api/v1/tls-intelligence", s.guard("read:findings", s.tlsIntelligenceAPI))
	mux.HandleFunc("/api/v1/dns-graph", s.guard("read:findings", s.dnsGraphAPI))
	mux.HandleFunc("/api/v1/core-ebpf", s.guard("read:health", s.coreEBPFAPI))
	mux.HandleFunc("/api/v1/benchmark", s.guard("lab:run", s.benchmarkAPI))
	mux.HandleFunc("/api/v1/investigation-workspace", s.guard("read:graph", s.investigationWorkspaceAPI))
	mux.HandleFunc("/api/v1/executive-overview", s.guard("read:status", s.executiveOverviewAPI))
	mux.HandleFunc("/api/v1/enrichment", s.guard("read:threat-intel", s.enrichmentAPI))
	mux.HandleFunc("/api/v1/profiles", s.guard("read:integrations", s.profilesAPI))
	mux.HandleFunc("/api/v1/evidence/verify", s.guard("read:evidence", s.verifyEvidence))
	mux.HandleFunc("/api/v1/sensors/ingest", s.sensorIngest)
	mux.HandleFunc("/api/v1/sensors/commands/poll", s.sensorCommandPoll)
	mux.HandleFunc("/api/v1/sensors/commands/ack", s.sensorCommandAck)
	mux.HandleFunc("/api/v1/sensors", s.guard("read:sensors", s.sensors))
	mux.HandleFunc("/api/v1/fleet", s.guard("read:sensors", s.fleet))
	mux.HandleFunc("/api/v1/fleet/commands", s.guard("admin:settings", s.fleetCommands))
	mux.HandleFunc("/api/v1/files", s.guard("read:files", s.filesAPI))
	mux.HandleFunc("/api/v1/files/", s.guard("read:files", s.fileAPI))
	mux.HandleFunc("/api/v1/c2/beacons", s.guard("read:findings", s.beaconsAPI))
	mux.HandleFunc("/api/v1/encrypted-dns", s.guard("read:findings", s.encryptedDNSAPI))
	mux.HandleFunc("/api/v1/identity-profiles", s.guard("read:assets", s.identityProfilesAPI))
	mux.HandleFunc("/api/v1/vulnerabilities", s.guard("read:assets", s.vulnerabilitiesAPI))
	mux.HandleFunc("/api/v1/protocol-packs", s.guard("read:status", s.protocolPacksAPI))
	mux.HandleFunc("/api/v1/streaming", s.guard("read:integrations", s.streamingAPI))
	mux.HandleFunc("/api/v1/plugins", s.guard("read:integrations", s.pluginsAPI))
	mux.HandleFunc("/api/v1/self-protection", s.guard("read:health", s.selfProtectionAPI))
	mux.HandleFunc("/api/v1/analyst", s.guard("read:hunt", s.analystAPI))
	mux.HandleFunc("/api/v1/stories", s.guard("read:findings", s.stories))
	mux.HandleFunc("/api/v1/tuning", s.guard("read:findings", s.tuning))
	mux.HandleFunc("/api/v1/timeline", s.guard("read:timeline", s.timeline))
	mux.HandleFunc("/api/v1/time-machine", s.guard("read:timeline", s.timeMachine))
	mux.HandleFunc("/api/v1/mitre", s.guard("read:findings", s.mitreMatrix))
	mux.HandleFunc("/api/v1/assets", s.guard("read:assets", s.assets))
	mux.HandleFunc("/api/v1/assets/", s.guard("read:assets", s.assetDetail))
	mux.HandleFunc("/api/v1/health", s.guard("read:health", s.health))
	mux.HandleFunc("/api/v1/integrations", s.guard("read:integrations", s.integrations))
	mux.HandleFunc("/api/v1/export/syslog", s.guard("read:integrations", s.syslogExport))
	mux.HandleFunc("/api/v1/export/syslog/", s.guard("read:integrations", s.syslogExport))
	mux.HandleFunc("/api/v1/export/flow", s.guard("read:integrations", s.flowExport))
	mux.HandleFunc("/api/v1/export/flow/", s.guard("read:integrations", s.flowExport))
	mux.HandleFunc("/api/v1/approvals", s.guard("read:approvals", s.approvalListCreate))
	mux.HandleFunc("/api/v1/approvals/", s.guard("response:execute", s.approvalAction))
	mux.HandleFunc("/api/v1/auth/me", s.guard("read:self", s.me))
	mux.HandleFunc("/api/v1/auth/logout", s.guard("read:self", s.logout))
	mux.HandleFunc("/api/v1/auth/change-password", s.guard("read:self", s.changePassword))
	mux.HandleFunc("/api/v1/auth/sessions", s.guard("read:self", s.sessions))
	mux.HandleFunc("/api/v1/auth/totp/setup", s.guard("read:self", s.totpSetup))
	mux.HandleFunc("/api/v1/auth/totp/enable", s.guard("read:self", s.totpEnable))
	mux.HandleFunc("/api/v1/auth/totp/disable", s.guard("read:self", s.totpDisable))
	mux.HandleFunc("/api/v1/admin/users", s.guard("admin:users", s.adminUsers))
	mux.HandleFunc("/api/v1/admin/users/", s.guard("admin:users", s.adminUserAction))
	mux.HandleFunc("/api/v1/admin/tokens", s.guard("admin:tokens", s.adminTokens))
	mux.HandleFunc("/api/v1/admin/tokens/", s.guard("admin:tokens", s.adminTokenAction))
	mux.HandleFunc("/api/v1/admin/audit", s.guard("admin:audit", s.auditEvents))
	mux.HandleFunc("/api/v1/admin/audit/verify", s.guard("admin:audit", s.auditVerify))
	mux.HandleFunc("/api/v1/admin/backup", s.guard("admin:backup", s.backupAPI))
	mux.HandleFunc("/metrics", s.guard("read:metrics", s.metrics))
	mux.HandleFunc("/ws", s.guard("read:telemetry", s.ws))
	sub, err := fs.Sub(webFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return securityHeaders(s.consoleACL(mux))
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc { return s.guard("read:generic", h) }
func (s *Server) guard(perm string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := func() (auth.Principal, error) {
			if s.Auth != nil {
				return s.Auth.AuthenticateRequest(r, s.Token)
			}
			if s.Token != "" {
				return legacyPrincipal(r, s.Token)
			}
			return auth.Principal{Username: "local", Role: "admin"}, nil
		}()
		if err != nil {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if p.SessionID != "" && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !sameOrigin(r) {
			jsonError(w, "cross-origin mutation rejected", http.StatusForbidden)
			return
		}
		if p.MustChange && !strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			jsonError(w, "password change required", http.StatusForbidden)
			return
		}
		if !auth.Can(p, perm) {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		h(w, r.WithContext(ctx))
	}
}
func legacyPrincipal(r *http.Request, want string) (auth.Principal, error) {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tok == "" {
		tok = r.Header.Get("X-NetProbe-Token")
	}
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		return auth.Principal{}, fmt.Errorf("unauthorized")
	}
	return auth.Principal{Username: "legacy-token", Role: "admin"}, nil
}
func principal(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey{}).(auth.Principal)
	return p
}
func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}
func (s *Server) require(r *http.Request, perm string) error {
	if !auth.Can(principal(r), perm) {
		return fmt.Errorf("forbidden")
	}
	return nil
}
func (s *Server) auditEvent(r *http.Request, action, resource, detail string, success bool) {
	if s.Audit == nil {
		return
	}
	p := principal(r)
	_ = s.Audit.Append(audit.Event{Username: p.Username, Role: p.Role, SourceIP: auth.ClientIP(r), Action: action, Resource: resource, Success: success, Detail: detail})
}
func (s *Server) consoleACL(next http.Handler) http.Handler {
	cidrs := s.Engine.Config.Security.ConsoleAllowedCIDRs
	if len(cidrs) == 0 {
		return next
	}
	var nets []*net.IPNet
	for _, x := range cidrs {
		_, n, e := net.ParseCIDR(strings.TrimSpace(x))
		if e == nil {
			nets = append(nets, n)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/sensors/ingest" {
			next.ServeHTTP(w, r)
			return
		}
		ip := net.ParseIP(auth.ClientIP(r))
		allowed := false
		for _, n := range nets {
			if ip != nil && n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			jsonError(w, "console access denied by CIDR policy", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}
func limit(r *http.Request, def int) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = def
	}
	if n > 5000 {
		n = 5000
	}
	return n
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	var idsLoadErrors []string
	if s.Engine.IDS != nil {
		idsLoadErrors = s.Engine.IDS.LoadErrors()
	}
	jsonOut(w, map[string]any{"status": s.Engine.Status(), "capture_health": s.Engine.CaptureHealth(), "last_error": s.Engine.LastError(), "ids_load_errors": idsLoadErrors})
}
func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Flows(limit(r, 500)))
}
func (s *Server) flowDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/flows/")
	f, ok := s.Engine.Store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, f)
}
func (s *Server) processes(w http.ResponseWriter, r *http.Request) { jsonOut(w, s.Engine.Processes()) }
func (s *Server) processDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/processes/")
	pid, err := strconv.Atoi(id)
	if err != nil || pid <= 0 {
		http.NotFound(w, r)
		return
	}
	d, ok := s.Engine.Process(pid)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, d)
}
func (s *Server) packets(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Packets(limit(r, 300)))
}
func (s *Server) packetDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/packets/")
	p, ok := s.Engine.Packet(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, p)
}
func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Browser control actions are same-origin only. CLI clients normally send no
	// Origin header and remain supported. This blocks cross-site forms/fetches
	// from pausing or resuming a loopback console without operator intent.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin control request rejected", http.StatusForbidden)
		return
	}
	action := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/control/"), "/")
	var err error
	responseAction := action
	switch action {
	case "start":
		err = s.Engine.StartCapture()
	case "stop":
		err = s.Engine.StopCapture()
	default:
		parts := strings.Split(action, "/")
		if len(parts) == 3 && parts[0] == "interface" {
			name, decErr := url.PathUnescape(parts[1])
			if decErr != nil {
				http.Error(w, "invalid interface", http.StatusBadRequest)
				return
			}
			switch parts[2] {
			case "start":
				err = s.Engine.StartInterface(name)
			case "stop":
				err = s.Engine.StopInterface(name)
			default:
				http.NotFound(w, r)
				return
			}
			responseAction = "interface/" + name + "/" + parts[2]
		} else {
			http.NotFound(w, r)
			return
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.auditEvent(r, "capture.control", responseAction, "", true)
	s.Engine.PublishSystemEvent("capture_control", map[string]any{"action": responseAction, "actor": principal(r).Username})
	jsonOut(w, map[string]any{"ok": true, "action": responseAction, "status": s.Engine.Status(), "capture_health": s.Engine.CaptureHealth()})
}
func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Alerts(limit(r, 500)))
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Findings(limit(r, 1000)))
}
func (s *Server) hunt(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Hunt(r.URL.Query().Get("q"), limit(r, 500)))
}
func (s *Server) findingDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	f, ok := s.Engine.Finding(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, f)
}
func (s *Server) reportData() report.Data {
	return report.Data{GeneratedAt: time.Now(), Status: s.Engine.Status(), Flows: s.Engine.Flows(5000), Alerts: s.Engine.Alerts(5000), SecurityFindings: s.Engine.Findings(5000), CaptureHealth: s.Engine.CaptureHealth()}
}
func (s *Server) reportJSON(w http.ResponseWriter, r *http.Request) {
	b, e := report.JSON(s.reportData())
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=netprobe-report.json")
	_, _ = w.Write(b)
}
func (s *Server) reportHTML(w http.ResponseWriter, r *http.Request) {
	b, e := report.HTML(s.reportData())
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=netprobe-report.html")
	_, _ = w.Write(b)
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	q := investigation.Query{Search: strings.TrimSpace(r.URL.Query().Get("q")), SourceIP: strings.TrimSpace(r.URL.Query().Get("src")), DestinationIP: strings.TrimSpace(r.URL.Query().Get("dst")), Asset: strings.TrimSpace(r.URL.Query().Get("asset")), Protocol: strings.TrimSpace(r.URL.Query().Get("proto")), Application: strings.TrimSpace(r.URL.Query().Get("app")), Severity: strings.TrimSpace(r.URL.Query().Get("severity")), FocusID: strings.TrimSpace(r.URL.Query().Get("focus")), ExpandCluster: strings.TrimSpace(r.URL.Query().Get("expand")), MaxNodes: 800, MaxEdges: 3000, EnableClustering: true}
	if x, _ := strconv.Atoi(r.URL.Query().Get("port")); x > 0 && x <= 65535 {
		q.Port = uint16(x)
	}
	if x, _ := strconv.Atoi(r.URL.Query().Get("max_nodes")); x > 0 {
		q.MaxNodes = x
	}
	if x, _ := strconv.Atoi(r.URL.Query().Get("max_edges")); x > 0 {
		q.MaxEdges = x
	}
	if x, _ := strconv.Atoi(r.URL.Query().Get("neighbors")); x > 0 && x <= 4 {
		q.Neighborhood = x
	}
	if r.URL.Query().Get("cluster") == "0" {
		q.EnableClustering = false
	}
	if x := r.URL.Query().Get("from"); x != "" {
		q.From, _ = time.Parse(time.RFC3339, x)
	}
	if x := r.URL.Query().Get("to"); x != "" {
		q.To, _ = time.Parse(time.RFC3339, x)
	}
	jsonOut(w, s.Engine.GraphQuery(q))
}
func (s *Server) trafficLive(w http.ResponseWriter, r *http.Request) {
	if s.Engine.TrafficSeries == nil {
		jsonError(w, "traffic telemetry unavailable", 503)
		return
	}
	jsonOut(w, s.Engine.TrafficSeries.Current())
}
func (s *Server) trafficHistory(w http.ResponseWriter, r *http.Request) {
	if s.Engine.TrafficSeries == nil {
		jsonError(w, "traffic telemetry unavailable", 503)
		return
	}
	d, err := trafficseries.ParseRange(r.URL.Query().Get("range"))
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"range": d.String(), "points": s.Engine.TrafficSeries.History(d, time.Now().UTC())})
}
func (s *Server) threatIntel(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]any{"indicators": s.Engine.ThreatIndicators(), "errors": s.Engine.ThreatIntelErrors()})
}
func (s *Server) baseline(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.BaselineSnapshot())
}

func (s *Server) cases(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonOut(w, s.Engine.CasesList())
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if err := s.require(r, "case:write"); err != nil {
		jsonError(w, err.Error(), 403)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin mutation rejected", 403)
		return
	}
	var q struct {
		FindingID     string `json:"finding_id"`
		WindowMinutes int    `json:"window_minutes"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil || q.FindingID == "" {
		http.Error(w, "finding_id required", 400)
		return
	}
	if q.WindowMinutes <= 0 {
		q.WindowMinutes = 10
	}
	if q.WindowMinutes > 120 {
		q.WindowMinutes = 120
	}
	c, e := s.Engine.CreateCaseFromFinding(q.FindingID, time.Duration(q.WindowMinutes)*time.Minute)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "case.create", c.ID, q.FindingID, true)
	jsonOut(w, c)
}
func (s *Server) caseDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/cases/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		c, e := s.Engine.Case(id)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		jsonOut(w, c)
		return
	}
	if len(parts) == 2 && parts[1] == "notes" && r.Method == http.MethodPost {
		if err := s.require(r, "case:write"); err != nil {
			jsonError(w, err.Error(), 403)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "cross-origin mutation rejected", 403)
			return
		}
		var q struct {
			Author string `json:"author"`
			Text   string `json:"text"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		c, e := s.Engine.AddCaseNote(id, q.Author, q.Text)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s.auditEvent(r, "case.note", id, "", true)
		jsonOut(w, c)
		return
	}
	if len(parts) == 2 && parts[1] == "lock" && r.Method == http.MethodPost {
		if err := s.require(r, "case:write"); err != nil {
			jsonError(w, err.Error(), 403)
			return
		}
		c, e := s.Engine.Cases.Lock(id)
		if e != nil {
			jsonError(w, e.Error(), 400)
			return
		}
		s.auditEvent(r, "case.lock", id, "forensic immutable lock", true)
		jsonOut(w, c)
		return
	}
	if len(parts) == 2 && parts[1] == "export" && r.Method == http.MethodGet {
		p, e := s.Engine.ExportCase(id)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(p))
		http.ServeFile(w, r, p)
		return
	}
	http.NotFound(w, r)
}
func (s *Server) activeResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin mutation rejected", 403)
		return
	}
	var q response.Request
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	res, e := s.Engine.Response.Execute(r.Context(), q)
	s.auditEvent(r, "response.execute", q.Action, q.IP+" "+q.Interface, e == nil)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	jsonOut(w, res)
}
func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin mutation rejected", 403)
		return
	}
	var q struct {
		Path string `json:"path"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	p, e := s.allowedFile(q.Path, s.Engine.Config.Lab.AllowExternalFiles)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	st, e := s.Engine.ReplayFile(p)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	s.auditEvent(r, "replay.run", filepath.Base(p), "", true)
	jsonOut(w, st)
}
func (s *Server) detectionLab(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin mutation rejected", 403)
		return
	}
	var q struct {
		Path          string   `json:"path"`
		RulesFile     string   `json:"rules_file"`
		IOCFile       string   `json:"ioc_file"`
		Label         string   `json:"label"`
		Benign        bool     `json:"benign"`
		ExpectedRules []string `json:"expected_rules"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	p, e := s.allowedFile(q.Path, s.Engine.Config.Lab.AllowExternalFiles)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	rules, err := s.optionalAllowedFile(q.RulesFile)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	ioc, err := s.optionalAllowedFile(q.IOCFile)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	res, e := detectionlab.Run(s.Engine.Config, p, rules, ioc)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if s.Engine.Quality != nil && (q.Benign || len(q.ExpectedRules) > 0 || strings.TrimSpace(q.Label) != "") {
		_ = s.Engine.RecordDetectionQuality(detectionquality.Run{Label: strings.TrimSpace(q.Label), Capture: filepath.Base(p), Benign: q.Benign, ExpectedRules: q.ExpectedRules, Observed: res.ByRule, Frames: res.Frames, ElapsedMS: res.ElapsedMS})
	}
	s.auditEvent(r, "detection_lab.run", filepath.Base(p), fmt.Sprintf("findings=%d", res.Findings), true)
	jsonOut(w, struct {
		detectionlab.Result
		Quality any `json:"quality"`
	}{Result: res, Quality: s.Engine.DetectionQuality()})
}
func (s *Server) verifyEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var q struct {
		Manifest string `json:"manifest"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q) != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	p, e := s.allowedFile(q.Manifest, false)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	b, e := os.ReadFile(p)
	if e == nil {
		e = evidence.VerifyManifestFiles(filepath.Dir(p), b)
	}
	if e != nil {
		jsonOut(w, map[string]any{"ok": false, "error": e.Error()})
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func (s *Server) sensors(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, s.Engine.Federation.List())
}
func (s *Server) sensorIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !s.Engine.Config.Federation.IngestEnabled {
		http.NotFound(w, r)
		return
	}
	want := s.Engine.Config.Federation.IngestToken
	got := r.Header.Get("X-NetProbe-Sensor-Token")
	if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	var snap federation.Snapshot
	if json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&snap) != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	if e := s.Engine.Federation.Ingest(snap); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}
func sameOrigin(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, e := url.Parse(origin)
		return e == nil && strings.EqualFold(u.Host, r.Host)
	}
	return true
}
func (s *Server) allowedFile(path string, allowExternal bool) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	base, err := filepath.Abs(s.Engine.Config.DataDir)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve symlinks before containment checks so a link inside data_dir
	// cannot escape into arbitrary host files.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if allowExternal {
		return real, nil
	}
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		baseReal = base
	}
	rel, err := filepath.Rel(baseReal, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("file must be under data_dir")
	}
	return real, nil
}
func (s *Server) optionalAllowedFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	return s.allowedFile(path, s.Engine.Config.Lab.AllowExternalFiles)
}

func metricLabel(s string) string {
	return strings.NewReplacer("\\", "_", "\"", "_", "\n", "_", "\r", "_").Replace(s)
}

func (s *Server) syslogExport(w http.ResponseWriter, r *http.Request) {
	if s.Engine.SyslogExport == nil {
		jsonError(w, "syslog exporter unavailable", 503)
		return
	}
	base := "/api/v1/export/syslog"
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, base), "/")
	if rest == "" {
		switch r.Method {
		case http.MethodGet:
			jsonOut(w, map[string]any{"destinations": s.Engine.SyslogExport.List(), "stats": s.Engine.SyslogExport.Stats()})
			return
		case http.MethodPost:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			var d syslogexport.Destination
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&d); err != nil {
				jsonError(w, "invalid JSON", 400)
				return
			}
			v, err := s.Engine.SyslogExport.Upsert(d)
			if err != nil {
				jsonError(w, err.Error(), 400)
				return
			}
			s.auditEvent(r, "settings.syslog.create", v.ID, "transport="+v.Transport+" format="+v.Format, true)
			jsonOut(w, v)
			return
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
	}
	parts := strings.Split(rest, "/")
	id, err := url.PathUnescape(parts[0])
	if err != nil || id == "" {
		jsonError(w, "invalid destination id", 400)
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			v, ok := s.Engine.SyslogExport.Get(id)
			if !ok {
				http.NotFound(w, r)
				return
			}
			jsonOut(w, v)
			return
		case http.MethodPut:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			var d syslogexport.Destination
			if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&d) != nil {
				jsonError(w, "invalid JSON", 400)
				return
			}
			d.ID = id
			v, e := s.Engine.SyslogExport.Upsert(d)
			if e != nil {
				jsonError(w, e.Error(), 400)
				return
			}
			s.auditEvent(r, "settings.syslog.update", id, "", true)
			jsonOut(w, v)
			return
		case http.MethodDelete:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			if e := s.Engine.SyslogExport.Delete(id); e != nil {
				http.NotFound(w, r)
				return
			}
			s.auditEvent(r, "settings.syslog.delete", id, "", true)
			jsonOut(w, map[string]any{"ok": true})
			return
		default:
			w.Header().Set("Allow", "GET, PUT, DELETE")
			http.Error(w, "method not allowed", 405)
			return
		}
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		if err := s.require(r, "admin:settings"); err != nil {
			jsonError(w, err.Error(), 403)
			return
		}
		switch parts[1] {
		case "enable", "disable":
			on := parts[1] == "enable"
			if e := s.Engine.SyslogExport.Enable(id, on); e != nil {
				http.NotFound(w, r)
				return
			}
			s.auditEvent(r, "settings.syslog."+parts[1], id, "", true)
			jsonOut(w, map[string]any{"ok": true, "enabled": on})
			return
		case "test":
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			e := s.Engine.SyslogExport.Test(ctx, id)
			s.auditEvent(r, "settings.syslog.test", id, errString(e), e == nil)
			if e != nil {
				jsonError(w, e.Error(), 502)
				return
			}
			jsonOut(w, map[string]any{"ok": true})
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) flowExport(w http.ResponseWriter, r *http.Request) {
	if s.Engine.FlowExport == nil {
		jsonError(w, "flow exporter unavailable", 503)
		return
	}
	base := "/api/v1/export/flow"
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, base), "/")
	if rest == "" {
		switch r.Method {
		case http.MethodGet:
			jsonOut(w, map[string]any{"collectors": s.Engine.FlowExport.List(), "stats": s.Engine.FlowExport.Stats()})
			return
		case http.MethodPost:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			var c flowexport.Collector
			if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c) != nil {
				jsonError(w, "invalid JSON", 400)
				return
			}
			v, e := s.Engine.FlowExport.Upsert(c)
			if e != nil {
				jsonError(w, e.Error(), 400)
				return
			}
			s.auditEvent(r, "settings.flow.create", v.ID, "protocol="+v.Protocol, true)
			jsonOut(w, v)
			return
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
	}
	parts := strings.Split(rest, "/")
	id, e := url.PathUnescape(parts[0])
	if e != nil || id == "" {
		jsonError(w, "invalid collector id", 400)
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			v, ok := s.Engine.FlowExport.Raw(id)
			if !ok {
				http.NotFound(w, r)
				return
			}
			jsonOut(w, v)
			return
		case http.MethodPut:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			var c flowexport.Collector
			if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c) != nil {
				jsonError(w, "invalid JSON", 400)
				return
			}
			c.ID = id
			v, er := s.Engine.FlowExport.Upsert(c)
			if er != nil {
				jsonError(w, er.Error(), 400)
				return
			}
			s.auditEvent(r, "settings.flow.update", id, "", true)
			jsonOut(w, v)
			return
		case http.MethodDelete:
			if err := s.require(r, "admin:settings"); err != nil {
				jsonError(w, err.Error(), 403)
				return
			}
			if er := s.Engine.FlowExport.Delete(id); er != nil {
				http.NotFound(w, r)
				return
			}
			s.auditEvent(r, "settings.flow.delete", id, "", true)
			jsonOut(w, map[string]any{"ok": true})
			return
		default:
			w.Header().Set("Allow", "GET, PUT, DELETE")
			http.Error(w, "method not allowed", 405)
			return
		}
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		if err := s.require(r, "admin:settings"); err != nil {
			jsonError(w, err.Error(), 403)
			return
		}
		switch parts[1] {
		case "enable", "disable":
			on := parts[1] == "enable"
			if er := s.Engine.FlowExport.Enable(id, on); er != nil {
				http.NotFound(w, r)
				return
			}
			s.auditEvent(r, "settings.flow."+parts[1], id, "", true)
			jsonOut(w, map[string]any{"ok": true, "enabled": on})
			return
		case "test":
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			er := s.Engine.FlowExport.Test(ctx, id)
			s.auditEvent(r, "settings.flow.test", id, errString(er), er == nil)
			if er != nil {
				jsonError(w, er.Error(), 502)
				return
			}
			jsonOut(w, map[string]any{"ok": true})
			return
		}
	}
	http.NotFound(w, r)
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	st := s.Engine.Status()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	running := 0
	if st.CaptureRunning {
		running = 1
	}
	fmt.Fprintf(w, "netprobe_capture_running %d\nnetprobe_packets_total %d\nnetprobe_bytes_total %d\nnetprobe_flows %d\nnetprobe_active_flows %d\nnetprobe_processes %d\nnetprobe_alerts %d\nnetprobe_security_findings %d\nnetprobe_critical_findings %d\nnetprobe_confirmed_findings %d\nnetprobe_capture_errors_total %d\nnetprobe_recorder_drops_total %d\n", running, st.Packets, st.Bytes, st.Flows, st.ActiveFlows, st.Processes, st.Alerts, st.SecurityFindings, st.CriticalFindings, st.ConfirmedFindings, st.CaptureErrors, st.RecorderDrops)
	if s.Engine.SyslogExport != nil {
		for _, x := range s.Engine.SyslogExport.Stats() {
			id := metricLabel(x.ID)
			last := int64(0)
			if !x.LastSuccess.IsZero() {
				last = x.LastSuccess.Unix()
			}
			state := metricLabel(x.State)
			fmt.Fprintf(w, "netprobe_syslog_sent_total{id=\"%s\"} %d\nnetprobe_syslog_failed_total{id=\"%s\"} %d\nnetprobe_syslog_dropped_total{id=\"%s\"} %d\nnetprobe_syslog_queue_depth{id=\"%s\"} %d\nnetprobe_syslog_reconnect_total{id=\"%s\"} %d\nnetprobe_syslog_event_bus_drops_total{id=\"%s\"} %d\nnetprobe_syslog_last_success_timestamp_seconds{id=\"%s\"} %d\nnetprobe_syslog_state{id=\"%s\",state=\"%s\"} 1\n", id, x.Sent, id, x.Failed, id, x.Dropped, id, x.QueueDepth, id, x.Reconnects, id, x.BusDrops, id, last, id, state)
		}
	}
	if s.Engine.FlowExport != nil {
		for _, x := range s.Engine.FlowExport.Stats() {
			id := metricLabel(x.ID)
			last := int64(0)
			if !x.LastSuccess.IsZero() {
				last = x.LastSuccess.Unix()
			}
			state := metricLabel(x.State)
			fmt.Fprintf(w, "netprobe_flow_exported_total{id=\"%s\"} %d\nnetprobe_flow_export_datagrams_total{id=\"%s\"} %d\nnetprobe_flow_failed_total{id=\"%s\"} %d\nnetprobe_flow_dropped_total{id=\"%s\"} %d\nnetprobe_flow_queue_depth{id=\"%s\"} %d\nnetprobe_flow_active{id=\"%s\"} %d\nnetprobe_flow_template_sends_total{id=\"%s\"} %d\nnetprobe_flow_reconnect_total{id=\"%s\"} %d\nnetprobe_flow_event_bus_drops_total{id=\"%s\"} %d\nnetprobe_flow_last_success_timestamp_seconds{id=\"%s\"} %d\nnetprobe_flow_state{id=\"%s\",state=\"%s\"} 1\n", id, x.ExportedFlows, id, x.ExportedPackets, id, x.FailedExports, id, x.DroppedExports, id, x.QueueDepth, id, x.ActiveFlows, id, x.TemplateSends, id, x.Reconnects, id, x.BusDrops, id, last, id, state)
		}
	}
	if s.Engine.Notifications != nil {
		ns := s.Engine.Notifications.Public()
		for _, x := range []struct {
			name string
			st   notifications.ChannelStats
		}{{"email", ns.EmailStats}, {"telegram", ns.TelegramStats}} {
			name := metricLabel(x.name)
			last := int64(0)
			if !x.st.LastSuccess.IsZero() {
				last = x.st.LastSuccess.Unix()
			}
			fmt.Fprintf(w, "netprobe_notification_sent_total{channel=\"%s\"} %d\nnetprobe_notification_failed_total{channel=\"%s\"} %d\nnetprobe_notification_dropped_total{channel=\"%s\"} %d\nnetprobe_notification_deduplicated_total{channel=\"%s\"} %d\nnetprobe_notification_queue_depth{channel=\"%s\"} %d\nnetprobe_notification_last_success_timestamp_seconds{channel=\"%s\"} %d\n", name, x.st.Sent, name, x.st.Failed, name, x.st.Dropped, name, x.st.Deduplicated, name, x.st.QueueDepth, name, last)
		}
	}
	if s.Engine.TrafficSeries != nil {
		p := s.Engine.TrafficSeries.Current()
		fmt.Fprintf(w, "netprobe_traffic_in_bits_per_second %f\nnetprobe_traffic_out_bits_per_second %f\nnetprobe_traffic_in_packets_per_second %f\nnetprobe_traffic_out_packets_per_second %f\nnetprobe_traffic_flows_per_second %f\n", p.InBitsSec, p.OutBitsSec, p.InPacketsSec, p.OutPacketsSec, p.FlowsSec)
	}
	files := s.Engine.FilesList(1000000)
	yaraMatches := 0
	for _, f := range files {
		yaraMatches += len(f.Yara)
	}
	fmt.Fprintf(w, "netprobe_file_artifacts %d\nnetprobe_yara_matches_total %d\nnetprobe_beacon_groups %d\n", len(files), yaraMatches, len(s.Engine.BeaconGroups()))
	edns := s.Engine.EncryptedDNS(1000000)
	suspiciousDNS := 0
	for _, x := range edns {
		if x.Suspicious {
			suspiciousDNS++
		}
	}
	fmt.Fprintf(w, "netprobe_encrypted_dns_observations %d\nnetprobe_encrypted_dns_suspicious %d\nnetprobe_identity_profiles %d\n", len(edns), suspiciousDNS, len(s.Engine.IdentityProfiles()))
	sp := s.Engine.SelfProtectionHealth()
	spOK := 0
	if sp.OK {
		spOK = 1
	}
	fmt.Fprintf(w, "netprobe_self_protection_ok %d\nnetprobe_self_protection_watched %d\nnetprobe_self_protection_disk_free_bytes %d\n", spOK, sp.Watched, sp.DiskFreeMB*(1<<20))
	q := s.Engine.DetectionQuality()
	fmt.Fprintf(w, "netprobe_detection_quality_score %d\nnetprobe_detection_quality_precision %f\nnetprobe_detection_quality_recall %f\nnetprobe_detection_quality_runs %d\nnetprobe_runtime_events_retained %d\nnetprobe_exploit_correlations %d\n", q.OverallQualityScore, q.OverallPrecision, q.OverallRecall, q.Runs, len(s.Engine.RuntimeEvents(1000000)), len(s.Engine.ExploitCorrelations()))
	fh := s.Engine.Federation.FleetHealth(time.Now().UTC())
	online, stale, offline := 0, 0, 0
	for _, x := range fh {
		switch x.State {
		case "online":
			online++
		case "stale":
			stale++
		case "offline":
			offline++
		}
	}
	fmt.Fprintf(w, "netprobe_fleet_sensors %d\nnetprobe_fleet_online %d\nnetprobe_fleet_stale %d\nnetprobe_fleet_offline %d\n", len(fh), online, stale, offline)
	for _, x := range s.Engine.StreamingStatus() {
		name, typ := metricLabel(x.Name), metricLabel(x.Type)
		state := metricLabel(x.State)
		last := int64(0)
		if !x.LastSuccess.IsZero() {
			last = x.LastSuccess.Unix()
		}
		fmt.Fprintf(w, "netprobe_stream_sent_total{name=\"%s\",type=\"%s\"} %d\nnetprobe_stream_failed_total{name=\"%s\",type=\"%s\"} %d\nnetprobe_stream_dropped_total{name=\"%s\",type=\"%s\"} %d\nnetprobe_stream_queue_depth{name=\"%s\",type=\"%s\"} %d\nnetprobe_stream_last_success_timestamp_seconds{name=\"%s\",type=\"%s\"} %d\nnetprobe_stream_state{name=\"%s\",type=\"%s\",state=\"%s\"} 1\n", name, typ, x.Sent, name, typ, x.Failed, name, typ, x.Dropped, name, typ, x.QueueDepth, name, typ, last, name, typ, state)
	}
}
func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", 400)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing websocket key", 400)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", 500)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(h[:])
	fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err := buf.Flush(); err != nil {
		return
	}
	p := principal(r)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tick := 0
	for range ticker.C {
		tick++
		if s.Auth != nil && (p.SessionID != "" || p.TokenID != "") {
			current, err := s.Auth.RevalidatePrincipal(p)
			if err != nil || !auth.Can(current, "read:telemetry") || current.MustChange {
				return
			}
			p = current
		}
		// High-frequency frames intentionally contain only status + the incremental
		// live-traffic point. The heavier retained telemetry snapshots are refreshed
		// every five seconds, reducing browser/network churn without changing the
		// existing WebSocket contract (fields are optional between snapshots).
		v := map[string]any{"status": s.Engine.Status(), "traffic_live": func() any {
			if s.Engine.TrafficSeries != nil {
				return s.Engine.TrafficSeries.Current()
			}
			return nil
		}()}
		if tick == 1 || tick%5 == 0 {
			v["flows"] = s.Engine.Flows(250)
			v["packets"] = s.Engine.Packets(250)
			v["processes"] = s.Engine.Processes()
			v["alerts"] = s.Engine.Alerts(150)
			v["findings"] = s.Engine.Findings(300)
		}
		payload, _ := json.Marshal(v)
		if err := writeTextFrame(conn, payload); err != nil {
			return
		}
	}
}
func writeTextFrame(w interface{ Write([]byte) (int, error) }, p []byte) error {
	hdr := []byte{0x81}
	n := len(p)
	if n < 126 {
		hdr = append(hdr, byte(n))
	} else if n <= 65535 {
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	} else {
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(uint64(n)>>24), byte(uint64(n)>>16), byte(uint64(n)>>8), byte(n))
	}
	if _, e := w.Write(hdr); e != nil {
		return e
	}
	_, e := w.Write(p)
	return e
}
