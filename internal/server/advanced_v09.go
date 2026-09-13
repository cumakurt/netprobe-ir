package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netprobe-ir/internal/analytics"
	"netprobe-ir/internal/assetintel"
	"netprobe-ir/internal/ocsf"
	"netprobe-ir/internal/otelprofiles"
	"netprobe-ir/internal/perflab"
	"netprobe-ir/internal/playbook"
	"netprobe-ir/internal/ruleimport"
	"netprobe-ir/internal/sigma"
)

func (s *Server) executiveOverviewAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	st := s.Engine.Status()
	fs := s.Engine.Findings(5000)
	stories := s.Engine.Stories(100)
	q := s.Engine.DetectionQuality()
	exploits := s.Engine.ExploitCorrelations()
	fleet := s.Engine.Federation.FleetHealth(time.Now().UTC())
	beacons := s.Engine.BeaconGroups()
	highConfidence := 0
	confirmed := 0
	critical := 0
	for _, f := range fs {
		if f.Confidence >= 90 {
			highConfidence++
		}
		if f.Severity == "critical" {
			critical++
		}
		if f.Verdict == "confirmed_ioc" || f.Verdict == "signature_match" || f.Verdict == "confirmed_exposure" {
			confirmed++
		}
	}
	rootCauses := 0
	criticalStories := 0
	for _, x := range stories {
		if x.RootCause != nil {
			rootCauses++
		}
		if x.Severity == "critical" {
			criticalStories++
		}
	}
	offline, stale := 0, 0
	fleetScore := 100
	if len(fleet) > 0 {
		sum := 0
		for _, x := range fleet {
			sum += x.HealthScore
			if x.State == "offline" {
				offline++
			}
			if x.State == "stale" {
				stale++
			}
		}
		fleetScore = sum / len(fleet)
	}
	posture := 100
	posture -= minInt(45, critical*12)
	posture -= minInt(20, len(exploits)*8)
	posture -= minInt(15, criticalStories*5)
	posture -= minInt(10, offline*5)
	if posture < 0 {
		posture = 0
	}
	jsonOut(w, map[string]any{"posture_score": posture, "status": st, "critical_findings": critical, "confirmed_findings": confirmed, "high_confidence_findings": highConfidence, "attack_stories": len(stories), "critical_stories": criticalStories, "root_causes": rootCauses, "exploit_chains": len(exploits), "advanced_beacons": len(beacons), "detection_quality": q, "fleet_health_score": fleetScore, "fleet_offline": offline, "fleet_stale": stale, "core_ebpf": s.Engine.CoreEBPF, "tls_clusters": len(s.Engine.TLSIntel.Clusters()), "dns_domains": len(s.Engine.DNSGraph.Domains())})
}

func (s *Server) ocsfAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	kind := strings.ToLower(r.URL.Query().Get("kind"))
	limit := parseLimit(r, 200)
	var out []ocsf.Event
	switch kind {
	case "flow", "flows":
		for _, x := range s.Engine.Flows(limit) {
			out = append(out, ocsf.Flow(x))
		}
	case "runtime":
		for _, x := range s.Engine.RuntimeEvents(limit) {
			out = append(out, ocsf.Runtime(x))
		}
	default:
		for _, x := range s.Engine.Findings(limit) {
			out = append(out, ocsf.Finding(x))
		}
	}
	jsonOut(w, map[string]any{"schema": "ocsf-compatible-canonical-envelope", "events": out})
}

func (s *Server) ruleImportAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Rule string `json:"rule"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || strings.TrimSpace(in.Rule) == "" {
		jsonError(w, "rule required", 400)
		return
	}
	rr, err := ruleimport.ParseLine(in.Rule)
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	s.auditEvent(r, "rule.import", strconv.Itoa(rr.SID), rr.Message, true)
	jsonOut(w, map[string]any{"parsed": rr, "translated": ruleimport.Translate(rr)})
}

func (s *Server) sigmaCorrelationAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Rule string `json:"rule"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || strings.TrimSpace(in.Rule) == "" {
		jsonError(w, "rule required", 400)
		return
	}
	c, err := sigma.ParseCorrelation(strings.NewReader(in.Rule))
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	p := sigma.CompileCorrelation(c)
	s.auditEvent(r, "sigma.correlation.translate", c.ID, c.Title, true)
	jsonOut(w, map[string]any{"correlation": c, "plan": p})
}

func (s *Server) playbooksAPI(w http.ResponseWriter, r *http.Request) {
	if s.Engine.Playbooks == nil {
		jsonError(w, "playbook store unavailable", 503)
		return
	}
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, map[string]any{"playbooks": s.Engine.Playbooks.List()})
	case http.MethodPost:
		var p playbook.Playbook
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p) != nil {
			jsonError(w, "invalid playbook", 400)
			return
		}
		if err := s.Engine.Playbooks.Upsert(p); err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		s.auditEvent(r, "playbook.upsert", p.ID, p.Name, true)
		jsonOut(w, map[string]any{"ok": true, "playbooks": s.Engine.Playbooks.List()})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			jsonError(w, "id required", 400)
			return
		}
		if err := s.Engine.Playbooks.Delete(id); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		s.auditEvent(r, "playbook.delete", id, id, true)
		jsonOut(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) analyticsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := analytics.Query{Process: r.URL.Query().Get("process"), Destination: r.URL.Query().Get("dst"), Limit: parseLimit(r, 1000)}
	if x := r.URL.Query().Get("from"); x != "" {
		q.Start, _ = time.Parse(time.RFC3339, x)
	}
	if x := r.URL.Query().Get("to"); x != "" {
		q.End, _ = time.Parse(time.RFC3339, x)
	}
	if x := r.URL.Query().Get("type"); x != "" {
		q.Types = strings.Split(x, ",")
	}
	if x := r.URL.Query().Get("severity"); x != "" {
		q.Severity = strings.Split(x, ",")
	}
	if err := q.Validate(); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	res, err := s.Engine.Analytics.Query(q)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOut(w, res)
}

func (s *Server) assetIntelligenceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	inv := assetintel.Current()
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		inv.Packages, _ = assetintel.ParseDPKGStatus("/var/lib/dpkg/status")
	}
	seenContainers := map[string]bool{}
	for _, f := range s.Engine.Flows(5000) {
		if f.Process == nil || strings.TrimSpace(f.Process.ContainerID) == "" {
			continue
		}
		key := f.Process.ContainerRuntime + "|" + f.Process.ContainerID
		if seenContainers[key] {
			continue
		}
		seenContainers[key] = true
		inv.Containers = append(inv.Containers, assetintel.Container{ID: f.Process.ContainerID, Runtime: f.Process.ContainerRuntime, Pod: f.Process.KubernetesPod, Namespace: f.Process.KubernetesNamespace})
	}
	fmtx := strings.ToLower(r.URL.Query().Get("format"))
	switch fmtx {
	case "cyclonedx", "cdx":
		jsonOut(w, assetintel.CycloneDX(inv))
	case "spdx":
		jsonOut(w, assetintel.SPDX(inv))
	default:
		jsonOut(w, inv)
	}
}

func (s *Server) tlsIntelligenceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"observations": s.Engine.TLSIntel.Observations(parseLimit(r, 500)), "clusters": s.Engine.TLSIntel.Clusters()})
}
func (s *Server) dnsGraphAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"domains": s.Engine.DNSGraph.Domains(), "edges": s.Engine.DNSGraph.Edges()})
}
func (s *Server) coreEBPFAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, s.Engine.CoreEBPF)
}

func (s *Server) benchmarkAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Iterations int `json:"iterations"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)
	if in.Iterations <= 0 {
		in.Iterations = 25000
	}
	if in.Iterations > 1000000 {
		in.Iterations = 1000000
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	x := uint64(0)
	res := perflab.Run(ctx, "synthetic-security-hotpath", in.Iterations, func(i int) { x ^= uint64(i) * 2654435761; x = (x << 7) | (x >> 57) })
	s.auditEvent(r, "benchmark.run", res.Name, strconv.Itoa(res.Iterations), true)
	jsonOut(w, map[string]any{"result": res, "checksum": x})
}

func (s *Server) investigationWorkspaceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("story"))
	if id == "" {
		jsonError(w, "story required", 400)
		return
	}
	var found any
	for _, st := range s.Engine.Stories(500) {
		if st.ID == id {
			found = st
			break
		}
	}
	if found == nil {
		jsonError(w, "story not found", 404)
		return
	}
	jsonOut(w, map[string]any{"story": found, "graph": s.Engine.Graph(5000), "files": s.Engine.FilesList(1000), "runtime_events": s.Engine.RuntimeEvents(2000), "exploit_chains": s.Engine.ExploitCorrelations(), "tls_clusters": s.Engine.TLSIntel.Clusters(), "dns_domains": s.Engine.DNSGraph.Domains()})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) enrichmentAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if s.Engine.Enrichment == nil {
		jsonOut(w, map[string]any{"ip": ip, "matched": false, "reason": "no local enrichment dataset configured"})
		return
	}
	h, ok := s.Engine.Enrichment.Lookup(ip)
	jsonOut(w, map[string]any{"matched": ok, "result": h})
}

func (s *Server) profilesAPI(w http.ResponseWriter, r *http.Request) {
	cfg := s.Engine.Config.Profiles
	if r.Method == http.MethodGet {
		jsonOut(w, map[string]any{"enabled": cfg.Enabled, "endpoint_configured": strings.TrimSpace(cfg.Endpoint) != "", "signal": "OpenTelemetry Profiles experimental adapter", "production_core_dependency": false})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if err := s.require(r, "admin:settings"); err != nil {
		jsonError(w, err.Error(), 403)
		return
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.Endpoint) == "" {
		jsonError(w, "profiles exporter disabled or endpoint missing", 400)
		return
	}
	var env otelprofiles.Envelope
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&env) != nil {
		jsonError(w, "invalid profile envelope", 400)
		return
	}
	token := ""
	if cfg.TokenEnv != "" {
		token = os.Getenv(cfg.TokenEnv)
	}
	ex := otelprofiles.Exporter{Endpoint: cfg.Endpoint, Token: token}
	if err := ex.Export(r.Context(), env); err != nil {
		jsonError(w, err.Error(), 502)
		return
	}
	s.auditEvent(r, "profiles.export", "otel", strconv.Itoa(len(env.Samples)), true)
	jsonOut(w, map[string]any{"ok": true, "samples": len(env.Samples)})
}
