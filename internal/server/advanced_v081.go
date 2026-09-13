package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"netprobe-ir/internal/ebpfattr"
	"netprobe-ir/internal/sigma"
)

func (s *Server) detectionQualityAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"summary": s.Engine.DetectionQuality(), "runs": s.Engine.DetectionQualityRuns(parseLimit(r, 100))})
}

func (s *Server) runtimeEventsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"backend": s.Engine.Status().AttributionBackend, "provider_available": s.Engine.EBPF != nil && s.Engine.EBPF.Available(), "capabilities": ebpfattr.Capabilities(), "events": s.Engine.RuntimeEvents(parseLimit(r, 500))})
}

func (s *Server) exploitCorrelationsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"chains": s.Engine.ExploitCorrelations()})
}

func (s *Server) fleetHealthAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"sensors": s.Engine.Federation.FleetHealth(time.Now().UTC())})
}

func (s *Server) sigmaTranslateAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Rule string `json:"rule"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil || strings.TrimSpace(in.Rule) == "" {
		jsonError(w, "rule required", 400)
		return
	}
	rule, err := sigma.Parse(strings.NewReader(in.Rule))
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	c := sigma.CompileQuery(rule)
	s.auditEvent(r, "sigma.translate", rule.ID, rule.Title, true)
	jsonOut(w, map[string]any{"rule": rule, "compiled": c, "npdl": sigma.RenderNPDL(rule)})
}
