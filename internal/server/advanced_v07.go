package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) filesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := parseLimit(r, 500)
	jsonOut(w, map[string]any{"artifacts": s.Engine.FilesList(limit), "yara_available": s.Engine.Files != nil && s.Engine.Files.AvailableYara()})
}
func (s *Server) fileAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	id, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/v1/files/"))
	if err != nil || id == "" {
		http.NotFound(w, r)
		return
	}
	a, ok := s.Engine.File(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, a)
}
func (s *Server) beaconsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"groups": s.Engine.BeaconGroups()})
}
func (s *Server) encryptedDNSAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"observations": s.Engine.EncryptedDNS(parseLimit(r, 500))})
}
func (s *Server) identityProfilesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"profiles": s.Engine.IdentityProfiles()})
}
func (s *Server) vulnerabilitiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, s.Engine.VulnerabilityContext())
}
func (s *Server) protocolPacksAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"enabled": s.Engine.Config.ProtocolPacks.Enabled, "http2": "cleartext h2c metadata", "http3": "QUIC/HTTP3 transport metadata; encrypted headers require session keys"})
}
func (s *Server) streamingAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"targets": s.Engine.StreamingStatus()})
}
func (s *Server) pluginsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"runtime": s.Engine.Config.WASM.Runtime, "enabled": s.Engine.Config.WASM.Enabled, "plugins": s.Engine.WASMStatus()})
}
func (s *Server) selfProtectionAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, s.Engine.SelfProtectionHealth())
	case http.MethodPost:
		if err := s.require(r, "admin:settings"); err != nil {
			jsonError(w, err.Error(), 403)
			return
		}
		if s.Engine.SelfProtect == nil {
			jsonError(w, "self-protection unavailable", 503)
			return
		}
		if err := s.Engine.SelfProtect.Rebaseline(s.Engine.Config.SelfProtection.Paths); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		s.auditEvent(r, "security.self_protection.rebaseline", "sensor", "", true)
		jsonOut(w, map[string]any{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) analystAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct {
		Query string `json:"query"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil || strings.TrimSpace(in.Query) == "" {
		jsonError(w, "query required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.Engine.AskAnalyst(ctx, strings.TrimSpace(in.Query))
	if err != nil {
		jsonError(w, err.Error(), 502)
		return
	}
	s.auditEvent(r, "analyst.query", "evidence", "", true)
	jsonOut(w, out)
}

func (s *Server) fleet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonOut(w, map[string]any{"sensors": s.Engine.Federation.Fleet()})
}
func (s *Server) fleetCommands(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := strings.TrimSpace(r.URL.Query().Get("sensor_id"))
		if id == "" {
			jsonError(w, "sensor_id required", 400)
			return
		}
		jsonOut(w, map[string]any{"commands": s.Engine.Federation.Commands(id, false)})
	case http.MethodPost:
		var in struct {
			SensorID   string         `json:"sensor_id"`
			Type       string         `json:"type"`
			Payload    map[string]any `json:"payload"`
			TTLSeconds int            `json:"ttl_seconds"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil {
			jsonError(w, "invalid JSON", 400)
			return
		}
		c, err := s.Engine.Federation.QueueCommand(in.SensorID, in.Type, in.Payload, time.Duration(in.TTLSeconds)*time.Second)
		if err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		s.auditEvent(r, "fleet.command.queue", c.SensorID, c.Type, true)
		jsonOut(w, c)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) sensorTokenOK(r *http.Request) bool {
	want := s.Engine.Config.Federation.IngestToken
	if want == "" {
		return false
	}
	got := r.Header.Get("X-NetProbe-Sensor-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
func (s *Server) sensorCommandPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !s.sensorTokenOK(r) {
		jsonError(w, "unauthorized", 401)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("sensor_id"))
	if id == "" {
		jsonError(w, "sensor_id required", 400)
		return
	}
	jsonOut(w, map[string]any{"commands": s.Engine.Federation.Commands(id, true)})
}
func (s *Server) sensorCommandAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !s.sensorTokenOK(r) {
		jsonError(w, "unauthorized", 401)
		return
	}
	var in struct {
		SensorID string `json:"sensor_id"`
		ID       string `json:"id"`
		State    string `json:"state"`
		Result   string `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil {
		jsonError(w, "invalid JSON", 400)
		return
	}
	if err := s.Engine.Federation.AckCommand(in.SensorID, in.ID, in.State, in.Result); err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	jsonOut(w, map[string]any{"ok": true})
}

func parseLimit(r *http.Request, def int) int {
	v := def
	if q := r.URL.Query().Get("limit"); q != "" {
		var n int
		if _, e := fmt.Sscanf(q, "%d", &n); e == nil && n > 0 && n <= 10000 {
			v = n
		}
	}
	return v
}
