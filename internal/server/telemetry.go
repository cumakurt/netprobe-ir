package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"netprobe-ir/internal/auth"
	"netprobe-ir/internal/telemetry"
)

func telemetryRange(v string) (time.Duration, error) {
	switch v {
	case "", "live", "1m":
		return time.Minute, nil
	case "5m":
		return 5 * time.Minute, nil
	case "15m":
		return 15 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "6h":
		return 6 * time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("unsupported range")
}
func (s *Server) telemetryAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonError(w, "method not allowed", 405)
		return
	}
	if s.Engine.Telemetry == nil {
		jsonError(w, "telemetry unavailable", 503)
		return
	}
	d, err := telemetryRange(r.URL.Query().Get("range"))
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	name := r.URL.Query().Get("interface")
	now := time.Now()
	snap, ok := s.Engine.Telemetry.Snapshot(name, now)
	if !ok {
		jsonError(w, "interface telemetry not available", 404)
		return
	}
	if r.URL.Path != "/api/v1/telemetry/stream" {
		jsonOut(w, map[string]any{"snapshot": snap, "history": s.Engine.Telemetry.History(name, d, now)})
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		jsonError(w, "streaming unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	p := principal(r)
	tick := 0
	for {
		if s.Auth != nil && (p.SessionID != "" || p.TokenID != "") {
			current, err := s.Auth.RevalidatePrincipal(p)
			if err != nil || !auth.Can(current, "read:telemetry") || current.MustChange {
				return
			}
			p = current
		}
		snap, ok = s.Engine.Telemetry.Snapshot(name, time.Now())
		if !ok {
			return
		}
		var history []telemetry.Point
		if tick%30 == 0 {
			history = s.Engine.Telemetry.History(name, d, time.Now())
		}
		payload, err := json.Marshal(struct {
			Snapshot *telemetry.Snapshot `json:"snapshot"`
			History  []telemetry.Point   `json:"history,omitempty"`
		}{snap, history})
		if err != nil {
			return
		}
		// Deadlines bound slow-client resource use; cancellation releases the ticker.
		if err = rc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil && err != http.ErrNotSupported {
			return
		}
		if _, err = fmt.Fprintf(w, "event: telemetry\ndata: %s\n\n", payload); err != nil {
			return
		}
		if err = rc.Flush(); err != nil {
			return
		}
		tick++
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
