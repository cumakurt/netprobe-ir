package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"netprobe-ir/internal/model"
	"netprobe-ir/internal/notifications"
)

type assetView struct {
	Kind          string    `json:"kind"`
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	IP            string    `json:"ip,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	MAC           string    `json:"mac,omitempty"`
	User          string    `json:"user,omitempty"`
	Container     string    `json:"container,omitempty"`
	KubernetesPod string    `json:"kubernetes_pod,omitempty"`
	Interface     string    `json:"interface,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	Flows         int       `json:"flows"`
	Bytes         uint64    `json:"bytes"`
	InTraffic     uint64    `json:"in_traffic"`
	OutTraffic    uint64    `json:"out_traffic"`
	Risk          int       `json:"risk"`
	Protocols     []string  `json:"protocols,omitempty"`
	Ports         []uint16  `json:"ports,omitempty"`
	RelatedAlerts []string  `json:"related_alerts,omitempty"`
	RelatedAssets []string  `json:"related_assets,omitempty"`
}

type assetAcc struct {
	v         assetView
	protocols map[string]bool
	ports     map[uint16]bool
	alerts    map[string]bool
	related   map[string]bool
	flowIDs   map[string]bool
}

func (s *Server) collectAssets() []assetView {
	m := map[string]*assetAcc{}
	add := func(kind, id, name string, f model.Flow) *assetAcc {
		key := kind + ":" + id
		a := m[key]
		if a == nil {
			a = &assetAcc{v: assetView{Kind: kind, ID: key, Name: name}, protocols: map[string]bool{}, ports: map[uint16]bool{}, alerts: map[string]bool{}, related: map[string]bool{}, flowIDs: map[string]bool{}}
			m[key] = a
		}
		if !a.flowIDs[f.ID] {
			a.flowIDs[f.ID] = true
			a.v.Flows++
			a.v.Bytes += f.BytesTX + f.BytesRX
			a.v.OutTraffic += f.BytesTX
			a.v.InTraffic += f.BytesRX
		}
		if a.v.FirstSeen.IsZero() || f.FirstSeen.Before(a.v.FirstSeen) {
			a.v.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(a.v.LastSeen) {
			a.v.LastSeen = f.LastSeen
		}
		if f.Risk > a.v.Risk {
			a.v.Risk = f.Risk
		}
		if f.NetworkProtocol != "" {
			a.protocols[f.NetworkProtocol] = true
		}
		if f.DPI.Protocol != "" {
			a.protocols[f.DPI.Protocol] = true
		}
		if f.DPI.Application != "" {
			a.protocols[f.DPI.Application] = true
		}
		if f.Remote.Port > 0 {
			a.ports[f.Remote.Port] = true
		}
		if a.v.Interface == "" && len(f.Interfaces) > 0 {
			a.v.Interface = f.Interfaces[0]
		}
		return a
	}
	flows := s.Engine.Flows(10000)
	for _, f := range flows {
		keys := []string{}
		if f.Process != nil {
			name := f.Process.Comm
			if name == "" {
				name = f.Process.Exe
			}
			a := add("process", strconv.Itoa(f.Process.PID), name, f)
			a.v.User = f.Process.User
			a.v.Container = f.Process.ContainerID
			a.v.KubernetesPod = f.Process.KubernetesPod
			keys = append(keys, a.v.ID)
			if f.Process.User != "" {
				keys = append(keys, add("user", f.Process.User, f.Process.User, f).v.ID)
			}
			if f.Process.ContainerID != "" {
				keys = append(keys, add("container", f.Process.ContainerID, f.Process.ContainerID, f).v.ID)
			}
			if f.Process.KubernetesPod != "" {
				keys = append(keys, add("kubernetes_pod", f.Process.KubernetesPod, f.Process.KubernetesPod, f).v.ID)
			}
		}
		if f.Local.IP != "" {
			a := add("local_ip", f.Local.IP, f.Local.IP, f)
			a.v.IP = f.Local.IP
			keys = append(keys, a.v.ID)
		}
		if f.Remote.IP != "" {
			a := add("remote_ip", f.Remote.IP, f.Remote.IP, f)
			a.v.IP = f.Remote.IP
			keys = append(keys, a.v.ID)
		}
		domain := ""
		if f.DPI.TLS != nil {
			domain = f.DPI.TLS.SNI
		}
		if domain == "" && f.DPI.HTTP != nil {
			domain = f.DPI.HTTP.Host
		}
		if domain == "" && f.DPI.DNS != nil {
			domain = f.DPI.DNS.Query
		}
		if domain != "" {
			keys = append(keys, add("domain", domain, domain, f).v.ID)
		}
		for _, ifn := range f.Interfaces {
			if ifn != "" {
				keys = append(keys, add("interface", ifn, ifn, f).v.ID)
			}
		}
		for _, a := range keys {
			for _, b := range keys {
				if a != b {
					m[a].related[b] = true
				}
			}
		}
	}
	findings := s.Engine.Findings(10000)
	for _, f := range findings {
		for _, a := range m {
			match := false
			switch a.v.Kind {
			case "remote_ip", "local_ip":
				match = a.v.IP == f.Source.IP || a.v.IP == f.Destination.IP
			case "process":
				pid, _ := strconv.Atoi(strings.TrimPrefix(a.v.ID, "process:"))
				match = pid > 0 && pid == f.PID
			case "domain":
				if x, ok := f.Evidence["domain"].(string); ok {
					match = strings.EqualFold(x, a.v.Name)
				}
			case "interface":
				match = f.Interface == a.v.Name
			}
			if match {
				a.alerts[f.ID] = true
				if severityRiskForAsset(f.Severity) > a.v.Risk {
					a.v.Risk = severityRiskForAsset(f.Severity)
				}
			}
		}
	}
	out := make([]assetView, 0, len(m))
	for _, a := range m {
		for x := range a.protocols {
			a.v.Protocols = append(a.v.Protocols, x)
		}
		sort.Strings(a.v.Protocols)
		for x := range a.ports {
			a.v.Ports = append(a.v.Ports, x)
		}
		sort.Slice(a.v.Ports, func(i, j int) bool { return a.v.Ports[i] < a.v.Ports[j] })
		for x := range a.alerts {
			a.v.RelatedAlerts = append(a.v.RelatedAlerts, x)
		}
		sort.Strings(a.v.RelatedAlerts)
		for x := range a.related {
			a.v.RelatedAssets = append(a.v.RelatedAssets, x)
		}
		sort.Strings(a.v.RelatedAssets)
		out = append(out, a.v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func severityRiskForAsset(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 30
	default:
		return 10
	}
}

func (s *Server) assetDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/api/v1/assets/")
	id, err := url.PathUnescape(raw)
	if err != nil || id == "" {
		jsonError(w, "invalid asset id", 400)
		return
	}
	for _, a := range s.collectAssets() {
		if a.ID == id || (strings.HasPrefix(id, "ip:") && a.IP == strings.TrimPrefix(id, "ip:")) {
			jsonOut(w, a)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) notificationsAPI(w http.ResponseWriter, r *http.Request) {
	if s.Engine.Notifications == nil {
		jsonError(w, "notifications unavailable", 503)
		return
	}
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, s.Engine.Notifications.Public())
	case http.MethodPut, http.MethodPost:
		var cfg notifications.Settings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg) != nil {
			jsonError(w, "invalid notification configuration", 400)
			return
		}
		if err := s.Engine.Notifications.Update(cfg); err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		s.auditEvent(r, "settings.notifications.update", "notifications", "email/telegram settings updated; secrets redacted", true)
		jsonOut(w, s.Engine.Notifications.Public())
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) notificationTestEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Engine.Notifications.TestEmail(ctx); err != nil {
		s.auditEvent(r, "notifications.email.test", "email", err.Error(), false)
		jsonError(w, err.Error(), 502)
		return
	}
	s.auditEvent(r, "notifications.email.test", "email", "success", true)
	jsonOut(w, map[string]any{"ok": true, "message": "Test email sent successfully"})
}
func (s *Server) notificationTestTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Engine.Notifications.TestTelegram(ctx); err != nil {
		s.auditEvent(r, "notifications.telegram.test", "telegram", err.Error(), false)
		jsonError(w, err.Error(), 502)
		return
	}
	s.auditEvent(r, "notifications.telegram.test", "telegram", "success", true)
	jsonOut(w, map[string]any{"ok": true, "message": "Test Telegram message sent successfully"})
}
