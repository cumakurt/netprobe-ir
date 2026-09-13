package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"netprobe-ir/internal/model"
	"strings"
	"sync"
	"time"
)

type Webhook struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Token       string `json:"token,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	Enabled     bool   `json:"enabled"`
}
type Syslog struct {
	Enabled     bool   `json:"enabled"`
	Network     string `json:"network"`
	Address     string `json:"address"`
	Format      string `json:"format"`
	MinSeverity string `json:"min_severity,omitempty"`
}
type Config struct {
	Webhooks []Webhook `json:"webhooks"`
	Syslog   Syslog    `json:"syslog"`
}
type Delivery struct {
	Time      time.Time `json:"time"`
	Target    string    `json:"target"`
	FindingID string    `json:"finding_id"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}
type Manager struct {
	cfg        Config
	client     *http.Client
	mu         sync.Mutex
	deliveries []Delivery
}

func New(c Config) *Manager { return &Manager{cfg: c, client: &http.Client{Timeout: 8 * time.Second}} }
func (m *Manager) Publish(f model.SecurityFinding) {
	if m == nil {
		return
	}
	for _, w := range m.cfg.Webhooks {
		if !w.Enabled || rank(f.Severity) < rank(w.MinSeverity) {
			continue
		}
		w := w
		go m.webhook(w, f)
	}
	if m.cfg.Syslog.Enabled && rank(f.Severity) >= rank(m.cfg.Syslog.MinSeverity) {
		go m.syslog(f)
	}
}
func (m *Manager) webhook(w Webhook, f model.SecurityFinding) {
	b, _ := json.Marshal(map[string]any{"product": "NetProbe IR", "event": "security_finding", "finding": f})
	req, e := http.NewRequestWithContext(context.Background(), http.MethodPost, w.URL, bytes.NewReader(b))
	if e == nil {
		req.Header.Set("Content-Type", "application/json")
		if w.Token != "" {
			req.Header.Set("Authorization", "Bearer "+w.Token)
		}
		var r *http.Response
		r, e = m.client.Do(req)
		if e == nil {
			r.Body.Close()
			if r.StatusCode < 200 || r.StatusCode >= 300 {
				e = fmt.Errorf("HTTP %d", r.StatusCode)
			}
		}
	}
	m.record(Delivery{Time: time.Now().UTC(), Target: "webhook:" + w.Name, FindingID: f.ID, Success: e == nil, Error: errstr(e)})
}
func (m *Manager) syslog(f model.SecurityFinding) {
	cfg := m.cfg.Syslog
	network := cfg.Network
	if network == "" {
		network = "udp"
	}
	c, e := net.DialTimeout(network, cfg.Address, 3*time.Second)
	if e == nil {
		msg := formatSyslog(cfg.Format, f)
		_, e = c.Write([]byte(msg))
		c.Close()
	}
	m.record(Delivery{Time: time.Now().UTC(), Target: "syslog:" + cfg.Address, FindingID: f.ID, Success: e == nil, Error: errstr(e)})
}
func formatSyslog(format string, f model.SecurityFinding) string {
	switch strings.ToLower(format) {
	case "leef":
		return fmt.Sprintf("LEEF:2.0|NetProbe|NetProbe IR|0.6.0|%s|sev=%s\tcat=%s\tsrc=%s\tdst=%s\tmsg=%s\n", f.RuleID, f.Severity, f.Category, f.Source.IP, f.Destination.IP, sanitize(f.Title))
	default:
		return fmt.Sprintf("CEF:0|NetProbe|NetProbe IR|0.6.0|%s|%s|%d|src=%s dst=%s cs1=%s cs1Label=Verdict msg=%s\n", f.RuleID, sanitize(f.Title), cefsev(f.Severity), f.Source.IP, f.Destination.IP, f.Verdict, sanitize(f.Description))
	}
}
func sanitize(s string) string { return strings.NewReplacer("\n", " ", "\r", " ", "|", "/").Replace(s) }
func cefsev(s string) int {
	return map[string]int{"critical": 10, "high": 8, "medium": 6, "low": 3, "info": 1}[strings.ToLower(s)]
}
func rank(s string) int {
	if s == "" {
		return 0
	}
	return map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[strings.ToLower(s)]
}
func errstr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
func (m *Manager) record(d Delivery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries = append(m.deliveries, d)
	if len(m.deliveries) > 500 {
		m.deliveries = m.deliveries[len(m.deliveries)-500:]
	}
}
func (m *Manager) Deliveries() []Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]Delivery(nil), m.deliveries...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
func (m *Manager) Config() Config { return m.cfg }
