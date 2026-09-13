package dnsintel

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Config struct {
	Enabled          bool
	KnownResolvers   []string
	AllowedProcesses []string
}
type Observation struct {
	Time       time.Time `json:"time"`
	Type       string    `json:"type"`
	Process    string    `json:"process,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Remote     string    `json:"remote"`
	SNI        string    `json:"sni,omitempty"`
	FlowID     string    `json:"flow_id"`
	Confidence int       `json:"confidence"`
	Suspicious bool      `json:"suspicious"`
}
type Engine struct {
	mu  sync.Mutex
	cfg Config
	obs []Observation
}

func New(c Config) *Engine {
	if len(c.KnownResolvers) == 0 {
		c.KnownResolvers = []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.nextdns.io", "mozilla.cloudflare-dns.com"}
	}
	return &Engine{cfg: c}
}
func (e *Engine) Observe(f model.Flow, created bool) (*Observation, *model.SecurityFinding) {
	if !e.cfg.Enabled || !created {
		return nil, nil
	}
	typ, conf := "", 0
	sni := ""
	if f.DPI.TLS != nil {
		sni = strings.ToLower(strings.TrimSuffix(f.DPI.TLS.SNI, "."))
	}
	if f.Remote.Port == 853 {
		if f.NetworkProtocol == "UDP" {
			typ = "DoQ"
		} else {
			typ = "DoT"
		}
		conf = 95
	}
	if f.DPI.HTTP != nil {
		p := strings.ToLower(f.DPI.HTTP.Path)
		ct := strings.ToLower(f.DPI.HTTP.ContentType)
		if strings.Contains(p, "dns-query") || strings.Contains(ct, "application/dns-message") {
			typ = "DoH"
			conf = 100
		}
	}
	if typ == "" && sni != "" && resolver(sni, e.cfg.KnownResolvers) && (f.Remote.Port == 443 || f.DPI.Encrypted) {
		typ = "DoH-like"
		conf = 75
	}
	if typ == "" {
		return nil, nil
	}
	o := Observation{Time: f.LastSeen, Type: typ, Remote: f.Remote.IP, SNI: sni, FlowID: f.ID, Confidence: conf}
	proc := ""
	if f.Process != nil {
		o.Process = f.Process.Comm
		o.PID = f.Process.PID
		proc = strings.ToLower(f.Process.Comm + " " + f.Process.Exe)
	}
	e.mu.Lock()
	e.obs = append(e.obs, o)
	if len(e.obs) > 2000 {
		e.obs = e.obs[len(e.obs)-2000:]
	}
	e.mu.Unlock()
	allowed := false
	for _, x := range e.cfg.AllowedProcesses {
		if strings.Contains(proc, strings.ToLower(x)) {
			allowed = true
			break
		}
	}
	if allowed {
		o.Suspicious = false
		return &o, nil
	}
	o.Suspicious = true
	h := sha256.Sum256([]byte("edns|" + f.ID + "|" + typ))
	sf := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: f.LastSeen, Severity: "medium", Confidence: conf, Verdict: "behavioral", RuleID: "NP-EDNS-1001", Title: "Unexpected encrypted DNS usage", Description: "A process used an encrypted DNS transport outside the configured process allowlist.", Category: "encrypted-dns", Tactic: "Command and Control", MITRE: []string{"T1071.004"}, FlowID: f.ID, Direction: f.Direction, Source: f.Local, Destination: f.Remote, Protocol: f.NetworkProtocol, Application: typ, PID: o.PID, Process: o.Process, Evidence: map[string]any{"encrypted_dns": typ, "sni": sni, "confidence": conf}}
	return &o, &sf
}
func resolver(s string, a []string) bool {
	for _, x := range a {
		x = strings.ToLower(strings.TrimSpace(x))
		if x != "" && (s == x || strings.HasSuffix(s, "."+x)) {
			return true
		}
	}
	return false
}
func (e *Engine) List(limit int) []Observation {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.obs) {
		limit = len(e.obs)
	}
	out := append([]Observation(nil), e.obs[len(e.obs)-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
