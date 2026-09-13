package dnsgraph

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type Edge struct {
	Domain    string    `json:"domain"`
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}
type DomainSummary struct {
	Domain   string   `json:"domain"`
	IPs      []string `json:"ips"`
	IPCount  int      `json:"ip_count"`
	Churn    float64  `json:"churn"`
	FastFlux bool     `json:"fast_flux"`
	Reasons  []string `json:"reasons,omitempty"`
}
type Graph struct {
	mu    sync.RWMutex
	edges map[string]*Edge
}

func New() *Graph { return &Graph{edges: map[string]*Edge{}} }
func (g *Graph) Observe(domain string, ips []string, t time.Time) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return
	}
	if t.IsZero() {
		t = time.Now().UTC()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		k := domain + "\x00" + ip
		e := g.edges[k]
		if e == nil {
			e = &Edge{Domain: domain, IP: ip, FirstSeen: t}
			g.edges[k] = e
		}
		e.LastSeen = t
		e.Count++
	}
}
func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
func (g *Graph) Domains() []DomainSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()
	m := map[string][]*Edge{}
	for _, e := range g.edges {
		m[e.Domain] = append(m[e.Domain], e)
	}
	out := make([]DomainSummary, 0, len(m))
	for d, es := range m {
		s := DomainSummary{Domain: d, IPCount: len(es)}
		var first, last time.Time
		for _, e := range es {
			s.IPs = append(s.IPs, e.IP)
			if first.IsZero() || e.FirstSeen.Before(first) {
				first = e.FirstSeen
			}
			if e.LastSeen.After(last) {
				last = e.LastSeen
			}
		}
		dur := last.Sub(first).Hours()
		if dur < 1 {
			dur = 1
		}
		s.Churn = float64(len(es)) / dur
		if len(es) >= 8 && s.Churn >= 2 {
			s.FastFlux = true
			s.Reasons = append(s.Reasons, "many IP mappings in a short observation window")
		}
		sort.Strings(s.IPs)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IPCount > out[j].IPCount })
	return out
}
