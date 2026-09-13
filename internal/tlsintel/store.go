package tlsintel

import (
	"netprobe-ir/internal/model"
	"sort"
	"strings"
	"sync"
	"time"
)

type Observation struct {
	Time          time.Time `json:"time"`
	RemoteIP      string    `json:"remote_ip"`
	SNI           string    `json:"sni,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	SPKI          string    `json:"spki_sha256,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	Serial        string    `json:"serial,omitempty"`
	SANs          []string  `json:"sans,omitempty"`
	SelfSigned    bool      `json:"self_signed"`
	Expired       bool      `json:"expired"`
	DaysRemaining int       `json:"days_remaining"`
	JA4           string    `json:"ja4,omitempty"`
}
type Cluster struct {
	Key        string    `json:"key"`
	Count      int       `json:"count"`
	IPs        []string  `json:"ips"`
	SNIs       []string  `json:"snis"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Suspicious bool      `json:"suspicious"`
	Reasons    []string  `json:"reasons,omitempty"`
}
type Store struct {
	mu  sync.RWMutex
	max int
	obs []Observation
}

func New(max int) *Store {
	if max <= 0 {
		max = 10000
	}
	return &Store{max: max}
}
func (s *Store) Observe(f model.Flow) {
	if f.DPI.TLS == nil || f.DPI.TLS.Certificate == nil {
		return
	}
	t := f.DPI.TLS
	c := t.Certificate
	now := f.LastSeen
	if now.IsZero() {
		now = time.Now().UTC()
	}
	o := Observation{Time: now, RemoteIP: f.Remote.IP, SNI: t.SNI, SHA256: c.SHA256, SPKI: c.SPKISHA256, Subject: c.SubjectCN, Issuer: c.IssuerCN, Serial: c.Serial, SANs: append([]string(nil), c.SANs...), SelfSigned: c.SelfSigned, JA4: t.JA4}
	if !c.NotAfter.IsZero() {
		o.Expired = now.After(c.NotAfter)
		o.DaysRemaining = int(c.NotAfter.Sub(now).Hours() / 24)
	}
	s.mu.Lock()
	s.obs = append(s.obs, o)
	if len(s.obs) > s.max {
		s.obs = append([]Observation(nil), s.obs[len(s.obs)-s.max:]...)
	}
	s.mu.Unlock()
}
func (s *Store) Observations(limit int) []Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.obs) {
		limit = len(s.obs)
	}
	return append([]Observation(nil), s.obs[len(s.obs)-limit:]...)
}
func (s *Store) Clusters() []Cluster {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := map[string]*Cluster{}
	ipsets := map[string]map[string]bool{}
	snsets := map[string]map[string]bool{}
	for _, o := range s.obs {
		k := o.SPKI
		if k == "" {
			k = o.SHA256
		}
		if k == "" {
			continue
		}
		c := m[k]
		if c == nil {
			c = &Cluster{Key: k, FirstSeen: o.Time}
			m[k] = c
			ipsets[k] = map[string]bool{}
			snsets[k] = map[string]bool{}
		}
		c.Count++
		if c.FirstSeen.IsZero() || o.Time.Before(c.FirstSeen) {
			c.FirstSeen = o.Time
		}
		if o.Time.After(c.LastSeen) {
			c.LastSeen = o.Time
		}
		if o.RemoteIP != "" {
			ipsets[k][o.RemoteIP] = true
		}
		if o.SNI != "" {
			snsets[k][strings.ToLower(o.SNI)] = true
		}
	}
	out := make([]Cluster, 0, len(m))
	for k, c := range m {
		for ip := range ipsets[k] {
			c.IPs = append(c.IPs, ip)
		}
		for n := range snsets[k] {
			c.SNIs = append(c.SNIs, n)
		}
		sort.Strings(c.IPs)
		sort.Strings(c.SNIs)
		if len(c.IPs) >= 5 && len(c.SNIs) >= 3 {
			c.Suspicious = true
			c.Reasons = append(c.Reasons, "certificate/SPKI reused across many IPs and names")
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
