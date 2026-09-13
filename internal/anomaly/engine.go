package anomaly

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Config struct {
	ExfiltrationBytes   uint64
	FanoutDestinations  int
	PortScanPorts       int
	BurstConnections    int
	BeaconMinSamples    int
	BeaconMaxJitter     float64
	DNSEntropyThreshold float64
}
type connEvent struct {
	t      time.Time
	proc   string
	remote string
	port   uint16
}
type Engine struct {
	mu      sync.Mutex
	cfg     Config
	alerts  []model.Alert
	seen    map[string]time.Time
	events  []connEvent
	beacons map[string][]time.Time
}

func New(c Config) *Engine {
	if c.ExfiltrationBytes == 0 {
		c.ExfiltrationBytes = 100 << 20
	}
	if c.FanoutDestinations == 0 {
		c.FanoutDestinations = 50
	}
	if c.PortScanPorts == 0 {
		c.PortScanPorts = 30
	}
	if c.BurstConnections == 0 {
		c.BurstConnections = 80
	}
	if c.BeaconMinSamples < 4 {
		c.BeaconMinSamples = 4
	}
	if c.BeaconMaxJitter <= 0 {
		c.BeaconMaxJitter = .15
	}
	if c.DNSEntropyThreshold <= 0 {
		c.DNSEntropyThreshold = 4.2
	}
	return &Engine{cfg: c, seen: map[string]time.Time{}, beacons: map[string][]time.Time{}}
}

func (e *Engine) Observe(f model.Flow, created bool) (int, []string, []model.Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := f.LastSeen
	var score int
	var reasons []string
	var out []model.Alert
	if f.BytesTX >= e.cfg.ExfiltrationBytes {
		score += 35
		reasons = append(reasons, fmt.Sprintf("outbound volume %.1f MiB exceeds threshold", float64(f.BytesTX)/(1<<20)))
		if a, ok := e.alert(now, "exfil-volume", f, 75, "high", "High outbound data volume", reasons[len(reasons)-1]); ok {
			out = append(out, a)
		}
	}
	if f.DPI.DNS != nil && f.DPI.DNS.Query != "" {
		ent := domainEntropy(f.DPI.DNS.Query)
		if len(f.DPI.DNS.Query) >= 24 && ent >= e.cfg.DNSEntropyThreshold {
			score += 25
			reasons = append(reasons, fmt.Sprintf("DNS query entropy %.2f is unusually high", ent))
			if a, ok := e.alert(now, "dns-entropy", f, 65, "medium", "High-entropy DNS name", reasons[len(reasons)-1]); ok {
				a.Evidence = map[string]any{"query": f.DPI.DNS.Query, "entropy": ent}
				out = append(out, a)
			}
		}
	}
	if created {
		proc := procKey(f)
		ev := connEvent{t: now, proc: proc, remote: f.Remote.IP, port: f.Remote.Port}
		e.events = append(e.events, ev)
		cut := now.Add(-60 * time.Second)
		k := 0
		for _, x := range e.events {
			if x.t.After(cut) {
				e.events[k] = x
				k++
			}
		}
		e.events = e.events[:k]
		dests := map[string]bool{}
		ports := map[string]bool{}
		burst := 0
		for _, x := range e.events {
			if x.proc != proc {
				continue
			}
			dests[x.remote] = true
			ports[fmt.Sprintf("%s:%d", x.remote, x.port)] = true
			if x.t.After(now.Add(-10 * time.Second)) {
				burst++
			}
		}
		if len(dests) >= e.cfg.FanoutDestinations {
			score += 20
			reasons = append(reasons, fmt.Sprintf("process contacted %d unique destinations in 60s", len(dests)))
			if a, ok := e.alert(now, "fanout", f, 60, "medium", "High destination fan-out", reasons[len(reasons)-1]); ok {
				out = append(out, a)
			}
		}
		if len(ports) >= e.cfg.PortScanPorts {
			score += 25
			reasons = append(reasons, fmt.Sprintf("process contacted %d remote endpoint/port pairs in 60s", len(ports)))
			if a, ok := e.alert(now, "port-scan", f, 70, "high", "Possible network scan", reasons[len(reasons)-1]); ok {
				out = append(out, a)
			}
		}
		if burst >= e.cfg.BurstConnections {
			score += 15
			reasons = append(reasons, fmt.Sprintf("%d new connections in 10s", burst))
			if a, ok := e.alert(now, "connection-burst", f, 55, "medium", "Connection burst", reasons[len(reasons)-1]); ok {
				out = append(out, a)
			}
		}
		bk := proc + "|" + f.Remote.IP + fmt.Sprintf(":%d", f.Remote.Port)
		hist := append(e.beacons[bk], now)
		if len(hist) > 12 {
			hist = hist[len(hist)-12:]
		}
		e.beacons[bk] = hist
		if len(hist) >= e.cfg.BeaconMinSamples {
			mean, cv := intervalStats(hist)
			if mean >= 2 && mean <= 3600 && cv <= e.cfg.BeaconMaxJitter {
				score += 30
				reasons = append(reasons, fmt.Sprintf("periodic connection interval %.1fs with %.1f%% jitter", mean, cv*100))
				if a, ok := e.alert(now, "beacon", f, 80, "high", "Possible beaconing", reasons[len(reasons)-1]); ok {
					a.Evidence = map[string]any{"mean_interval_seconds": mean, "coefficient_of_variation": cv, "samples": len(hist)}
					out = append(out, a)
				}
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score, reasons, out
}
func procKey(f model.Flow) string {
	if f.Process != nil {
		if f.Process.Exe != "" {
			return fmt.Sprintf("%d:%s", f.Process.PID, f.Process.Exe)
		}
		return fmt.Sprintf("pid:%d", f.Process.PID)
	}
	return "unattributed:" + f.Local.IP
}
func (e *Engine) alert(t time.Time, rule string, f model.Flow, score int, sev, title, desc string) (model.Alert, bool) {
	dk := rule + "|" + f.ID
	if last, ok := e.seen[dk]; ok && t.Sub(last) < 2*time.Minute {
		return model.Alert{}, false
	}
	e.seen[dk] = t
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", dk, t.UnixNano())))
	a := model.Alert{ID: hex.EncodeToString(h[:8]), Time: t, Severity: sev, Score: score, Rule: rule, Title: title, Description: desc, FlowID: f.ID, Remote: fmt.Sprintf("%s:%d", f.Remote.IP, f.Remote.Port)}
	if f.Process != nil {
		a.PID = f.Process.PID
		a.Process = f.Process.Comm
	}
	e.alerts = append(e.alerts, a)
	if len(e.alerts) > 5000 {
		e.alerts = e.alerts[len(e.alerts)-5000:]
	}
	return a, true
}
func (e *Engine) Alerts(limit int) []model.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]model.Alert(nil), e.alerts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func (e *Engine) Counts() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := 0
	for _, a := range e.alerts {
		if a.Severity == "critical" {
			c++
		}
	}
	return len(e.alerts), c
}
func intervalStats(ts []time.Time) (float64, float64) {
	if len(ts) < 2 {
		return 0, 1
	}
	xs := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		xs = append(xs, ts[i].Sub(ts[i-1]).Seconds())
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	m := sum / float64(len(xs))
	if m == 0 {
		return 0, 1
	}
	var ss float64
	for _, x := range xs {
		d := x - m
		ss += d * d
	}
	sd := math.Sqrt(ss / float64(len(xs)))
	return m, sd / m
}
func domainEntropy(s string) float64 {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	n := 0
	for _, r := range s {
		if r == '.' || r == '-' {
			continue
		}
		freq[r]++
		n++
	}
	if n == 0 {
		return 0
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
