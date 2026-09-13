package beacon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"netprobe-ir/internal/model"
)

type Config struct {
	MinSamples    int
	MaxJitter     float64
	MinSimilarity float64
}
type Group struct {
	Key              string   `json:"key"`
	Process          string   `json:"process"`
	PID              int      `json:"pid"`
	Remote           string   `json:"remote"`
	Port             uint16   `json:"port"`
	Application      string   `json:"application"`
	Samples          int      `json:"samples"`
	MedianInterval   float64  `json:"median_interval_seconds"`
	Jitter           float64  `json:"jitter"`
	SizeSimilarity   float64  `json:"size_similarity"`
	Periodicity      float64  `json:"periodicity"`
	TXRXRatio        float64  `json:"tx_rx_ratio"`
	DestinationCount int      `json:"destination_count"`
	JA4Reuse         float64  `json:"ja4_reuse"`
	Reasons          []string `json:"reasons,omitempty"`
	Score            int      `json:"score"`
}
type Engine struct{ cfg Config }

func New(c Config) *Engine {
	if c.MinSamples < 4 {
		c.MinSamples = 5
	}
	if c.MaxJitter <= 0 {
		c.MaxJitter = .15
	}
	if c.MinSimilarity <= 0 {
		c.MinSimilarity = .8
	}
	return &Engine{cfg: c}
}
func (e *Engine) Analyze(flows []model.Flow) ([]Group, []model.SecurityFinding) {
	buckets := map[string][]model.Flow{}
	type procCtx struct {
		dest  map[string]bool
		ja4   map[string]int
		total int
	}
	procContexts := map[string]*procCtx{}
	for _, f := range flows {
		if f.Process == nil || f.Direction != model.DirectionOutbound || f.Remote.IP == "" {
			continue
		}
		k := fmt.Sprintf("%d|%s|%d|%s", f.Process.PID, f.Remote.IP, f.Remote.Port, f.DPI.Application)
		buckets[k] = append(buckets[k], f)
		pk := fmt.Sprintf("%d|%s", f.Process.PID, f.DPI.Application)
		pc := procContexts[pk]
		if pc == nil {
			pc = &procCtx{dest: map[string]bool{}, ja4: map[string]int{}}
			procContexts[pk] = pc
		}
		pc.dest[f.Remote.IP] = true
		pc.total++
		if f.DPI.TLS != nil && f.DPI.TLS.JA4 != "" {
			pc.ja4[f.DPI.TLS.JA4]++
		}
	}
	var groups []Group
	var findings []model.SecurityFinding
	for k, a := range buckets {
		if len(a) < e.cfg.MinSamples {
			continue
		}
		sort.Slice(a, func(i, j int) bool { return a[i].FirstSeen.Before(a[j].FirstSeen) })
		var ints []float64
		var sizes []float64
		var tx, rx uint64
		for i, f := range a {
			tx += f.BytesTX
			rx += f.BytesRX
			sizes = append(sizes, float64(f.BytesTX+f.BytesRX))
			if i > 0 {
				d := f.FirstSeen.Sub(a[i-1].FirstSeen).Seconds()
				if d > 0 {
					ints = append(ints, d)
				}
			}
		}
		if len(ints) < e.cfg.MinSamples-1 {
			continue
		}
		med := median(ints)
		j := relativeMAD(ints, med)
		sim := sizeSimilarity(sizes)
		period := periodicity(ints, med)
		pk := fmt.Sprintf("%d|%s", a[0].Process.PID, a[0].DPI.Application)
		pc := procContexts[pk]
		destCount, ja4Reuse := 1, 0.0
		if pc != nil {
			destCount = len(pc.dest)
			maxJA4 := 0
			for _, n := range pc.ja4 {
				if n > maxJA4 {
					maxJA4 = n
				}
			}
			if pc.total > 0 {
				ja4Reuse = float64(maxJA4) / float64(pc.total)
			}
		}
		ratio := float64(tx) / math.Max(1, float64(rx))
		base := .45*clamp(1-j/max(e.cfg.MaxJitter, .01), 0, 1) + .22*sim + .20*period + .08*clamp(ja4Reuse, 0, 1) + .05*clamp(float64(destCount-1)/8, 0, 1)
		score := int(math.Round(100 * base))
		var reasons []string
		if j <= e.cfg.MaxJitter {
			reasons = append(reasons, "low timing jitter")
		}
		if sim >= e.cfg.MinSimilarity {
			reasons = append(reasons, "high transfer-size similarity")
		}
		if period >= .75 {
			reasons = append(reasons, "strong periodicity")
		}
		if ja4Reuse >= .8 {
			reasons = append(reasons, "stable JA4 fingerprint reuse")
		}
		if destCount >= 4 {
			reasons = append(reasons, fmt.Sprintf("destination rotation across %d IPs", destCount))
		}
		if ratio >= 4 {
			reasons = append(reasons, "TX-heavy transfer ratio")
		}
		if med < 1 || med > 86400 {
			score -= 20
		}
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		g := Group{Key: k, Process: a[0].Process.Comm, PID: a[0].Process.PID, Remote: a[0].Remote.IP, Port: a[0].Remote.Port, Application: a[0].DPI.Application, Samples: len(a), MedianInterval: round(med), Jitter: round(j), SizeSimilarity: round(sim), Periodicity: round(period), TXRXRatio: round(ratio), DestinationCount: destCount, JA4Reuse: round(ja4Reuse), Reasons: reasons, Score: score}
		groups = append(groups, g)
		if score >= 75 {
			sev := "high"
			if score < 88 {
				sev = "medium"
			}
			findings = append(findings, model.SecurityFinding{ID: beaconID(a[0].Process.PID, a[0].Remote.IP, a[0].Remote.Port, a[len(a)-1].ID), Time: a[len(a)-1].LastSeen, Severity: sev, Confidence: score, Verdict: "behavioral", RuleID: "NP-C2-BEACON-ADV", Title: "C2-like periodic beaconing", Description: "Repeated outbound connections have low timing jitter and similar transfer sizes", Category: "command-and-control", Tactic: "Command and Control", MITRE: []string{"T1071"}, FlowID: a[len(a)-1].ID, Direction: model.DirectionOutbound, Destination: a[0].Remote, Protocol: a[0].NetworkProtocol, Application: a[0].DPI.Application, PID: a[0].Process.PID, Process: a[0].Process.Comm, Evidence: map[string]any{"samples": len(a), "median_interval_seconds": g.MedianInterval, "jitter": g.Jitter, "size_similarity": g.SizeSimilarity, "periodicity": g.Periodicity, "tx_rx_ratio": g.TXRXRatio, "destination_count": g.DestinationCount, "ja4_reuse": g.JA4Reuse, "reasons": g.Reasons, "score": score}})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Score > groups[j].Score })
	return groups, findings
}
func median(a []float64) float64 {
	b := append([]float64(nil), a...)
	sort.Float64s(b)
	n := len(b)
	if n%2 == 1 {
		return b[n/2]
	}
	return (b[n/2-1] + b[n/2]) / 2
}
func relativeMAD(a []float64, m float64) float64 {
	if m == 0 {
		return 1
	}
	d := make([]float64, len(a))
	for i, x := range a {
		d[i] = math.Abs(x - m)
	}
	return median(d) / m
}
func sizeSimilarity(a []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	m := median(a)
	if m <= 0 {
		return 0
	}
	var d float64
	for _, x := range a {
		d += math.Abs(x-m) / m
	}
	return clamp(1-d/float64(len(a)), 0, 1)
}
func periodicity(a []float64, m float64) float64 {
	if len(a) < 2 || m <= 0 {
		return 0
	}
	var good float64
	for _, x := range a {
		if math.Abs(x-m) <= math.Max(1, m*.1) {
			good++
		}
	}
	return good / float64(len(a))
}
func clamp(v, a, b float64) float64 {
	if v < a {
		return a
	}
	if v > b {
		return b
	}
	return v
}
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func round(v float64) float64 { return math.Round(v*1000) / 1000 }
func KeySummary(g Group) string {
	return strings.TrimSpace(fmt.Sprintf("%s → %s:%d %s", g.Process, g.Remote, g.Port, g.Application))
}

func beaconID(pid int, ip string, port uint16, last string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%d|%s", pid, ip, port, last)))
	return "beacon-" + hex.EncodeToString(h[:8])
}
