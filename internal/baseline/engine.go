package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type profile struct {
	Total        int            `json:"total"`
	Destinations map[string]int `json:"destinations"`
	Applications map[string]int `json:"applications"`
	Hours        [24]int        `json:"hours"`
	LastSeen     time.Time      `json:"last_seen"`
}
type diskState struct {
	Profiles map[string]*profile `json:"profiles"`
}

type Engine struct {
	mu       sync.Mutex
	path     string
	min      int
	profiles map[string]*profile
	dirty    int
}

func New(path string, min int) *Engine {
	if min < 5 {
		min = 20
	}
	e := &Engine{path: path, min: min, profiles: map[string]*profile{}}
	e.load()
	return e
}
func procKey(f model.Flow) string {
	if f.Process == nil {
		return ""
	}
	if f.Process.Exe != "" {
		return f.Process.Exe
	}
	return f.Process.Comm
}
func app(f model.Flow) string {
	a := strings.TrimSpace(f.DPI.Application)
	if a == "" {
		a = strings.TrimSpace(f.DPI.Protocol)
	}
	if a == "" {
		a = f.NetworkProtocol
	}
	return a
}
func (e *Engine) Observe(f model.Flow, created bool) []model.SecurityFinding {
	if !created || f.Process == nil {
		return nil
	}
	k := procKey(f)
	if k == "" {
		return nil
	}
	dest := f.Remote.IP
	ap := app(f)
	hour := f.FirstSeen.Hour()
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.profiles[k]
	if p == nil {
		p = &profile{Destinations: map[string]int{}, Applications: map[string]int{}}
		e.profiles[k] = p
	}
	var out []model.SecurityFinding
	if p.Total >= e.min {
		if dest != "" && p.Destinations[dest] == 0 {
			out = append(out, e.finding(f, "NP-BL-1001", "New destination for established process baseline", "The process contacted a destination not present in its established baseline.", 72, map[string]any{"baseline_observations": p.Total, "new_destination": dest}))
		}
		if ap != "" && p.Applications[ap] == 0 {
			out = append(out, e.finding(f, "NP-BL-1002", "New application protocol for established process baseline", "The process used an application protocol not present in its established baseline.", 75, map[string]any{"baseline_observations": p.Total, "new_application": ap}))
		}
		if p.Hours[hour] == 0 && p.Total >= e.min*2 {
			out = append(out, e.finding(f, "NP-BL-1003", "Unusual process network hour", "The process generated network traffic in an hour not previously observed in its mature baseline.", 60, map[string]any{"baseline_observations": p.Total, "hour": hour}))
		}
	}
	p.Total++
	if dest != "" {
		p.Destinations[dest]++
	}
	if ap != "" {
		p.Applications[ap]++
	}
	p.Hours[hour]++
	p.LastSeen = f.LastSeen
	e.dirty++
	if e.dirty >= 25 {
		_ = e.saveLocked()
		e.dirty = 0
	}
	return out
}
func (e *Engine) finding(f model.Flow, id, title, desc string, confidence int, ev map[string]any) model.SecurityFinding {
	h := sha256.Sum256([]byte(id + "|" + f.ID + "|" + f.LastSeen.String()))
	sf := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: f.LastSeen, Severity: "medium", Confidence: confidence, Verdict: "behavioral", RuleID: id, Title: title, Description: desc, Category: "baseline-deviation", Tactic: "Command and Control", MITRE: []string{"T1071"}, FlowID: f.ID, Direction: f.Direction, Source: f.Local, Destination: f.Remote, Protocol: f.NetworkProtocol, Application: f.DPI.Application, Evidence: ev}
	if f.Process != nil {
		sf.PID = f.Process.PID
		sf.Process = f.Process.Comm
	}
	return sf
}
func (e *Engine) Flush() error { e.mu.Lock(); defer e.mu.Unlock(); return e.saveLocked() }
func (e *Engine) Snapshot() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]any{}
	for k, p := range e.profiles {
		out[k] = map[string]any{"total": p.Total, "destinations": len(p.Destinations), "applications": len(p.Applications), "last_seen": p.LastSeen}
	}
	return out
}
func (e *Engine) load() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var d diskState
	if json.Unmarshal(b, &d) == nil && d.Profiles != nil {
		e.profiles = d.Profiles
		for _, p := range e.profiles {
			if p.Destinations == nil {
				p.Destinations = map[string]int{}
			}
			if p.Applications == nil {
				p.Applications = map[string]int{}
			}
		}
	}
}
func (e *Engine) saveLocked() error {
	if e.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(diskState{Profiles: e.profiles}, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}
