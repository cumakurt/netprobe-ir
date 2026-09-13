package identitybaseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Profile struct {
	Kind         string         `json:"kind"`
	Identity     string         `json:"identity"`
	Total        int            `json:"total"`
	Destinations map[string]int `json:"destinations"`
	Applications map[string]int `json:"applications"`
	Hours        [24]int        `json:"hours"`
	LastSeen     time.Time      `json:"last_seen"`
}
type Engine struct {
	mu       sync.Mutex
	path     string
	min      int
	profiles map[string]*Profile
	dirty    int
}

func New(path string, min int) *Engine {
	if min < 5 {
		min = 20
	}
	e := &Engine{path: path, min: min, profiles: map[string]*Profile{}}
	e.load()
	return e
}
func identities(p *model.ProcessInfo) map[string]string {
	m := map[string]string{}
	if p == nil {
		return m
	}
	if x := strings.TrimSpace(p.Exe); x != "" {
		m["process"] = x
	} else if p.Comm != "" {
		m["process"] = p.Comm
	}
	if p.User != "" {
		m["user"] = p.User
	} else if p.UID > 0 {
		m["user"] = fmt.Sprintf("uid:%d", p.UID)
	}
	if p.ContainerID != "" {
		m["container"] = p.ContainerID
	}
	if p.KubernetesPod != "" {
		m["pod"] = p.KubernetesNamespace + "/" + p.KubernetesPod
	}
	if p.Cgroup != "" {
		m["service"] = p.Cgroup
	}
	return m
}
func app(f model.Flow) string {
	x := f.DPI.Application
	if x == "" {
		x = f.DPI.Protocol
	}
	if x == "" {
		x = f.NetworkProtocol
	}
	return x
}
func (e *Engine) Observe(f model.Flow, created bool) []model.SecurityFinding {
	if !created || f.Process == nil {
		return nil
	}
	ids := identities(f.Process)
	if len(ids) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []model.SecurityFinding
	for kind, id := range ids {
		k := kind + ":" + id
		p := e.profiles[k]
		if p == nil {
			p = &Profile{Kind: kind, Identity: id, Destinations: map[string]int{}, Applications: map[string]int{}}
			e.profiles[k] = p
		}
		dest := f.Remote.IP
		ap := app(f)
		hour := f.FirstSeen.Hour()
		if p.Total >= e.min {
			if dest != "" && p.Destinations[dest] == 0 {
				out = append(out, e.finding(f, p, "NP-IDBL-DEST", "New destination for "+kind, 72, map[string]any{"identity_kind": kind, "identity": id, "new_destination": dest, "observations": p.Total}))
			}
			if ap != "" && p.Applications[ap] == 0 {
				out = append(out, e.finding(f, p, "NP-IDBL-APP", "New application for "+kind, 75, map[string]any{"identity_kind": kind, "identity": id, "new_application": ap, "observations": p.Total}))
			}
			if p.Total >= e.min*2 && p.Hours[hour] == 0 {
				out = append(out, e.finding(f, p, "NP-IDBL-HOUR", "Unusual network hour for "+kind, 62, map[string]any{"identity_kind": kind, "identity": id, "hour": hour, "observations": p.Total}))
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
	}
	if e.dirty >= 50 {
		_ = e.saveLocked()
		e.dirty = 0
	}
	return out
}
func (e *Engine) finding(f model.Flow, p *Profile, id, title string, conf int, ev map[string]any) model.SecurityFinding {
	h := sha256.Sum256([]byte(id + "|" + p.Kind + "|" + p.Identity + "|" + f.ID + "|" + f.LastSeen.String()))
	x := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: f.LastSeen, Severity: "medium", Confidence: conf, Verdict: "behavioral", RuleID: id + "-" + strings.ToUpper(p.Kind), Title: title, Description: "Identity-specific network behavior deviated from its mature baseline.", Category: "identity-baseline", FlowID: f.ID, Direction: f.Direction, Source: f.Local, Destination: f.Remote, Protocol: f.NetworkProtocol, Application: f.DPI.Application, Evidence: ev}
	if f.Process != nil {
		x.PID = f.Process.PID
		x.Process = f.Process.Comm
	}
	return x
}
func (e *Engine) Profiles() []Profile {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Profile, 0, len(e.profiles))
	for _, p := range e.profiles {
		cp := *p
		out = append(out, cp)
	}
	return out
}
func (e *Engine) Flush() error { e.mu.Lock(); defer e.mu.Unlock(); return e.saveLocked() }
func (e *Engine) load() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var x map[string]*Profile
	if json.Unmarshal(b, &x) == nil && x != nil {
		e.profiles = x
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
	b, err := json.MarshalIndent(e.profiles, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}
