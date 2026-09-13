package wasmplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
)

type Plugin struct {
	Name        string `json:"name"`
	Module      string `json:"module"`
	Enabled     bool   `json:"enabled"`
	TimeoutMS   int    `json:"timeout_ms"`
	MaxOutputKB int    `json:"max_output_kb"`
}
type Result struct {
	Findings   []model.SecurityFinding `json:"findings,omitempty"`
	Enrichment map[string]any          `json:"enrichment,omitempty"`
}
type Status struct {
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Runs      uint64    `json:"runs"`
	Failures  uint64    `json:"failures"`
	Dropped   uint64    `json:"dropped"`
	LastError string    `json:"last_error,omitempty"`
	LastRun   time.Time `json:"last_run,omitempty"`
}
type state struct {
	cfg                     Plugin
	runs, failures, dropped atomic.Uint64
	mu                      sync.RWMutex
	lastErr                 string
	lastRun                 time.Time
}
type Runner struct {
	Binary  string
	mu      sync.RWMutex
	plugins []*state
}

func New(binary string, plugins []Plugin) *Runner {
	if binary == "" {
		binary = "wasmtime"
	}
	r := &Runner{Binary: binary}
	for _, p := range plugins {
		if p.Enabled {
			if p.TimeoutMS <= 0 {
				p.TimeoutMS = 1000
			}
			if p.MaxOutputKB <= 0 {
				p.MaxOutputKB = 256
			}
			r.plugins = append(r.plugins, &state{cfg: p})
		}
	}
	return r
}
func (r *Runner) Available() bool { _, e := exec.LookPath(r.Binary); return e == nil }
func (r *Runner) Process(ev eventbus.Event) []Result {
	r.mu.RLock()
	ps := append([]*state(nil), r.plugins...)
	r.mu.RUnlock()
	var out []Result
	for _, p := range ps {
		x, e := r.run(p, ev)
		if e != nil {
			p.failures.Add(1)
			p.mu.Lock()
			p.lastErr = e.Error()
			p.lastRun = time.Now().UTC()
			p.mu.Unlock()
			continue
		}
		p.runs.Add(1)
		p.mu.Lock()
		p.lastErr = ""
		p.lastRun = time.Now().UTC()
		p.mu.Unlock()
		out = append(out, x)
	}
	return out
}
func (r *Runner) run(p *state, ev eventbus.Event) (Result, error) {
	path, e := exec.LookPath(r.Binary)
	if e != nil {
		return Result{}, e
	}
	if _, e = os.Stat(p.cfg.Module); e != nil {
		return Result{}, e
	}
	b, e := json.Marshal(ev)
	if e != nil {
		return Result{}, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.cfg.TimeoutMS)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "run", p.cfg.Module)
	cmd.Stdin = bytes.NewReader(b)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{W: &stdout, N: int64(p.cfg.MaxOutputKB) << 10}
	cmd.Stderr = &limitedBuffer{W: &stderr, N: 64 << 10}
	e = cmd.Run()
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("plugin timeout")
	}
	if e != nil {
		return Result{}, fmt.Errorf("wasmtime: %w: %s", e, strings.TrimSpace(stderr.String()))
	}
	var v Result
	if e = json.Unmarshal(stdout.Bytes(), &v); e != nil {
		return Result{}, fmt.Errorf("plugin JSON: %w", e)
	}
	return v, nil
}

type limitedBuffer struct {
	W io.Writer
	N int64
	n int64
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	orig := len(p)
	if l.n >= l.N {
		return orig, nil
	}
	remain := l.N - l.n
	if int64(len(p)) > remain {
		p = p[:remain]
	}
	n, e := l.W.Write(p)
	l.n += int64(n)
	if e != nil {
		return 0, e
	}
	return orig, nil
}
func (r *Runner) Status() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Status, 0, len(r.plugins))
	for _, p := range r.plugins {
		p.mu.RLock()
		st := Status{Name: p.cfg.Name, State: "healthy", Runs: p.runs.Load(), Failures: p.failures.Load(), Dropped: p.dropped.Load(), LastError: p.lastErr, LastRun: p.lastRun}
		if p.lastErr != "" {
			st.State = "degraded"
		}
		p.mu.RUnlock()
		out = append(out, st)
	}
	return out
}
