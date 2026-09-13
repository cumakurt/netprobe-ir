package response

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Enabled        bool
	DryRun         bool
	AllowedActions []string
	Allowlist      []string
	MaxTTLSeconds  int
}
type Request struct {
	Action     string `json:"action"`
	IP         string `json:"ip,omitempty"`
	PID        int    `json:"pid,omitempty"`
	Interface  string `json:"interface,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Confirm    string `json:"confirm,omitempty"`
	Reason     string `json:"reason,omitempty"`
}
type Result struct {
	OK         bool       `json:"ok"`
	DryRun     bool       `json:"dry_run"`
	Action     string     `json:"action"`
	Command    []string   `json:"command,omitempty"`
	Message    string     `json:"message"`
	RollbackAt *time.Time `json:"rollback_at,omitempty"`
}
type Runner interface {
	Run(context.Context, string, ...string) error
}
type execRunner struct{}

func (execRunner) Run(ctx context.Context, n string, a ...string) error {
	return exec.CommandContext(ctx, n, a...).Run()
}

type Manager struct {
	cfg     Config
	allowed map[string]bool
	nets    []*net.IPNet
	ips     map[string]bool
	runner  Runner
	mu      sync.Mutex
	timers  map[string]*time.Timer
}

func New(c Config) *Manager {
	if c.MaxTTLSeconds <= 0 {
		c.MaxTTLSeconds = 3600
	}
	m := &Manager{cfg: c, allowed: map[string]bool{}, ips: map[string]bool{}, runner: execRunner{}, timers: map[string]*time.Timer{}}
	for _, a := range c.AllowedActions {
		m.allowed[strings.ToLower(strings.TrimSpace(a))] = true
	}
	for _, x := range c.Allowlist {
		x = strings.TrimSpace(x)
		if ip := net.ParseIP(x); ip != nil {
			m.ips[ip.String()] = true
		} else if _, n, e := net.ParseCIDR(x); e == nil {
			m.nets = append(m.nets, n)
		}
	}
	return m
}
func (m *Manager) SetRunner(r Runner) {
	if r != nil {
		m.runner = r
	}
}
func (m *Manager) Execute(ctx context.Context, r Request) (Result, error) {
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	res := Result{Action: r.Action, DryRun: m.cfg.DryRun}
	if !m.cfg.Enabled {
		return res, fmt.Errorf("active response is disabled")
	}
	if !m.allowed[r.Action] {
		return res, fmt.Errorf("response action %q is not allowed", r.Action)
	}
	if !m.cfg.DryRun && r.Confirm != "APPLY" {
		return res, fmt.Errorf("confirm must be APPLY for live response")
	}
	var name string
	var args []string
	var rollback func() error
	switch r.Action {
	case "block_ip":
		ip, err := m.validTargetIP(r.IP)
		if err != nil {
			return res, err
		}
		name = "nft"
		args = []string{"add", "element", "inet", "netprobe_ir", "blocked_ips", "{", ip, "}"}
		rollback = func() error {
			return m.runner.Run(context.Background(), "nft", "delete", "element", "inet", "netprobe_ir", "blocked_ips", "{", ip, "}")
		}
	case "unblock_ip":
		ip, err := m.validTargetIP(r.IP)
		if err != nil {
			return res, err
		}
		name = "nft"
		args = []string{"delete", "element", "inet", "netprobe_ir", "blocked_ips", "{", ip, "}"}
	case "kill_process":
		if r.PID <= 1 {
			return res, fmt.Errorf("refusing PID <= 1")
		}
		if r.PID == syscall.Getpid() {
			return res, fmt.Errorf("refusing to terminate NetProbe itself")
		}
		name = "kill"
		args = []string{"-TERM", strconv.Itoa(r.PID)}
	case "disable_interface", "enable_interface":
		if !validIface(r.Interface) {
			return res, fmt.Errorf("invalid interface")
		}
		state := "down"
		if r.Action == "enable_interface" {
			state = "up"
		}
		name = "ip"
		args = []string{"link", "set", "dev", r.Interface, state}
	default:
		return res, fmt.Errorf("unsupported action")
	}
	res.Command = append([]string{name}, args...)
	if m.cfg.DryRun {
		res.OK = true
		res.Message = "dry-run: no system change was made"
		return res, nil
	}
	if r.Action == "block_ip" {
		_ = m.ensureNFT(ctx)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := m.runner.Run(cctx, name, args...); err != nil {
		return res, err
	}
	res.OK = true
	res.Message = "response applied"
	if rollback != nil && r.TTLSeconds > 0 {
		ttl := r.TTLSeconds
		if ttl > m.cfg.MaxTTLSeconds {
			ttl = m.cfg.MaxTTLSeconds
		}
		at := time.Now().Add(time.Duration(ttl) * time.Second)
		res.RollbackAt = &at
		m.mu.Lock()
		key := r.Action + "|" + r.IP
		if old := m.timers[key]; old != nil {
			old.Stop()
		}
		m.timers[key] = time.AfterFunc(time.Duration(ttl)*time.Second, func() { _ = rollback(); m.mu.Lock(); delete(m.timers, key); m.mu.Unlock() })
		m.mu.Unlock()
	}
	return res, nil
}
func (m *Manager) ensureNFT(ctx context.Context) error {
	_ = m.runner.Run(ctx, "nft", "add", "table", "inet", "netprobe_ir")
	_ = m.runner.Run(ctx, "nft", "add", "set", "inet", "netprobe_ir", "blocked_ips", "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}")
	_ = m.runner.Run(ctx, "nft", "add", "chain", "inet", "netprobe_ir", "output", "{", "type", "filter", "hook", "output", "priority", "-10", ";", "}")
	_ = m.runner.Run(ctx, "nft", "add", "chain", "inet", "netprobe_ir", "input", "{", "type", "filter", "hook", "input", "priority", "-10", ";", "}")
	_ = m.runner.Run(ctx, "nft", "add", "rule", "inet", "netprobe_ir", "output", "ip", "daddr", "@blocked_ips", "drop")
	_ = m.runner.Run(ctx, "nft", "add", "rule", "inet", "netprobe_ir", "input", "ip", "saddr", "@blocked_ips", "drop")
	return nil
}
func (m *Manager) validTargetIP(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", fmt.Errorf("refusing loopback/unspecified/multicast target")
	}
	canon := ip.String()
	if m.ips[canon] {
		return "", fmt.Errorf("target is response-allowlisted")
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return "", fmt.Errorf("target is response-allowlisted")
		}
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("block_ip currently supports IPv4 only")
	}
	return canon, nil
}
func validIface(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r)) {
			return false
		}
	}
	return true
}
