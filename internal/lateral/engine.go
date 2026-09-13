package lateral

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type Config struct {
	Window           time.Duration
	HostThreshold    int
	ServiceThreshold int
}
type event struct {
	t                      time.Time
	actor, service, remote string
	pid                    int
	flow                   string
	ntlm                   bool
}
type Engine struct {
	mu     sync.Mutex
	cfg    Config
	events []event
}

func New(c Config) *Engine {
	if c.Window <= 0 {
		c.Window = 2 * time.Minute
	}
	if c.HostThreshold < 3 {
		c.HostThreshold = 5
	}
	if c.ServiceThreshold < 2 {
		c.ServiceThreshold = 3
	}
	return &Engine{cfg: c}
}
func actor(f model.Flow) string {
	if f.Process == nil {
		return ""
	}
	if f.Process.User != "" {
		return "user:" + f.Process.User
	}
	if f.Process.UID > 0 {
		return fmt.Sprintf("uid:%d", f.Process.UID)
	}
	if f.Process.Exe != "" {
		return "exe:" + f.Process.Exe
	}
	return "proc:" + f.Process.Comm
}
func service(f model.Flow) string {
	x := strings.ToLower(f.DPI.Application + " " + f.DPI.Protocol)
	switch {
	case strings.Contains(x, "smb"):
		return "SMB"
	case strings.Contains(x, "rdp"):
		return "RDP"
	case strings.Contains(x, "ssh"):
		return "SSH"
	case strings.Contains(x, "winrm"):
		return "WinRM"
	case strings.Contains(x, "kerberos"):
		return "Kerberos"
	case strings.Contains(x, "ldap"):
		return "LDAP"
	}
	switch f.Remote.Port {
	case 445:
		return "SMB"
	case 3389:
		return "RDP"
	case 22:
		return "SSH"
	case 5985, 5986:
		return "WinRM"
	case 88:
		return "Kerberos"
	case 389, 636:
		return "LDAP"
	}
	return ""
}
func (e *Engine) Observe(p *decode.Packet, f model.Flow, created bool) []model.SecurityFinding {
	if !created || f.Direction != model.DirectionOutbound {
		return nil
	}
	svc := service(f)
	if svc == "" {
		return nil
	}
	a := actor(f)
	if a == "" {
		return nil
	}
	ntlm := p != nil && strings.Contains(string(p.Payload), "NTLMSSP\x00")
	now := f.FirstSeen
	e.mu.Lock()
	defer e.mu.Unlock()
	cut := now.Add(-e.cfg.Window)
	j := 0
	for _, x := range e.events {
		if x.t.After(cut) {
			e.events[j] = x
			j++
		}
	}
	e.events = e.events[:j]
	e.events = append(e.events, event{t: now, actor: a, service: svc, remote: f.Remote.IP, pid: f.Process.PID, flow: f.ID, ntlm: ntlm})
	hosts := map[string]bool{}
	services := map[string]bool{}
	ntlmHosts := map[string]bool{}
	for _, x := range e.events {
		if x.actor != a {
			continue
		}
		hosts[x.remote] = true
		services[x.service] = true
		if x.ntlm {
			ntlmHosts[x.remote] = true
		}
	}
	var out []model.SecurityFinding
	if len(hosts) >= e.cfg.HostThreshold {
		out = append(out, e.finding(f, "NP-LAT-1001", "Lateral-movement service fan-out", "The same identity/process reached multiple hosts using remote administration/authentication services.", 85, []string{"T1021"}, map[string]any{"actor": a, "distinct_hosts": len(hosts), "services": keys(services), "window_seconds": int(e.cfg.Window.Seconds())}))
	}
	if len(ntlmHosts) >= e.cfg.HostThreshold {
		out = append(out, e.finding(f, "NP-CRED-1001", "NTLM authentication fan-out", "NTLM authentication material was observed across multiple remote hosts in a short window.", 88, []string{"T1110.003", "T1021.002"}, map[string]any{"actor": a, "ntlm_hosts": len(ntlmHosts), "window_seconds": int(e.cfg.Window.Seconds())}))
	}
	return out
}
func keys(m map[string]bool) []string {
	a := make([]string, 0, len(m))
	for x := range m {
		a = append(a, x)
	}
	return a
}
func (e *Engine) finding(f model.Flow, id, title, desc string, conf int, mitre []string, ev map[string]any) model.SecurityFinding {
	h := sha256.Sum256([]byte(id + "|" + actor(f) + "|" + f.Remote.IP + "|" + f.FirstSeen.Truncate(time.Minute).String()))
	x := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: f.FirstSeen, Severity: "high", Confidence: conf, Verdict: "behavioral", RuleID: id, Title: title, Description: desc, Category: "lateral-movement", Tactic: "Lateral Movement", MITRE: mitre, FlowID: f.ID, Direction: f.Direction, Source: f.Local, Destination: f.Remote, Protocol: f.NetworkProtocol, Application: f.DPI.Application, Evidence: ev}
	if f.Process != nil {
		x.PID = f.Process.PID
		x.Process = f.Process.Comm
	}
	return x
}
