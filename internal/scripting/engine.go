package scripting

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/model"
)

type Condition struct{ Field, Op, Value string }
type Rule struct {
	ID, Title, Severity string
	Confidence          int
	MITRE               []string
	Conditions          []Condition
	Enabled             bool
}
type Context struct {
	Flow    model.Flow
	Packet  *model.PacketSummary
	Finding *model.SecurityFinding
	File    *model.FileArtifact
}
type Engine struct {
	mu         sync.RWMutex
	rules      []Rule
	seq        atomic.Uint64
	loadErrors []string
}

func New() *Engine { return &Engine{} }
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}
func (e *Engine) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rules, err := Parse(string(b))
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.rules = rules
	e.loadErrors = nil
	e.mu.Unlock()
	return nil
}

// Parse implements the NetProbe Detection Language (NPDL). The grammar is
// intentionally non-Turing-complete: no loops, imports, filesystem or network.
//
// rule suspicious_python_tls
// title Suspicious Python TLS
// severity high
// confidence 85
// mitre T1071.001,T1059.006
// when process ~ python AND app ~ TLS AND direction = outbound
// end
func Parse(src string) ([]Rule, error) {
	sc := bufio.NewScanner(strings.NewReader(src))
	line := 0
	var cur *Rule
	var out []Rule
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.Fields(raw)
		if len(parts) == 0 {
			continue
		}
		key := strings.ToLower(parts[0])
		switch key {
		case "rule":
			if cur != nil {
				return nil, fmt.Errorf("line %d: nested rule", line)
			}
			if len(parts) != 2 {
				return nil, fmt.Errorf("line %d: rule id required", line)
			}
			cur = &Rule{ID: parts[1], Severity: "medium", Confidence: 70, Enabled: true}
		case "end":
			if cur == nil {
				return nil, fmt.Errorf("line %d: end without rule", line)
			}
			if cur.Title == "" {
				cur.Title = cur.ID
			}
			if len(cur.Conditions) == 0 {
				return nil, fmt.Errorf("line %d: rule %s has no conditions", line, cur.ID)
			}
			out = append(out, *cur)
			cur = nil
		default:
			if cur == nil {
				return nil, fmt.Errorf("line %d: directive outside rule", line)
			}
			val := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]))
			switch key {
			case "title":
				cur.Title = val
			case "severity":
				cur.Severity = strings.ToLower(val)
			case "confidence":
				n, e := strconv.Atoi(val)
				if e != nil || n < 1 || n > 100 {
					return nil, fmt.Errorf("line %d: invalid confidence", line)
				}
				cur.Confidence = n
			case "mitre":
				for _, x := range strings.Split(val, ",") {
					x = strings.TrimSpace(x)
					if x != "" {
						cur.MITRE = append(cur.MITRE, x)
					}
				}
			case "enabled":
				cur.Enabled = !strings.EqualFold(val, "false")
			case "when":
				cs, e := parseConditions(val)
				if e != nil {
					return nil, fmt.Errorf("line %d: %w", line, e)
				}
				cur.Conditions = cs
			default:
				return nil, fmt.Errorf("line %d: unknown directive %s", line, key)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur != nil {
		return nil, fmt.Errorf("unterminated rule %s", cur.ID)
	}
	return out, nil
}

var condRE = regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*(=|!=|~|>=|<=|>|<)\s*(.+)$`)

func parseConditions(s string) ([]Condition, error) {
	chunks := regexp.MustCompile(`(?i)\s+AND\s+`).Split(s, -1)
	var out []Condition
	for _, ch := range chunks {
		m := condRE.FindStringSubmatch(strings.TrimSpace(ch))
		if len(m) != 4 {
			return nil, fmt.Errorf("invalid condition %q", ch)
		}
		v := strings.Trim(strings.TrimSpace(m[3]), `"'`)
		out = append(out, Condition{Field: strings.ToLower(m[1]), Op: m[2], Value: v})
	}
	return out, nil
}
func (e *Engine) Evaluate(c Context) []model.SecurityFinding {
	e.mu.RLock()
	rules := append([]Rule(nil), e.rules...)
	e.mu.RUnlock()
	var out []model.SecurityFinding
	for _, r := range rules {
		if !r.Enabled || !matches(r, c) {
			continue
		}
		f := findingFromContext(r, c, e.seq.Add(1))
		out = append(out, f)
	}
	return out
}
func findingFromContext(r Rule, c Context, n uint64) model.SecurityFinding {
	f := model.SecurityFinding{ID: fmt.Sprintf("script-%d-%d", time.Now().UnixNano(), n), Time: time.Now().UTC(), Severity: r.Severity, Confidence: r.Confidence, Verdict: "script_match", RuleID: "NPDL-" + r.ID, Title: r.Title, Description: "Matched NetProbe Detection Language rule", Category: "script", MITRE: append([]string(nil), r.MITRE...), Evidence: map[string]any{"script_rule": r.ID}}
	if c.Packet != nil {
		f.Time = c.Packet.Time
		f.FlowID = c.Packet.FlowID
		f.PacketID = c.Packet.ID
		f.Interface = c.Packet.Interface
		f.Direction = c.Packet.Direction
		f.Source = c.Packet.Source
		f.Destination = c.Packet.Destination
		f.Protocol = c.Packet.NetworkProtocol
		if c.Packet.Process != nil {
			f.PID = c.Packet.Process.PID
			f.Process = c.Packet.Process.Comm
		}
		f.Application = c.Packet.DPI.Application
	}
	if c.Flow.ID != "" {
		f.Time = c.Flow.LastSeen
		f.FlowID = c.Flow.ID
		f.Direction = c.Flow.Direction
		f.Destination = c.Flow.Remote
		f.Protocol = c.Flow.NetworkProtocol
		f.Application = c.Flow.DPI.Application
		if c.Flow.Process != nil {
			f.PID = c.Flow.Process.PID
			f.Process = c.Flow.Process.Comm
		}
	}
	if c.File != nil {
		f.FlowID = c.File.FlowID
		f.Source = c.File.Source
		f.Destination = c.File.Destination
		if c.File.Process != nil {
			f.PID = c.File.Process.PID
			f.Process = c.File.Process.Comm
		}
		f.Evidence["file_sha256"] = c.File.SHA256
		f.Evidence["file_name"] = c.File.Name
	}
	return f
}
func matches(r Rule, c Context) bool {
	for _, x := range r.Conditions {
		if !match(x, field(x.Field, c)) {
			return false
		}
	}
	return true
}
func field(k string, c Context) string {
	f := c.Flow
	switch k {
	case "process":
		if c.File != nil && c.File.Process != nil {
			return c.File.Process.Comm
		}
		if f.Process != nil {
			return f.Process.Comm
		}
		if c.Packet != nil && c.Packet.Process != nil {
			return c.Packet.Process.Comm
		}
	case "exe":
		if f.Process != nil {
			return f.Process.Exe
		}
		if c.Packet != nil && c.Packet.Process != nil {
			return c.Packet.Process.Exe
		}
	case "app", "application":
		if c.Packet != nil {
			return c.Packet.DPI.Application
		}
		return f.DPI.Application
	case "protocol":
		if c.Packet != nil {
			return c.Packet.NetworkProtocol
		}
		return f.NetworkProtocol
	case "direction":
		if c.Packet != nil {
			return string(c.Packet.Direction)
		}
		return string(f.Direction)
	case "src_ip":
		if c.Packet != nil {
			return c.Packet.Source.IP
		}
		return f.Local.IP
	case "dst_ip", "remote_ip":
		if c.Packet != nil {
			return c.Packet.Destination.IP
		}
		return f.Remote.IP
	case "port", "dst_port":
		if c.Packet != nil {
			return strconv.Itoa(int(c.Packet.Destination.Port))
		}
		return strconv.Itoa(int(f.Remote.Port))
	case "sni":
		if c.Packet != nil && c.Packet.DPI.TLS != nil {
			return c.Packet.DPI.TLS.SNI
		}
		if f.DPI.TLS != nil {
			return f.DPI.TLS.SNI
		}
	case "ja4":
		if c.Packet != nil && c.Packet.DPI.TLS != nil {
			return c.Packet.DPI.TLS.JA4
		}
		if f.DPI.TLS != nil {
			return f.DPI.TLS.JA4
		}
	case "http_host":
		if c.Packet != nil && c.Packet.DPI.HTTP != nil {
			return c.Packet.DPI.HTTP.Host
		}
		if f.DPI.HTTP != nil {
			return f.DPI.HTTP.Host
		}
	case "risk":
		return strconv.Itoa(f.Risk)
	case "file_sha256":
		if c.File != nil {
			return c.File.SHA256
		}
	case "file_name":
		if c.File != nil {
			return c.File.Name
		}
	case "yara":
		if c.File != nil {
			var a []string
			for _, m := range c.File.Yara {
				a = append(a, m.Rule)
			}
			return strings.Join(a, ",")
		}
	case "finding_rule":
		if c.Finding != nil {
			return c.Finding.RuleID
		}
	}
	return ""
}
func match(c Condition, v string) bool {
	switch c.Op {
	case "=":
		return strings.EqualFold(v, c.Value)
	case "!=":
		return !strings.EqualFold(v, c.Value)
	case "~":
		return strings.Contains(strings.ToLower(v), strings.ToLower(c.Value))
	case ">", ">=", "<", "<=":
		a, e1 := strconv.ParseFloat(v, 64)
		b, e2 := strconv.ParseFloat(c.Value, 64)
		if e1 != nil || e2 != nil {
			return false
		}
		switch c.Op {
		case ">":
			return a > b
		case ">=":
			return a >= b
		case "<":
			return a < b
		case "<=":
			return a <= b
		}
	}
	return false
}
