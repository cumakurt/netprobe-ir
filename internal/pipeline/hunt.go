package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"netprobe-ir/internal/model"
)

// HuntResult is a server-side cross-telemetry search result. The browser uses
// the same query language for live focus, while this API searches all telemetry
// still retained by the daemon rather than only the browser's current window.
type HuntResult struct {
	Query     string                  `json:"query"`
	Flows     []model.Flow            `json:"flows"`
	Packets   []model.PacketSummary   `json:"packets"`
	Processes []ProcessSummary        `json:"processes"`
	Alerts    []model.Alert           `json:"alerts"`
	Findings  []model.SecurityFinding `json:"findings"`
	Counts    map[string]int          `json:"counts"`
}

type huntToken struct {
	key   string
	value string
}

// Hunt executes a deterministic AND query over the daemon's retained evidence.
// Supported fields intentionally mirror the web console: src, dst, ip, sport,
// dport, port, proto, app, process, pid, iface, dir, severity, verdict, rule,
// mitre and free-text terms. Values may be quoted.
func (e *Engine) Hunt(query string, limit int) HuntResult {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	tokens := parseHunt(query)
	out := HuntResult{Query: strings.TrimSpace(query), Counts: map[string]int{}}

	for _, f := range e.VisibleFlows(0) {
		if huntMatch(flowContext(f), tokens) {
			out.Counts["flows"]++
			if len(out.Flows) < limit {
				out.Flows = append(out.Flows, f)
			}
		}
	}
	for _, p := range e.VisiblePackets(0) {
		if huntMatch(packetContext(p), tokens) {
			out.Counts["packets"]++
			if len(out.Packets) < limit {
				out.Packets = append(out.Packets, p)
			}
		}
	}
	for _, p := range e.Processes() {
		if huntMatch(processContext(p), tokens) {
			out.Counts["processes"]++
			if len(out.Processes) < limit {
				out.Processes = append(out.Processes, p)
			}
		}
	}
	for _, a := range e.Alerts(5000) {
		if huntMatch(alertContext(a), tokens) {
			out.Counts["alerts"]++
			if len(out.Alerts) < limit {
				out.Alerts = append(out.Alerts, a)
			}
		}
	}
	for _, f := range e.Findings(5000) {
		if huntMatch(findingContext(f), tokens) {
			out.Counts["findings"]++
			if len(out.Findings) < limit {
				out.Findings = append(out.Findings, f)
			}
		}
	}
	return out
}

func parseHunt(q string) []huntToken {
	var out []huntToken
	var b strings.Builder
	quoted := false
	flush := func() {
		s := strings.TrimSpace(b.String())
		b.Reset()
		if s == "" {
			return
		}
		key, value := "text", s
		if i := strings.IndexByte(s, ':'); i > 0 {
			k := strings.ToLower(strings.TrimSpace(s[:i]))
			v := strings.TrimSpace(s[i+1:])
			if knownHuntField(k) && v != "" {
				key, value = k, v
			}
		}
		out = append(out, huntToken{key: key, value: strings.ToLower(value)})
	}
	for _, r := range q {
		switch {
		case r == '"':
			quoted = !quoted
		case unicode.IsSpace(r) && !quoted:
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

func knownHuntField(k string) bool {
	switch k {
	case "src", "dst", "ip", "sport", "dport", "port", "proto", "protocol", "app", "application", "process", "pid", "iface", "interface", "dir", "direction", "severity", "verdict", "rule", "mitre", "category":
		return true
	default:
		return false
	}
}

func huntMatch(ctx map[string]string, toks []huntToken) bool {
	for _, t := range toks {
		key := t.key
		switch key {
		case "protocol":
			key = "proto"
		case "application":
			key = "app"
		case "interface":
			key = "iface"
		case "direction":
			key = "dir"
		}
		v, ok := ctx[key]
		if !ok {
			v = ctx["text"]
		}
		if !strings.Contains(strings.ToLower(v), t.value) {
			return false
		}
	}
	return true
}

func contextText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func flowContext(f model.Flow) map[string]string {
	src, dst := f.Local, f.Remote
	if f.Direction == model.DirectionInbound {
		src, dst = f.Remote, f.Local
	}
	proc, pid := "", ""
	if f.Process != nil {
		proc = f.Process.Comm + " " + f.Process.Exe
		pid = fmt.Sprint(f.Process.PID)
	}
	return map[string]string{
		"src": src.IP, "dst": dst.IP, "ip": src.IP + " " + dst.IP,
		"sport": fmt.Sprint(src.Port), "dport": fmt.Sprint(dst.Port), "port": fmt.Sprintf("%d %d", src.Port, dst.Port),
		"proto": f.NetworkProtocol + " " + f.DPI.Protocol, "app": f.DPI.Application,
		"process": proc, "pid": pid, "iface": strings.Join(f.Interfaces, " "), "dir": string(f.Direction),
		"text": contextText(f),
	}
}

func packetContext(p model.PacketSummary) map[string]string {
	proc, pid := "", ""
	if p.Process != nil {
		proc = p.Process.Comm + " " + p.Process.Exe
		pid = fmt.Sprint(p.Process.PID)
	}
	return map[string]string{
		"src": p.Source.IP, "dst": p.Destination.IP, "ip": p.Source.IP + " " + p.Destination.IP,
		"sport": fmt.Sprint(p.Source.Port), "dport": fmt.Sprint(p.Destination.Port), "port": fmt.Sprintf("%d %d", p.Source.Port, p.Destination.Port),
		"proto": p.NetworkProtocol + " " + p.DPI.Protocol, "app": p.DPI.Application,
		"process": proc, "pid": pid, "iface": p.Interface, "dir": string(p.Direction), "text": contextText(p),
	}
}

func processContext(p ProcessSummary) map[string]string {
	return map[string]string{"process": p.Name + " " + p.Exe, "pid": fmt.Sprint(p.PID), "text": contextText(p)}
}

func alertContext(a model.Alert) map[string]string {
	return map[string]string{"dst": a.Remote, "ip": a.Remote, "process": a.Process, "pid": fmt.Sprint(a.PID), "severity": a.Severity, "verdict": "behavioral", "rule": a.Rule, "text": contextText(a)}
}

func findingContext(f model.SecurityFinding) map[string]string {
	return map[string]string{
		"src": f.Source.IP, "dst": f.Destination.IP, "ip": f.Source.IP + " " + f.Destination.IP,
		"sport": fmt.Sprint(f.Source.Port), "dport": fmt.Sprint(f.Destination.Port), "port": fmt.Sprintf("%d %d", f.Source.Port, f.Destination.Port),
		"proto": f.Protocol, "app": f.Application, "process": f.Process, "pid": fmt.Sprint(f.PID), "iface": f.Interface,
		"dir": string(f.Direction), "severity": f.Severity, "verdict": f.Verdict, "rule": f.RuleID,
		"mitre": strings.Join(f.MITRE, " "), "category": f.Category, "text": contextText(f),
	}
}
