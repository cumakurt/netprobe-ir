package smartpcap

import (
	"net"
	"strings"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type Rule struct {
	Name        string `json:"name"`
	Action      string `json:"action"`
	Process     string `json:"process,omitempty"`
	Application string `json:"application,omitempty"`
	Interface   string `json:"interface,omitempty"`
	IP          string `json:"ip,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	Direction   string `json:"direction,omitempty"`
}
type Policy struct {
	Mode          string `json:"mode"`
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
}
type Decision struct {
	Action string `json:"action"`
	Rule   string `json:"rule,omitempty"`
}

func (p Policy) Decide(pkt *decode.Packet, f model.Flow) Decision {
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" || mode == "full" {
		return Decision{Action: "full"}
	}
	for _, r := range p.Rules {
		if match(r, pkt, f) {
			a := normalize(r.Action)
			return Decision{Action: a, Rule: r.Name}
		}
	}
	a := normalize(p.DefaultAction)
	if a == "" {
		if mode == "metadata" {
			a = "metadata"
		} else {
			a = "headers"
		}
	}
	return Decision{Action: a}
}
func normalize(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "full", "headers", "metadata", "drop":
		return strings.ToLower(strings.TrimSpace(a))
	}
	return ""
}
func match(r Rule, p *decode.Packet, f model.Flow) bool {
	if r.Process != "" {
		if f.Process == nil || !strings.Contains(strings.ToLower(f.Process.Comm+" "+f.Process.Exe), strings.ToLower(r.Process)) {
			return false
		}
	}
	if r.Application != "" && !strings.Contains(strings.ToLower(f.DPI.Application+" "+f.DPI.Protocol), strings.ToLower(r.Application)) {
		return false
	}
	if r.Interface != "" && !strings.EqualFold(r.Interface, p.Interface) {
		return false
	}
	if r.Direction != "" && !strings.EqualFold(r.Direction, string(f.Direction)) {
		return false
	}
	if r.IP != "" && r.IP != p.SrcIP && r.IP != p.DstIP {
		return false
	}
	if r.CIDR != "" {
		_, n, e := net.ParseCIDR(r.CIDR)
		if e != nil {
			return false
		}
		if !n.Contains(net.ParseIP(p.SrcIP)) && !n.Contains(net.ParseIP(p.DstIP)) {
			return false
		}
	}
	return true
}

// Apply returns a frame suitable for evidence recording and whether it should be recorded.
// headers preserves Ethernet/IP/L4 headers and removes application payload; metadata/drop
// avoid PCAP storage entirely while telemetry continues normally.
func Apply(d Decision, p *decode.Packet, fr capture.Frame) (capture.Frame, bool) {
	switch d.Action {
	case "metadata", "drop":
		return capture.Frame{}, false
	case "headers":
		off := len(p.Raw) - len(p.Payload)
		if off < 0 || off > len(fr.Data) {
			off = len(fr.Data)
		}
		cp := append([]byte(nil), fr.Data[:off]...)
		fr.Data = cp
		return fr, true
	default:
		fr.Data = append([]byte(nil), fr.Data...)
		return fr, true
	}
}
