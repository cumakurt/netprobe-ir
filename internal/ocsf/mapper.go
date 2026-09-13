package ocsf

import (
	"fmt"
	"strings"
	"time"

	"netprobe-ir/internal/model"
)

// Event is NetProbe IR's vendor-neutral canonical security event envelope.
// Field names intentionally follow OCSF concepts without claiming exhaustive
// coverage of the full OCSF schema. The envelope is stable and exporter-ready.
type Event struct {
	Time         time.Time      `json:"time"`
	ClassUID     int            `json:"class_uid"`
	ClassName    string         `json:"class_name"`
	CategoryUID  int            `json:"category_uid"`
	CategoryName string         `json:"category_name"`
	ActivityID   int            `json:"activity_id,omitempty"`
	SeverityID   int            `json:"severity_id,omitempty"`
	Severity     string         `json:"severity,omitempty"`
	Confidence   int            `json:"confidence,omitempty"`
	Status       string         `json:"status,omitempty"`
	Message      string         `json:"message,omitempty"`
	Metadata     Metadata       `json:"metadata"`
	Actor        *Actor         `json:"actor,omitempty"`
	Src          *Endpoint      `json:"src_endpoint,omitempty"`
	Dst          *Endpoint      `json:"dst_endpoint,omitempty"`
	Network      *Network       `json:"network,omitempty"`
	Device       *Device        `json:"device,omitempty"`
	Observables  []Observable   `json:"observables,omitempty"`
	Unmapped     map[string]any `json:"unmapped,omitempty"`
}

type Metadata struct {
	Product Product `json:"product"`
	UID     string  `json:"uid,omitempty"`
	Version string  `json:"version,omitempty"`
}

type Product struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor_name"`
	Feature string `json:"feature_name,omitempty"`
}

type Actor struct {
	Process *Process `json:"process,omitempty"`
	User    *User    `json:"user,omitempty"`
}
type User struct {
	Name string `json:"name,omitempty"`
	UID  int    `json:"uid,omitempty"`
}
type Process struct {
	PID         int    `json:"pid,omitempty"`
	PPID        int    `json:"parent_pid,omitempty"`
	Name        string `json:"name,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	CmdLine     string `json:"cmd_line,omitempty"`
	ContainerID string `json:"container_uid,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}
type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
type Network struct {
	Protocol    string         `json:"protocol_name,omitempty"`
	Application string         `json:"application_name,omitempty"`
	Direction   string         `json:"direction,omitempty"`
	Bytes       uint64         `json:"bytes,omitempty"`
	Packets     uint64         `json:"packets,omitempty"`
	TLS         map[string]any `json:"tls,omitempty"`
}
type Device struct {
	Interface string `json:"interface,omitempty"`
}
type Observable struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func base(uid, feature string, t time.Time) Event {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return Event{Time: t, Metadata: Metadata{Product: Product{Name: "NetProbe IR", Vendor: "Cuma KURT", Feature: feature}, UID: uid}}
}

func Finding(f model.SecurityFinding) Event {
	e := base(f.ID, "Detection", f.Time)
	e.ClassUID = 2004
	e.ClassName = "Detection Finding"
	e.CategoryUID = 2
	e.CategoryName = "Findings"
	e.Severity = f.Severity
	e.SeverityID = severityID(f.Severity)
	e.Confidence = f.Confidence
	e.Status = f.Verdict
	e.Message = f.Title + ": " + f.Description
	e.Src = &Endpoint{IP: f.Source.IP, Port: f.Source.Port}
	e.Dst = &Endpoint{IP: f.Destination.IP, Port: f.Destination.Port}
	e.Network = &Network{Protocol: f.Protocol, Application: f.Application, Direction: string(f.Direction)}
	e.Device = &Device{Interface: f.Interface}
	if f.PID != 0 || f.Process != "" {
		e.Actor = &Actor{Process: &Process{PID: f.PID, Name: f.Process}}
	}
	e.Observables = append(e.Observables, Observable{Name: "rule_id", Type: "Rule", Value: f.RuleID})
	for _, m := range f.MITRE {
		e.Observables = append(e.Observables, Observable{Name: "mitre", Type: "Technique", Value: m})
	}
	e.Unmapped = map[string]any{"category": f.Category, "tactic": f.Tactic, "tags": f.Tags, "evidence": f.Evidence, "flow_id": f.FlowID, "packet_id": f.PacketID}
	return e
}

func Flow(f model.Flow) Event {
	e := base(f.ID, "Network Activity", f.LastSeen)
	e.ClassUID = 4001
	e.ClassName = "Network Activity"
	e.CategoryUID = 4
	e.CategoryName = "Network Activity"
	e.SeverityID = severityFromRisk(f.Risk)
	e.Severity = riskSeverity(f.Risk)
	e.Message = fmt.Sprintf("%s %s flow", f.NetworkProtocol, f.Direction)
	e.Src = &Endpoint{IP: f.Local.IP, Port: f.Local.Port}
	e.Dst = &Endpoint{IP: f.Remote.IP, Port: f.Remote.Port}
	if f.Direction == model.DirectionInbound {
		e.Src, e.Dst = e.Dst, e.Src
	}
	e.Network = &Network{Protocol: f.NetworkProtocol, Application: firstNonEmpty(f.DPI.Application, f.DPI.Protocol), Direction: string(f.Direction), Bytes: f.BytesTX + f.BytesRX, Packets: f.PacketsTX + f.PacketsRX}
	if f.DPI.TLS != nil {
		e.Network.TLS = map[string]any{"sni": f.DPI.TLS.SNI, "ja3": f.DPI.TLS.JA3, "ja4": f.DPI.TLS.JA4, "version": f.DPI.TLS.Version}
	}
	if len(f.Interfaces) > 0 {
		e.Device = &Device{Interface: strings.Join(f.Interfaces, ",")}
	}
	if f.Process != nil {
		e.Actor = actorFromProcess(f.Process)
	}
	e.Unmapped = map[string]any{"risk": f.Risk, "risk_reasons": f.RiskReasons, "attribution": f.Attribution, "tcp_flags": f.TCPFlags, "tos": f.ToS, "vlan_id": f.VLANID}
	return e
}

func Runtime(r model.RuntimeEvent) Event {
	e := base(fmt.Sprintf("runtime-%d-%d", r.PID, r.Time.UnixNano()), "Runtime Security", r.Time)
	e.ClassUID = 1007
	e.ClassName = "Process Activity"
	e.CategoryUID = 1
	e.CategoryName = "System Activity"
	e.Confidence = r.Confidence
	e.Status = map[bool]string{true: "success", false: "failure"}[r.Success]
	e.Message = r.Kind
	e.Actor = &Actor{Process: &Process{PID: r.PID, PPID: r.PPID, Name: r.Comm, FilePath: r.Path}, User: &User{UID: r.UID}}
	if r.Local.IP != "" {
		e.Src = &Endpoint{IP: r.Local.IP, Port: r.Local.Port}
	}
	if r.Remote.IP != "" {
		e.Dst = &Endpoint{IP: r.Remote.IP, Port: r.Remote.Port}
	}
	e.Network = &Network{Protocol: r.Proto}
	e.Unmapped = map[string]any{"kind": r.Kind, "source": r.Source, "meta": r.Meta}
	return e
}

func actorFromProcess(p *model.ProcessInfo) *Actor {
	if p == nil {
		return nil
	}
	return &Actor{Process: &Process{PID: p.PID, PPID: p.PPID, Name: p.Comm, FilePath: p.Exe, CmdLine: p.Cmdline, ContainerID: p.ContainerID, Pod: p.KubernetesPod, Namespace: p.KubernetesNamespace}, User: &User{Name: p.User, UID: p.UID}}
}

func severityID(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 6
	case "high":
		return 5
	case "medium":
		return 4
	case "low":
		return 3
	case "info":
		return 1
	default:
		return 0
	}
}
func severityFromRisk(r int) int {
	if r >= 90 {
		return 6
	}
	if r >= 70 {
		return 5
	}
	if r >= 40 {
		return 4
	}
	if r > 0 {
		return 3
	}
	return 1
}
func riskSeverity(r int) string {
	if r >= 90 {
		return "critical"
	}
	if r >= 70 {
		return "high"
	}
	if r >= 40 {
		return "medium"
	}
	if r > 0 {
		return "low"
	}
	return "informational"
}
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
