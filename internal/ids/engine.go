package ids

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/model"
)

const maxIDSStateEvents = 50000

// Config controls the native security detection engine. The engine intentionally
// distinguishes exact IOC/signature matches from behavioral heuristics.
type Config struct {
	Enabled               bool
	HomeNets              []string
	PortScanPorts         int
	HostSweepHosts        int
	WindowSeconds         int
	DNSHighEntropyQueries int
	NXDomainThreshold     int
	IOCFile               string
	RulesFile             string
	RulesSignature        string
	RulesTrustedPublicKey string
	RequireSignedRules    bool
	MaxFindings           int
	RuleLabMode           bool
}

type IOCSet struct {
	IPs     []string `json:"ips"`
	Domains []string `json:"domains"`
	SNI     []string `json:"sni"`
	JA3     []string `json:"ja3"`
	JA4     []string `json:"ja4"`
}

type RuleTestExpectation struct {
	Name       string `json:"name,omitempty"`
	Capture    string `json:"capture,omitempty"`
	MinMatches int    `json:"min_matches,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"`
}

type CustomRule struct {
	ID                 string                `json:"id"`
	Enabled            *bool                 `json:"enabled,omitempty"`
	Status             string                `json:"status,omitempty"`
	Author             string                `json:"author,omitempty"`
	Version            string                `json:"version,omitempty"`
	MinEngineVersion   string                `json:"min_engine_version,omitempty"`
	FalsePositiveNotes string                `json:"false_positive_notes,omitempty"`
	References         []string              `json:"references,omitempty"`
	Tests              []RuleTestExpectation `json:"tests,omitempty"`
	Title              string                `json:"title"`
	Description        string                `json:"description"`
	Severity           string                `json:"severity"`
	Confidence         int                   `json:"confidence"`
	Verdict            string                `json:"verdict"`
	Category           string                `json:"category"`
	Tactic             string                `json:"tactic,omitempty"`
	MITRE              []string              `json:"mitre,omitempty"`
	Tags               []string              `json:"tags,omitempty"`
	Protocol           string                `json:"protocol,omitempty"`
	Direction          string                `json:"direction,omitempty"`
	Field              string                `json:"field"`
	Operator           string                `json:"operator"`
	Value              string                `json:"value"`
}

type compiledRule struct {
	CustomRule
	re *regexp.Regexp
}

type connEvent struct {
	t       time.Time
	source  string
	dest    string
	port    uint16
	process string
}

type dnsEvent struct {
	t        time.Time
	actor    string
	query    string
	entropy  float64
	nxdomain bool
}

type Engine struct {
	mu  sync.Mutex
	cfg Config

	findings []model.SecurityFinding
	seen     map[string]time.Time
	conns    []connEvent
	dns      []dnsEvent

	homeNets []*net.IPNet
	iocIP    map[string]struct{}
	iocDom   map[string]struct{}
	iocSNI   map[string]struct{}
	iocJA3   map[string]struct{}
	iocJA4   map[string]struct{}
	rules    []compiledRule
	loadErrs []string
}

func New(c Config) *Engine {
	if c.PortScanPorts < 5 {
		c.PortScanPorts = 20
	}
	if c.HostSweepHosts < 5 {
		c.HostSweepHosts = 20
	}
	if c.WindowSeconds < 5 {
		c.WindowSeconds = 30
	}
	if c.DNSHighEntropyQueries < 3 {
		c.DNSHighEntropyQueries = 12
	}
	if c.NXDomainThreshold < 5 {
		c.NXDomainThreshold = 20
	}
	if c.MaxFindings < 100 {
		c.MaxFindings = 5000
	}
	e := &Engine{cfg: c, seen: map[string]time.Time{}, iocIP: map[string]struct{}{}, iocDom: map[string]struct{}{}, iocSNI: map[string]struct{}{}, iocJA3: map[string]struct{}{}, iocJA4: map[string]struct{}{}}
	for _, cidr := range c.HomeNets {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
			e.homeNets = append(e.homeNets, n)
		} else {
			e.loadErrs = append(e.loadErrs, "invalid home_net "+cidr+": "+err.Error())
		}
	}
	if c.IOCFile != "" {
		e.loadIOC(c.IOCFile)
	}
	if c.RulesFile != "" {
		e.loadRules(c.RulesFile)
	}
	return e
}

func (e *Engine) AddFinding(f model.SecurityFinding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.ID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", f.RuleID, f.FlowID, f.Time.UnixNano())))
		f.ID = hex.EncodeToString(h[:8])
	}
	for i := len(e.findings) - 1; i >= 0 && i >= len(e.findings)-256; i-- {
		if e.findings[i].ID == f.ID {
			return
		}
	}
	e.findings = append(e.findings, f)
	if len(e.findings) > e.cfg.MaxFindings {
		e.findings = e.findings[len(e.findings)-e.cfg.MaxFindings:]
	}
}

func (e *Engine) LoadErrors() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.loadErrs...)
}

func (e *Engine) loadIOC(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		e.loadErrs = append(e.loadErrs, "ioc_file: "+err.Error())
		return
	}
	var x IOCSet
	if err := json.Unmarshal(b, &x); err != nil {
		e.loadErrs = append(e.loadErrs, "ioc_file parse: "+err.Error())
		return
	}
	for _, v := range x.IPs {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			e.iocIP[ip.String()] = struct{}{}
		}
	}
	for _, v := range x.Domains {
		if v = normDomain(v); v != "" {
			e.iocDom[v] = struct{}{}
		}
	}
	for _, v := range x.SNI {
		if v = normDomain(v); v != "" {
			e.iocSNI[v] = struct{}{}
		}
	}
	for _, v := range x.JA3 {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			e.iocJA3[v] = struct{}{}
		}
	}
	for _, v := range x.JA4 {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			e.iocJA4[v] = struct{}{}
		}
	}
}

func (e *Engine) loadRules(path string) {
	if e.cfg.RequireSignedRules || strings.TrimSpace(e.cfg.RulesSignature) != "" {
		sigPath := strings.TrimSpace(e.cfg.RulesSignature)
		if sigPath == "" {
			sigPath = path + ".sig.json"
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			e.loadErrs = append(e.loadErrs, "rules signature: "+err.Error())
			return
		}
		if err := evidence.VerifyDetachedFile(path, sig, strings.TrimSpace(e.cfg.RulesTrustedPublicKey)); err != nil {
			e.loadErrs = append(e.loadErrs, "rules signature verification: "+err.Error())
			return
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		e.loadErrs = append(e.loadErrs, "rules_file: "+err.Error())
		return
	}
	var rules []CustomRule
	if err := json.Unmarshal(b, &rules); err != nil {
		e.loadErrs = append(e.loadErrs, "rules_file parse: "+err.Error())
		return
	}
	if len(rules) > 500 {
		rules = rules[:500]
		e.loadErrs = append(e.loadErrs, "rules_file limited to 500 rules")
	}
	for _, r := range rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(r.Status))
		if status == "" {
			status = "enabled"
		}
		if status != "enabled" && !(e.cfg.RuleLabMode && (status == "draft" || status == "test")) {
			continue
		}
		if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Field) == "" || strings.TrimSpace(r.Value) == "" {
			e.loadErrs = append(e.loadErrs, "custom rule missing id/field/value")
			continue
		}
		cr := compiledRule{CustomRule: r}
		if strings.EqualFold(r.Operator, "regex") {
			re, err := regexp.Compile(r.Value)
			if err != nil {
				e.loadErrs = append(e.loadErrs, "rule "+r.ID+" regex: "+err.Error())
				continue
			}
			cr.re = re
		}
		e.rules = append(e.rules, cr)
	}
}

// Observe evaluates one decoded packet and its correlated flow. packetID is the
// retained packet-summary identifier used for one-click evidence drill-down.
func (e *Engine) Observe(p *decode.Packet, f model.Flow, created bool, packetID string) []model.SecurityFinding {
	if !e.cfg.Enabled {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := p.Time
	e.compactSeen(now)
	var out []model.SecurityFinding
	add := func(ruleID, title, desc, severity, verdict, category, tactic string, confidence int, mitre, tags []string, ev map[string]any, dedup string) {
		if confidence < 0 {
			confidence = 0
		}
		if confidence > 100 {
			confidence = 100
		}
		key := ruleID + "|" + dedup
		if last, ok := e.seen[key]; ok && now.Sub(last) < 2*time.Minute {
			return
		}
		e.seen[key] = now
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", key, packetID, now.UnixNano())))
		sf := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: now, Severity: severity, Confidence: confidence, Verdict: verdict, RuleID: ruleID, Title: title, Description: desc, Category: category, Tactic: tactic, MITRE: mitre, Tags: tags, FlowID: f.ID, PacketID: packetID, Interface: p.Interface, Direction: f.Direction, Source: model.Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Destination: model.Endpoint{IP: p.DstIP, Port: p.DstPort}, Protocol: p.Protocol, Application: f.DPI.Application, Evidence: ev}
		if f.Process != nil {
			sf.PID = f.Process.PID
			sf.Process = f.Process.Comm
		}
		e.findings = append(e.findings, sf)
		out = append(out, sf)
		if len(e.findings) > e.cfg.MaxFindings {
			e.findings = e.findings[len(e.findings)-e.cfg.MaxFindings:]
		}
	}

	flowDedup := f.ID
	flags := p.TCPFlags
	if p.Protocol == "TCP" {
		switch {
		case flags&0x03 == 0x03: // FIN + SYN
			add("NP-IDS-1001", "Malformed TCP SYN+FIN", "SYN and FIN were set in the same TCP packet; this flag combination is strongly associated with evasion or scan traffic.", "high", "signature_match", "network-scan", "Discovery", 99, []string{"T1046"}, []string{"tcp", "scan", "evasion"}, map[string]any{"tcp_flags": decode.TCPFlagsString(flags)}, p.SrcIP+">"+p.DstIP)
		case flags&0x06 == 0x06: // SYN + RST
			add("NP-IDS-1002", "Malformed TCP SYN+RST", "SYN and RST were set simultaneously.", "high", "signature_match", "protocol-anomaly", "Defense Evasion", 99, nil, []string{"tcp", "malformed"}, map[string]any{"tcp_flags": decode.TCPFlagsString(flags)}, p.SrcIP+">"+p.DstIP)
		case flags == 0 && len(p.Payload) == 0:
			add("NP-IDS-1003", "TCP NULL scan pattern", "A TCP packet without control flags or payload matched a classic NULL-scan pattern.", "high", "signature_match", "network-scan", "Discovery", 98, []string{"T1046"}, []string{"tcp", "scan"}, map[string]any{"tcp_flags": "NONE"}, p.SrcIP+">"+p.DstIP)
		case flags&0x29 == 0x29: // FIN+PSH+URG
			add("NP-IDS-1004", "TCP XMAS scan pattern", "FIN, PSH and URG flags matched the classic XMAS-scan pattern.", "high", "signature_match", "network-scan", "Discovery", 98, []string{"T1046"}, []string{"tcp", "scan"}, map[string]any{"tcp_flags": decode.TCPFlagsString(flags)}, p.SrcIP+">"+p.DstIP)
		}
	}

	// Strong payload/application signatures. Inspection is bounded to avoid
	// turning the IDS path into an unbounded payload scanner.
	payload := p.Payload
	if len(payload) > 16384 {
		payload = payload[:16384]
	}
	low := strings.ToLower(string(payload))
	if strings.Contains(low, "${jndi:") {
		add("NP-IDS-1201", "JNDI injection exploit signature", "Observed a ${jndi:...} token in application payload, a high-confidence Log4Shell-style exploit indicator.", "critical", "signature_match", "exploit-attempt", "Initial Access", 99, []string{"T1190"}, []string{"http", "jndi", "log4shell", "exploit"}, map[string]any{"match": "${jndi:"}, flowDedup)
	}
	if strings.Contains(low, "() {") && (strings.Contains(low, "user-agent:") || strings.Contains(low, "cookie:") || strings.Contains(low, "referer:")) {
		add("NP-IDS-1202", "Shellshock exploit signature", "Observed shell-function syntax inside HTTP-like headers, matching a Shellshock-style exploit attempt.", "critical", "signature_match", "exploit-attempt", "Initial Access", 98, []string{"T1190"}, []string{"http", "shellshock", "exploit"}, map[string]any{"match": "() {"}, flowDedup)
	}
	if containsAny(low, []string{"bash -i >& /dev/tcp/", "/bin/bash -i", "/bin/sh -i", "nc -e /bin/", "ncat --exec", "socat exec:", "powershell -enc ", "powershell.exe -encodedcommand"}) {
		add("NP-IDS-1207", "Interactive/reverse-shell command signature", "Observed a plaintext command token strongly associated with interactive reverse shells or encoded PowerShell execution. Validate whether the payload is executable traffic or benign text/code transfer.", "critical", "signature_match", "command-execution", "Execution", 95, []string{"T1059"}, []string{"shell", "reverse-shell", "execution"}, map[string]any{"match_class": "reverse-shell-or-encoded-command"}, flowDedup)
	}
	if f.DPI.HTTP != nil {
		h := f.DPI.HTTP
		pathLow := strings.ToLower(h.Path)
		uaLow := strings.ToLower(h.UserAgent)
		if containsAny(uaLow, []string{"sqlmap", "nikto", "nmap scripting engine", "acunetix", "nessus", "wpscan", "gobuster", "dirbuster", "masscan"}) {
			add("NP-IDS-1203", "Security scanner user-agent", "HTTP User-Agent identifies a common vulnerability scanner or reconnaissance tool.", "high", "signature_match", "reconnaissance", "Discovery", 96, []string{"T1046"}, []string{"http", "scanner"}, map[string]any{"user_agent": h.UserAgent}, flowDedup)
		}
		if containsAny(pathLow, []string{"../", "..%2f", "%2e%2e%2f", "%252e%252e", "..\\"}) {
			add("NP-IDS-1204", "HTTP path traversal signature", "The HTTP path contains traversal encodings commonly used to escape the intended web root.", "high", "signature_match", "exploit-attempt", "Initial Access", 95, []string{"T1190"}, []string{"http", "path-traversal"}, map[string]any{"path": h.Path}, flowDedup)
		}
		if containsAny(pathLow, []string{"union%20select", "union+select", "information_schema", "sleep(", "benchmark(", "%27%20or%201%3d1", "' or 1=1"}) {
			add("NP-IDS-1205", "SQL injection signature", "The HTTP path matched common SQL injection operators or database enumeration tokens.", "high", "signature_match", "exploit-attempt", "Initial Access", 94, []string{"T1190"}, []string{"http", "sqli"}, map[string]any{"path": h.Path}, flowDedup)
		}
		if containsAny(pathLow, []string{"%3bwget%20", "%3bcurl%20", ";wget ", ";curl ", "%7cbash", "|bash", "cmd.exe", "/bin/sh"}) {
			add("NP-IDS-1206", "HTTP command injection signature", "The HTTP path contains shell execution/download tokens associated with command-injection attempts.", "critical", "signature_match", "exploit-attempt", "Execution", 96, []string{"T1059", "T1190"}, []string{"http", "command-injection"}, map[string]any{"path": h.Path}, flowDedup)
		}
		if strings.Contains(low, "authorization: basic ") && strings.EqualFold(f.DPI.Protocol, "HTTP") {
			add("NP-IDS-1301", "Cleartext HTTP Basic credentials", "HTTP Basic Authorization was observed without TLS. Credentials are only encoded, not encrypted, and can be recovered from traffic.", "high", "confirmed_exposure", "credential-exposure", "Credential Access", 100, []string{"T1557"}, []string{"http", "credentials", "cleartext"}, map[string]any{"host": h.Host, "path": h.Path}, flowDedup)
		}
		ext := strings.ToLower(pathLow)
		if hasAnySuffix(ext, []string{".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".scr", ".elf", ".so", ".sh"}) && f.Direction == model.DirectionInbound {
			add("NP-IDS-1701", "Executable/script delivered over HTTP", "An executable or script-like object was received over cleartext HTTP.", "medium", "policy_exposure", "payload-delivery", "Command and Control", 82, []string{"T1105"}, []string{"http", "download", "executable"}, map[string]any{"path": h.Path, "content_type": h.ContentType}, flowDedup)
		}
	}
	if p.Protocol == "TCP" && (p.SrcPort == 21 || p.DstPort == 21) && (strings.HasPrefix(strings.TrimSpace(strings.ToUpper(string(payload))), "USER ") || strings.HasPrefix(strings.TrimSpace(strings.ToUpper(string(payload))), "PASS ")) {
		add("NP-IDS-1302", "FTP credentials in cleartext", "FTP USER/PASS command observed on an unencrypted control channel.", "high", "confirmed_exposure", "credential-exposure", "Credential Access", 100, nil, []string{"ftp", "credentials", "cleartext"}, map[string]any{"command": firstToken(string(payload))}, flowDedup)
	}
	if p.Protocol == "TCP" && (p.SrcPort == 23 || p.DstPort == 23) {
		add("NP-IDS-1303", "Telnet cleartext remote terminal", "Telnet traffic is unencrypted and exposes interactive session content and often credentials to observers.", "high", "confirmed_exposure", "cleartext-protocol", "Credential Access", 100, nil, []string{"telnet", "cleartext"}, map[string]any{"port": 23}, flowDedup)
	}
	if p.Protocol == "TCP" && (p.SrcPort == 110 || p.DstPort == 110 || p.SrcPort == 143 || p.DstPort == 143) && containsAny(strings.ToUpper(strings.TrimSpace(string(payload))), []string{"USER ", "PASS ", " LOGIN "}) {
		add("NP-IDS-1304", "Mail authentication over cleartext protocol", "Credential-like authentication was observed over POP3/IMAP without evidence of TLS on this flow.", "high", "confirmed_exposure", "credential-exposure", "Credential Access", 98, nil, []string{"mail", "credentials", "cleartext"}, map[string]any{"port": maxPort(p.SrcPort, p.DstPort)}, flowDedup)
	}

	// Exposure and boundary rules.
	remote := net.ParseIP(f.Remote.IP)
	external := e.isExternal(remote)
	if external && f.Direction == model.DirectionOutbound && f.Remote.Port == 445 {
		add("NP-IDS-1401", "Outbound SMB to external network", "The host initiated SMB directly to an external address. Internet-bound SMB is a high-risk exposure and common lateral/exfiltration path.", "critical", "policy_exposure", "network-exposure", "Lateral Movement", 95, []string{"T1021.002"}, []string{"smb", "external"}, map[string]any{"remote": f.Remote.IP, "port": 445}, flowDedup)
	}
	if external && f.Direction == model.DirectionInbound && f.Local.Port == 3389 {
		add("NP-IDS-1402", "Inbound RDP from external network", "An external address reached the local RDP service.", "high", "policy_exposure", "remote-service-exposure", "Lateral Movement", 94, []string{"T1021.001"}, []string{"rdp", "external"}, map[string]any{"remote": f.Remote.IP, "local_port": 3389}, flowDedup)
	}

	// Exact IOC matches are the strongest native verdict because the user owns
	// the IOC source. No hard-coded stale threat feed is shipped in the binary.
	if _, ok := e.iocIP[p.SrcIP]; ok {
		add("NP-IOC-IP", "Exact IOC IP match", "Source IP exactly matched the configured IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071"}, []string{"ioc", "ip"}, map[string]any{"matched_ip": p.SrcIP}, "src:"+p.SrcIP)
	}
	if _, ok := e.iocIP[p.DstIP]; ok {
		add("NP-IOC-IP", "Exact IOC IP match", "Destination IP exactly matched the configured IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071"}, []string{"ioc", "ip"}, map[string]any{"matched_ip": p.DstIP}, "dst:"+p.DstIP)
	}
	if f.DPI.DNS != nil {
		q := normDomain(f.DPI.DNS.Query)
		if e.domainIOC(q) {
			add("NP-IOC-DOMAIN", "Exact IOC domain match", "DNS query matched the configured domain IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071.004"}, []string{"ioc", "dns"}, map[string]any{"domain": q}, flowDedup+"|"+q)
		}
	}
	if f.DPI.TLS != nil {
		sni := normDomain(f.DPI.TLS.SNI)
		if e.domainIOC(sni) {
			add("NP-IOC-SNI", "Exact IOC TLS SNI match", "TLS SNI matched the configured domain/SNI IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071.001"}, []string{"ioc", "tls"}, map[string]any{"sni": sni}, flowDedup+"|"+sni)
		}
		ja3 := strings.ToLower(strings.TrimSpace(f.DPI.TLS.JA3))
		if _, ok := e.iocJA3[ja3]; ok && ja3 != "" {
			add("NP-IOC-JA3", "Exact IOC JA3 match", "TLS JA3 fingerprint exactly matched the configured IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071.001"}, []string{"ioc", "ja3"}, map[string]any{"ja3": ja3}, flowDedup+"|"+ja3)
		}
		ja4 := strings.ToLower(strings.TrimSpace(f.DPI.TLS.JA4))
		if _, ok := e.iocJA4[ja4]; ok && ja4 != "" {
			add("NP-IOC-JA4", "Exact IOC JA4 match", "TLS JA4 fingerprint exactly matched the configured IOC set.", "critical", "confirmed_ioc", "threat-intelligence", "Command and Control", 100, []string{"T1071.001"}, []string{"ioc", "ja4"}, map[string]any{"ja4": ja4}, flowDedup+"|"+ja4)
		}
	}

	if created {
		actor := eventActor(f, p)
		e.conns = append(e.conns, connEvent{t: now, source: p.SrcIP, dest: p.DstIP, port: p.DstPort, process: actor})
		cut := now.Add(-time.Duration(e.cfg.WindowSeconds) * time.Second)
		e.conns = compactConns(e.conns, cut)
		if len(e.conns) > maxIDSStateEvents {
			e.conns = append([]connEvent(nil), e.conns[len(e.conns)-maxIDSStateEvents:]...)
		}
		// A port scan is evaluated against one target host. A host sweep is
		// evaluated against one target service port. Keeping these dimensions
		// separate substantially reduces false positives from normal browsers,
		// package managers and CDN-heavy applications.
		ports := map[uint16]struct{}{}
		hosts := map[string]struct{}{}
		for _, x := range e.conns {
			if x.process != actor {
				continue
			}
			if x.dest == p.DstIP {
				ports[x.port] = struct{}{}
			}
			if x.port == p.DstPort {
				hosts[x.dest] = struct{}{}
			}
		}
		if len(ports) >= e.cfg.PortScanPorts {
			add("NP-IDS-1101", "Multi-port network scan", "One process/source contacted many unique ports on the same destination host inside the detection window.", "high", "behavioral", "network-scan", "Discovery", 92, []string{"T1046"}, []string{"scan", "stateful"}, map[string]any{"unique_ports": len(ports), "target": p.DstIP, "window_seconds": e.cfg.WindowSeconds, "actor": actor}, actor+"|ports|"+p.DstIP)
		}
		if len(hosts) >= e.cfg.HostSweepHosts {
			add("NP-IDS-1102", "Host sweep / network discovery", "One process/source contacted the same destination service port across many unique remote hosts inside the detection window.", "high", "behavioral", "network-scan", "Discovery", 90, []string{"T1046"}, []string{"scan", "host-sweep", "stateful"}, map[string]any{"unique_hosts": len(hosts), "target_port": p.DstPort, "window_seconds": e.cfg.WindowSeconds, "actor": actor}, actor+"|hosts|"+strconv.Itoa(int(p.DstPort)))
		}
	}

	if f.DPI.DNS != nil && f.DPI.DNS.Query != "" {
		d := f.DPI.DNS
		actor := eventActor(f, p)
		ent := entropy(d.Query)
		e.dns = append(e.dns, dnsEvent{t: now, actor: actor, query: d.Query, entropy: ent, nxdomain: d.ResponseCode == 3})
		cut := now.Add(-time.Duration(e.cfg.WindowSeconds) * time.Second)
		e.dns = compactDNS(e.dns, cut)
		if len(e.dns) > maxIDSStateEvents {
			e.dns = append([]dnsEvent(nil), e.dns[len(e.dns)-maxIDSStateEvents:]...)
		}
		high := 0
		nx := 0
		unique := map[string]struct{}{}
		for _, x := range e.dns {
			if x.actor != actor {
				continue
			}
			if x.entropy >= 4.2 && longestLabel(x.query) >= 35 {
				high++
				unique[x.query] = struct{}{}
			}
			if x.nxdomain {
				nx++
			}
		}
		if high >= e.cfg.DNSHighEntropyQueries && len(unique) >= e.cfg.DNSHighEntropyQueries/2 {
			add("NP-IDS-1501", "Probable DNS tunneling behavior", "Repeated high-entropy, long DNS labels crossed the stateful tunneling threshold.", "high", "behavioral", "dns-tunneling", "Exfiltration", 88, []string{"T1048.003"}, []string{"dns", "tunnel", "exfiltration"}, map[string]any{"high_entropy_queries": high, "unique_queries": len(unique), "window_seconds": e.cfg.WindowSeconds}, actor+"|dns-tunnel")
		}
		if nx >= e.cfg.NXDomainThreshold {
			add("NP-IDS-1502", "Excessive DNS NXDOMAIN responses", "A process/source generated a high rate of failed DNS names, consistent with DGA discovery or faulty/malicious domain generation.", "medium", "behavioral", "dns-anomaly", "Command and Control", 78, []string{"T1071.004"}, []string{"dns", "nxdomain", "dga"}, map[string]any{"nxdomain_count": nx, "window_seconds": e.cfg.WindowSeconds}, actor+"|nxdomain")
		}
	}

	if (p.Protocol == "ICMP" || p.Protocol == "ICMPv6") && len(p.Payload) > 1200 {
		add("NP-IDS-1901", "Oversized ICMP payload", "An unusually large ICMP payload can indicate tunneling or covert data transfer; verify against expected diagnostics.", "medium", "behavioral", "icmp-tunneling", "Command and Control", 70, []string{"T1095"}, []string{"icmp", "tunnel"}, map[string]any{"payload_bytes": len(p.Payload)}, p.SrcIP+">"+p.DstIP)
	}

	for _, r := range e.rules {
		if r.Protocol != "" && !strings.EqualFold(r.Protocol, p.Protocol) && !strings.EqualFold(r.Protocol, f.DPI.Protocol) {
			continue
		}
		if r.Direction != "" && !strings.EqualFold(r.Direction, string(f.Direction)) {
			continue
		}
		val := fieldValue(r.Field, p, f)
		if val == "" || !match(r, val) {
			continue
		}
		sev := normSeverity(r.Severity)
		verdict := r.Verdict
		if verdict == "" {
			verdict = "signature_match"
		}
		cat := r.Category
		if cat == "" {
			cat = "custom-rule"
		}
		conf := r.Confidence
		if conf == 0 {
			conf = 90
		}
		add(r.ID, r.Title, r.Description, sev, verdict, cat, r.Tactic, conf, r.MITRE, append([]string{"custom"}, r.Tags...), map[string]any{"field": r.Field, "operator": r.Operator, "match": r.Value}, flowDedup+"|"+r.ID)
	}

	return out
}

func (e *Engine) Findings(limit int) []model.SecurityFinding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]model.SecurityFinding(nil), e.findings...)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func (e *Engine) Finding(id string) (model.SecurityFinding, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.findings) - 1; i >= 0; i-- {
		if e.findings[i].ID == id {
			return e.findings[i], true
		}
	}
	return model.SecurityFinding{}, false
}
func (e *Engine) Counts() (total, critical, confirmed int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	total = len(e.findings)
	for _, f := range e.findings {
		if f.Severity == "critical" {
			critical++
		}
		if strings.HasPrefix(f.Verdict, "confirmed_") || f.Verdict == "signature_match" {
			confirmed++
		}
	}
	return
}

func (e *Engine) compactSeen(now time.Time) {
	maxSeen := e.cfg.MaxFindings * 4
	if maxSeen < 2000 {
		maxSeen = 2000
	}
	if len(e.seen) <= maxSeen {
		return
	}
	cut := now.Add(-10 * time.Minute)
	for k, t := range e.seen {
		if t.Before(cut) {
			delete(e.seen, k)
		}
	}
	// If a hostile high-cardinality stream filled the dedup table entirely
	// inside the expiry window, cap it anyway. Deduplication is a convenience;
	// bounded memory is a stronger invariant.
	for k := range e.seen {
		if len(e.seen) <= maxSeen {
			break
		}
		delete(e.seen, k)
	}
}

func (e *Engine) isExternal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range e.homeNets {
		if n.Contains(ip) {
			return false
		}
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast())
}
func (e *Engine) domainIOC(d string) bool {
	if d == "" {
		return false
	}
	if _, ok := e.iocDom[d]; ok {
		return true
	}
	if _, ok := e.iocSNI[d]; ok {
		return true
	}
	for k := range e.iocDom {
		if strings.HasSuffix(d, "."+k) {
			return true
		}
	}
	for k := range e.iocSNI {
		if strings.HasSuffix(d, "."+k) {
			return true
		}
	}
	return false
}
func compactConns(in []connEvent, cut time.Time) []connEvent {
	n := 0
	for _, x := range in {
		if !x.t.Before(cut) {
			in[n] = x
			n++
		}
	}
	return in[:n]
}
func compactDNS(in []dnsEvent, cut time.Time) []dnsEvent {
	n := 0
	for _, x := range in {
		if !x.t.Before(cut) {
			in[n] = x
			n++
		}
	}
	return in[:n]
}
func actorKey(f model.Flow, fallback string) string {
	if f.Process != nil {
		return strconv.Itoa(f.Process.PID) + ":" + f.Process.Exe
	}
	return "ip:" + fallback
}
func eventActor(f model.Flow, p *decode.Packet) string {
	if f.Direction == model.DirectionOutbound && f.Process != nil {
		return actorKey(f, p.SrcIP)
	}
	return "ip:" + p.SrcIP
}
func containsAny(s string, xs []string) bool {
	for _, x := range xs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
func hasAnySuffix(s string, xs []string) bool {
	for _, x := range xs {
		if strings.HasSuffix(s, x) || strings.Contains(s, x+"?") {
			return true
		}
	}
	return false
}
func firstToken(s string) string {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return ""
	}
	return strings.ToUpper(f[0])
}
func maxPort(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}
func normDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "medium"
	}
}
func entropy(s string) float64 {
	s = normDomain(s)
	freq := map[rune]int{}
	n := 0
	for _, r := range s {
		if r == '.' || r == '-' {
			continue
		}
		freq[r]++
		n++
	}
	if n == 0 {
		return 0
	}
	h := 0.0
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
func longestLabel(s string) int {
	m := 0
	for _, x := range strings.Split(normDomain(s), ".") {
		if len(x) > m {
			m = len(x)
		}
	}
	return m
}
func fieldValue(field string, p *decode.Packet, f model.Flow) string {
	switch strings.ToLower(field) {
	case "payload":
		b := p.Payload
		if len(b) > 16384 {
			b = b[:16384]
		}
		return string(b)
	case "http.path":
		if f.DPI.HTTP != nil {
			return f.DPI.HTTP.Path
		}
	case "http.host":
		if f.DPI.HTTP != nil {
			return f.DPI.HTTP.Host
		}
	case "http.user_agent":
		if f.DPI.HTTP != nil {
			return f.DPI.HTTP.UserAgent
		}
	case "dns.query":
		if f.DPI.DNS != nil {
			return f.DPI.DNS.Query
		}
	case "tls.sni":
		if f.DPI.TLS != nil {
			return f.DPI.TLS.SNI
		}
	case "tls.ja3":
		if f.DPI.TLS != nil {
			return f.DPI.TLS.JA3
		}
	case "tls.ja4":
		if f.DPI.TLS != nil {
			return f.DPI.TLS.JA4
		}
	case "tls.server_fingerprint":
		if f.DPI.TLS != nil {
			return f.DPI.TLS.ServerFingerprint
		}
	case "quic.version":
		if f.DPI.QUIC != nil {
			return f.DPI.QUIC.VersionHex
		}
	case "quic.fingerprint":
		if f.DPI.QUIC != nil {
			return f.DPI.QUIC.Fingerprint
		}
	case "process":
		if f.Process != nil {
			return f.Process.Exe + " " + f.Process.Comm
		}
	case "src.ip":
		return p.SrcIP
	case "dst.ip":
		return p.DstIP
	case "application":
		return f.DPI.Application
	}
	return ""
}
func match(r compiledRule, val string) bool {
	switch strings.ToLower(strings.TrimSpace(r.Operator)) {
	case "equals":
		return strings.EqualFold(val, r.Value)
	case "prefix":
		return strings.HasPrefix(strings.ToLower(val), strings.ToLower(r.Value))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(val), strings.ToLower(r.Value))
	case "regex":
		return r.re != nil && r.re.MatchString(val)
	default:
		return strings.Contains(strings.ToLower(val), strings.ToLower(r.Value))
	}
}
