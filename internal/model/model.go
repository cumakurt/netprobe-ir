package model

import "time"

type Direction string

const (
	DirectionOutbound  Direction = "outbound"
	DirectionInbound   Direction = "inbound"
	DirectionForwarded Direction = "forwarded"
	DirectionUnknown   Direction = "unknown"
)

type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type ProcessInfo struct {
	PID                 int    `json:"pid"`
	PPID                int    `json:"ppid,omitempty"`
	UID                 int    `json:"uid,omitempty"`
	User                string `json:"user,omitempty"`
	Comm                string `json:"comm,omitempty"`
	Exe                 string `json:"exe,omitempty"`
	Cmdline             string `json:"cmdline,omitempty"`
	Cgroup              string `json:"cgroup,omitempty"`
	ContainerID         string `json:"container_id,omitempty"`
	ContainerRuntime    string `json:"container_runtime,omitempty"`
	KubernetesPod       string `json:"kubernetes_pod,omitempty"`
	KubernetesNamespace string `json:"kubernetes_namespace,omitempty"`
	Attribution         string `json:"attribution,omitempty"`
}

type DNSInfo struct {
	Query        string   `json:"query,omitempty"`
	QType        uint16   `json:"qtype,omitempty"`
	ResponseCode uint8    `json:"response_code,omitempty"`
	Answers      []string `json:"answers,omitempty"`
}

type HTTP2Info struct {
	PrefaceSeen bool              `json:"preface_seen,omitempty"`
	Frames      int               `json:"frames,omitempty"`
	Streams     []uint32          `json:"streams,omitempty"`
	Settings    map[uint16]uint32 `json:"settings,omitempty"`
	LastType    uint8             `json:"last_type,omitempty"`
	LastFlags   uint8             `json:"last_flags,omitempty"`
}

type HTTPInfo struct {
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	Status      int    `json:"status,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type TLSCertificateInfo struct {
	SHA256     string    `json:"sha256,omitempty"`
	SPKISHA256 string    `json:"spki_sha256,omitempty"`
	SubjectCN  string    `json:"subject_cn,omitempty"`
	IssuerCN   string    `json:"issuer_cn,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	SelfSigned bool      `json:"self_signed,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
}

type TLSInfo struct {
	Version           string              `json:"version,omitempty"`
	SNI               string              `json:"sni,omitempty"`
	ALPN              []string            `json:"alpn,omitempty"`
	JA3               string              `json:"ja3,omitempty"`
	JA4               string              `json:"ja4,omitempty"`
	ServerVersion     string              `json:"server_version,omitempty"`
	ServerCipher      string              `json:"server_cipher,omitempty"`
	ServerFingerprint string              `json:"server_fingerprint,omitempty"`
	Certificate       *TLSCertificateInfo `json:"certificate,omitempty"`
	Fingerprint       string              `json:"fingerprint,omitempty"`
	CipherCount       int                 `json:"cipher_count,omitempty"`
	ExtensionCount    int                 `json:"extension_count,omitempty"`
}

type QUICInfo struct {
	VersionHex         string `json:"version_hex,omitempty"`
	PacketType         string `json:"packet_type,omitempty"`
	DCID               string `json:"dcid,omitempty"`
	SCID               string `json:"scid,omitempty"`
	TokenLength        uint64 `json:"token_length,omitempty"`
	LongHeader         bool   `json:"long_header,omitempty"`
	VersionNegotiation bool   `json:"version_negotiation,omitempty"`
	Retry              bool   `json:"retry,omitempty"`
	Fingerprint        string `json:"fingerprint,omitempty"`
}

type DPIInfo struct {
	Protocol     string     `json:"protocol,omitempty"`
	Application  string     `json:"application,omitempty"`
	Confidence   int        `json:"confidence,omitempty"`
	Encrypted    bool       `json:"encrypted,omitempty"`
	DNS          *DNSInfo   `json:"dns,omitempty"`
	HTTP         *HTTPInfo  `json:"http,omitempty"`
	HTTP2        *HTTP2Info `json:"http2,omitempty"`
	TLS          *TLSInfo   `json:"tls,omitempty"`
	QUIC         *QUICInfo  `json:"quic,omitempty"`
	SSHBanner    string     `json:"ssh_banner,omitempty"`
	ProtocolPack string     `json:"protocol_pack,omitempty"`
}

type Flow struct {
	ID              string       `json:"id"`
	NetworkProtocol string       `json:"network_protocol"`
	IPVersion       int          `json:"ip_version"`
	Local           Endpoint     `json:"local"`
	Remote          Endpoint     `json:"remote"`
	Direction       Direction    `json:"direction"`
	Interfaces      []string     `json:"interfaces"`
	FirstSeen       time.Time    `json:"first_seen"`
	LastSeen        time.Time    `json:"last_seen"`
	ClosedAt        *time.Time   `json:"closed_at,omitempty"`
	PacketsTX       uint64       `json:"packets_tx"`
	PacketsRX       uint64       `json:"packets_rx"`
	BytesTX         uint64       `json:"bytes_tx"`
	BytesRX         uint64       `json:"bytes_rx"`
	TCPFlags        string       `json:"tcp_flags,omitempty"`
	ToS             uint8        `json:"tos,omitempty"`
	VLANID          uint16       `json:"vlan_id,omitempty"`
	ICMPType        uint8        `json:"icmp_type,omitempty"`
	ICMPCode        uint8        `json:"icmp_code,omitempty"`
	Process         *ProcessInfo `json:"process,omitempty"`
	DPI             DPIInfo      `json:"dpi"`
	Risk            int          `json:"risk"`
	RiskReasons     []string     `json:"risk_reasons,omitempty"`
	Attribution     string       `json:"attribution"`
}

type Alert struct {
	ID          string         `json:"id"`
	Time        time.Time      `json:"time"`
	Severity    string         `json:"severity"`
	Score       int            `json:"score"`
	Rule        string         `json:"rule"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	FlowID      string         `json:"flow_id,omitempty"`
	PID         int            `json:"pid,omitempty"`
	Process     string         `json:"process,omitempty"`
	Remote      string         `json:"remote,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

// SecurityFinding is a security-focused detection result. It deliberately
// separates verdict/confidence from severity so heuristic behavior is never
// presented with the same certainty as an exact IOC or strong signature match.
type SecurityFinding struct {
	ID          string         `json:"id"`
	Time        time.Time      `json:"time"`
	Severity    string         `json:"severity"`
	Confidence  int            `json:"confidence"`
	Verdict     string         `json:"verdict"`
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Tactic      string         `json:"tactic,omitempty"`
	MITRE       []string       `json:"mitre,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	FlowID      string         `json:"flow_id,omitempty"`
	PacketID    string         `json:"packet_id,omitempty"`
	Interface   string         `json:"interface,omitempty"`
	Direction   Direction      `json:"direction,omitempty"`
	Source      Endpoint       `json:"source"`
	Destination Endpoint       `json:"destination"`
	Protocol    string         `json:"protocol,omitempty"`
	Application string         `json:"application,omitempty"`
	PID         int            `json:"pid,omitempty"`
	Process     string         `json:"process,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

type PacketSummary struct {
	ID              string       `json:"id"`
	Time            time.Time    `json:"time"`
	Interface       string       `json:"interface"`
	Direction       Direction    `json:"direction"`
	NetworkProtocol string       `json:"network_protocol"`
	IPVersion       int          `json:"ip_version"`
	Source          Endpoint     `json:"source"`
	Destination     Endpoint     `json:"destination"`
	Length          int          `json:"length"`
	TCPFlags        string       `json:"tcp_flags,omitempty"`
	ToS             uint8        `json:"tos,omitempty"`
	VLANID          uint16       `json:"vlan_id,omitempty"`
	ICMPType        uint8        `json:"icmp_type,omitempty"`
	ICMPCode        uint8        `json:"icmp_code,omitempty"`
	FlowID          string       `json:"flow_id,omitempty"`
	Process         *ProcessInfo `json:"process,omitempty"`
	DPI             DPIInfo      `json:"dpi"`
	Attribution     string       `json:"attribution"`
}

// YaraMatch is a malware-rule match returned by an external YARA-X scanner.
type YaraMatch struct {
	Rule      string         `json:"rule"`
	Namespace string         `json:"namespace,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
}

// FileArtifact is a reconstructed application-layer file or transfer object.
// Raw packet payload is never included in this structure.
type FileArtifact struct {
	ID          string         `json:"id"`
	Time        time.Time      `json:"time"`
	FlowID      string         `json:"flow_id"`
	Protocol    string         `json:"protocol"`
	Direction   Direction      `json:"direction"`
	Name        string         `json:"name"`
	StoredPath  string         `json:"stored_path,omitempty"`
	MIME        string         `json:"mime,omitempty"`
	Size        int64          `json:"size"`
	SHA256      string         `json:"sha256"`
	SHA1        string         `json:"sha1,omitempty"`
	MD5         string         `json:"md5,omitempty"`
	Entropy     float64        `json:"entropy"`
	Source      Endpoint       `json:"source"`
	Destination Endpoint       `json:"destination"`
	Process     *ProcessInfo   `json:"process,omitempty"`
	Yara        []YaraMatch    `json:"yara,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
}

// RuntimeEvent is a host-runtime signal supplied by the optional eBPF/bpftrace
// provider. It is kept separate from ProcessInfo because events are temporal
// evidence, not attributes of a process snapshot.
type RuntimeEvent struct {
	Time       time.Time      `json:"time"`
	Kind       string         `json:"kind"`
	PID        int            `json:"pid"`
	PPID       int            `json:"ppid,omitempty"`
	UID        int            `json:"uid,omitempty"`
	Comm       string         `json:"comm,omitempty"`
	Path       string         `json:"path,omitempty"`
	Proto      string         `json:"proto,omitempty"`
	Local      Endpoint       `json:"local,omitempty"`
	Remote     Endpoint       `json:"remote,omitempty"`
	Success    bool           `json:"success"`
	Source     string         `json:"source"`
	Confidence int            `json:"confidence"`
	Meta       map[string]any `json:"meta,omitempty"`
}

type InterfaceStats struct {
	Name      string     `json:"name"`
	Backend   string     `json:"backend,omitempty"`
	Packets   uint64     `json:"packets"`
	Bytes     uint64     `json:"bytes"`
	Errors    uint64     `json:"errors"`
	Dropped   uint64     `json:"dropped"`
	Running   bool       `json:"running"`
	State     string     `json:"state"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	StoppedAt *time.Time `json:"stopped_at,omitempty"`
}

type Status struct {
	StartedAt          time.Time        `json:"started_at"`
	UptimeSeconds      int64            `json:"uptime_seconds"`
	CaptureMode        string           `json:"capture_mode"`
	CaptureRunning     bool             `json:"capture_running"`
	CaptureState       string           `json:"capture_state"`
	CaptureStartedAt   *time.Time       `json:"capture_started_at,omitempty"`
	CaptureStoppedAt   *time.Time       `json:"capture_stopped_at,omitempty"`
	Interfaces         []InterfaceStats `json:"interfaces"`
	Flows              int              `json:"flows"`
	ActiveFlows        int              `json:"active_flows"`
	Processes          int              `json:"processes"`
	Alerts             int              `json:"alerts"`
	CriticalAlerts     int              `json:"critical_alerts"`
	SecurityFindings   int              `json:"security_findings"`
	CriticalFindings   int              `json:"critical_findings"`
	ConfirmedFindings  int              `json:"confirmed_findings"`
	Packets            uint64           `json:"packets"`
	Bytes              uint64           `json:"bytes"`
	CaptureErrors      uint64           `json:"capture_errors"`
	RecorderDrops      uint64           `json:"recorder_drops"`
	ProcessMapAgeMS    int64            `json:"process_map_age_ms"`
	AttributionBackend string           `json:"attribution_backend,omitempty"`
	AFXDPAvailable     bool             `json:"af_xdp_available"`
	AFXDPReason        string           `json:"af_xdp_reason,omitempty"`
	ThreatIndicators   int              `json:"threat_indicators,omitempty"`
	Cases              int              `json:"cases,omitempty"`
	Sensors            int              `json:"sensors,omitempty"`
}
