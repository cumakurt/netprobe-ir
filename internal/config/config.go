package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Listen     string   `json:"listen"`
	Interfaces []string `json:"interfaces"`
	DataDir    string   `json:"data_dir"`
	AuthToken  string   `json:"auth_token"`
	Auth       struct {
		Enabled               bool   `json:"enabled"`
		DefaultUsername       string `json:"default_username"`
		SessionIdleMinutes    int    `json:"session_idle_minutes"`
		SessionAbsoluteHours  int    `json:"session_absolute_hours"`
		MaxFailures           int    `json:"max_failures"`
		LockoutSeconds        int    `json:"lockout_seconds"`
		PasswordIterations    int    `json:"password_iterations"`
		PasswordMinLength     int    `json:"password_min_length"`
		RequirePasswordChange bool   `json:"require_password_change"`
	} `json:"auth"`
	Security struct {
		ConsoleAllowedCIDRs    []string `json:"console_allowed_cidrs"`
		RequireSignedConfig    bool     `json:"require_signed_config"`
		ConfigSignature        string   `json:"config_signature"`
		ConfigTrustedPublicKey string   `json:"config_trusted_public_key"`
		ForensicImmutable      bool     `json:"forensic_immutable"`
	} `json:"security"`
	OIDC struct {
		Enabled       bool     `json:"enabled"`
		Issuer        string   `json:"issuer"`
		ClientID      string   `json:"client_id"`
		ClientSecret  string   `json:"client_secret"`
		RedirectURL   string   `json:"redirect_url"`
		DefaultRole   string   `json:"default_role"`
		UsernameClaim string   `json:"username_claim"`
		Scopes        []string `json:"scopes"`
	} `json:"oidc"`
	Integrations struct {
		Webhooks []struct {
			Name        string `json:"name"`
			URL         string `json:"url"`
			Token       string `json:"token"`
			MinSeverity string `json:"min_severity"`
			Enabled     bool   `json:"enabled"`
		} `json:"webhooks"`
		Syslog struct {
			Enabled     bool   `json:"enabled"`
			Network     string `json:"network"`
			Address     string `json:"address"`
			Format      string `json:"format"`
			MinSeverity string `json:"min_severity"`
		} `json:"syslog"`
	} `json:"integrations"`
	Timeline struct {
		Enabled         bool `json:"enabled"`
		IntervalSeconds int  `json:"interval_seconds"`
		MaxSnapshots    int  `json:"max_snapshots"`
	} `json:"timeline"`
	AllowUnauthenticatedRemote bool `json:"allow_unauthenticated_remote"`
	Capture                    struct {
		Backend         string `json:"backend"`
		SnapLen         int    `json:"snap_len"`
		ReadBuffer      int    `json:"read_buffer"`
		FlowIdleSeconds int    `json:"flow_idle_seconds"`
	} `json:"capture"`
	Recorder struct {
		Enabled        bool  `json:"enabled"`
		SegmentMB      int64 `json:"segment_mb"`
		MaxDiskMB      int64 `json:"max_disk_mb"`
		IncidentCopies bool  `json:"incident_copies"`
	} `json:"recorder"`
	DPI struct {
		MaxStreamBytes int `json:"max_stream_bytes"`
	} `json:"dpi"`
	Anomaly struct {
		Enabled             bool    `json:"enabled"`
		ExfiltrationMB      uint64  `json:"exfiltration_mb"`
		FanoutDestinations  int     `json:"fanout_destinations"`
		PortScanPorts       int     `json:"port_scan_ports"`
		BurstConnections    int     `json:"burst_connections"`
		BeaconMinSamples    int     `json:"beacon_min_samples"`
		BeaconMaxJitter     float64 `json:"beacon_max_jitter"`
		DNSEntropyThreshold float64 `json:"dns_entropy_threshold"`
	} `json:"anomaly"`
	IDS struct {
		Enabled               bool     `json:"enabled"`
		HomeNets              []string `json:"home_nets"`
		PortScanPorts         int      `json:"port_scan_ports"`
		HostSweepHosts        int      `json:"host_sweep_hosts"`
		WindowSeconds         int      `json:"window_seconds"`
		DNSHighEntropyQueries int      `json:"dns_high_entropy_queries"`
		NXDomainThreshold     int      `json:"nxdomain_threshold"`
		IOCFile               string   `json:"ioc_file"`
		RulesFile             string   `json:"rules_file"`
		RulesSignature        string   `json:"rules_signature,omitempty"`
		RulesTrustedPublicKey string   `json:"rules_trusted_public_key,omitempty"`
		RequireSignedRules    bool     `json:"require_signed_rules,omitempty"`
		MaxFindings           int      `json:"max_findings"`
		RuleLabMode           bool     `json:"rule_lab_mode,omitempty"`
	} `json:"ids"`
	Attribution struct {
		Backend      string `json:"backend"`
		BPFTracePath string `json:"bpftrace_path"`
		CoreObject   string `json:"core_object,omitempty"`
	} `json:"attribution"`
	ThreatIntel struct {
		Enabled        bool     `json:"enabled"`
		STIXFiles      []string `json:"stix_files"`
		RefreshSeconds int      `json:"refresh_seconds"`
		EnrichmentFile string   `json:"enrichment_file,omitempty"`
		TAXII          []struct {
			Name       string `json:"name"`
			ObjectsURL string `json:"objects_url"`
			Token      string `json:"token"`
			Username   string `json:"username"`
			Password   string `json:"password"`
		} `json:"taxii"`
	} `json:"threat_intel"`
	Baseline struct {
		Enabled         bool `json:"enabled"`
		MinObservations int  `json:"min_observations"`
	} `json:"baseline"`
	Response struct {
		Enabled        bool     `json:"enabled"`
		DryRun         bool     `json:"dry_run"`
		AllowedActions []string `json:"allowed_actions"`
		Allowlist      []string `json:"allowlist"`
		MaxTTLSeconds  int      `json:"max_ttl_seconds"`
	} `json:"response"`
	Federation struct {
		SensorID        string `json:"sensor_id"`
		ControllerURL   string `json:"controller_url"`
		SensorToken     string `json:"sensor_token"`
		IngestEnabled   bool   `json:"ingest_enabled"`
		IngestToken     string `json:"ingest_token"`
		IntervalSeconds int    `json:"interval_seconds"`
	} `json:"federation"`
	Evidence struct {
		SigningEnabled bool `json:"signing_enabled"`
	} `json:"evidence"`
	FileExtraction struct {
		Enabled      bool   `json:"enabled"`
		StorePayload bool   `json:"store_payload"`
		MaxFileMB    int    `json:"max_file_mb"`
		MaxArtifacts int    `json:"max_artifacts"`
		YaraXBinary  string `json:"yara_x_binary"`
		YaraRules    string `json:"yara_rules"`
	} `json:"file_extraction"`
	Scripting struct {
		Enabled   bool   `json:"enabled"`
		RulesFile string `json:"rules_file"`
	} `json:"scripting"`
	SmartPCAP struct {
		Mode          string `json:"mode"`
		DefaultAction string `json:"default_action"`
		Rules         []struct {
			Name        string `json:"name"`
			Action      string `json:"action"`
			Process     string `json:"process,omitempty"`
			Application string `json:"application,omitempty"`
			Interface   string `json:"interface,omitempty"`
			IP          string `json:"ip,omitempty"`
			CIDR        string `json:"cidr,omitempty"`
			Direction   string `json:"direction,omitempty"`
		} `json:"rules"`
	} `json:"smart_pcap"`
	Streaming struct {
		Targets []struct {
			Name               string `json:"name"`
			Type               string `json:"type"`
			Enabled            bool   `json:"enabled"`
			Address            string `json:"address"`
			Topic              string `json:"topic,omitempty"`
			Token              string `json:"token,omitempty"`
			TLS                bool   `json:"tls,omitempty"`
			InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
			Binary             string `json:"binary,omitempty"`
			Queue              int    `json:"queue,omitempty"`
		} `json:"targets"`
	} `json:"streaming"`
	SelfProtection struct {
		Enabled              bool     `json:"enabled"`
		Paths                []string `json:"paths"`
		MinFreeMB            uint64   `json:"min_free_mb"`
		ClockRollbackSeconds int      `json:"clock_rollback_seconds"`
	} `json:"self_protection"`
	WASM struct {
		Enabled bool   `json:"enabled"`
		Runtime string `json:"runtime"`
		Plugins []struct {
			Name        string `json:"name"`
			Module      string `json:"module"`
			Enabled     bool   `json:"enabled"`
			TimeoutMS   int    `json:"timeout_ms"`
			MaxOutputKB int    `json:"max_output_kb"`
		} `json:"plugins"`
	} `json:"wasm"`
	Analyst struct {
		Enabled        bool   `json:"enabled"`
		RemoteEnabled  bool   `json:"remote_enabled"`
		Endpoint       string `json:"endpoint"`
		Model          string `json:"model"`
		APIKeyEnv      string `json:"api_key_env"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"analyst"`
	Vulnerability struct {
		Enabled          bool   `json:"enabled"`
		KEVFile          string `json:"kev_file"`
		KEVURL           string `json:"kev_url"`
		RefreshSeconds   int    `json:"refresh_seconds"`
		DiscoverPackages bool   `json:"discover_packages"`
	} `json:"vulnerability"`
	EncryptedDNS struct {
		Enabled          bool     `json:"enabled"`
		KnownResolvers   []string `json:"known_resolvers"`
		AllowedProcesses []string `json:"allowed_processes"`
	} `json:"encrypted_dns"`
	IdentityBaseline struct {
		Enabled         bool `json:"enabled"`
		MinObservations int  `json:"min_observations"`
	} `json:"identity_baseline"`
	Lateral struct {
		Enabled       bool `json:"enabled"`
		WindowSeconds int  `json:"window_seconds"`
		HostThreshold int  `json:"host_threshold"`
	} `json:"lateral"`
	Beacon struct {
		AdvancedEnabled   bool    `json:"advanced_enabled"`
		MinSamples        int     `json:"min_samples"`
		MaxJitter         float64 `json:"max_jitter"`
		MinSizeSimilarity float64 `json:"min_size_similarity"`
	} `json:"beacon"`
	ProtocolPacks struct {
		Enabled []string `json:"enabled"`
	} `json:"protocol_packs"`
	Analytics struct {
		MaxEvents int `json:"max_events"`
	} `json:"analytics"`
	Profiles struct {
		Enabled  bool   `json:"enabled"`
		Endpoint string `json:"endpoint"`
		TokenEnv string `json:"token_env"`
	} `json:"profiles"`
	Lab struct {
		AllowExternalFiles bool `json:"allow_external_files"`
	} `json:"lab"`
}

func Default() Config {
	var c Config
	c.Listen = "127.0.0.1:8443"
	c.Auth.Enabled = true
	c.Auth.DefaultUsername = "admin"
	c.Auth.SessionIdleMinutes = 30
	c.Auth.SessionAbsoluteHours = 12
	c.Auth.MaxFailures = 5
	c.Auth.LockoutSeconds = 300
	c.Auth.PasswordIterations = 600000
	c.Auth.PasswordMinLength = 12
	c.Auth.RequirePasswordChange = true
	c.Security.ConsoleAllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	c.OIDC.DefaultRole = "viewer"
	c.OIDC.UsernameClaim = "preferred_username"
	c.OIDC.Scopes = []string{"openid", "profile", "email"}
	c.Timeline.Enabled = true
	c.Timeline.IntervalSeconds = 30
	c.Timeline.MaxSnapshots = 10000
	c.DataDir = "/tmp/netprobe-ir"
	c.Capture.Backend = "auto"
	c.Capture.SnapLen = 65535
	c.Capture.ReadBuffer = 4 << 20
	c.Capture.FlowIdleSeconds = 120
	c.Recorder.Enabled = true
	c.Recorder.SegmentMB = 64
	c.Recorder.MaxDiskMB = 1024
	c.Recorder.IncidentCopies = true
	c.DPI.MaxStreamBytes = 128 * 1024
	c.Anomaly.Enabled = true
	c.Anomaly.ExfiltrationMB = 100
	c.Anomaly.FanoutDestinations = 50
	c.Anomaly.PortScanPorts = 30
	c.Anomaly.BurstConnections = 80
	c.Anomaly.BeaconMinSamples = 4
	c.Anomaly.BeaconMaxJitter = 0.15
	c.Anomaly.DNSEntropyThreshold = 4.2
	c.IDS.Enabled = true
	c.IDS.PortScanPorts = 20
	c.IDS.HostSweepHosts = 20
	c.IDS.WindowSeconds = 30
	c.IDS.DNSHighEntropyQueries = 12
	c.IDS.NXDomainThreshold = 20
	c.IDS.MaxFindings = 5000
	c.Attribution.Backend = "auto"
	c.ThreatIntel.Enabled = true
	c.ThreatIntel.RefreshSeconds = 900
	c.Baseline.Enabled = true
	c.Baseline.MinObservations = 20
	c.Response.DryRun = true
	c.Response.MaxTTLSeconds = 3600
	c.Response.AllowedActions = []string{"block_ip", "unblock_ip", "kill_process", "disable_interface", "enable_interface"}
	c.Federation.IntervalSeconds = 10
	c.Evidence.SigningEnabled = true
	c.FileExtraction.Enabled = true
	c.FileExtraction.StorePayload = true
	c.FileExtraction.MaxFileMB = 32
	c.FileExtraction.MaxArtifacts = 2000
	c.FileExtraction.YaraXBinary = "yr"
	c.SmartPCAP.Mode = "full"
	c.SmartPCAP.DefaultAction = "full"
	c.SelfProtection.Enabled = true
	c.SelfProtection.MinFreeMB = 256
	c.SelfProtection.ClockRollbackSeconds = 5
	c.Analyst.Enabled = true
	c.Analyst.TimeoutSeconds = 20
	c.Vulnerability.Enabled = true
	c.Vulnerability.RefreshSeconds = 86400
	c.Vulnerability.DiscoverPackages = true
	c.EncryptedDNS.Enabled = true
	c.IdentityBaseline.Enabled = true
	c.IdentityBaseline.MinObservations = 20
	c.Lateral.Enabled = true
	c.Lateral.WindowSeconds = 120
	c.Lateral.HostThreshold = 5
	c.Beacon.AdvancedEnabled = true
	c.Beacon.MinSamples = 5
	c.Beacon.MaxJitter = 0.15
	c.Beacon.MinSizeSimilarity = 0.80
	c.ProtocolPacks.Enabled = []string{"core", "enterprise", "database", "devops", "ics"}
	c.Analytics.MaxEvents = 200000
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Config) Prepare() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir cannot be empty")
	}
	switch strings.ToLower(strings.TrimSpace(c.Capture.Backend)) {
	case "", "auto", "tpacket_v3", "packet_mmap", "af_packet":
	case "af_xdp":
		return fmt.Errorf("capture.backend=af_xdp is not a passive-safe backend; use auto/tpacket_v3")
	default:
		return fmt.Errorf("unknown capture.backend %q", c.Capture.Backend)
	}
	switch strings.ToLower(strings.TrimSpace(c.Attribution.Backend)) {
	case "", "auto", "proc", "ebpf":
	default:
		return fmt.Errorf("unknown attribution.backend %q", c.Attribution.Backend)
	}
	if c.Federation.IngestEnabled && strings.TrimSpace(c.Federation.IngestToken) == "" {
		return fmt.Errorf("federation.ingest_token is required when ingest_enabled=true")
	}
	if c.Federation.ControllerURL != "" && strings.TrimSpace(c.Federation.SensorID) == "" {
		return fmt.Errorf("federation.sensor_id is required when controller_url is configured")
	}
	for _, cidr := range c.Security.ConsoleAllowedCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid security.console_allowed_cidrs entry %q", cidr)
		}
	}
	if c.Security.RequireSignedConfig && strings.TrimSpace(c.Security.ConfigTrustedPublicKey) == "" {
		return fmt.Errorf("security.config_trusted_public_key is required when require_signed_config=true")
	}
	if mode := strings.ToLower(strings.TrimSpace(c.SmartPCAP.Mode)); mode != "" && mode != "full" && mode != "smart" && mode != "metadata" {
		return fmt.Errorf("invalid smart_pcap.mode %q", c.SmartPCAP.Mode)
	}
	for _, t := range c.Streaming.Targets {
		if !t.Enabled {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(t.Type)) {
		case "otlp", "opentelemetry", "nats", "kafka", "clickhouse":
		default:
			return fmt.Errorf("invalid streaming target type %q", t.Type)
		}
		if strings.TrimSpace(t.Address) == "" {
			return fmt.Errorf("streaming target %q address is required", t.Name)
		}
	}
	if c.WASM.Enabled && len(c.WASM.Plugins) > 0 && strings.TrimSpace(c.WASM.Runtime) == "" {
		c.WASM.Runtime = "wasmtime"
	}
	if c.OIDC.Enabled {
		if strings.TrimSpace(c.OIDC.Issuer) == "" || strings.TrimSpace(c.OIDC.ClientID) == "" || strings.TrimSpace(c.OIDC.RedirectURL) == "" {
			return fmt.Errorf("oidc issuer, client_id and redirect_url are required when OIDC is enabled")
		}
		u, err := url.Parse(c.OIDC.RedirectURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid oidc.redirect_url")
		}
		switch c.OIDC.DefaultRole {
		case "viewer", "analyst", "responder", "admin":
		default:
			return fmt.Errorf("invalid oidc.default_role %q", c.OIDC.DefaultRole)
		}
	}
	if c.Analytics.MaxEvents <= 0 {
		c.Analytics.MaxEvents = 200000
	}
	if c.Profiles.Enabled {
		u, err := url.Parse(strings.TrimSpace(c.Profiles.Endpoint))
		if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("profiles.endpoint must be a valid HTTP/HTTPS URL when profiles.enabled=true")
		}
	}
	for _, wh := range c.Integrations.Webhooks {
		if !wh.Enabled {
			continue
		}
		u, err := url.Parse(wh.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid enabled webhook URL %q", wh.URL)
		}
	}
	for _, d := range []string{c.DataDir, filepath.Join(c.DataDir, "pcap"), filepath.Join(c.DataDir, "incidents"), filepath.Join(c.DataDir, "reports"), filepath.Join(c.DataDir, "cases"), filepath.Join(c.DataDir, "evidence"), filepath.Join(c.DataDir, "baseline"), filepath.Join(c.DataDir, "replay"), filepath.Join(c.DataDir, "auth"), filepath.Join(c.DataDir, "audit"), filepath.Join(c.DataDir, "tuning"), filepath.Join(c.DataDir, "timeline"), filepath.Join(c.DataDir, "backups"), filepath.Join(c.DataDir, "exporters"), filepath.Join(c.DataDir, "files"), filepath.Join(c.DataDir, "federation"), filepath.Join(c.DataDir, "analytics"), filepath.Join(c.DataDir, "response"), filepath.Join(c.DataDir, "bpf")} {
		if err := os.MkdirAll(d, 0750); err != nil {
			return err
		}
	}
	host := c.Listen
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	if !loopback && !c.Auth.Enabled && c.AuthToken == "" && !c.AllowUnauthenticatedRemote {
		return fmt.Errorf("refusing unauthenticated remote web binding %q; enable auth, configure auth_token, or allow_unauthenticated_remote", c.Listen)
	}
	return nil
}
