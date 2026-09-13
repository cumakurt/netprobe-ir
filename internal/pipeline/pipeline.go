package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/analyst"
	"netprobe-ir/internal/analytics"
	"netprobe-ir/internal/anomaly"
	"netprobe-ir/internal/baseline"
	"netprobe-ir/internal/beacon"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/cases"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/coreebpf"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/detectionquality"
	"netprobe-ir/internal/dnsgraph"
	"netprobe-ir/internal/dnsintel"
	"netprobe-ir/internal/dpi"
	"netprobe-ir/internal/ebpfattr"
	"netprobe-ir/internal/enrichment"
	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/federation"
	"netprobe-ir/internal/fileextract"
	"netprobe-ir/internal/flow"
	"netprobe-ir/internal/flowexport"
	"netprobe-ir/internal/identitybaseline"
	"netprobe-ir/internal/ids"
	"netprobe-ir/internal/integrations"
	"netprobe-ir/internal/investigation"
	"netprobe-ir/internal/lateral"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/netbaseline"
	"netprobe-ir/internal/notifications"
	"netprobe-ir/internal/pcapng"
	"netprobe-ir/internal/playbook"
	"netprobe-ir/internal/procmap"
	"netprobe-ir/internal/replay"
	"netprobe-ir/internal/response"
	"netprobe-ir/internal/runtimeanomaly"
	"netprobe-ir/internal/scripting"
	"netprobe-ir/internal/selfprotect"
	"netprobe-ir/internal/smartpcap"
	"netprobe-ir/internal/stories"
	"netprobe-ir/internal/streaming"
	"netprobe-ir/internal/syslogexport"
	"netprobe-ir/internal/threatintel"
	"netprobe-ir/internal/timeline"
	"netprobe-ir/internal/tlsintel"
	"netprobe-ir/internal/trafficseries"
	"netprobe-ir/internal/tuning"
	"netprobe-ir/internal/vulnintel"
	"netprobe-ir/internal/wasmplugin"
)

const packetHistoryLimit = 1000

type captureSession struct {
	capture    capture.Source
	cancel     context.CancelFunc
	done       chan struct{}
	running    bool
	stopping   bool
	generation uint64
	startedAt  *time.Time
	stoppedAt  *time.Time
}

type Engine struct {
	Config           config.Config
	Started          time.Time
	Store            *flow.Store
	DPI              *dpi.Engine
	Proc             *procmap.Tracker
	Anomaly          *anomaly.Engine
	IDS              *ids.Engine
	Baseline         *baseline.Engine
	ThreatIntel      *threatintel.Hub
	Cases            *cases.Store
	Evidence         *evidence.Signer
	Response         *response.Manager
	RuntimeAnomaly   *runtimeanomaly.Engine
	Federation       *federation.Hub
	Integrations     *integrations.Manager
	EventBus         *eventbus.Bus
	SyslogExport     *syslogexport.Manager
	FlowExport       *flowexport.Manager
	Files            *fileextract.Engine
	Scripts          *scripting.Engine
	AdvancedBeacon   *beacon.Engine
	DNSIntel         *dnsintel.Engine
	Quality          *detectionquality.Store
	Analytics        *analytics.Store
	DNSGraph         *dnsgraph.Graph
	TLSIntel         *tlsintel.Store
	Playbooks        *playbook.Store
	PlaybookApproval func(model.SecurityFinding, playbook.Match)
	CoreEBPF         coreebpf.Capability
	Enrichment       *enrichment.Cache
	IdentityBaseline *identitybaseline.Engine
	Lateral          *lateral.Engine
	Streaming        *streaming.Manager
	SelfProtect      *selfprotect.Monitor
	WASM             *wasmplugin.Runner
	VulnIntel        *vulnintel.Hub
	Analyst          *analyst.Analyst
	SmartPolicy      smartpcap.Policy
	Tuning           *tuning.Store
	Timeline         *timeline.Store
	NetworkBaseline  *netbaseline.Store
	Notifications    *notifications.Manager
	TrafficSeries    *trafficseries.Store
	EBPF             *ebpfattr.Runner
	Recorder         *pcapng.Recorder
	frames           chan capture.Frame
	decodeErrors     atomic.Uint64
	recorderDrops    atomic.Uint64
	packetSeq        atomic.Uint64

	mu            sync.RWMutex
	lastError     string
	packets       []model.PacketSummary
	runtimeEvents []model.RuntimeEvent

	lifecycleMu        sync.Mutex
	rootCtx            context.Context
	captureRunning     bool
	captureStarted     *time.Time
	captureStopped     *time.Time
	captures           map[string]*captureSession
	backgroundStart    sync.Once
	attributionBackend string
	afxdpAvailable     bool
	afxdpReason        string
	beaconGroups       []beacon.Group
	selfHealth         selfprotect.Health
}

func New(c config.Config) *Engine {
	an := anomaly.New(anomaly.Config{ExfiltrationBytes: c.Anomaly.ExfiltrationMB << 20, FanoutDestinations: c.Anomaly.FanoutDestinations, PortScanPorts: c.Anomaly.PortScanPorts, BurstConnections: c.Anomaly.BurstConnections, BeaconMinSamples: c.Anomaly.BeaconMinSamples, BeaconMaxJitter: c.Anomaly.BeaconMaxJitter, DNSEntropyThreshold: c.Anomaly.DNSEntropyThreshold})
	id := ids.New(ids.Config{Enabled: c.IDS.Enabled, HomeNets: c.IDS.HomeNets, PortScanPorts: c.IDS.PortScanPorts, HostSweepHosts: c.IDS.HostSweepHosts, WindowSeconds: c.IDS.WindowSeconds, DNSHighEntropyQueries: c.IDS.DNSHighEntropyQueries, NXDomainThreshold: c.IDS.NXDomainThreshold, IOCFile: c.IDS.IOCFile, RulesFile: c.IDS.RulesFile, RulesSignature: c.IDS.RulesSignature, RulesTrustedPublicKey: c.IDS.RulesTrustedPublicKey, RequireSignedRules: c.IDS.RequireSignedRules, MaxFindings: c.IDS.MaxFindings, RuleLabMode: c.IDS.RuleLabMode})
	e := &Engine{Config: c, Started: time.Now(), Store: flow.New(time.Duration(c.Capture.FlowIdleSeconds) * time.Second), DPI: dpi.New(c.DPI.MaxStreamBytes), Proc: procmap.New(), Anomaly: an, IDS: id, frames: make(chan capture.Frame, 16384), packets: make([]model.PacketSummary, 0, packetHistoryLimit), runtimeEvents: make([]model.RuntimeEvent, 0, 2000), captures: map[string]*captureSession{}, attributionBackend: "proc"}
	e.Quality = detectionquality.New(filepath.Join(c.DataDir, "detection-quality", "runs.json"))
	e.Analytics = analytics.Open(filepath.Join(c.DataDir, "analytics", "events.jsonl"), c.Analytics.MaxEvents)
	e.DNSGraph = dnsgraph.New()
	e.TLSIntel = tlsintel.New(10000)
	e.Playbooks, _ = playbook.Open(filepath.Join(c.DataDir, "response", "playbooks.json"))
	coreObj := strings.TrimSpace(c.Attribution.CoreObject)
	if coreObj == "" {
		coreObj = filepath.Join(c.DataDir, "bpf", "netprobe_runtime.bpf.o")
	}
	e.CoreEBPF = coreebpf.Probe(coreObj)
	if strings.TrimSpace(c.ThreatIntel.EnrichmentFile) != "" {
		if ec, err := enrichment.Load(c.ThreatIntel.EnrichmentFile); err == nil {
			e.Enrichment = ec
		} else {
			e.setError("enrichment: " + err.Error())
		}
	}
	e.DPI.SetProtocolPacks(c.ProtocolPacks.Enabled)
	e.EventBus = eventbus.New()
	e.TrafficSeries = trafficseries.New(e.EventBus, 90000)
	if nm, err := notifications.Open(c.DataDir); err == nil {
		e.Notifications = nm
	} else {
		e.setError("notifications: " + err.Error())
	}
	if sm, err := syslogexport.New(c.DataDir+"/exporters/syslog.json", e.EventBus); err == nil {
		e.SyslogExport = sm
	} else {
		e.setError("syslog exporter: " + err.Error())
	}
	if fm, err := flowexport.New(c.DataDir+"/exporters/flow.json", e.EventBus); err == nil {
		e.FlowExport = fm
	} else {
		e.setError("flow exporter: " + err.Error())
	}
	// v0.7 analysis and extension modules share the same event/model pipeline.
	e.Files = fileextract.New(c.DataDir+"/files", fileextract.Config{Enabled: c.FileExtraction.Enabled, StorePayload: c.FileExtraction.StorePayload, MaxFileBytes: c.FileExtraction.MaxFileMB << 20, MaxArtifacts: c.FileExtraction.MaxArtifacts, YaraBinary: c.FileExtraction.YaraXBinary, YaraRules: c.FileExtraction.YaraRules}, nil)
	e.Scripts = scripting.New()
	if c.Scripting.Enabled && strings.TrimSpace(c.Scripting.RulesFile) != "" {
		if err := e.Scripts.Load(c.Scripting.RulesFile); err != nil {
			e.setError("scripting: " + err.Error())
		}
	}
	e.AdvancedBeacon = beacon.New(beacon.Config{MinSamples: c.Beacon.MinSamples, MaxJitter: c.Beacon.MaxJitter, MinSimilarity: c.Beacon.MinSizeSimilarity})
	e.DNSIntel = dnsintel.New(dnsintel.Config{Enabled: c.EncryptedDNS.Enabled, KnownResolvers: c.EncryptedDNS.KnownResolvers, AllowedProcesses: c.EncryptedDNS.AllowedProcesses})
	e.IdentityBaseline = identitybaseline.New(c.DataDir+"/baseline/identity-network.json", c.IdentityBaseline.MinObservations)
	e.Lateral = lateral.New(lateral.Config{Window: time.Duration(c.Lateral.WindowSeconds) * time.Second, HostThreshold: c.Lateral.HostThreshold})
	var streamTargets []streaming.Target
	for _, t := range c.Streaming.Targets {
		streamTargets = append(streamTargets, streaming.Target{Name: t.Name, Type: t.Type, Enabled: t.Enabled, Address: t.Address, Topic: t.Topic, Token: t.Token, TLS: t.TLS, InsecureSkipVerify: t.InsecureSkipVerify, Binary: t.Binary, Queue: t.Queue})
	}
	e.Streaming = streaming.New(e.EventBus, streamTargets)
	watch := append([]string(nil), c.SelfProtection.Paths...)
	if len(watch) == 0 {
		if x, err := os.Executable(); err == nil {
			watch = append(watch, x)
		}
		if c.IDS.RulesFile != "" {
			watch = append(watch, c.IDS.RulesFile)
		}
		if c.IDS.IOCFile != "" {
			watch = append(watch, c.IDS.IOCFile)
		}
	}
	e.SelfProtect = selfprotect.New(selfprotect.Config{Enabled: c.SelfProtection.Enabled, Paths: watch, DataDir: c.DataDir, MinFreeMB: c.SelfProtection.MinFreeMB, ClockRollbackSeconds: c.SelfProtection.ClockRollbackSeconds})
	var wp []wasmplugin.Plugin
	for _, x := range c.WASM.Plugins {
		wp = append(wp, wasmplugin.Plugin{Name: x.Name, Module: x.Module, Enabled: x.Enabled, TimeoutMS: x.TimeoutMS, MaxOutputKB: x.MaxOutputKB})
	}
	if c.WASM.Enabled {
		e.WASM = wasmplugin.New(c.WASM.Runtime, wp)
	}
	e.VulnIntel = vulnintel.New()
	e.Analyst = analyst.New(analyst.Config{Enabled: c.Analyst.Enabled, RemoteEnabled: c.Analyst.RemoteEnabled, Endpoint: c.Analyst.Endpoint, Model: c.Analyst.Model, APIKeyEnv: c.Analyst.APIKeyEnv, TimeoutSeconds: c.Analyst.TimeoutSeconds})
	e.SmartPolicy = smartpcap.Policy{Mode: c.SmartPCAP.Mode, DefaultAction: c.SmartPCAP.DefaultAction}
	for _, r := range c.SmartPCAP.Rules {
		e.SmartPolicy.Rules = append(e.SmartPolicy.Rules, smartpcap.Rule{Name: r.Name, Action: r.Action, Process: r.Process, Application: r.Application, Interface: r.Interface, IP: r.IP, CIDR: r.CIDR, Direction: r.Direction})
	}
	e.Baseline = baseline.New(c.DataDir+"/baseline/process-network.json", c.Baseline.MinObservations)
	e.ThreatIntel = threatintel.New()
	e.Response = response.New(response.Config{Enabled: c.Response.Enabled, DryRun: c.Response.DryRun, AllowedActions: c.Response.AllowedActions, Allowlist: c.Response.Allowlist, MaxTTLSeconds: c.Response.MaxTTLSeconds})
	e.RuntimeAnomaly = runtimeanomaly.New()
	e.Federation = federation.NewHubPersistent(filepath.Join(c.DataDir, "federation", "fleet.json"))
	ic := integrations.Config{}
	for _, w := range c.Integrations.Webhooks {
		ic.Webhooks = append(ic.Webhooks, integrations.Webhook{Name: w.Name, URL: w.URL, Token: w.Token, MinSeverity: w.MinSeverity, Enabled: w.Enabled})
	}
	ic.Syslog = integrations.Syslog{Enabled: c.Integrations.Syslog.Enabled, Network: c.Integrations.Syslog.Network, Address: c.Integrations.Syslog.Address, Format: c.Integrations.Syslog.Format, MinSeverity: c.Integrations.Syslog.MinSeverity}
	e.Integrations = integrations.New(ic)
	e.Tuning, _ = tuning.New(c.DataDir + "/tuning/suppressions.json")
	if c.Timeline.Enabled {
		e.Timeline = timeline.New(c.DataDir+"/timeline/snapshots.jsonl", c.Timeline.MaxSnapshots)
	}
	e.NetworkBaseline = netbaseline.New(c.DataDir + "/baseline/network-events.jsonl")
	e.EBPF = &ebpfattr.Runner{Path: c.Attribution.BPFTracePath}
	e.afxdpAvailable, e.afxdpReason = capture.ProbeAFXDP()
	if signer, err := evidence.NewSigner(c.DataDir+"/evidence/ed25519.key", c.Evidence.SigningEnabled); err == nil {
		e.Evidence = signer
	} else {
		e.setError("evidence signer: " + err.Error())
	}
	if cs, err := cases.New(c.DataDir+"/cases", e.Evidence); err == nil {
		e.Cases = cs
		e.Cases.SetImmutable(c.Security.ForensicImmutable)
	} else {
		e.setError("case store: " + err.Error())
	}
	if c.Recorder.Enabled {
		e.Recorder = pcapng.New(c.DataDir+"/pcap", c.Recorder.SegmentMB, c.Recorder.MaxDiskMB, c.Recorder.IncidentCopies)
	}
	return e
}

func DiscoverInterfaces() []string {
	ifs, _ := net.Interfaces()
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 {
			out = append(out, i.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Start launches the long-lived processing services and begins packet capture.
// The web/API server can later pause and resume only the capture layer without
// terminating the daemon, which keeps the control plane reachable.
func (e *Engine) Start(ctx context.Context) error {
	e.lifecycleMu.Lock()
	if e.rootCtx == nil {
		e.rootCtx = ctx
	}
	e.lifecycleMu.Unlock()

	e.backgroundStart.Do(func() {
		go e.Proc.Run(ctx, 2*time.Second)
		go e.startThreatIntel(ctx)
		go e.startAttribution(ctx)
		if e.Files != nil {
			e.Files.Start(ctx)
			go e.consumeFileUpdates(ctx)
		}
		if e.Streaming != nil {
			e.Streaming.Start(ctx)
		}
		go e.startVulnerability(ctx)
		if e.WASM != nil {
			go e.startWASM(ctx)
		}
		if e.SyslogExport != nil {
			e.SyslogExport.Start(ctx)
		}
		if e.FlowExport != nil {
			e.FlowExport.Start(ctx)
		}
		if e.Recorder != nil {
			go func() {
				if err := e.Recorder.Run(ctx); err != nil && ctx.Err() == nil {
					e.setError("recorder: " + err.Error())
				}
			}()
		}
		go e.processor(ctx)
		go e.maintenance(ctx)
		go func() {
			<-ctx.Done()
			_ = e.StopCapture()
			if e.Notifications != nil {
				e.Notifications.Close()
			}
			if e.TrafficSeries != nil {
				e.TrafficSeries.Close()
			}
		}()
	})
	return e.StartCapture()
}

// StartCapture starts or resumes every configured/discovered interface. Calling
// it while all interfaces are already active is idempotent.
func (e *Engine) StartCapture() error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if e.rootCtx == nil {
		return fmt.Errorf("engine background services are not started")
	}
	if err := e.rootCtx.Err(); err != nil {
		return fmt.Errorf("engine context is closed: %w", err)
	}
	if err := e.ensureCaptureSessionsLocked(); err != nil {
		return err
	}
	for name, cs := range e.captures {
		if cs.stopping {
			return fmt.Errorf("interface %s is still stopping", name)
		}
		if !cs.running {
			e.startInterfaceLocked(name, cs)
		}
	}
	e.captureRunning = e.anyRunningLocked()
	if e.captureRunning {
		now := time.Now()
		e.captureStarted = &now
		e.captureStopped = nil
		e.clearError()
	}
	return nil
}

// StopCapture stops packet acquisition on every interface while keeping the
// web/API control plane and retained evidence available.
func (e *Engine) StopCapture() error {
	e.lifecycleMu.Lock()
	var waits []<-chan struct{}
	for _, cs := range e.captures {
		if !cs.running {
			continue
		}
		cs.running = false
		cs.stopping = true
		now := time.Now()
		cs.stoppedAt = &now
		if cs.cancel != nil {
			cs.cancel()
		}
		if cs.done != nil {
			waits = append(waits, cs.done)
		}
	}
	e.captureRunning = false
	now := time.Now()
	e.captureStopped = &now
	e.lifecycleMu.Unlock()
	for _, done := range waits {
		<-done
	}
	e.lifecycleMu.Lock()
	for _, cs := range e.captures {
		cs.stopping = false
	}
	e.lifecycleMu.Unlock()
	return nil
}

// StartInterface starts acquisition only for one interface. It can be used
// while other interfaces remain paused.
func (e *Engine) StartInterface(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("interface name is required")
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if e.rootCtx == nil {
		return fmt.Errorf("engine background services are not started")
	}
	if err := e.rootCtx.Err(); err != nil {
		return fmt.Errorf("engine context is closed: %w", err)
	}
	if err := e.ensureCaptureSessionsLocked(); err != nil {
		return err
	}
	cs := e.captures[name]
	if cs == nil {
		return fmt.Errorf("interface %q is not configured or active", name)
	}
	if cs.stopping {
		return fmt.Errorf("interface %s is still stopping", name)
	}
	if !cs.running {
		e.startInterfaceLocked(name, cs)
	}
	e.captureRunning = e.anyRunningLocked()
	now := time.Now()
	e.captureStarted = &now
	e.captureStopped = nil
	e.clearError()
	return nil
}

// StopInterface pauses one capture source without affecting the remaining
// interfaces. The call waits for the AF_PACKET goroutine to release its socket.
func (e *Engine) StopInterface(name string) error {
	name = strings.TrimSpace(name)
	e.lifecycleMu.Lock()
	cs := e.captures[name]
	if cs == nil {
		e.lifecycleMu.Unlock()
		return fmt.Errorf("interface %q is not configured", name)
	}
	if !cs.running && !cs.stopping {
		e.lifecycleMu.Unlock()
		return nil
	}
	if cs.stopping {
		done := cs.done
		e.lifecycleMu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	cs.running = false
	cs.stopping = true
	now := time.Now()
	cs.stoppedAt = &now
	if cs.cancel != nil {
		cs.cancel()
	}
	done := cs.done
	e.captureRunning = e.anyRunningLocked()
	if !e.captureRunning {
		e.captureStopped = &now
	}
	e.lifecycleMu.Unlock()
	if done != nil {
		<-done
	}
	e.lifecycleMu.Lock()
	cs.stopping = false
	e.lifecycleMu.Unlock()
	return nil
}

func (e *Engine) CaptureRunning() bool {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.anyRunningLocked()
}

func (e *Engine) ensureCaptureSessionsLocked() error {
	if len(e.captures) > 0 {
		return nil
	}
	names := append([]string(nil), e.Config.Interfaces...)
	if len(names) == 0 {
		names = DiscoverInterfaces()
	}
	if len(names) == 0 {
		return fmt.Errorf("no active interfaces found")
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := e.captures[name]; ok {
			continue
		}
		src, err := capture.NewSource(e.Config.Capture.Backend, capture.SourceConfig{Interface: name, SnapLen: e.Config.Capture.SnapLen, ReceiveBuffer: e.Config.Capture.ReadBuffer})
		if err != nil {
			return fmt.Errorf("capture backend for %s: %w", name, err)
		}
		e.captures[name] = &captureSession{capture: src}
	}
	if len(e.captures) == 0 {
		return fmt.Errorf("no usable interfaces found")
	}
	return nil
}

func (e *Engine) startInterfaceLocked(name string, cs *captureSession) {
	ctx, cancel := context.WithCancel(e.rootCtx)
	cs.cancel = cancel
	cs.done = make(chan struct{})
	cs.running = true
	cs.stopping = false
	cs.generation++
	generation := cs.generation
	now := time.Now()
	cs.startedAt = &now
	cs.stoppedAt = nil
	capObj := cs.capture
	done := cs.done
	go func() {
		defer close(done)
		err := capObj.Run(ctx, e.frames)
		if err != nil && ctx.Err() == nil {
			e.setError(fmt.Sprintf("capture %s: %v", name, err))
		}
		e.lifecycleMu.Lock()
		defer e.lifecycleMu.Unlock()
		current := e.captures[name]
		if current == nil || current.generation != generation {
			return
		}
		if ctx.Err() == nil {
			current.running = false
			current.stopping = false
			t := time.Now()
			current.stoppedAt = &t
		}
		e.captureRunning = e.anyRunningLocked()
		if !e.captureRunning {
			t := time.Now()
			e.captureStopped = &t
		}
	}()
}

func (e *Engine) anyRunningLocked() bool {
	for _, cs := range e.captures {
		if cs.running {
			return true
		}
	}
	return false
}

func (e *Engine) setError(s string) { e.mu.Lock(); e.lastError = s; e.mu.Unlock() }
func (e *Engine) clearError()       { e.mu.Lock(); e.lastError = ""; e.mu.Unlock() }
func (e *Engine) LastError() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.lastError }

func (e *Engine) processor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case fr := <-e.frames:
			e.ProcessFrame(fr)
		}
	}
}

func (e *Engine) ProcessFrame(fr capture.Frame)       { e.processFrame(fr, true) }
func (e *Engine) ProcessReplayFrame(fr capture.Frame) { e.processFrame(fr, false) }
func (e *Engine) processFrame(fr capture.Frame, attributeProcess bool) {
	p, err := decode.ParseEthernet(fr.Data, fr.Time, fr.Interface, fr.Direction)
	if err != nil {
		e.decodeErrors.Add(1)
		return
	}
	var proc *model.ProcessInfo
	attr := "offline-replay"
	if attributeProcess {
		proc, attr = e.Proc.LookupFresh(p.Protocol, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Direction)
	}
	dir := p.Direction
	localIP, remoteIP := p.SrcIP, p.DstIP
	localPort, remotePort := p.SrcPort, p.DstPort
	if attr == "forwarded" {
		dir = model.DirectionForwarded
	} else if dir == model.DirectionInbound {
		localIP, remoteIP = p.DstIP, p.SrcIP
		localPort, remotePort = p.DstPort, p.SrcPort
	}
	id := flow.Key(p, localIP, localPort, remoteIP, remotePort)
	di := e.DPI.Inspect(id, dir, p)
	f, created := e.Store.Observe(p, proc, attr, di, localIP, localPort, remoteIP, remotePort, dir)
	if attributeProcess && created && e.NetworkBaseline != nil {
		_ = e.NetworkBaseline.Observe(f)
	}
	if created && e.Analytics != nil {
		procName := ""
		if f.Process != nil {
			procName = f.Process.Comm
		}
		_ = e.Analytics.Append(analytics.Event{Time: f.FirstSeen, Type: "flow", Process: procName, Destination: f.Remote.IP, Key: f.ID, Meta: map[string]any{"protocol": f.NetworkProtocol, "application": f.DPI.Application, "direction": f.Direction}})
	}
	if e.DNSGraph != nil && di.DNS != nil && di.DNS.Query != "" && len(di.DNS.Answers) > 0 {
		e.DNSGraph.Observe(di.DNS.Query, di.DNS.Answers, p.Time)
	}
	if e.TLSIntel != nil && di.TLS != nil && di.TLS.Certificate != nil {
		e.TLSIntel.Observe(f)
	}
	packetID := e.recordPacket(p, proc, attr, di, id, dir)
	decision := e.SmartPolicy.Decide(p, f)
	if e.Recorder != nil {
		if evidenceFrame, ok := smartpcap.Apply(decision, p, fr); ok && !e.Recorder.Record(evidenceFrame) {
			e.recorderDrops.Add(1)
		}
	}
	// File reconstruction is evidence retention, not merely transient DPI. Respect
	// Smart-PCAP privacy policy: headers/metadata/drop modes must not create a
	// second payload-retention path through reconstructed files.
	if e.Files != nil && decision.Action == "full" {
		for _, a := range e.Files.Observe(p, f, di) {
			if e.EventBus != nil {
				e.EventBus.Publish(eventbus.Event{Time: a.Time, Category: "file", Type: "file_artifact", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: a})
			}
			if e.Scripts != nil && e.Config.Scripting.Enabled {
				for _, sf := range e.Scripts.Evaluate(scripting.Context{Flow: f, File: &a}) {
					e.IDS.AddFinding(sf)
					e.onFinding(sf)
				}
			}
		}
	}

	riskScore := 0
	var riskReasons []string
	if e.Config.Lateral.Enabled && e.Lateral != nil {
		for _, finding := range e.Lateral.Observe(p, f, created) {
			e.IDS.AddFinding(finding)
			e.onFinding(finding)
			r := findingRisk(finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "Lateral "+finding.RuleID+": "+finding.Title)
		}
	}
	if e.Config.Anomaly.Enabled {
		score, reasons, alerts := e.Anomaly.Observe(f, created)
		if score > riskScore {
			riskScore = score
		}
		riskReasons = append(riskReasons, reasons...)
		for _, a := range alerts {
			if e.EventBus != nil {
				e.EventBus.Publish(eventbus.Event{Time: a.Time, Category: "anomaly", Type: "anomaly_alert", Severity: a.Severity, FlowID: a.FlowID, Payload: a})
			}
			if (a.Severity == "high" || a.Severity == "critical") && e.Recorder != nil {
				e.Recorder.Protect(a.Rule)
			}
		}
	}
	if e.Config.IDS.Enabled && e.IDS != nil {
		findings := e.IDS.Observe(p, f, created, packetID)
		for _, finding := range findings {
			e.onFinding(finding)
			r := findingRisk(finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "IDS "+finding.RuleID+": "+finding.Title)
			if (finding.Severity == "high" || finding.Severity == "critical") && e.Recorder != nil {
				e.Recorder.Protect(finding.RuleID)
			}
		}
	}
	if e.Config.Baseline.Enabled && e.Baseline != nil {
		for _, finding := range e.Baseline.Observe(f, created) {
			e.IDS.AddFinding(finding)
			e.onFinding(finding)
			r := findingRisk(finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "Baseline "+finding.RuleID+": "+finding.Title)
		}
	}
	if e.Config.IdentityBaseline.Enabled && e.IdentityBaseline != nil {
		for _, finding := range e.IdentityBaseline.Observe(f, created) {
			e.IDS.AddFinding(finding)
			e.onFinding(finding)
			r := findingRisk(finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "Identity baseline "+finding.RuleID+": "+finding.Title)
		}
	}
	if e.DNSIntel != nil {
		if _, finding := e.DNSIntel.Observe(f, created); finding != nil {
			e.IDS.AddFinding(*finding)
			e.onFinding(*finding)
			r := findingRisk(*finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "Encrypted DNS: "+finding.Title)
		}
	}
	if e.Scripts != nil && e.Config.Scripting.Enabled {
		if ps, ok := e.Packet(packetID); ok {
			for _, finding := range e.Scripts.Evaluate(scripting.Context{Flow: f, Packet: &ps}) {
				e.IDS.AddFinding(finding)
				e.onFinding(finding)
				r := findingRisk(finding)
				if r > riskScore {
					riskScore = r
				}
				riskReasons = append(riskReasons, "NPDL "+finding.RuleID+": "+finding.Title)
			}
		}
	}
	if e.Config.ThreatIntel.Enabled && e.ThreatIntel != nil {
		for _, m := range e.ThreatIntel.MatchFlow(f) {
			finding := e.threatFinding(f, p, packetID, m)
			e.IDS.AddFinding(finding)
			e.onFinding(finding)
			r := findingRisk(finding)
			if r > riskScore {
				riskScore = r
			}
			riskReasons = append(riskReasons, "Threat Intel: "+m.Indicator.Type+"="+m.Observed)
			if e.Recorder != nil {
				e.Recorder.Protect(finding.RuleID)
			}
		}
	}
	if riskScore > 0 {
		e.Store.SetRisk(f.ID, riskScore, uniqueStrings(riskReasons))
	}
	if latest, ok := e.Store.Get(f.ID); ok {
		f = latest
	}
	e.publishTelemetry(p, f, proc, di, packetID)
}

func (e *Engine) PublishSystemEvent(kind string, payload any) {
	if e.EventBus != nil {
		e.EventBus.Publish(eventbus.Event{Time: time.Now().UTC(), Category: "system", Type: kind, Severity: "info", Payload: payload})
	}
}

func (e *Engine) publishTelemetry(p *decode.Packet, f model.Flow, proc *model.ProcessInfo, di model.DPIInfo, packetID string) {
	if e.EventBus == nil {
		return
	}
	packet := model.PacketSummary{ID: packetID, Time: p.Time, Interface: p.Interface, Direction: f.Direction, NetworkProtocol: p.Protocol, IPVersion: p.IPVersion, Source: model.Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Destination: model.Endpoint{IP: p.DstIP, Port: p.DstPort}, Length: len(p.Raw), TCPFlags: decode.TCPFlagsString(p.TCPFlags), ToS: p.ToS, VLANID: p.VLANID, ICMPType: p.ICMPType, ICMPCode: p.ICMPCode, FlowID: f.ID, DPI: di, Attribution: f.Attribution}
	if proc != nil {
		cp := *proc
		packet.Process = &cp
	}
	e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "network", Type: "packet_metadata", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: packet})
	e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "flow", Type: "flow_update", Interface: p.Interface, FlowID: f.ID, Payload: f})
	if di.Protocol != "" || di.Application != "" {
		e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "dpi", Type: "dpi_classification", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: di})
	}
	if di.DNS != nil {
		e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "dns", Type: "dns", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: di.DNS})
	}
	if di.HTTP != nil {
		e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "http", Type: "http", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: di.HTTP})
	}
	if di.TLS != nil {
		e.EventBus.Publish(eventbus.Event{Time: p.Time, Category: "tls", Type: "tls", Interface: p.Interface, FlowID: f.ID, PacketID: packetID, Payload: di.TLS})
	}
}

func findingRisk(f model.SecurityFinding) int {
	if f.Verdict == "confirmed_ioc" {
		return 100
	}
	base := map[string]int{"critical": 95, "high": 80, "medium": 60, "low": 35, "info": 10}[f.Severity]
	if base == 0 {
		base = 50
	}
	if f.Confidence > base && f.Confidence <= 100 {
		return f.Confidence
	}
	return base
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (e *Engine) recordPacket(p *decode.Packet, proc *model.ProcessInfo, attr string, di model.DPIInfo, flowID string, dir model.Direction) string {
	seq := e.packetSeq.Add(1)
	ps := model.PacketSummary{
		ID:              strconv.FormatUint(seq, 10),
		Time:            p.Time,
		Interface:       p.Interface,
		Direction:       dir,
		NetworkProtocol: p.Protocol,
		IPVersion:       p.IPVersion,
		Source:          model.Endpoint{IP: p.SrcIP, Port: p.SrcPort},
		Destination:     model.Endpoint{IP: p.DstIP, Port: p.DstPort},
		Length:          len(p.Raw),
		TCPFlags:        decode.TCPFlagsString(p.TCPFlags),
		ToS:             p.ToS,
		VLANID:          p.VLANID,
		ICMPType:        p.ICMPType,
		ICMPCode:        p.ICMPCode,
		FlowID:          flowID,
		DPI:             di,
		Attribution:     attr,
	}
	if proc != nil {
		cp := *proc
		ps.Process = &cp
	}
	e.mu.Lock()
	if len(e.packets) >= packetHistoryLimit {
		copy(e.packets, e.packets[len(e.packets)-packetHistoryLimit+1:])
		e.packets = e.packets[:packetHistoryLimit-1]
	}
	e.packets = append(e.packets, ps)
	e.mu.Unlock()
	return ps.ID
}

func (e *Engine) maintenance(ctx context.Context) {
	interval := 30 * time.Second
	if e.Config.Timeline.IntervalSeconds > 0 {
		interval = time.Duration(e.Config.Timeline.IntervalSeconds) * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tk.C:
			for _, id := range e.Store.GC(t) {
				e.DPI.Forget(id)
			}
			if e.Config.Beacon.AdvancedEnabled && e.AdvancedBeacon != nil {
				groups, findings := e.AdvancedBeacon.Analyze(e.Flows(5000))
				e.mu.Lock()
				e.beaconGroups = groups
				e.mu.Unlock()
				for _, f := range findings {
					if _, ok := e.IDS.Finding(f.ID); !ok {
						e.IDS.AddFinding(f)
						e.onFinding(f)
						if f.Severity == "high" && e.Recorder != nil {
							e.Recorder.Protect(f.RuleID)
						}
					}
				}
			}
			if e.Config.SelfProtection.Enabled && e.SelfProtect != nil {
				h, fs := e.SelfProtect.Check()
				e.mu.Lock()
				e.selfHealth = h
				e.mu.Unlock()
				for _, f := range fs {
					if _, ok := e.IDS.Finding(f.ID); !ok {
						e.IDS.AddFinding(f)
						e.onFinding(f)
					}
				}
			}
			if e.Timeline != nil {
				st := e.Status()
				_ = e.Timeline.Add(timeline.Snapshot{Time: t.UTC(), Packets: st.Packets, Bytes: st.Bytes, Flows: st.Flows, ActiveFlows: st.ActiveFlows, Processes: st.Processes, Alerts: st.Alerts, Findings: st.SecurityFindings, Critical: st.CriticalFindings, Confirmed: st.ConfirmedFindings, CaptureRunning: st.CaptureRunning})
			}
		}
	}
}

func (e *Engine) Flows(limit int) []model.Flow   { return e.Store.Snapshot(limit) }
func (e *Engine) Alerts(limit int) []model.Alert { return e.Anomaly.Alerts(limit) }
func (e *Engine) Findings(limit int) []model.SecurityFinding {
	if e.IDS == nil {
		return nil
	}
	raw := e.IDS.Findings(0)
	out := make([]model.SecurityFinding, 0, len(raw))
	for _, f := range raw {
		if e.Tuning != nil && e.Tuning.Suppressed(f) {
			continue
		}
		out = append(out, f)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
func (e *Engine) Finding(id string) (model.SecurityFinding, bool) {
	if e.IDS == nil {
		return model.SecurityFinding{}, false
	}
	f, ok := e.IDS.Finding(id)
	if !ok || (e.Tuning != nil && e.Tuning.Suppressed(f)) {
		return model.SecurityFinding{}, false
	}
	return f, true
}
func (e *Engine) onFinding(f model.SecurityFinding) {
	if e.EventBus != nil {
		e.EventBus.Publish(eventbus.Event{Time: f.Time, Category: "security", Type: "security_finding", Severity: f.Severity, Interface: f.Interface, FlowID: f.FlowID, PacketID: f.PacketID, Payload: f})
	}
	if e.Analytics != nil {
		_ = e.Analytics.Append(analytics.Event{Time: f.Time, Type: "finding", Severity: f.Severity, Process: f.Process, Destination: f.Destination.IP, Key: f.ID, Meta: map[string]any{"rule_id": f.RuleID, "verdict": f.Verdict, "confidence": f.Confidence, "category": f.Category}})
	}
	if e.Playbooks != nil {
		for _, m := range e.Playbooks.Evaluate(f) {
			if e.EventBus != nil {
				e.EventBus.Publish(eventbus.Event{Time: f.Time, Category: "response", Type: "playbook_match", Severity: f.Severity, FlowID: f.FlowID, PacketID: f.PacketID, Payload: m})
			}
			if m.RequiresApproval && e.PlaybookApproval != nil {
				go e.PlaybookApproval(f, m)
			}
			if m.Automatic {
				go e.executeAutomaticPlaybook(f, m)
			}
		}
	}
	if e.Integrations != nil {
		e.Integrations.Publish(f)
	}
	if e.Notifications != nil {
		e.Notifications.Enqueue(f)
	}
}

func (e *Engine) executeAutomaticPlaybook(f model.SecurityFinding, m playbook.Match) {
	for _, a := range m.Actions {
		var result any
		var err error
		switch a.Type {
		case "block_ip":
			if e.Response == nil {
				err = fmt.Errorf("response unavailable")
				break
			}
			result, err = e.Response.Execute(context.Background(), response.Request{Action: "block_ip", IP: f.Destination.IP, TTLSeconds: a.TTLSeconds, Confirm: "APPLY", Reason: firstString(a.Reason, "automatic playbook "+m.PlaybookName)})
		case "kill_process":
			if e.Response == nil {
				err = fmt.Errorf("response unavailable")
				break
			}
			result, err = e.Response.Execute(context.Background(), response.Request{Action: "kill_process", PID: f.PID, Confirm: "APPLY", Reason: firstString(a.Reason, "automatic playbook "+m.PlaybookName)})
		case "protect_pcap":
			if e.Recorder != nil {
				e.Recorder.Protect(firstString(f.RuleID, m.PlaybookID))
				result = map[string]any{"protected": true}
			} else {
				err = fmt.Errorf("recorder unavailable")
			}
		case "create_case":
			if e.Cases == nil {
				err = fmt.Errorf("case store unavailable")
				break
			}
			result, err = e.Cases.Create(cases.Case{Title: "Playbook: " + m.PlaybookName, Severity: f.Severity, FindingIDs: []string{f.ID}, Findings: []model.SecurityFinding{f}, Tags: []string{"automatic-playbook", m.PlaybookID}})
		default:
			err = fmt.Errorf("unsupported playbook action %q", a.Type)
		}
		if e.EventBus != nil {
			e.EventBus.Publish(eventbus.Event{Time: time.Now().UTC(), Category: "response", Type: "playbook_action", Severity: f.Severity, FlowID: f.FlowID, PacketID: f.PacketID, Payload: map[string]any{"playbook_id": m.PlaybookID, "finding_id": f.ID, "action": a.Type, "result": result, "error": errorString(err)}})
		}
	}
}

func firstString(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func (e *Engine) Stories(limit int) []stories.Story {
	return stories.BuildExtended(e.Findings(5000), e.Flows(5000), e.FilesList(1000), e.RuntimeEvents(2000), limit)
}
func (e *Engine) Suppressions() []tuning.Rule {
	if e.Tuning == nil {
		return nil
	}
	return e.Tuning.List()
}
func (e *Engine) AddSuppression(r tuning.Rule) (tuning.Rule, error) {
	if e.Tuning == nil {
		return tuning.Rule{}, fmt.Errorf("tuning unavailable")
	}
	return e.Tuning.Add(r)
}
func (e *Engine) DeleteSuppression(id string) error {
	if e.Tuning == nil {
		return fmt.Errorf("tuning unavailable")
	}
	return e.Tuning.Delete(id)
}
func (e *Engine) TimelineRange(from, to time.Time, limit int) []timeline.Snapshot {
	if e.Timeline == nil {
		return nil
	}
	return e.Timeline.Range(from, to, limit)
}
func (e *Engine) TimeMachine(at time.Time) map[string]any {
	var snap timeline.Snapshot
	ok := false
	if e.Timeline != nil {
		snap, ok = e.Timeline.Nearest(at)
	}
	from := at.Add(-5 * time.Minute)
	to := at.Add(5 * time.Minute)
	var fs []model.SecurityFinding
	for _, f := range e.Findings(5000) {
		if !f.Time.Before(from) && !f.Time.After(to) {
			fs = append(fs, f)
		}
	}
	var flows []model.Flow
	for _, f := range e.Flows(5000) {
		if !f.LastSeen.Before(from) && !f.FirstSeen.After(to) {
			flows = append(flows, f)
		}
	}
	var packets []model.PacketSummary
	for _, p := range e.Packets(1000) {
		if !p.Time.Before(from) && !p.Time.After(to) {
			packets = append(packets, p)
		}
	}
	return map[string]any{"at": at, "snapshot": snap, "snapshot_found": ok, "window_seconds": 600, "flows": flows, "findings": fs, "packets": packets}
}

func (e *Engine) Packets(limit int) []model.PacketSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.packets) {
		limit = len(e.packets)
	}
	out := make([]model.PacketSummary, 0, limit)
	for i := len(e.packets) - 1; i >= 0 && len(out) < limit; i-- {
		p := e.packets[i]
		out = append(out, p)
	}
	return out
}

func (e *Engine) Packet(id string) (model.PacketSummary, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i := len(e.packets) - 1; i >= 0; i-- {
		if e.packets[i].ID == id {
			return e.packets[i], true
		}
	}
	return model.PacketSummary{}, false
}

func (e *Engine) Status() model.Status {
	total, active := e.Store.Counts()
	ac, crit := e.Anomaly.Counts()
	fc, fcrit, confirmed := 0, 0, 0
	for _, f := range e.Findings(0) {
		fc++
		if f.Severity == "critical" {
			fcrit++
		}
		if f.Verdict == "confirmed_ioc" || f.Verdict == "signature_match" || f.Verdict == "confirmed_exposure" {
			confirmed++
		}
	}
	s := model.Status{StartedAt: e.Started, UptimeSeconds: int64(time.Since(e.Started).Seconds()), CaptureMode: e.Config.Capture.Backend, Flows: total, ActiveFlows: active, Processes: e.Store.ProcessCount(), Alerts: ac, CriticalAlerts: crit, SecurityFindings: fc, CriticalFindings: fcrit, ConfirmedFindings: confirmed, ProcessMapAgeMS: e.Proc.Age().Milliseconds(), AttributionBackend: e.attributionBackend, AFXDPAvailable: e.afxdpAvailable, AFXDPReason: e.afxdpReason}
	if e.ThreatIntel != nil {
		s.ThreatIndicators = e.ThreatIntel.Count()
	}
	if e.Cases != nil {
		s.Cases = e.Cases.Count()
	}
	if e.Federation != nil {
		s.Sensors = e.Federation.Count()
	}

	type capSnap struct {
		name      string
		c         capture.Source
		running   bool
		stopping  bool
		startedAt *time.Time
		stoppedAt *time.Time
	}
	var caps []capSnap
	e.lifecycleMu.Lock()
	s.CaptureRunning = e.anyRunningLocked()
	if s.CaptureRunning {
		s.CaptureState = "running"
	} else {
		s.CaptureState = "stopped"
	}
	if e.captureStarted != nil {
		t := *e.captureStarted
		s.CaptureStartedAt = &t
	}
	if e.captureStopped != nil {
		t := *e.captureStopped
		s.CaptureStoppedAt = &t
	}
	for name, cs := range e.captures {
		ss := capSnap{name: name, c: cs.capture, running: cs.running, stopping: cs.stopping}
		if cs.startedAt != nil {
			t := *cs.startedAt
			ss.startedAt = &t
		}
		if cs.stoppedAt != nil {
			t := *cs.stoppedAt
			ss.stoppedAt = &t
		}
		caps = append(caps, ss)
	}
	e.lifecycleMu.Unlock()
	sort.Slice(caps, func(i, j int) bool { return caps[i].name < caps[j].name })

	for _, cs := range caps {
		state := "stopped"
		if cs.stopping {
			state = "stopping"
		} else if cs.running {
			state = "running"
		}
		v := cs.c.StatsView()
		is := model.InterfaceStats{Name: cs.name, Backend: cs.c.Backend(), Packets: v.Packets, Bytes: v.Bytes, Errors: v.Errors, Dropped: v.Dropped, Running: cs.running, State: state, StartedAt: cs.startedAt, StoppedAt: cs.stoppedAt}
		s.Interfaces = append(s.Interfaces, is)
		s.Packets += is.Packets
		s.Bytes += is.Bytes
		s.CaptureErrors += is.Errors + is.Dropped
	}
	s.CaptureErrors += e.decodeErrors.Load()
	if e.Recorder != nil {
		s.RecorderDrops = e.Recorder.Drops() + e.recorderDrops.Load()
	}
	return s
}

type ProcessSummary struct {
	PID          int    `json:"pid"`
	Name         string `json:"name"`
	Exe          string `json:"exe"`
	User         string `json:"user"`
	TX           uint64 `json:"tx"`
	RX           uint64 `json:"rx"`
	Flows        int    `json:"flows"`
	Risk         int    `json:"risk"`
	Destinations int    `json:"destinations"`
	Findings     int    `json:"findings"`
}

type ProcessDetail struct {
	Summary  ProcessSummary          `json:"summary"`
	Info     *model.ProcessInfo      `json:"info,omitempty"`
	Flows    []model.Flow            `json:"flows"`
	Alerts   []model.Alert           `json:"alerts"`
	Findings []model.SecurityFinding `json:"findings"`
}

func (e *Engine) Processes() []ProcessSummary {
	type acc struct {
		p ProcessSummary
		d map[string]bool
	}
	m := map[string]*acc{}
	for _, f := range e.Store.Snapshot(0) {
		if f.Process == nil {
			continue
		}
		k := fmt.Sprintf("%d|%s", f.Process.PID, f.Process.Exe)
		a := m[k]
		if a == nil {
			a = &acc{p: ProcessSummary{PID: f.Process.PID, Name: f.Process.Comm, Exe: f.Process.Exe, User: f.Process.User}, d: map[string]bool{}}
			m[k] = a
		}
		a.p.TX += f.BytesTX
		a.p.RX += f.BytesRX
		a.p.Flows++
		if f.Risk > a.p.Risk {
			a.p.Risk = f.Risk
		}
		a.d[f.Remote.IP] = true
	}
	out := make([]ProcessSummary, 0, len(m))
	for _, f := range e.Findings(5000) {
		if f.PID <= 0 {
			continue
		}
		for _, a := range m {
			if a.p.PID == f.PID {
				a.p.Findings++
				break
			}
		}
	}
	for _, a := range m {
		a.p.Destinations = len(a.d)
		out = append(out, a.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].TX+out[i].RX > out[j].TX+out[j].RX
	})
	return out
}

func (e *Engine) Process(pid int) (ProcessDetail, bool) {
	var d ProcessDetail
	seenDest := map[string]bool{}
	for _, f := range e.Store.Snapshot(0) {
		if f.Process == nil || f.Process.PID != pid {
			continue
		}
		if d.Info == nil {
			cp := *f.Process
			d.Info = &cp
			d.Summary.PID = cp.PID
			d.Summary.Name = cp.Comm
			d.Summary.Exe = cp.Exe
			d.Summary.User = cp.User
		}
		d.Summary.TX += f.BytesTX
		d.Summary.RX += f.BytesRX
		d.Summary.Flows++
		if f.Risk > d.Summary.Risk {
			d.Summary.Risk = f.Risk
		}
		seenDest[f.Remote.IP] = true
		d.Flows = append(d.Flows, f)
	}
	if d.Info == nil {
		return ProcessDetail{}, false
	}
	d.Summary.Destinations = len(seenDest)
	for _, a := range e.Alerts(5000) {
		if a.PID == pid {
			d.Alerts = append(d.Alerts, a)
		}
	}
	for _, f := range e.Findings(5000) {
		if f.PID == pid {
			d.Findings = append(d.Findings, f)
			d.Summary.Findings++
		}
	}
	return d, true
}

func (e *Engine) CaptureHealth() string {
	s := e.Status()
	if !s.CaptureRunning {
		return "stopped"
	}
	if s.CaptureErrors == 0 && s.RecorderDrops == 0 {
		return "healthy"
	}
	return strings.TrimSpace(fmt.Sprintf("capture_errors=%d recorder_drops=%d", s.CaptureErrors, s.RecorderDrops))
}

func (e *Engine) startAttribution(ctx context.Context) {
	mode := strings.ToLower(strings.TrimSpace(e.Config.Attribution.Backend))
	if mode == "" {
		mode = "auto"
	}
	if mode == "proc" {
		e.attributionBackend = "proc"
		return
	}
	if e.EBPF == nil || !e.EBPF.Available() {
		if mode == "ebpf" {
			e.setError("eBPF attribution requested but bpftrace is unavailable")
		}
		e.attributionBackend = "proc-fallback"
		return
	}
	e.attributionBackend = "ebpf+bpftrace"
	err := e.EBPF.Run(ctx, func(ev ebpfattr.Event) {
		if ev.Kind == "connect" {
			e.Proc.AddKernelEvent(procmap.KernelEvent{Proto: ev.Proto, LocalIP: ev.LocalIP, LocalPort: ev.LocalPort, RemoteIP: ev.RemoteIP, RemotePort: ev.RemotePort, PID: ev.PID, UID: ev.UID, Comm: ev.Comm, Time: ev.Time})
		}
		e.addRuntimeEvent(model.RuntimeEvent{Time: ev.Time, Kind: ev.Kind, PID: ev.PID, PPID: ev.PPID, UID: ev.UID, Comm: ev.Comm, Path: ev.Path, Proto: ev.Proto, Local: model.Endpoint{IP: ev.LocalIP, Port: ev.LocalPort}, Remote: model.Endpoint{IP: ev.RemoteIP, Port: ev.RemotePort}, Success: ev.Success, Source: "ebpf+bpftrace", Confidence: 95})
	})
	if err != nil && ctx.Err() == nil {
		e.setError("eBPF attribution: " + err.Error())
		e.attributionBackend = "proc-fallback"
	}
}

func (e *Engine) addRuntimeEvent(ev model.RuntimeEvent) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	e.mu.Lock()
	e.runtimeEvents = append(e.runtimeEvents, ev)
	if len(e.runtimeEvents) > 2000 {
		e.runtimeEvents = append([]model.RuntimeEvent(nil), e.runtimeEvents[len(e.runtimeEvents)-2000:]...)
	}
	e.mu.Unlock()
	if e.EventBus != nil {
		e.EventBus.Publish(eventbus.Event{Time: ev.Time, Category: "runtime", Type: ev.Kind, Severity: "info", Payload: ev})
	}
	if e.Analytics != nil {
		_ = e.Analytics.Append(analytics.Event{Time: ev.Time, Type: "runtime", Process: ev.Comm, Destination: ev.Remote.IP, Key: ev.Kind, Meta: map[string]any{"pid": ev.PID, "ppid": ev.PPID, "path": ev.Path, "source": ev.Source}})
	}
	if e.RuntimeAnomaly != nil && e.IDS != nil {
		if finding, ok := e.RuntimeAnomaly.Observe(ev); ok {
			e.IDS.AddFinding(finding)
			e.onFinding(finding)
		}
	}
}

func (e *Engine) RuntimeEvents(limit int) []model.RuntimeEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := len(e.runtimeEvents)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := append([]model.RuntimeEvent(nil), e.runtimeEvents[n-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (e *Engine) DetectionQuality() detectionquality.Summary {
	if e.Quality == nil {
		return detectionquality.Summary{}
	}
	return e.Quality.Summary()
}

func (e *Engine) DetectionQualityRuns(limit int) []detectionquality.Run {
	if e.Quality == nil {
		return nil
	}
	return e.Quality.Runs(limit)
}

func (e *Engine) RecordDetectionQuality(r detectionquality.Run) error {
	if e.Quality == nil {
		return fmt.Errorf("detection quality unavailable")
	}
	return e.Quality.Record(r)
}

func (e *Engine) ExploitCorrelations() []vulnintel.ExploitChain {
	if e.VulnIntel == nil {
		return nil
	}
	return e.VulnIntel.CorrelateRuntime(e.Findings(5000), e.RuntimeEvents(2000))
}

func (e *Engine) startThreatIntel(ctx context.Context) {
	if !e.Config.ThreatIntel.Enabled || e.ThreatIntel == nil {
		return
	}
	feeds := make([]threatintel.TAXIIFeed, 0, len(e.Config.ThreatIntel.TAXII))
	for _, f := range e.Config.ThreatIntel.TAXII {
		feeds = append(feeds, threatintel.TAXIIFeed{Name: f.Name, ObjectsURL: f.ObjectsURL, Token: f.Token, Username: f.Username, Password: f.Password})
	}
	refresh := time.Duration(e.Config.ThreatIntel.RefreshSeconds) * time.Second
	e.ThreatIntel.Run(ctx, e.Config.ThreatIntel.STIXFiles, feeds, refresh)
}

func (e *Engine) threatFinding(f model.Flow, p *decode.Packet, packetID string, m threatintel.Match) model.SecurityFinding {
	sev := "high"
	if m.Indicator.Confidence >= 90 {
		sev = "critical"
	}
	now := p.Time
	h := sha256.Sum256([]byte("TI|" + m.Indicator.ID + "|" + f.ID + "|" + m.Observed))
	id := hex.EncodeToString(h[:8])
	sf := model.SecurityFinding{ID: id, Time: now, Severity: sev, Confidence: m.Indicator.Confidence, Verdict: "confirmed_ioc", RuleID: "NP-TI-IOC", Title: "Threat intelligence indicator matched", Description: "Observed network metadata exactly matched an imported threat-intelligence indicator.", Category: "threat-intelligence", Tags: append([]string{"ioc", m.Indicator.Type}, m.Indicator.Labels...), FlowID: f.ID, PacketID: packetID, Interface: p.Interface, Direction: f.Direction, Source: model.Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Destination: model.Endpoint{IP: p.DstIP, Port: p.DstPort}, Protocol: p.Protocol, Application: f.DPI.Application, Evidence: map[string]any{"field": m.Field, "observed": m.Observed, "indicator_type": m.Indicator.Type, "source": m.Indicator.Source, "indicator_id": m.Indicator.ID}}
	if f.Process != nil {
		sf.PID = f.Process.PID
		sf.Process = f.Process.Comm
	}
	return sf
}

func (e *Engine) Graph(limit int) investigation.Graph {
	return investigation.BuildExtended(e.Flows(limit), e.Findings(limit), e.FilesList(limit), limit)
}
func (e *Engine) GraphQuery(q investigation.Query) investigation.Graph {
	return investigation.BuildQuery(e.Flows(10000), e.Findings(10000), e.FilesList(10000), q)
}
func (e *Engine) ThreatIndicators() []threatintel.Indicator {
	if e.ThreatIntel == nil {
		return nil
	}
	return e.ThreatIntel.Indicators()
}
func (e *Engine) ThreatIntelErrors() []string {
	if e.ThreatIntel == nil {
		return nil
	}
	return e.ThreatIntel.Errors()
}
func (e *Engine) BaselineSnapshot() map[string]any {
	if e.Baseline == nil {
		return nil
	}
	return e.Baseline.Snapshot()
}
func (e *Engine) NetworkBaselineDiff(at time.Time, recent, historical time.Duration) (netbaseline.Diff, error) {
	if e.NetworkBaseline == nil {
		return netbaseline.Diff{}, fmt.Errorf("network baseline unavailable")
	}
	return e.NetworkBaseline.Compare(at, recent, historical)
}
func (e *Engine) ReplayFile(path string) (replay.Stats, error) {
	return replay.Stream(path, func(fr capture.Frame) error { e.ProcessReplayFrame(fr); return nil })
}
func (e *Engine) SensorSnapshot(id, host string) federation.Snapshot {
	return federation.Snapshot{SensorID: id, Hostname: host, Time: time.Now().UTC(), Status: e.Status(), Flows: e.Flows(100), Findings: e.Findings(100)}
}

func (e *Engine) CreateCaseFromFinding(id string, window time.Duration) (cases.Case, error) {
	if e.Cases == nil {
		return cases.Case{}, fmt.Errorf("case store unavailable")
	}
	finding, ok := e.Finding(id)
	if !ok {
		return cases.Case{}, fmt.Errorf("finding not found")
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	c := cases.Case{Title: finding.RuleID + " · " + finding.Title, Severity: finding.Severity, FindingIDs: []string{finding.ID}, Findings: []model.SecurityFinding{finding}, Tags: append([]string(nil), finding.Tags...)}
	start, end := finding.Time.Add(-window), finding.Time.Add(window)
	seenProc := map[int]bool{}
	for _, f := range e.Flows(0) {
		if f.LastSeen.Before(start) || f.FirstSeen.After(end) {
			continue
		}
		if f.ID == finding.FlowID || (finding.PID > 0 && f.Process != nil && f.Process.PID == finding.PID) || f.Remote.IP == finding.Source.IP || f.Remote.IP == finding.Destination.IP {
			c.Flows = append(c.Flows, f)
			c.FlowIDs = append(c.FlowIDs, f.ID)
			if f.Process != nil && !seenProc[f.Process.PID] {
				c.Processes = append(c.Processes, *f.Process)
				seenProc[f.Process.PID] = true
			}
		}
	}
	for _, p := range e.Packets(0) {
		if p.Time.Before(start) || p.Time.After(end) {
			continue
		}
		if p.FlowID == finding.FlowID || (finding.PID > 0 && p.Process != nil && p.Process.PID == finding.PID) {
			c.Packets = append(c.Packets, p)
			c.PacketIDs = append(c.PacketIDs, p.ID)
		}
	}
	if e.Recorder != nil {
		c.PCAPFiles = e.Recorder.Protect("case-" + finding.RuleID)
	}
	return e.Cases.Create(c)
}
func (e *Engine) CasesList() []cases.Case {
	if e.Cases == nil {
		return nil
	}
	return e.Cases.List()
}
func (e *Engine) Case(id string) (cases.Case, error) {
	if e.Cases == nil {
		return cases.Case{}, fmt.Errorf("case store unavailable")
	}
	return e.Cases.Get(id)
}
func (e *Engine) AddCaseNote(id, author, text string) (cases.Case, error) {
	if e.Cases == nil {
		return cases.Case{}, fmt.Errorf("case store unavailable")
	}
	return e.Cases.AddNote(id, author, text)
}
func (e *Engine) ExportCase(id string) (string, error) {
	if e.Cases == nil {
		return "", fmt.Errorf("case store unavailable")
	}
	dst := e.Config.DataDir + "/cases/" + id + "-evidence.zip"
	return e.Cases.Export(id, dst)
}

func (e *Engine) consumeFileUpdates(ctx context.Context) {
	if e.Files == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-e.Files.Updates():
			if e.EventBus != nil {
				e.EventBus.Publish(eventbus.Event{Time: time.Now().UTC(), Category: "file", Type: "file_scan_update", FlowID: a.FlowID, Payload: a})
			}
			for _, y := range a.Yara {
				h := sha256.Sum256([]byte("yara|" + a.ID + "|" + y.Rule))
				f := model.SecurityFinding{ID: hex.EncodeToString(h[:8]), Time: time.Now().UTC(), Severity: "critical", Confidence: 100, Verdict: "signature_match", RuleID: "NP-YARAX-" + y.Rule, Title: "YARA-X malware rule match", Description: "A reconstructed network file matched a YARA-X malware rule.", Category: "malware", Tactic: "Execution", MITRE: []string{"T1204"}, FlowID: a.FlowID, Direction: a.Direction, Source: a.Source, Destination: a.Destination, Evidence: map[string]any{"file_id": a.ID, "file_name": a.Name, "sha256": a.SHA256, "yara_rule": y.Rule, "yara_namespace": y.Namespace, "tags": y.Tags}}
				if a.Process != nil {
					f.PID = a.Process.PID
					f.Process = a.Process.Comm
				}
				e.IDS.AddFinding(f)
				e.onFinding(f)
				if e.Recorder != nil {
					e.Recorder.Protect(f.RuleID)
				}
			}
			if e.Scripts != nil && e.Config.Scripting.Enabled {
				for _, f := range e.Scripts.Evaluate(scripting.Context{File: &a}) {
					e.IDS.AddFinding(f)
					e.onFinding(f)
				}
			}
		}
	}
}
func (e *Engine) startWASM(ctx context.Context) {
	if e.WASM == nil || e.EventBus == nil {
		return
	}
	sub := e.EventBus.Subscribe(1024)
	defer e.EventBus.Unsubscribe(sub)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			if ev.Category == "plugin" {
				continue
			}
			for _, res := range e.WASM.Process(ev) {
				for _, f := range res.Findings {
					if f.ID == "" {
						h := sha256.Sum256([]byte(fmt.Sprintf("wasm|%s|%s|%d", f.RuleID, ev.FlowID, time.Now().UnixNano())))
						f.ID = hex.EncodeToString(h[:8])
					}
					if f.Time.IsZero() {
						f.Time = ev.Time
					}
					if f.FlowID == "" {
						f.FlowID = ev.FlowID
					}
					if f.PacketID == "" {
						f.PacketID = ev.PacketID
					}
					if f.Interface == "" {
						f.Interface = ev.Interface
					}
					if f.Verdict == "" {
						f.Verdict = "plugin_match"
					}
					if f.Category == "" {
						f.Category = "plugin"
					}
					e.IDS.AddFinding(f)
					e.onFinding(f)
				}
				if len(res.Enrichment) > 0 {
					e.EventBus.Publish(eventbus.Event{Time: time.Now().UTC(), Category: "plugin", Type: "enrichment", FlowID: ev.FlowID, PacketID: ev.PacketID, Payload: res.Enrichment})
				}
			}
		}
	}
}
func (e *Engine) startVulnerability(ctx context.Context) {
	if e.VulnIntel == nil || !e.Config.Vulnerability.Enabled {
		return
	}
	refresh := func() {
		if e.Config.Vulnerability.DiscoverPackages {
			if p, err := vulnintel.DiscoverPackages(); err == nil {
				e.VulnIntel.SetPackages(p)
			}
		}
		if x := strings.TrimSpace(e.Config.Vulnerability.KEVFile); x != "" {
			_ = e.VulnIntel.LoadKEVFile(x)
		}
		if u := strings.TrimSpace(e.Config.Vulnerability.KEVURL); u != "" {
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = e.VulnIntel.FetchKEV(cctx, u, nil)
			cancel()
		}
	}
	refresh()
	iv := time.Duration(e.Config.Vulnerability.RefreshSeconds) * time.Second
	if iv <= 0 {
		iv = 24 * time.Hour
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			refresh()
		}
	}
}
func (e *Engine) FilesList(limit int) []model.FileArtifact {
	if e.Files == nil {
		return nil
	}
	return e.Files.List(limit)
}
func (e *Engine) File(id string) (model.FileArtifact, bool) {
	if e.Files == nil {
		return model.FileArtifact{}, false
	}
	return e.Files.Get(id)
}
func (e *Engine) BeaconGroups() []beacon.Group {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]beacon.Group(nil), e.beaconGroups...)
}
func (e *Engine) EncryptedDNS(limit int) []dnsintel.Observation {
	if e.DNSIntel == nil {
		return nil
	}
	return e.DNSIntel.List(limit)
}
func (e *Engine) IdentityProfiles() []identitybaseline.Profile {
	if e.IdentityBaseline == nil {
		return nil
	}
	return e.IdentityBaseline.Profiles()
}
func (e *Engine) VulnerabilityContext() map[string]any {
	if e.VulnIntel == nil {
		return map[string]any{}
	}
	return map[string]any{"kev_count": e.VulnIntel.KEVCount(), "last_refresh": e.VulnIntel.LastRefresh(), "packages": e.VulnIntel.Inventory(), "exposures": e.VulnIntel.Exposures(), "errors": e.VulnIntel.Errors()}
}
func (e *Engine) StreamingStatus() []streaming.Status {
	if e.Streaming == nil {
		return nil
	}
	return e.Streaming.Status()
}
func (e *Engine) WASMStatus() []wasmplugin.Status {
	if e.WASM == nil {
		return nil
	}
	return e.WASM.Status()
}
func (e *Engine) SelfProtectionHealth() selfprotect.Health {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.selfHealth
}
func (e *Engine) AskAnalyst(ctx context.Context, q string) (analyst.Answer, error) {
	if e.Analyst == nil {
		return analyst.Answer{}, fmt.Errorf("analyst unavailable")
	}
	return e.Analyst.Ask(ctx, analyst.EvidencePack{Query: q, Flows: e.Flows(300), Findings: e.Findings(300), Files: e.FilesList(100), Packets: e.Packets(200)})
}
