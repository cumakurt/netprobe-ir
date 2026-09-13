package flowexport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
)

const defaultQueue = 4096

type Collector struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Enabled                bool   `json:"enabled"`
	Host                   string `json:"host"`
	Port                   int    `json:"port"`
	Protocol               string `json:"protocol"` // netflow5, netflow9, ipfix, sflow
	SourceInterface        string `json:"source_interface,omitempty"`
	ObservationDomain      uint32 `json:"observation_domain"`
	ActiveTimeoutSeconds   int    `json:"active_timeout_seconds"`
	InactiveTimeoutSeconds int    `json:"inactive_timeout_seconds"`
	TemplateRefreshSeconds int    `json:"template_refresh_seconds"`
	SamplingRate           uint32 `json:"sampling_rate"`
	QueueSize              int    `json:"queue_size,omitempty"`
	AgentAddress           string `json:"agent_address,omitempty"`
}

type Stats struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Protocol        string    `json:"protocol"`
	State           string    `json:"state"`
	ActiveFlows     uint64    `json:"active_flows"`
	ExportedFlows   uint64    `json:"exported_flows"`
	ExportedPackets uint64    `json:"exported_packets"`
	FailedExports   uint64    `json:"failed_exports"`
	DroppedExports  uint64    `json:"dropped_exports"`
	QueueDepth      int       `json:"queue_depth"`
	TemplateSends   uint64    `json:"template_sends"`
	Reconnects      uint64    `json:"reconnect_count"`
	LastSuccess     time.Time `json:"last_success,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	BusDrops        uint64    `json:"event_bus_drops"`
}

type flowState struct {
	flow                                 model.Flow
	updated, lastExport                  time.Time
	exportedPacketsTX, exportedPacketsRX uint64
	exportedBytesTX, exportedBytesRX     uint64
}
type exportJob struct {
	flow   *model.Flow
	packet *model.PacketSummary
}
type worker struct {
	cfg              Collector
	q                chan exportJob
	cancel           context.CancelFunc
	enc              *encoder
	active           map[string]*flowState
	activeCount      atomic.Uint64
	exported         atomic.Uint64
	packets          atomic.Uint64
	failed           atomic.Uint64
	dropped          atomic.Uint64
	reconnect        atomic.Uint64
	mu               sync.RWMutex
	state, lastError string
	lastSuccess      time.Time
}
type fileConfig struct {
	Version    int         `json:"version"`
	Collectors []Collector `json:"collectors"`
}
type Manager struct {
	path    string
	bus     *eventbus.Bus
	sub     *eventbus.Subscription
	mu      sync.RWMutex
	cfg     map[string]Collector
	workers map[string]*worker
	ctx     context.Context
	cancel  context.CancelFunc
}

func New(path string, bus *eventbus.Bus) (*Manager, error) {
	m := &Manager{path: path, bus: bus, cfg: map[string]Collector{}, workers: map[string]*worker{}}
	if err := m.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	if m.bus != nil {
		m.sub = m.bus.Subscribe(8192)
	}
	for _, c := range m.cfg {
		if c.Enabled {
			m.startWorkerLocked(c)
		}
	}
	sub := m.sub
	cctx := m.ctx
	m.mu.Unlock()
	if sub != nil {
		go m.dispatch(cctx, sub)
	}
}
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.sub != nil && m.bus != nil {
		m.bus.Unsubscribe(m.sub)
		m.sub = nil
	}
	for id, w := range m.workers {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, id)
	}
	m.mu.Unlock()
}
func (m *Manager) dispatch(ctx context.Context, sub *eventbus.Subscription) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			m.mu.RLock()
			for _, w := range m.workers {
				var job exportJob
				if w.cfg.Protocol == "sflow" {
					if e.Category != "network" || e.Type != "packet_metadata" {
						continue
					}
					p, ok := e.Payload.(model.PacketSummary)
					if !ok {
						continue
					}
					if w.cfg.SourceInterface != "" && p.Interface != w.cfg.SourceInterface {
						continue
					}
					key := p.ID
					if key == "" {
						key = e.PacketID
					}
					if !sampled(key, w.cfg.SamplingRate) {
						continue
					}
					cp := p
					job.packet = &cp
				} else {
					if e.Category != "flow" {
						continue
					}
					f, ok := e.Payload.(model.Flow)
					if !ok {
						continue
					}
					if w.cfg.SourceInterface != "" && !contains(f.Interfaces, w.cfg.SourceInterface) {
						continue
					}
					// NetFlow/IPFIX sampling selects logical flows deterministically.
					if !sampled(f.ID, w.cfg.SamplingRate) {
						continue
					}
					cp := f
					job.flow = &cp
				}
				select {
				case w.q <- job:
				default:
					w.dropped.Add(1)
				}
			}
			m.mu.RUnlock()
		}
	}
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func normalize(c *Collector) {
	c.Name = strings.TrimSpace(c.Name)
	c.Host = strings.Trim(strings.TrimSpace(c.Host), "[]")
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	c.SourceInterface = strings.TrimSpace(c.SourceInterface)
	if c.ActiveTimeoutSeconds <= 0 {
		c.ActiveTimeoutSeconds = 60
	}
	if c.InactiveTimeoutSeconds <= 0 {
		c.InactiveTimeoutSeconds = 15
	}
	if c.TemplateRefreshSeconds <= 0 {
		c.TemplateRefreshSeconds = 30
	}
	if c.SamplingRate == 0 {
		c.SamplingRate = 1
	}
	if c.QueueSize <= 0 {
		c.QueueSize = defaultQueue
	}
	if c.AgentAddress == "" {
		c.AgentAddress = "127.0.0.1"
	}
}
func Validate(c Collector) error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !validHost(c.Host) {
		return fmt.Errorf("invalid host")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	switch c.Protocol {
	case "netflow5", "netflow9", "ipfix", "sflow":
	default:
		return fmt.Errorf("unsupported protocol %q", c.Protocol)
	}
	if c.ActiveTimeoutSeconds < 1 || c.ActiveTimeoutSeconds > 86400 {
		return fmt.Errorf("active timeout out of range")
	}
	if c.InactiveTimeoutSeconds < 1 || c.InactiveTimeoutSeconds > 86400 {
		return fmt.Errorf("inactive timeout out of range")
	}
	if c.TemplateRefreshSeconds < 1 || c.TemplateRefreshSeconds > 86400 {
		return fmt.Errorf("template refresh out of range")
	}
	if c.SamplingRate < 1 || c.SamplingRate > 1000000 {
		return fmt.Errorf("sampling_rate out of range")
	}
	if c.QueueSize < 1 || c.QueueSize > 65536 {
		return fmt.Errorf("queue_size out of range")
	}
	if net.ParseIP(c.AgentAddress) == nil {
		return fmt.Errorf("agent_address must be an IP address")
	}
	return nil
}
func validHost(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "/\\\x00\r\n\t ") {
		return false
	}
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return true
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func randomID() string {
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return fmt.Sprintf("flow-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (m *Manager) List() []Collector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Collector, 0, len(m.cfg))
	for _, c := range m.cfg {
		out = append(out, c)
	}
	sortCollectors(out)
	return out
}
func sortCollectors(a []Collector) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && strings.ToLower(a[j].Name) < strings.ToLower(a[j-1].Name); j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
func (m *Manager) Raw(id string) (Collector, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.cfg[id]
	return c, ok
}
func (m *Manager) Upsert(c Collector) (Collector, error) {
	if c.ID == "" {
		c.ID = randomID()
	}
	normalize(&c)
	if err := Validate(c); err != nil {
		return Collector{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if w := m.workers[c.ID]; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, c.ID)
	}
	m.cfg[c.ID] = c
	if err := m.saveLocked(); err != nil {
		return Collector{}, err
	}
	if c.Enabled && m.ctx != nil {
		m.startWorkerLocked(c)
	}
	return c, nil
}
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.cfg[id]; !ok {
		return os.ErrNotExist
	}
	if w := m.workers[id]; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, id)
	}
	delete(m.cfg, id)
	return m.saveLocked()
}
func (m *Manager) Enable(id string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cfg[id]
	if !ok {
		return os.ErrNotExist
	}
	c.Enabled = on
	m.cfg[id] = c
	if w := m.workers[id]; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, id)
	}
	if err := m.saveLocked(); err != nil {
		return err
	}
	if on && m.ctx != nil {
		m.startWorkerLocked(c)
	}
	return nil
}
func (m *Manager) startWorkerLocked(c Collector) {
	ctx, cancel := context.WithCancel(m.ctx)
	w := &worker{cfg: c, q: make(chan exportJob, c.QueueSize), cancel: cancel, enc: newEncoder(), active: map[string]*flowState{}, state: "starting"}
	m.workers[c.ID] = w
	go w.run(ctx)
}
func (w *worker) setState(s, e string) { w.mu.Lock(); w.state = s; w.lastError = e; w.mu.Unlock() }
func (w *worker) run(ctx context.Context) {
	var conn net.Conn
	var nextDial time.Time
	backoff := time.Second
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-w.q:
			now := time.Now()
			if job.packet != nil && w.cfg.Protocol == "sflow" {
				if conn == nil {
					if !nextDial.IsZero() && now.Before(nextDial) {
						w.dropped.Add(1)
						continue
					}
					c, err := net.DialTimeout("udp", net.JoinHostPort(w.cfg.Host, strconv.Itoa(w.cfg.Port)), 3*time.Second)
					if err != nil {
						w.failed.Add(1)
						w.reconnect.Add(1)
						w.setState("backoff", err.Error())
						nextDial = now.Add(backoff)
						if backoff < 30*time.Second {
							backoff *= 2
						}
						continue
					}
					conn = c
					nextDial = time.Time{}
					backoff = time.Second
					w.setState("ready", "")
				}
				if err := w.exportPacket(conn, *job.packet, now); err != nil {
					w.failed.Add(1)
					w.reconnect.Add(1)
					w.setState("backoff", err.Error())
					_ = conn.Close()
					conn = nil
					nextDial = now.Add(backoff)
					if backoff < 30*time.Second {
						backoff *= 2
					}
				}
				continue
			}
			if job.flow == nil {
				continue
			}
			f := *job.flow
			st := w.active[f.ID]
			if st == nil {
				st = &flowState{lastExport: now}
				w.active[f.ID] = st
			}
			st.flow = f
			st.updated = now
			w.activeCount.Store(uint64(len(w.active)))
		case now := <-tick.C:
			if len(w.active) == 0 {
				continue
			}
			if conn == nil {
				if !nextDial.IsZero() && now.Before(nextDial) {
					continue
				}
				c, err := net.DialTimeout("udp", net.JoinHostPort(w.cfg.Host, strconv.Itoa(w.cfg.Port)), 3*time.Second)
				if err != nil {
					w.failed.Add(1)
					w.setState("backoff", err.Error())
					w.reconnect.Add(1)
					nextDial = now.Add(backoff)
					backoff *= 2
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
					continue
				}
				conn = c
				nextDial = time.Time{}
				backoff = time.Second
				w.setState("ready", "")
			}
			if err := w.flushDue(conn, now); err != nil {
				w.failed.Add(1)
				w.setState("backoff", err.Error())
				_ = conn.Close()
				conn = nil
				w.reconnect.Add(1)
				nextDial = now.Add(backoff)
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}
}
func (w *worker) flushDue(conn net.Conn, now time.Time) error {
	active := time.Duration(w.cfg.ActiveTimeoutSeconds) * time.Second
	inactive := time.Duration(w.cfg.InactiveTimeoutSeconds) * time.Second
	for id, st := range w.active {
		dueInactive := now.Sub(st.updated) >= inactive
		dueActive := now.Sub(st.lastExport) >= active
		if !dueInactive && !dueActive {
			continue
		}
		delta, changed := deltaFlow(st)
		if changed {
			if err := w.export(conn, delta, now, false); err != nil {
				return err
			}
			st.exportedPacketsTX = st.flow.PacketsTX
			st.exportedPacketsRX = st.flow.PacketsRX
			st.exportedBytesTX = st.flow.BytesTX
			st.exportedBytesRX = st.flow.BytesRX
		}
		st.lastExport = now
		if dueInactive {
			delete(w.active, id)
		}
	}
	w.activeCount.Store(uint64(len(w.active)))
	return nil
}
func (w *worker) export(conn net.Conn, f model.Flow, now time.Time, forceTemplate bool) error {
	if conn == nil {
		return fmt.Errorf("collector connection unavailable")
	}
	records := directionalFlows(f)
	for i, df := range records {
		datagrams, err := w.enc.encode(w.cfg, df, now, forceTemplate && i == 0)
		if err != nil {
			return err
		}
		for _, d := range datagrams {
			if _, err = conn.Write(d); err != nil {
				return err
			}
			w.packets.Add(1)
		}
		w.exported.Add(1)
	}
	w.mu.Lock()
	w.state = "ready"
	w.lastError = ""
	w.lastSuccess = time.Now().UTC()
	w.mu.Unlock()
	return nil
}

func deltaFlow(st *flowState) (model.Flow, bool) {
	f := st.flow
	if f.PacketsTX < st.exportedPacketsTX || f.PacketsRX < st.exportedPacketsRX || f.BytesTX < st.exportedBytesTX || f.BytesRX < st.exportedBytesRX {
		// Defensive reset if an upstream flow counter restarts.
		st.exportedPacketsTX, st.exportedPacketsRX, st.exportedBytesTX, st.exportedBytesRX = 0, 0, 0, 0
	}
	f.PacketsTX -= st.exportedPacketsTX
	f.PacketsRX -= st.exportedPacketsRX
	f.BytesTX -= st.exportedBytesTX
	f.BytesRX -= st.exportedBytesRX
	if !st.lastExport.IsZero() && st.lastExport.After(f.FirstSeen) {
		f.FirstSeen = st.lastExport
	}
	return f, f.PacketsTX > 0 || f.PacketsRX > 0 || f.BytesTX > 0 || f.BytesRX > 0
}

func directionalFlows(f model.Flow) []model.Flow {
	out := make([]model.Flow, 0, 2)
	if f.PacketsTX > 0 || f.BytesTX > 0 {
		x := f
		x.Direction = model.DirectionOutbound
		x.PacketsRX = 0
		x.BytesRX = 0
		out = append(out, x)
	}
	if f.PacketsRX > 0 || f.BytesRX > 0 {
		x := f
		x.Direction = model.DirectionInbound
		x.PacketsTX = 0
		x.BytesTX = 0
		out = append(out, x)
	}
	if len(out) == 0 {
		out = append(out, f)
	}
	return out
}
func (w *worker) exportPacket(conn net.Conn, p model.PacketSummary, now time.Time) error {
	if conn == nil {
		return fmt.Errorf("collector connection unavailable")
	}
	d, err := w.enc.sflowPacket(w.cfg, p, now)
	if err != nil {
		return err
	}
	if _, err = conn.Write(d); err != nil {
		return err
	}
	w.packets.Add(1)
	w.exported.Add(1)
	w.mu.Lock()
	w.state = "ready"
	w.lastError = ""
	w.lastSuccess = time.Now().UTC()
	w.mu.Unlock()
	return nil
}

func (m *Manager) Test(ctx context.Context, id string) error {
	c, ok := m.Raw(id)
	if !ok {
		return os.ErrNotExist
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	now := time.Now().UTC()
	f := model.Flow{ID: "netprobe-export-test", NetworkProtocol: "TCP", IPVersion: 4, Local: model.Endpoint{IP: "192.0.2.10", Port: 54321}, Remote: model.Endpoint{IP: "198.51.100.10", Port: 443}, Direction: model.DirectionOutbound, FirstSeen: now.Add(-time.Second), LastSeen: now, PacketsTX: 1, BytesTX: 128, TCPFlags: "SYN", DPI: model.DPIInfo{Protocol: "TLS", Application: "HTTPS"}}
	enc := newEncoder()
	if c.Protocol == "sflow" {
		p := model.PacketSummary{ID: "netprobe-sflow-test", Time: now, Interface: c.SourceInterface, Direction: model.DirectionOutbound, NetworkProtocol: "TCP", IPVersion: 4, Source: model.Endpoint{IP: "192.0.2.10", Port: 54321}, Destination: model.Endpoint{IP: "198.51.100.10", Port: 443}, Length: 128, TCPFlags: "SYN"}
		d, er := enc.sflowPacket(c, p, now)
		if er != nil {
			return er
		}
		_, er = conn.Write(d)
		return er
	}
	ds, err := enc.encode(c, f, now, true)
	if err != nil {
		return err
	}
	for _, d := range ds {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if _, err = conn.Write(d); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) Stats() []Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Stats, 0, len(m.cfg))
	busdrops := uint64(0)
	if m.sub != nil {
		busdrops = m.sub.Dropped()
	}
	for id, c := range m.cfg {
		s := Stats{ID: id, Name: c.Name, Protocol: c.Protocol, State: "disabled", BusDrops: busdrops}
		if w := m.workers[id]; w != nil {
			w.mu.RLock()
			s.State = w.state
			s.LastSuccess = w.lastSuccess
			s.LastError = w.lastError
			w.mu.RUnlock()
			s.ActiveFlows = w.activeCount.Load()
			s.ExportedFlows = w.exported.Load()
			s.ExportedPackets = w.packets.Load()
			s.FailedExports = w.failed.Load()
			s.DroppedExports = w.dropped.Load()
			s.QueueDepth = len(w.q)
			s.TemplateSends = w.enc.templateSends.Load()
			s.Reconnects = w.reconnect.Load()
		}
		out = append(out, s)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && strings.ToLower(out[j].Name) < strings.ToLower(out[j-1].Name); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
func (m *Manager) load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	var f fileConfig
	if err = json.Unmarshal(b, &f); err != nil {
		return err
	}
	for _, c := range f.Collectors {
		normalize(&c)
		if err := Validate(c); err != nil {
			return fmt.Errorf("stored collector %s: %w", c.ID, err)
		}
		m.cfg[c.ID] = c
	}
	return nil
}
func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	f := fileConfig{Version: 1}
	for _, c := range m.cfg {
		f.Collectors = append(f.Collectors, c)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
