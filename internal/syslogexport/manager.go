package syslogexport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
)

const (
	defaultQueue    = 2048
	maxDestinations = 32
)

type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CAFile             string `json:"ca_file,omitempty"`
	ClientCertFile     string `json:"client_cert_file,omitempty"`
	ClientKeyFile      string `json:"client_key_file,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
}

type Destination struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Transport  string    `json:"transport"` // udp, tcp, tls
	Format     string    `json:"format"`    // rfc3164, rfc5424
	Framing    string    `json:"framing"`   // octet-counting, non-transparent
	Facility   int       `json:"facility"`
	Severity   int       `json:"severity"`
	Hostname   string    `json:"hostname,omitempty"`
	Categories []string  `json:"categories,omitempty"`
	QueueSize  int       `json:"queue_size,omitempty"`
	TLS        TLSConfig `json:"tls,omitempty"`
}

type PublicDestination struct {
	Destination
	HasClientKey bool `json:"has_client_key"`
}

type Stats struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	Sent        uint64    `json:"sent_messages"`
	Failed      uint64    `json:"failed_messages"`
	Dropped     uint64    `json:"dropped_messages"`
	QueueDepth  int       `json:"queue_depth"`
	Reconnects  uint64    `json:"reconnect_count"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	BusDrops    uint64    `json:"event_bus_drops"`
}

type worker struct {
	cfg         Destination
	q           chan eventbus.Event
	cancel      context.CancelFunc
	sent        atomic.Uint64
	failed      atomic.Uint64
	dropped     atomic.Uint64
	reconnect   atomic.Uint64
	mu          sync.RWMutex
	state       string
	lastSuccess time.Time
	lastError   string
}

type fileConfig struct {
	Version      int           `json:"version"`
	Destinations []Destination `json:"destinations"`
}

type Manager struct {
	path    string
	bus     *eventbus.Bus
	sub     *eventbus.Subscription
	mu      sync.RWMutex
	cfg     map[string]Destination
	workers map[string]*worker
	ctx     context.Context
	cancel  context.CancelFunc
}

func New(path string, bus *eventbus.Bus) (*Manager, error) {
	m := &Manager{path: path, bus: bus, cfg: map[string]Destination{}, workers: map[string]*worker{}}
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
		m.sub = m.bus.Subscribe(4096)
	}
	for _, d := range m.cfg {
		if d.Enabled {
			m.startWorkerLocked(d)
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
				if !categoryAllowed(w.cfg.Categories, e.Category) {
					continue
				}
				select {
				case w.q <- e:
				default:
					w.dropped.Add(1)
				}
			}
			m.mu.RUnlock()
		}
	}
}

func categoryAllowed(set []string, category string) bool {
	if len(set) == 0 {
		return true
	}
	category = strings.ToLower(category)
	for _, x := range set {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "all" || x == "all_events" || x == category {
			return true
		}
	}
	return false
}

func (m *Manager) List() []PublicDestination {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PublicDestination, 0, len(m.cfg))
	for _, d := range m.cfg {
		out = append(out, public(d))
	}
	sortPublic(out)
	return out
}
func sortPublic(a []PublicDestination) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && strings.ToLower(a[j].Name) < strings.ToLower(a[j-1].Name); j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
func public(d Destination) PublicDestination {
	p := PublicDestination{Destination: d, HasClientKey: d.TLS.ClientKeyFile != ""}
	p.TLS.ClientKeyFile = ""
	return p
}

func (m *Manager) Upsert(d Destination) (PublicDestination, error) {
	if d.ID == "" {
		d.ID = randomID()
	}
	normalizeDestination(&d)
	if err := Validate(d); err != nil {
		return PublicDestination{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.cfg[d.ID]; !ok && len(m.cfg) >= maxDestinations {
		return PublicDestination{}, fmt.Errorf("maximum %d syslog destinations", maxDestinations)
	}
	// Preserve private key path when UI sends the redacted object unchanged.
	if old, ok := m.cfg[d.ID]; ok && d.TLS.ClientKeyFile == "" && old.TLS.ClientKeyFile != "" && d.TLS.ClientCertFile == old.TLS.ClientCertFile {
		d.TLS.ClientKeyFile = old.TLS.ClientKeyFile
	}
	if w := m.workers[d.ID]; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, d.ID)
	}
	m.cfg[d.ID] = d
	if err := m.saveLocked(); err != nil {
		return PublicDestination{}, err
	}
	if d.Enabled && m.ctx != nil {
		m.startWorkerLocked(d)
	}
	return public(d), nil
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
func (m *Manager) Get(id string) (PublicDestination, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.cfg[id]
	return public(d), ok
}
func (m *Manager) Raw(id string) (Destination, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.cfg[id]
	return d, ok
}

func (m *Manager) Enable(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.cfg[id]
	if !ok {
		return os.ErrNotExist
	}
	d.Enabled = enabled
	m.cfg[id] = d
	if w := m.workers[id]; w != nil {
		if w.cancel != nil {
			w.cancel()
		}
		delete(m.workers, id)
	}
	if err := m.saveLocked(); err != nil {
		return err
	}
	if enabled && m.ctx != nil {
		m.startWorkerLocked(d)
	}
	return nil
}

func (m *Manager) startWorkerLocked(d Destination) {
	qs := d.QueueSize
	if qs <= 0 {
		qs = defaultQueue
	}
	ctx, cancel := context.WithCancel(m.ctx)
	w := &worker{cfg: d, q: make(chan eventbus.Event, qs), cancel: cancel, state: "starting"}
	m.workers[d.ID] = w
	go w.run(ctx)
}

func (w *worker) setState(state, err string) {
	w.mu.Lock()
	w.state = state
	w.lastError = err
	w.mu.Unlock()
}
func (w *worker) run(ctx context.Context) {
	var conn net.Conn
	var backoff time.Duration
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
		w.setState("stopped", "")
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-w.q:
			if conn == nil {
				c, err := dial(ctx, w.cfg)
				if err != nil {
					w.failed.Add(1)
					w.setState("backoff", err.Error())
					if backoff == 0 {
						backoff = time.Second
					} else {
						backoff *= 2
						if backoff > 30*time.Second {
							backoff = 30 * time.Second
						}
					}
					t := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						t.Stop()
						return
					case <-t.C:
					}
					w.reconnect.Add(1)
					continue
				}
				conn = c
				backoff = 0
				w.setState("connected", "")
			}
			msg, err := Format(w.cfg, e)
			if err == nil {
				_, err = conn.Write(frame(w.cfg, msg))
			}
			if err != nil {
				w.failed.Add(1)
				w.setState("error", err.Error())
				_ = conn.Close()
				conn = nil
				continue
			}
			w.sent.Add(1)
			w.mu.Lock()
			w.lastSuccess = time.Now().UTC()
			w.lastError = ""
			w.mu.Unlock()
		}
	}
}

func dial(ctx context.Context, d Destination) (net.Conn, error) {
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	nd := net.Dialer{Timeout: 3 * time.Second}
	switch d.Transport {
	case "udp", "tcp":
		return nd.DialContext(ctx, d.Transport, addr)
	case "tls":
		tc, err := tlsClientConfig(d)
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(&nd, "tcp", addr, tc)
	default:
		return nil, fmt.Errorf("unsupported transport %q", d.Transport)
	}
}

func tlsClientConfig(d Destination) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: d.TLS.InsecureSkipVerify, ServerName: d.TLS.ServerName}
	if tc.ServerName == "" {
		tc.ServerName = d.Host
	}
	if d.TLS.CAFile != "" {
		pem, err := os.ReadFile(d.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
		tc.RootCAs = roots
	}
	if d.TLS.ClientCertFile != "" || d.TLS.ClientKeyFile != "" {
		if d.TLS.ClientCertFile == "" || d.TLS.ClientKeyFile == "" {
			return nil, fmt.Errorf("both client cert and key are required")
		}
		cert, err := tls.LoadX509KeyPair(d.TLS.ClientCertFile, d.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

func frame(d Destination, msg []byte) []byte {
	if d.Transport == "udp" {
		return msg
	}
	framing := d.Framing
	if framing == "" && d.Transport == "tls" {
		framing = "octet-counting"
	}
	if framing == "octet-counting" {
		return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
	}
	return append(msg, '\n')
}

func Format(d Destination, e eventbus.Event) ([]byte, error) {
	body, err := json.Marshal(map[string]any{"product": "NetProbe IR", "version": "0.6.0", "event": e})
	if err != nil {
		return nil, err
	}
	host := safeToken(d.Hostname, 255)
	if host == "" {
		host = "netprobe-ir"
	}
	pri := d.Facility*8 + d.Severity
	if d.Format == "rfc3164" {
		return []byte(fmt.Sprintf("<%d>%s %s netprobe-ir: %s", pri, e.Time.UTC().Format("Jan _2 15:04:05"), host, body)), nil
	}
	sd := fmt.Sprintf(`[netprobe@32473 category="%s" eventType="%s" flowID="%s" packetID="%s"]`, sdEscape(e.Category), sdEscape(e.Type), sdEscape(e.FlowID), sdEscape(e.PacketID))
	return []byte(fmt.Sprintf("<%d>1 %s %s netprobe-ir - %s %s %s", pri, e.Time.UTC().Format(time.RFC3339Nano), host, safeToken(e.Type, 32), sd, body)), nil
}
func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}
func safeToken(s string, max int) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r <= 32 || r == 127 {
			return '_'
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func Validate(d Destination) error {
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if !validHost(d.Host) {
		return fmt.Errorf("invalid host")
	}
	if d.Port < 1 || d.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	switch d.Transport {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("transport must be udp, tcp or tls")
	}
	switch d.Format {
	case "rfc3164", "rfc5424":
	default:
		return fmt.Errorf("format must be rfc3164 or rfc5424")
	}
	if d.Transport != "udp" {
		switch d.Framing {
		case "octet-counting", "non-transparent":
		default:
			return fmt.Errorf("invalid TCP framing")
		}
	}
	if d.Facility < 0 || d.Facility > 23 {
		return fmt.Errorf("facility must be 0..23")
	}
	if d.Severity < 0 || d.Severity > 7 {
		return fmt.Errorf("severity must be 0..7")
	}
	if d.QueueSize < 0 || d.QueueSize > 65536 {
		return fmt.Errorf("queue_size out of range")
	}
	if d.Transport == "tls" && ((d.TLS.ClientCertFile == "") != (d.TLS.ClientKeyFile == "")) {
		return fmt.Errorf("both client certificate and private key are required")
	}
	for _, c := range d.Categories {
		if !validCategory(c) {
			return fmt.Errorf("invalid event category %q", c)
		}
	}
	return nil
}
func validCategory(c string) bool {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "all", "all_events", "security", "network", "dpi", "dns", "http", "tls", "flow", "anomaly", "system":
		return true
	}
	return false
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
func normalizeDestination(d *Destination) {
	d.Name = strings.TrimSpace(d.Name)
	d.Host = strings.Trim(strings.TrimSpace(d.Host), "[]")
	d.Transport = strings.ToLower(strings.TrimSpace(d.Transport))
	d.Format = strings.ToLower(strings.TrimSpace(d.Format))
	d.Framing = strings.ToLower(strings.TrimSpace(d.Framing))
	if d.Transport == "udp" {
		d.Framing = ""
	}
	if d.Transport != "udp" && d.Framing == "" {
		d.Framing = "octet-counting"
	}
	if d.QueueSize == 0 {
		d.QueueSize = defaultQueue
	}
	if len(d.Categories) == 0 {
		d.Categories = []string{"security", "network", "dpi", "dns", "http", "tls", "flow", "anomaly", "system"}
	}
}
func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("syslog-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (m *Manager) Test(ctx context.Context, id string) error {
	d, ok := m.Raw(id)
	if !ok {
		return os.ErrNotExist
	}
	c, err := dial(ctx, d)
	if err != nil {
		return err
	}
	defer c.Close()
	msg, err := Format(d, eventbus.Event{Time: time.Now().UTC(), Category: "system", Type: "syslog_test", Severity: "info", Payload: map[string]any{"message": "NetProbe IR remote syslog test"}})
	if err != nil {
		return err
	}
	_, err = c.Write(frame(d, msg))
	return err
}

func (m *Manager) Stats() []Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Stats, 0, len(m.cfg))
	busdrops := uint64(0)
	if m.sub != nil {
		busdrops = m.sub.Dropped()
	}
	for id, d := range m.cfg {
		s := Stats{ID: id, Name: d.Name, State: "disabled", BusDrops: busdrops}
		if w := m.workers[id]; w != nil {
			w.mu.RLock()
			s.State = w.state
			s.LastSuccess = w.lastSuccess
			s.LastError = w.lastError
			w.mu.RUnlock()
			s.Sent = w.sent.Load()
			s.Failed = w.failed.Load()
			s.Dropped = w.dropped.Load()
			s.Reconnects = w.reconnect.Load()
			s.QueueDepth = len(w.q)
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
	for _, d := range f.Destinations {
		normalizeDestination(&d)
		if err := Validate(d); err != nil {
			return fmt.Errorf("stored syslog destination %s: %w", d.ID, err)
		}
		m.cfg[d.ID] = d
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
	for _, d := range m.cfg {
		f.Destinations = append(f.Destinations, d)
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
