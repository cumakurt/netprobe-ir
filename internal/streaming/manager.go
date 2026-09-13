package streaming

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/eventbus"
)

type Target struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	Enabled            bool   `json:"enabled"`
	Address            string `json:"address,omitempty"`
	Topic              string `json:"topic,omitempty"`
	Token              string `json:"token,omitempty"`
	TLS                bool   `json:"tls,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	Binary             string `json:"binary,omitempty"`
	Queue              int    `json:"queue,omitempty"`
}
type Status struct {
	Name, Type, State     string
	Sent, Failed, Dropped uint64
	QueueDepth            int
	LastSuccess           time.Time
	LastError             string
}
type worker struct {
	cfg                   Target
	ch                    chan eventbus.Event
	sent, failed, dropped atomic.Uint64
	mu                    sync.RWMutex
	state, lastErr        string
	last                  time.Time
}
type Manager struct {
	bus     *eventbus.Bus
	sub     *eventbus.Subscription
	mu      sync.RWMutex
	workers []*worker
	client  *http.Client
}

func New(bus *eventbus.Bus, targets []Target) *Manager {
	m := &Manager{bus: bus, client: &http.Client{Timeout: 10 * time.Second}}
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		q := t.Queue
		if q <= 0 {
			q = 1024
		}
		m.workers = append(m.workers, &worker{cfg: t, ch: make(chan eventbus.Event, q), state: "configured"})
	}
	return m
}
func (m *Manager) Start(ctx context.Context) {
	if m == nil || m.bus == nil {
		return
	}
	m.sub = m.bus.Subscribe(4096)
	for _, w := range m.workers {
		go m.runWorker(ctx, w)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-m.sub.C:
				if !ok {
					return
				}
				for _, w := range m.workers {
					select {
					case w.ch <- ev:
					default:
						w.dropped.Add(1)
					}
				}
			}
		}
	}()
}
func (m *Manager) runWorker(ctx context.Context, w *worker) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.ch:
			err := m.send(ctx, w.cfg, ev)
			if err != nil {
				w.failed.Add(1)
				w.mu.Lock()
				w.state = "degraded"
				w.lastErr = err.Error()
				w.mu.Unlock()
			} else {
				w.sent.Add(1)
				w.mu.Lock()
				w.state = "healthy"
				w.lastErr = ""
				w.last = time.Now().UTC()
				w.mu.Unlock()
			}
		}
	}
}
func (m *Manager) send(ctx context.Context, t Target, ev eventbus.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	switch strings.ToLower(t.Type) {
	case "otlp", "opentelemetry":
		return m.sendOTLP(ctx, t, ev, b)
	case "nats":
		return sendNATS(ctx, t, b)
	case "kafka":
		return sendKafka(ctx, t, b)
	case "clickhouse":
		return m.sendClickHouse(ctx, t, ev, b)
	default:
		return fmt.Errorf("unsupported stream target type %q", t.Type)
	}
}
func (m *Manager) sendOTLP(ctx context.Context, t Target, ev eventbus.Event, body []byte) error {
	sev := ev.Severity
	if sev == "" {
		sev = "INFO"
	}
	attrs := []any{
		map[string]any{"key": "netprobe.category", "value": map[string]any{"stringValue": ev.Category}},
		map[string]any{"key": "netprobe.type", "value": map[string]any{"stringValue": ev.Type}},
		map[string]any{"key": "netprobe.flow_id", "value": map[string]any{"stringValue": ev.FlowID}},
	}
	record := map[string]any{
		"timeUnixNano": strconv.FormatInt(ev.Time.UnixNano(), 10),
		"severityText": strings.ToUpper(sev),
		"body":         map[string]any{"stringValue": string(body)},
		"attributes":   attrs,
	}
	obj := map[string]any{
		"resourceLogs": []any{
			map[string]any{
				"resource": map[string]any{"attributes": []any{
					map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "netprobe-ir"}},
				}},
				"scopeLogs": []any{
					map[string]any{"scope": map[string]any{"name": "netprobe-ir"}, "logRecords": []any{record}},
				},
			},
		},
	}
	payload, _ := json.Marshal(obj)
	url := strings.TrimRight(t.Address, "/")
	if !strings.HasSuffix(url, "/v1/logs") {
		url += "/v1/logs"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("OTLP HTTP %s", resp.Status)
	}
	return nil
}

func (m *Manager) sendClickHouse(ctx context.Context, t Target, ev eventbus.Event, raw []byte) error {
	table := strings.TrimSpace(t.Topic)
	if table == "" {
		table = "netprobe_events"
	}
	for _, r := range table {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return fmt.Errorf("invalid ClickHouse table")
		}
	}
	row := map[string]any{"event_time": ev.Time.UTC().Format(time.RFC3339Nano), "category": ev.Category, "event_type": ev.Type, "severity": ev.Severity, "interface": ev.Interface, "flow_id": ev.FlowID, "packet_id": ev.PacketID, "payload_json": string(raw)}
	body, _ := json.Marshal(row)
	body = append(body, '\n')
	url := strings.TrimRight(t.Address, "/") + "/?query=" + url.QueryEscape("INSERT INTO "+table+" FORMAT JSONEachRow")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ClickHouse HTTP %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func sendNATS(ctx context.Context, t Target, payload []byte) error {
	topic := strings.TrimSpace(t.Topic)
	if topic == "" {
		topic = "netprobe.events"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	var c net.Conn
	var e error
	if t.TLS {
		c, e = tls.DialWithDialer(&d, "tcp", t.Address, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.InsecureSkipVerify})
	} else {
		c, e = d.DialContext(ctx, "tcp", t.Address)
	}
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	line, _ := r.ReadString('\n')
	_ = line
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	connect := `CONNECT {"verbose":false,"pedantic":false,"lang":"go","version":"1.0.0"}` + "\r\n"
	if t.Token != "" {
		connect = `CONNECT {"verbose":false,"auth_token":"` + strings.ReplaceAll(t.Token, `"`, ``) + `"}` + "\r\n"
	}
	if _, e = c.Write([]byte(connect)); e != nil {
		return e
	}
	hdr := fmt.Sprintf("PUB %s %d\r\n", topic, len(payload))
	if _, e = c.Write(append(append([]byte(hdr), payload...), []byte("\r\n")...)); e != nil {
		return e
	}
	return nil
}
func sendKafka(ctx context.Context, t Target, payload []byte) error {
	bin := t.Binary
	if bin == "" {
		bin = "kcat"
	}
	path, e := exec.LookPath(bin)
	if e != nil {
		return fmt.Errorf("Kafka adapter requires kcat: %w", e)
	}
	topic := t.Topic
	if topic == "" {
		topic = "netprobe.events"
	}
	cmd := exec.CommandContext(ctx, path, "-b", t.Address, "-t", topic, "-P", "-q")
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	var er bytes.Buffer
	cmd.Stderr = &er
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("kcat: %w: %s", e, strings.TrimSpace(er.String()))
	}
	return nil
}
func (m *Manager) Status() []Status {
	m.mu.RLock()
	ws := append([]*worker(nil), m.workers...)
	m.mu.RUnlock()
	out := make([]Status, 0, len(ws))
	for _, w := range ws {
		w.mu.RLock()
		st := Status{Name: w.cfg.Name, Type: w.cfg.Type, State: w.state, Sent: w.sent.Load(), Failed: w.failed.Load(), Dropped: w.dropped.Load(), QueueDepth: len(w.ch), LastSuccess: w.last, LastError: w.lastErr}
		w.mu.RUnlock()
		out = append(out, st)
	}
	return out
}
