package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Snapshot struct {
	SensorID     string                  `json:"sensor_id"`
	Hostname     string                  `json:"hostname,omitempty"`
	Version      string                  `json:"version,omitempty"`
	ConfigSHA256 string                  `json:"config_sha256,omitempty"`
	RulesSHA256  string                  `json:"rules_sha256,omitempty"`
	Time         time.Time               `json:"time"`
	Status       model.Status            `json:"status"`
	Flows        []model.Flow            `json:"flows,omitempty"`
	Findings     []model.SecurityFinding `json:"findings,omitempty"`
}
type Hub struct {
	mu       sync.RWMutex
	sensors  map[string]Snapshot
	commands map[string][]FleetCommand
	desired  map[string]FleetState
	path     string
}

type persistedHub struct {
	Sensors  map[string]Snapshot       `json:"sensors"`
	Commands map[string][]FleetCommand `json:"commands"`
	Desired  map[string]FleetState     `json:"desired"`
}

func NewHub() *Hub { return NewHubPersistent("") }
func NewHubPersistent(path string) *Hub {
	h := &Hub{sensors: map[string]Snapshot{}, commands: map[string][]FleetCommand{}, desired: map[string]FleetState{}, path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var p persistedHub
			if json.Unmarshal(b, &p) == nil {
				if p.Sensors != nil {
					h.sensors = p.Sensors
				}
				if p.Commands != nil {
					h.commands = p.Commands
				}
				if p.Desired != nil {
					h.desired = p.Desired
				}
			}
		}
	}
	return h
}
func (h *Hub) persistLocked() {
	if h.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(h.path), 0750)
	b, err := json.MarshalIndent(persistedHub{Sensors: h.sensors, Commands: h.commands, Desired: h.desired}, "", "  ")
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if os.WriteFile(tmp, b, 0640) == nil {
		_ = os.Rename(tmp, h.path)
	}
}
func (h *Hub) Ingest(s Snapshot) error {
	s.SensorID = strings.TrimSpace(s.SensorID)
	if s.SensorID == "" {
		return fmt.Errorf("sensor_id required")
	}
	if s.Time.IsZero() {
		s.Time = time.Now().UTC()
	}
	if len(s.Flows) > 500 {
		s.Flows = s.Flows[:500]
	}
	if len(s.Findings) > 500 {
		s.Findings = s.Findings[:500]
	}
	h.mu.Lock()
	h.sensors[s.SensorID] = s
	h.persistLocked()
	h.mu.Unlock()
	return nil
}
func (h *Hub) List() []Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Snapshot, 0, len(h.sensors))
	for _, s := range h.sensors {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}
func (h *Hub) Count() int { h.mu.RLock(); defer h.mu.RUnlock(); return len(h.sensors) }

type FleetHealth struct {
	FleetState
	State       string   `json:"health_state"`
	HealthScore int      `json:"health_score"`
	Drift       []string `json:"drift,omitempty"`
	AgeSeconds  int64    `json:"age_seconds"`
	Critical    int      `json:"critical_findings"`
}

func (h *Hub) FleetHealth(now time.Time) []FleetHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	base := h.Fleet()
	out := make([]FleetHealth, 0, len(base))
	for _, s := range base {
		age := int64(now.Sub(s.Time).Seconds())
		if age < 0 {
			age = 0
		}
		state := "online"
		score := 100
		if age > 120 {
			state = "offline"
			score -= 60
		} else if age > 30 {
			state = "stale"
			score -= 25
		}
		if !s.Status.CaptureRunning {
			score -= 20
		}
		if s.Status.CaptureErrors > 0 || s.Status.RecorderDrops > 0 {
			score -= 15
		}
		var drift []string
		if s.DesiredVersion != "" && s.Version != "" && s.DesiredVersion != s.Version {
			drift = append(drift, "version")
			score -= 10
		}
		if s.DesiredConfigSHA256 != "" && s.ConfigSHA256 != "" && !strings.EqualFold(s.DesiredConfigSHA256, s.ConfigSHA256) {
			drift = append(drift, "config")
			score -= 10
		}
		if s.DesiredRulesSHA256 != "" && s.RulesSHA256 != "" && !strings.EqualFold(s.DesiredRulesSHA256, s.RulesSHA256) {
			drift = append(drift, "rules")
			score -= 10
		}
		if score < 0 {
			score = 0
		}
		out = append(out, FleetHealth{FleetState: s, State: state, HealthScore: score, Drift: drift, AgeSeconds: age, Critical: s.Status.CriticalFindings})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HealthScore != out[j].HealthScore {
			return out[i].HealthScore < out[j].HealthScore
		}
		return out[i].SensorID < out[j].SensorID
	})
	return out
}

type Client struct {
	URL, Token, SensorID, Hostname string
	Interval                       time.Duration
	HTTP                           *http.Client
	Snapshot                       func() Snapshot
	HandleCommand                  func(context.Context, FleetCommand) (string, error)
}

func (c *Client) Send(ctx context.Context) error {
	if c.Snapshot == nil {
		return fmt.Errorf("snapshot callback required")
	}
	s := c.Snapshot()
	s.SensorID = c.SensorID
	if s.Time.IsZero() {
		s.Time = time.Now().UTC()
	}
	if s.Hostname == "" {
		s.Hostname = c.Hostname
	}
	b, _ := json.Marshal(s)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/api/v1/sensors/ingest", bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NetProbe-Sensor-Token", c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, e := hc.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("controller HTTP %s", resp.Status)
	}
	return nil
}
func (c *Client) FetchCommands(ctx context.Context) ([]FleetCommand, error) {
	u := strings.TrimRight(c.URL, "/") + "/api/v1/sensors/commands/poll?sensor_id=" + c.SensorID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-NetProbe-Sensor-Token", c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("controller HTTP %s", resp.Status)
	}
	var out struct {
		Commands []FleetCommand `json:"commands"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}
func (c *Client) AckCommand(ctx context.Context, cmd FleetCommand, state, result string) error {
	b, _ := json.Marshal(map[string]any{"sensor_id": c.SensorID, "id": cmd.ID, "state": state, "result": result})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/api/v1/sensors/commands/ack", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NetProbe-Sensor-Token", c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("controller HTTP %s", resp.Status)
	}
	return nil
}
func (c *Client) processCommands(ctx context.Context) {
	if c.HandleCommand == nil {
		return
	}
	cmds, err := c.FetchCommands(ctx)
	if err != nil {
		return
	}
	for _, cmd := range cmds {
		result, er := c.HandleCommand(ctx, cmd)
		state := "completed"
		if er != nil {
			state = "failed"
			result = er.Error()
		}
		_ = c.AckCommand(ctx, cmd, state, result)
	}
}

func (c *Client) Run(ctx context.Context) {
	iv := c.Interval
	if iv <= 0 {
		iv = 10 * time.Second
	}
	_ = c.Send(ctx)
	c.processCommands(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Send(ctx)
			c.processCommands(ctx)
		}
	}
}

// FleetCommand is a controller-to-sensor management instruction. Commands are
// intentionally declarative; the sensor decides how to apply them and reports
// completion. Config/rule rollout payloads carry a SHA-256 hash so accidental or
// malicious corruption can be rejected before activation.
type FleetCommand struct {
	ID        string         `json:"id"`
	SensorID  string         `json:"sensor_id"`
	Type      string         `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	State     string         `json:"state"`
	Result    string         `json:"result,omitempty"`
}

type FleetState struct {
	Snapshot
	DesiredConfigSHA256 string    `json:"desired_config_sha256,omitempty"`
	DesiredRulesSHA256  string    `json:"desired_rules_sha256,omitempty"`
	DesiredVersion      string    `json:"desired_version,omitempty"`
	LastCommandAt       time.Time `json:"last_command_at,omitempty"`
}

var fleetSeq uint64

func (h *Hub) QueueCommand(sensorID, typ string, payload map[string]any, ttl time.Duration) (FleetCommand, error) {
	sensorID = strings.TrimSpace(sensorID)
	typ = strings.TrimSpace(typ)
	if sensorID == "" || typ == "" {
		return FleetCommand{}, fmt.Errorf("sensor_id and type required")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.commands == nil {
		h.commands = map[string][]FleetCommand{}
	}
	fleetSeq++
	now := time.Now().UTC()
	c := FleetCommand{ID: fmt.Sprintf("cmd-%d-%d", now.UnixNano(), fleetSeq), SensorID: sensorID, Type: typ, CreatedAt: now, Payload: payload, State: "queued"}
	if ttl > 0 {
		c.ExpiresAt = now.Add(ttl)
	}
	h.commands[sensorID] = append(h.commands[sensorID], c)
	if len(h.commands[sensorID]) > 200 {
		h.commands[sensorID] = h.commands[sensorID][len(h.commands[sensorID])-200:]
	}
	h.persistLocked()
	return c, nil
}
func (h *Hub) Commands(sensorID string, pendingOnly bool) []FleetCommand {
	h.mu.RLock()
	defer h.mu.RUnlock()
	now := time.Now().UTC()
	var out []FleetCommand
	for _, c := range h.commands[sensorID] {
		if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
			continue
		}
		if pendingOnly && c.State != "queued" {
			continue
		}
		out = append(out, c)
	}
	return out
}
func (h *Hub) AckCommand(sensorID, id, state, result string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.commands[sensorID]
	for i := range a {
		if a[i].ID == id {
			if state == "" {
				state = "completed"
			}
			a[i].State = state
			a[i].Result = result
			h.commands[sensorID] = a
			h.persistLocked()
			return nil
		}
	}
	return fmt.Errorf("command not found")
}
func (h *Hub) SetDesired(sensorID, configSHA, rulesSHA, version string) {
	h.mu.Lock()
	if h.desired == nil {
		h.desired = map[string]FleetState{}
	}
	x := h.desired[sensorID]
	x.DesiredConfigSHA256 = configSHA
	x.DesiredRulesSHA256 = rulesSHA
	x.DesiredVersion = version
	h.desired[sensorID] = x
	h.persistLocked()
	h.mu.Unlock()
}
func (h *Hub) Fleet() []FleetState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]FleetState, 0, len(h.sensors))
	for id, s := range h.sensors {
		x := h.desired[id]
		x.Snapshot = s
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}
