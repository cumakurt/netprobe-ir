// Package telemetry aggregates live packet observations independently of retained
// forensic snapshots. Counters count capture observations, not unique wire packets.
package telemetry

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

const maxKeys = 4096
const maxFlows = 50000
const maxTrackedFlows = 100000
const maxTrackedKeys = 100000
const maxScopes = 64

var Directions = []string{"inbound", "outbound", "forwarded", "unknown"}

type Count struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

func (c *Count) add(v Count) { c.Bytes += v.Bytes; c.Packets += v.Packets; c.Flows += v.Flows }

type Ranked struct {
	Key string `json:"key"`
	Count
}
type Point struct {
	KernelSeconds float64   `json:"kernel_seconds"`
	Time          time.Time `json:"time"`
	Seconds       float64   `json:"seconds"`
	Bytes         [4]uint64 `json:"bytes"`
	Packets       [4]uint64 `json:"packets"`
	Flows         uint64    `json:"flows"`
	Connections   uint64    `json:"connections"`
	RX            *Count    `json:"rx"`
	TX            *Count    `json:"tx"`
}
type Conversation struct {
	ID          string         `json:"id"`
	Source      model.Endpoint `json:"source"`
	Destination model.Endpoint `json:"destination"`
	Protocol    string         `json:"protocol"`
	Application string         `json:"application"`
	First       time.Time      `json:"first"`
	Last        time.Time      `json:"last"`
	Duration    float64        `json:"duration"`
	Count
	Closed    bool `json:"closed"`
	Initiated bool `json:"initiated"`
}
type scope struct {
	flowLimited bool
	totals      Count
	directions  [4]Count
	current     Point
	seconds     []Point
	minutes     []Point
	minute      Point
	groups      map[string]map[string]Count
	flows       map[string]*Conversation
	overflow    bool
	kernel      *InterfaceCounters
	lastKernel  *InterfaceCounters
	currentRate Point
	cache       *Snapshot
	cacheAt     time.Time
}
type Snapshot struct {
	FlowLimited bool                `json:"flow_limited"`
	Time        time.Time           `json:"time"`
	Since       time.Time           `json:"since"`
	Interface   string              `json:"interface"`
	Totals      Count               `json:"totals"`
	Directions  [4]Count            `json:"directions"`
	Current     Point               `json:"current"`
	Groups      map[string][]Ranked `json:"groups"`
	Active      int                 `json:"active_flows"`
	ActiveTCP   int                 `json:"active_tcp"`
	ActiveUDP   int                 `json:"active_udp"`
	Longest     []Conversation      `json:"longest"`
	Largest     []Conversation      `json:"largest"`
	MostPackets []Conversation      `json:"most_packets"`
	Interfaces  []string            `json:"interfaces"`
	Kernel      *InterfaceCounters  `json:"kernel"`
	Limited     bool                `json:"limited"`
	IdleSeconds float64             `json:"idle_seconds"`
}
type Store struct {
	trackedFlows int
	trackedKeys  int
	mu           sync.Mutex
	scopes       map[string]*scope
	since        time.Time
	last         time.Time
	idle         time.Duration
	limited      bool
}

func newScope() *scope {
	return &scope{groups: map[string]map[string]Count{}, flows: map[string]*Conversation{}, seconds: make([]Point, 0, 900), minutes: make([]Point, 0, 1440)}
}
func New(now time.Time, idle time.Duration) *Store {
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	return &Store{scopes: map[string]*scope{"": newScope()}, since: now, last: now, idle: idle}
}
func (s *Store) ensure(name string) *scope {
	x := s.scopes[name]
	if x == nil {
		if len(s.scopes) >= maxScopes {
			s.limited = true
			return nil
		}
		x = newScope()
		s.scopes[name] = x
	}
	return x
}
func (s *Store) group(x *scope, name, key string, c Count) {
	if key == "" {
		key = "Unknown"
	}
	m := x.groups[name]
	if m == nil {
		m = map[string]Count{}
		x.groups[name] = m
	}
	if _, ok := m[key]; !ok && (len(m) >= maxKeys || s.trackedKeys >= maxTrackedKeys) {
		key = "Other (cardinality limit)"
		x.overflow = true
	}
	if _, exists := m[key]; !exists {
		s.trackedKeys++
	}
	v := m[key]
	v.add(c)
	m[key] = v
}
func dirIndex(d model.Direction) int {
	switch d {
	case model.DirectionInbound:
		return 0
	case model.DirectionOutbound:
		return 1
	case model.DirectionForwarded:
		return 2
	default:
		return 3
	}
}
func packetSize(n int) string {
	switch {
	case n <= 64:
		return "≤64 B"
	case n <= 128:
		return "65–128 B"
	case n <= 256:
		return "129–256 B"
	case n <= 512:
		return "257–512 B"
	case n <= 1024:
		return "513–1024 B"
	case n <= 1518:
		return "1025–1518 B"
	default:
		return ">1518 B"
	}
}
func application(d model.DPIInfo) string {
	if d.Confidence >= 80 && d.Application != "" && d.Evidence != "port" {
		return d.Application
	}
	return "Unknown / Unclassified"
}

// Observe receives only live, decoded packet metadata. It never scans flow history
// and performs a bounded number of map updates regardless of traffic cardinality.
func (s *Store) Observe(p model.PacketSummary) {
	if p.Length < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range []string{"", p.Interface} {
		if name == "" && p.Interface == "" { // Only one global update for unnamed captures.
			s.observe(s.scopes[""], p)
			break
		}
		if x := s.ensure(name); x != nil {
			s.observe(x, p)
		}
	}
}
func (s *Store) observe(x *scope, p model.PacketSummary) {
	c := Count{Bytes: uint64(p.Length), Packets: 1}
	d := dirIndex(p.Direction)
	x.totals.add(c)
	x.directions[d].add(c)
	x.current.Bytes[d] += c.Bytes
	x.current.Packets[d]++
	proto := p.NetworkProtocol
	if strings.HasPrefix(proto, "ICMP") {
		proto = "ICMP"
	}
	if proto != "TCP" && proto != "UDP" && proto != "ICMP" {
		proto = "Other"
	}
	app := application(p.DPI)
	s.group(x, "sources", p.Source.IP, c)
	s.group(x, "destinations", p.Destination.IP, c)
	s.group(x, "endpoints", p.Source.IP, c)
	if p.Source.IP != p.Destination.IP {
		s.group(x, "endpoints", p.Destination.IP, c)
	}
	s.group(x, "protocols", proto, c)
	s.group(x, "ip_versions", fmt.Sprintf("IPv%d", p.IPVersion), c)
	s.group(x, "applications", app, c)
	s.group(x, "packet_sizes", packetSize(p.Length), c)
	known := "Known"
	if app == "Unknown / Unclassified" {
		known = "Unknown / Unclassified"
	}
	s.group(x, "classification", known, c)
	service := "Unknown / Unclassified"
	if app != "Unknown / Unclassified" {
		service = p.DPI.Protocol
	}
	s.group(x, "services", service, c)
	s.group(x, "direction_"+Directions[d], p.Source.IP+" → "+p.Destination.IP, c)
	if p.NetworkProtocol == "TCP" || p.NetworkProtocol == "UDP" { // Both endpoint port incidences; equal ports count once.
		g := strings.ToLower(p.NetworkProtocol) + "_ports"
		s.group(x, g, fmt.Sprint(p.Source.Port), c)
		if p.Source.Port != p.Destination.Port {
			s.group(x, g, fmt.Sprint(p.Destination.Port), c)
		}
	}
	if p.FlowID == "" {
		return
	}
	// Canonical packet endpoints keep reverse traffic in the same conversation,
	// including routed packets whose collector flow IDs may differ by direction.
	a, b := p.Source, p.Destination
	if a.IP > b.IP || a.IP == b.IP && a.Port > b.Port {
		a, b = b, a
	}
	key := fmt.Sprintf("%s|%s:%d|%s:%d", p.NetworkProtocol, a.IP, a.Port, b.IP, b.Port)
	f := x.flows[key]
	syn := p.NetworkProtocol == "TCP" && strings.Contains(p.TCPFlags, "SYN") && !strings.Contains(p.TCPFlags, "ACK")
	if f != nil && (p.Time.Sub(f.Last) > s.idle || f.Closed && syn) {
		delete(x.flows, key)
		s.trackedFlows--
		f = nil
	}

	if f == nil {
		if len(x.flows) >= maxFlows || s.trackedFlows >= maxTrackedFlows {
			x.flowLimited = true
			x.overflow = true
			return
		}
		f = &Conversation{ID: p.FlowID, Source: p.Source, Destination: p.Destination, Protocol: p.NetworkProtocol, First: p.Time, Last: p.Time}
		x.flows[key] = f
		s.trackedFlows++
		x.totals.Flows++
		x.current.Flows++
		s.group(x, "flow_sources", p.Source.IP, Count{Flows: 1})
		s.group(x, "flow_destinations", p.Destination.IP, Count{Flows: 1})
	}
	if syn && (!f.Initiated || f.Closed) {
		f.Initiated = true
		f.Source = p.Source
		f.Destination = p.Destination
		f.Closed = false
		f.First = p.Time
		x.current.Connections++
		s.group(x, "connection_sources", p.Source.IP, Count{Flows: 1})
		s.group(x, "connection_destinations", p.Destination.IP, Count{Flows: 1})
	}
	if p.Time.After(f.Last) {
		f.Last = p.Time
	}
	if p.Time.Before(f.First) {
		f.First = p.Time
	}
	f.Duration = f.Last.Sub(f.First).Seconds()
	f.Count.add(c)
	f.Application = app
	if strings.Contains(p.TCPFlags, "FIN") || strings.Contains(p.TCPFlags, "RST") {
		f.Closed = true
	}
}
func (s *Store) Run(ctx context.Context) {
	s.Tick(time.Now(), ReadInterfaces())
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(time.Now(), ReadInterfaces())
		}
	}
}
func appendBounded(xs []Point, p Point, max int) []Point {
	if len(xs) == max {
		copy(xs, xs[1:])
		xs[len(xs)-1] = p
		return xs
	}
	return append(xs, p)
}
func addPoint(a *Point, b Point) {
	a.Seconds += b.Seconds
	a.KernelSeconds += b.KernelSeconds
	a.Flows += b.Flows
	a.Connections += b.Connections
	for i := range a.Bytes {
		a.Bytes[i] += b.Bytes[i]
		a.Packets[i] += b.Packets[i]
	}
	if b.RX != nil {
		if a.RX == nil {
			a.RX = &Count{}
			a.TX = &Count{}
		}
		a.RX.add(*b.RX)
		a.TX.add(*b.TX)
	}
}

// Tick finalizes a complete measurement interval. Kernel resets produce a gap,
// never a negative rate or a huge unsigned counter delta.
func (s *Store) Tick(now time.Time, kernel map[string]InterfaceCounters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed := now.Sub(s.last).Seconds()
	if elapsed <= 0 {
		return
	}
	for name := range kernel {
		s.ensure(name)
	}
	for name, x := range s.scopes {
		p := x.current
		p.Time = now
		p.Seconds = elapsed
		k, ok := kernel[name]
		x.kernel = nil
		if ok {
			cp := k
			x.kernel = &cp
			if x.lastKernel != nil && k.RX.Bytes >= x.lastKernel.RX.Bytes && k.TX.Bytes >= x.lastKernel.TX.Bytes && k.RX.Packets >= x.lastKernel.RX.Packets && k.TX.Packets >= x.lastKernel.TX.Packets {
				p.KernelSeconds = elapsed
				p.RX = &Count{Bytes: k.RX.Bytes - x.lastKernel.RX.Bytes, Packets: k.RX.Packets - x.lastKernel.RX.Packets}
				p.TX = &Count{Bytes: k.TX.Bytes - x.lastKernel.TX.Bytes, Packets: k.TX.Packets - x.lastKernel.TX.Packets}
			}
			x.lastKernel = &cp
		} else {
			x.lastKernel = nil
		}
		x.currentRate = p
		x.current = Point{}
		x.seconds = appendBounded(x.seconds, p, 900)
		minute := now.Truncate(time.Minute)
		if !x.minute.Time.IsZero() && !x.minute.Time.Equal(minute) {
			x.minutes = appendBounded(x.minutes, x.minute, 1440)
			x.minute = Point{}
		}
		x.minute.Time = minute
		addPoint(&x.minute, p)
		for key, f := range x.flows {
			if now.Sub(f.Last) > s.idle {
				delete(x.flows, key)
				s.trackedFlows--
			}
		}
		x.cache = nil
	}
	s.last = now
}
func rank(m map[string]Count, metric string) []Ranked {
	out := make([]Ranked, 0, len(m))
	for k, v := range m {
		out = append(out, Ranked{k, v})
	}
	value := func(c Count) uint64 {
		if metric == "flows" {
			return c.Flows
		}
		if metric == "packets" {
			return c.Packets
		}
		return c.Bytes
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := value(out[i].Count), value(out[j].Count)
		if a == b {
			return out[i].Key < out[j].Key
		}
		return a > b
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// Keep only the best 20 candidates: large flow tables never become API payloads.
func addTopFlow(top []Conversation, f Conversation, metric string) []Conversation {
	better := func(a, b Conversation) bool {
		switch metric {
		case "duration":
			if a.Duration != b.Duration {
				return a.Duration > b.Duration
			}
		case "packets":
			if a.Packets != b.Packets {
				return a.Packets > b.Packets
			}
		default:
			if a.Bytes != b.Bytes {
				return a.Bytes > b.Bytes
			}
		}
		return a.ID < b.ID
	}
	if len(top) == 20 && !better(f, top[19]) {
		return top
	}
	pos := sort.Search(len(top), func(i int) bool { return better(f, top[i]) })
	if len(top) < 20 {
		top = append(top, Conversation{})
	}
	copy(top[pos+1:], top[pos:len(top)-1])
	top[pos] = f
	return top
}
func (s *Store) Snapshot(name string, now time.Time) (*Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.scopes[name]
	if x == nil {
		return nil, false
	}
	if x.cache != nil && now.Sub(x.cacheAt) < time.Second {
		return x.cache, true
	}
	v := &Snapshot{FlowLimited: x.flowLimited, Time: s.last, Since: s.since, Interface: name, Totals: x.totals, Directions: x.directions, Current: x.currentRate, Groups: map[string][]Ranked{}, Kernel: x.kernel, Limited: s.limited || x.overflow, IdleSeconds: s.idle.Seconds()}
	for name := range s.scopes {
		if name != "" {
			v.Interfaces = append(v.Interfaces, name)
		}
	}
	sort.Strings(v.Interfaces)
	for k, m := range x.groups {
		metric := "bytes"
		if strings.HasPrefix(k, "flow_") || strings.HasPrefix(k, "connection_") {
			metric = "flows"
		}
		if k == "packet_sizes" {
			metric = "packets"
		}
		v.Groups[k] = rank(m, metric)
	}
	v.Longest = make([]Conversation, 0, 20)
	v.Largest = make([]Conversation, 0, 20)
	v.MostPackets = make([]Conversation, 0, 20)
	active := map[string]Count{}
	for _, f := range x.flows {
		if now.Sub(f.Last) > s.idle {
			continue
		}
		v.Largest = addTopFlow(v.Largest, *f, "bytes")
		v.MostPackets = addTopFlow(v.MostPackets, *f, "packets")
		if !f.Closed {
			v.Longest = addTopFlow(v.Longest, *f, "duration")
		}
		if !f.Closed {
			v.Active++
			if f.Protocol == "TCP" {
				v.ActiveTCP++
			}
			if f.Protocol == "UDP" {
				v.ActiveUDP++
			}
			c := active[f.Source.IP]
			c.Flows++
			active[f.Source.IP] = c
		}
	}
	v.Groups["active_sources"] = rank(active, "flows")
	x.cache = v
	x.cacheAt = now
	return v, true
}
func (s *Store) History(name string, d time.Duration, now time.Time) []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.scopes[name]
	out := []Point{}
	if x == nil {
		return out
	}
	src := x.seconds
	if d > 15*time.Minute {
		src = append(append([]Point{}, x.minutes...), x.minute)
	}
	for _, p := range src {
		if !p.Time.Before(now.Add(-d)) && !p.Time.After(now) && p.Seconds > 0 {
			// The open minute bucket is still being accumulated by Tick.
			// Detach counters before readers marshal outside the store lock.
			if p.RX != nil {
				rx, tx := *p.RX, *p.TX
				p.RX = &rx
				p.TX = &tx
			}
			out = append(out, p)
		}
	}
	// Bound payload/render cost to at most 360 points, preserving measured duration.
	step := (len(out) + 359) / 360
	if step <= 1 {
		return out
	}
	compact := []Point{}
	for i := 0; i < len(out); i += step {
		p := Point{Time: out[i].Time}
		for j := i; j < len(out) && j < i+step; j++ {
			addPoint(&p, out[j])
		}
		compact = append(compact, p)
	}
	return compact
}
