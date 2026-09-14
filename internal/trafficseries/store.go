package trafficseries

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
)

type Point struct {
	Time       time.Time `json:"time"`
	InBytes    uint64    `json:"in_bytes"`
	OutBytes   uint64    `json:"out_bytes"`
	InPackets  uint64    `json:"in_packets"`
	OutPackets uint64    `json:"out_packets"`
	Flows      uint64    `json:"flows"`
	InFlows    uint64    `json:"in_flows"`
	OutFlows   uint64    `json:"out_flows"`
}

type RatePoint struct {
	Time          time.Time `json:"time"`
	InBytesSec    float64   `json:"in_bytes_sec"`
	OutBytesSec   float64   `json:"out_bytes_sec"`
	InBitsSec     float64   `json:"in_bits_sec"`
	OutBitsSec    float64   `json:"out_bits_sec"`
	InPacketsSec  float64   `json:"in_packets_sec"`
	OutPacketsSec float64   `json:"out_packets_sec"`
	FlowsSec      float64   `json:"flows_sec"`
	InFlowsSec    float64   `json:"in_flows_sec"`
	OutFlowsSec   float64   `json:"out_flows_sec"`
}

type Store struct {
	mu      sync.RWMutex
	points  []Point
	max     int
	current Point
	seen    map[string]time.Time
	bus     *eventbus.Bus
	sub     *eventbus.Subscription
	stop    chan struct{}
	done    chan struct{}
}

func New(bus *eventbus.Bus, max int) *Store {
	if max <= 0 {
		max = 90000
	}
	s := &Store{bus: bus, max: max, seen: map[string]time.Time{}, stop: make(chan struct{}), done: make(chan struct{})}
	if bus != nil {
		s.sub = bus.Subscribe(4096)
		go s.run()
	} else {
		close(s.done)
	}
	return s
}

func (s *Store) run() {
	defer close(s.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case ev, ok := <-s.sub.C:
			if !ok {
				return
			}
			s.consume(ev)
		case now := <-t.C:
			s.flush(now.UTC().Truncate(time.Second))
		}
	}
}

func (s *Store) consume(ev eventbus.Event) {
	if ev.Type != "packet_metadata" {
		return
	}
	p, ok := ev.Payload.(model.PacketSummary)
	if !ok || p.SensorTraffic {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := uint64(0)
	if p.Length > 0 {
		l = uint64(p.Length)
	}
	switch p.Direction {
	case model.DirectionInbound:
		s.current.InBytes += l
		s.current.InPackets++
	case model.DirectionOutbound:
		s.current.OutBytes += l
		s.current.OutPackets++
	case model.DirectionForwarded:
		// Forwarded traffic traverses the monitored host; count it on both sides.
		s.current.InBytes += l
		s.current.OutBytes += l
		s.current.InPackets++
		s.current.OutPackets++
	}
	if p.FlowID != "" {
		if _, exists := s.seen[p.FlowID]; !exists {
			s.current.Flows++
			switch p.Direction {
			case model.DirectionInbound:
				s.current.InFlows++
			case model.DirectionOutbound:
				s.current.OutFlows++
			case model.DirectionForwarded:
				s.current.InFlows++
				s.current.OutFlows++
			}
			s.seen[p.FlowID] = ev.Time
		}
	}
}

func (s *Store) flush(ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.current
	p.Time = ts
	s.current = Point{}
	s.points = append(s.points, p)
	if len(s.points) > s.max {
		s.points = append([]Point(nil), s.points[len(s.points)-s.max:]...)
	}
	cut := ts.Add(-2 * time.Hour)
	for id, seen := range s.seen {
		if seen.Before(cut) {
			delete(s.seen, id)
		}
	}
}

func (s *Store) Close() {
	if s == nil || s.sub == nil {
		return
	}
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	<-s.done
	if s.bus != nil && s.sub != nil {
		s.bus.Unsubscribe(s.sub)
		s.sub = nil
	}
}

func ParseRange(v string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1m", "":
		return time.Minute, nil
	case "5m":
		return 5 * time.Minute, nil
	case "15m":
		return 15 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported range")
	}
}

func stepFor(d time.Duration) time.Duration {
	switch {
	case d <= time.Minute:
		return time.Second
	case d <= 5*time.Minute:
		return 5 * time.Second
	case d <= 15*time.Minute:
		return 15 * time.Second
	case d <= time.Hour:
		return 30 * time.Second
	default:
		return 5 * time.Minute
	}
}

func (s *Store) History(d time.Duration, now time.Time) []RatePoint {
	if s == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	from := now.Add(-d)
	step := stepFor(d)
	s.mu.RLock()
	src := append([]Point(nil), s.points...)
	cur := s.current
	s.mu.RUnlock()
	if cur.InBytes+cur.OutBytes+cur.InPackets+cur.OutPackets+cur.Flows > 0 {
		cur.Time = now
		src = append(src, cur)
	}
	type acc struct {
		p Point
		n int
	}
	buckets := map[int64]*acc{}
	for _, p := range src {
		if p.Time.Before(from) || p.Time.After(now.Add(time.Second)) {
			continue
		}
		k := p.Time.Unix() / int64(step/time.Second)
		a := buckets[k]
		if a == nil {
			a = &acc{}
			buckets[k] = a
		}
		a.p.Time = time.Unix(k*int64(step/time.Second), 0).UTC()
		a.p.InBytes += p.InBytes
		a.p.OutBytes += p.OutBytes
		a.p.InPackets += p.InPackets
		a.p.OutPackets += p.OutPackets
		a.p.Flows += p.Flows
		a.p.InFlows += p.InFlows
		a.p.OutFlows += p.OutFlows
		a.n++
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	sec := step.Seconds()
	out := make([]RatePoint, 0, len(keys))
	for _, k := range keys {
		p := buckets[k].p
		out = append(out, RatePoint{Time: p.Time, InBytesSec: float64(p.InBytes) / sec, OutBytesSec: float64(p.OutBytes) / sec, InBitsSec: float64(p.InBytes) * 8 / sec, OutBitsSec: float64(p.OutBytes) * 8 / sec, InPacketsSec: float64(p.InPackets) / sec, OutPacketsSec: float64(p.OutPackets) / sec, FlowsSec: float64(p.Flows) / sec, InFlowsSec: float64(p.InFlows) / sec, OutFlowsSec: float64(p.OutFlows) / sec})
	}
	return out
}

func (s *Store) Current() RatePoint {
	xs := s.History(time.Minute, time.Now().UTC())
	if len(xs) == 0 {
		return RatePoint{Time: time.Now().UTC()}
	}
	return xs[len(xs)-1]
}
