package eventbus

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event is the normalized internal telemetry envelope passed from the packet
// processing pipeline to non-blocking exporters. Payload must contain only
// structured metadata; raw packet payload bytes are intentionally excluded.
type Event struct {
	Time      time.Time `json:"time"`
	Category  string    `json:"category"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity,omitempty"`
	Interface string    `json:"interface,omitempty"`
	FlowID    string    `json:"flow_id,omitempty"`
	PacketID  string    `json:"packet_id,omitempty"`
	Payload   any       `json:"payload,omitempty"`
}

type Subscription struct {
	C       <-chan Event
	ch      chan Event
	dropped atomic.Uint64
}

func (s *Subscription) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

type Bus struct {
	mu   sync.RWMutex
	subs map[*Subscription]struct{}
}

func New() *Bus { return &Bus{subs: make(map[*Subscription]struct{})} }

func (b *Bus) Subscribe(size int) *Subscription {
	if size <= 0 {
		size = 1024
	}
	ch := make(chan Event, size)
	s := &Subscription{C: ch, ch: ch}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

func (b *Bus) Unsubscribe(s *Subscription) {
	if s == nil {
		return
	}
	b.mu.Lock()
	if _, ok := b.subs[s]; ok {
		delete(b.subs, s)
		close(s.ch)
	}
	b.mu.Unlock()
}

// Publish never waits for an exporter. A slow subscriber drops only its own
// copy of the event and increments a bounded-queue drop counter.
func (b *Bus) Publish(e Event) {
	if b == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		select {
		case s.ch <- e:
		default:
			s.dropped.Add(1)
		}
	}
}
