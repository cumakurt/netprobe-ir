package eventbus

import (
	"runtime"
	"testing"
	"time"
)

func TestNonBlockingAndDropAccounting(t *testing.T) {
	b := New()
	s := b.Subscribe(1)
	b.Publish(Event{Category: "network", Type: "packet"})
	done := make(chan struct{})
	go func() { b.Publish(Event{Category: "network", Type: "packet"}); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("publish blocked")
	}
	if s.Dropped() != 1 {
		t.Fatalf("dropped=%d", s.Dropped())
	}
}

func TestLoadRemainsBoundedAndNonBlocking(t *testing.T) {
	b := New()
	s := b.Subscribe(8)
	before := runtime.NumGoroutine()
	start := time.Now()
	for i := 0; i < 100000; i++ {
		b.Publish(Event{Category: "network", Type: "packet"})
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("event bus publish path became blocking")
	}
	if len(s.C) > 8 {
		t.Fatalf("bounded queue exceeded capacity: %d", len(s.C))
	}
	if s.Dropped() == 0 {
		t.Fatal("expected drop accounting under a stalled subscriber")
	}
	if runtime.NumGoroutine() > before+2 {
		t.Fatal("publisher created unbounded goroutines")
	}
}
