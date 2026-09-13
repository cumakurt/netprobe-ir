package pcapng

import (
	"context"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderWritesValidPCAPNG(t *testing.T) {
	d := t.TempDir()
	r := New(filepath.Join(d, "pcap"), 1, 4, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	r.Record(capture.Frame{Time: time.Now(), Interface: "eth0", Direction: model.DirectionOutbound, Data: make([]byte, 64)})
	time.Sleep(30 * time.Millisecond)
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	fs, _ := filepath.Glob(filepath.Join(d, "pcap", "*.pcapng"))
	if len(fs) != 1 {
		t.Fatalf("files=%v", fs)
	}
	if e := Validate(fs[0]); e != nil {
		t.Fatal(e)
	}
}

func TestProtectProducesValidClosedArtifact(t *testing.T) {
	d := t.TempDir()
	r := New(filepath.Join(d, "pcap"), 1, 8, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	r.Record(capture.Frame{Time: time.Now(), Interface: "eth0", Direction: model.DirectionOutbound, Data: make([]byte, 128)})
	time.Sleep(30 * time.Millisecond)
	protected := r.Protect("unit-test")
	if len(protected) == 0 {
		t.Fatal("no protected files")
	}
	for _, p := range protected {
		if e := Validate(p); e != nil {
			t.Fatalf("protected %s invalid: %v", p, e)
		}
	}
	cancel()
	<-done
}
