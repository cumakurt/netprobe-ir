package detectionlab

import (
	"context"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/pcapng"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLabReplay(t *testing.T) {
	d := t.TempDir()
	pcd := filepath.Join(d, "pcap")
	r := pcapng.New(pcd, 1, 10, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	r.Record(capture.Frame{Time: time.Now(), Interface: "e0", Data: make([]byte, 60)})
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	es, _ := os.ReadDir(pcd)
	if len(es) == 0 {
		t.Fatal("no capture")
	}
	c := config.Default()
	out, e := Run(c, filepath.Join(pcd, es[0].Name()), "", "")
	if e != nil {
		t.Fatal(e)
	}
	if out.Frames != 1 {
		t.Fatalf("%+v", out)
	}
}
