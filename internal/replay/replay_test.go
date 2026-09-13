package replay

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/pcapng"
)

func TestPCAPNGReplay(t *testing.T) {
	d := t.TempDir()
	r := pcapng.New(d, 1, 10, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	fr := capture.Frame{Time: time.Unix(1700000000, 123000000), Interface: "eth-test", Data: make([]byte, 60)}
	if !r.Record(fr) {
		t.Fatal("record dropped")
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(d)
	if len(ents) == 0 {
		t.Fatal("no pcapng")
	}
	var got capture.Frame
	st, err := Stream(filepath.Join(d, ents[0].Name()), func(f capture.Frame) error { got = f; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 1 || got.Interface != "eth-test" || len(got.Data) != 60 {
		t.Fatalf("bad replay %+v %+v", st, got)
	}
}
