package baseline

import (
	"fmt"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestBaselineDeviation(t *testing.T) {
	e := New(t.TempDir()+"/b.json", 5)
	p := &model.ProcessInfo{PID: 1, Comm: "agent", Exe: "/bin/agent"}
	for i := 0; i < 5; i++ {
		f := model.Flow{ID: fmt.Sprint(i), FirstSeen: time.Date(2026, 1, 1, 10, 0, i, 0, time.UTC), LastSeen: time.Now(), Process: p, Remote: model.Endpoint{IP: "10.0.0.1"}, DPI: model.DPIInfo{Application: "HTTPS"}}
		if x := e.Observe(f, true); len(x) != 0 {
			t.Fatalf("warmup finding %+v", x)
		}
	}
	f := model.Flow{ID: "new", FirstSeen: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), LastSeen: time.Now(), Process: p, Remote: model.Endpoint{IP: "203.0.113.10"}, DPI: model.DPIInfo{Application: "SSH"}}
	x := e.Observe(f, true)
	if len(x) < 2 {
		t.Fatalf("expected destination+app deviations: %+v", x)
	}
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
}
