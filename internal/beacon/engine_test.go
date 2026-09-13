package beacon

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestBeacon(t *testing.T) {
	now := time.Now()
	var fs []model.Flow
	for i := 0; i < 7; i++ {
		x := now.Add(time.Duration(i*30) * time.Second)
		fs = append(fs, model.Flow{ID: string(rune('a' + i)), FirstSeen: x, LastSeen: x.Add(time.Second), Direction: model.DirectionOutbound, Remote: model.Endpoint{IP: "1.2.3.4", Port: 443}, Process: &model.ProcessInfo{PID: 5, Comm: "python3"}, DPI: model.DPIInfo{Application: "TLS"}, BytesTX: 100, BytesRX: 50})
	}
	g, f := New(Config{}).Analyze(fs)
	if len(g) != 1 || len(f) != 1 || g[0].Score < 75 {
		t.Fatalf("g=%#v f=%#v", g, f)
	}
}
