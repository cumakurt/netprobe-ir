package lateral

import (
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestFanout(t *testing.T) {
	e := New(Config{HostThreshold: 3})
	var got int
	for i := 0; i < 3; i++ {
		f := model.Flow{ID: string(rune('a' + i)), FirstSeen: time.Now(), Direction: model.DirectionOutbound, Remote: model.Endpoint{IP: "10.0.0." + string(rune('1'+i)), Port: 445}, Process: &model.ProcessInfo{PID: 3, User: "alice"}, DPI: model.DPIInfo{Application: "SMB"}}
		got += len(e.Observe(&decode.Packet{}, f, true))
	}
	if got == 0 {
		t.Fatal("no finding")
	}
}
