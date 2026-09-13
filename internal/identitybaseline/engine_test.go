package identitybaseline

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestIdentityDeviation(t *testing.T) {
	e := New("", 5)
	base := model.Flow{Direction: model.DirectionOutbound, FirstSeen: time.Now(), LastSeen: time.Now(), Remote: model.Endpoint{IP: "1.1.1.1", Port: 443}, Process: &model.ProcessInfo{PID: 1, Comm: "svc", User: "alice", ContainerID: "c1"}, DPI: model.DPIInfo{Application: "TLS"}}
	for i := 0; i < 5; i++ {
		base.ID = string(rune('a' + i))
		e.Observe(base, true)
	}
	base.ID = "z"
	base.Remote.IP = "9.9.9.9"
	f := e.Observe(base, true)
	if len(f) < 3 {
		t.Fatalf("want multiple identities, got %d", len(f))
	}
}
