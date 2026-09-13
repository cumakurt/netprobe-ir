package dnsintel

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestDoT(t *testing.T) {
	e := New(Config{Enabled: true, AllowedProcesses: []string{"firefox"}})
	f := model.Flow{ID: "x", LastSeen: time.Now(), Direction: model.DirectionOutbound, NetworkProtocol: "TCP", Remote: model.Endpoint{IP: "1.1.1.1", Port: 853}, Process: &model.ProcessInfo{PID: 2, Comm: "python3"}}
	o, s := e.Observe(f, true)
	if o == nil || o.Type != "DoT" || s == nil {
		t.Fatalf("%#v %#v", o, s)
	}
}
