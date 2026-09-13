package netbaseline

import (
	"netprobe-ir/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestDiff(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "n.jsonl"))
	now := time.Now().UTC()
	_ = s.Observe(model.Flow{LastSeen: now.Add(-2 * time.Hour), Remote: model.Endpoint{IP: "1.1.1.1"}, NetworkProtocol: "TCP"})
	_ = s.Observe(model.Flow{LastSeen: now.Add(-10 * time.Minute), Remote: model.Endpoint{IP: "1.1.1.1"}, NetworkProtocol: "TCP"})
	_ = s.Observe(model.Flow{LastSeen: now.Add(-5 * time.Minute), Remote: model.Endpoint{IP: "2.2.2.2"}, NetworkProtocol: "UDP"})
	d, e := s.Compare(now, time.Hour, 24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, x := range d.New {
		if x.Value == "2.2.2.2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%#v", d)
	}
}
