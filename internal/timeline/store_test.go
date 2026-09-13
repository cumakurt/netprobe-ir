package timeline

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTimeline(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "t.jsonl"), 100)
	n := time.Now()
	_ = s.Add(Snapshot{Time: n, Flows: 1})
	_ = s.Add(Snapshot{Time: n.Add(time.Minute), Flows: 2})
	v, ok := s.Nearest(n.Add(50 * time.Second))
	if !ok || v.Flows != 2 {
		t.Fatalf("%#v", v)
	}
	if len(s.Range(n, n.Add(2*time.Minute), 10)) != 2 {
		t.Fatal("range")
	}
}
