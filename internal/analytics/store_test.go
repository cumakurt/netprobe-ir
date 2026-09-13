package analytics

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQuery(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "events.jsonl"), 10)
	now := time.Now()
	_ = s.Append(Event{Time: now, Type: "finding", Severity: "critical", Process: "python", Destination: "1.2.3.4"})
	_ = s.Append(Event{Time: now.Add(time.Second), Type: "flow", Process: "curl", Destination: "8.8.8.8"})
	r, e := s.Query(Query{Types: []string{"finding"}, Process: "py", Limit: 10})
	if e != nil || r.Count != 1 || r.BySeverity["critical"] != 1 {
		t.Fatalf("%v %#v", e, r)
	}
}
