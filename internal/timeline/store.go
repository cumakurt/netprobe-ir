package timeline

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Snapshot struct {
	Time           time.Time `json:"time"`
	Packets        uint64    `json:"packets"`
	Bytes          uint64    `json:"bytes"`
	Flows          int       `json:"flows"`
	ActiveFlows    int       `json:"active_flows"`
	Processes      int       `json:"processes"`
	Alerts         int       `json:"alerts"`
	Findings       int       `json:"findings"`
	Critical       int       `json:"critical"`
	Confirmed      int       `json:"confirmed"`
	CaptureRunning bool      `json:"capture_running"`
}
type Store struct {
	mu    sync.Mutex
	path  string
	max   int
	items []Snapshot
}

func New(path string, max int) *Store {
	if max < 100 {
		max = 10000
	}
	s := &Store{path: path, max: max}
	s.load()
	return s
}
func (s *Store) Add(v Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Time.IsZero() {
		v.Time = time.Now().UTC()
	}
	s.items = append(s.items, v)
	if len(s.items) > s.max {
		s.items = append([]Snapshot(nil), s.items[len(s.items)-s.max:]...)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	f, e := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if e != nil {
		return e
	}
	_, e = f.Write(append(b, '\n'))
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func (s *Store) Range(from, to time.Time, limit int) []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Snapshot
	for _, v := range s.items {
		if !from.IsZero() && v.Time.Before(from) {
			continue
		}
		if !to.IsZero() && v.Time.After(to) {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
func (s *Store) Nearest(at time.Time) (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) == 0 {
		return Snapshot{}, false
	}
	best := s.items[0]
	bd := abs(best.Time.Sub(at))
	for _, v := range s.items[1:] {
		d := abs(v.Time.Sub(at))
		if d < bd {
			best = v
			bd = d
		}
	}
	return best, true
}
func (s *Store) load() {
	f, e := os.Open(s.path)
	if e != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var v Snapshot
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			s.items = append(s.items, v)
		}
	}
	if len(s.items) > s.max {
		s.items = s.items[len(s.items)-s.max:]
	}
}
func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
