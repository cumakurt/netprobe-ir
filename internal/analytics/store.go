package analytics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Time        time.Time      `json:"time"`
	Type        string         `json:"type"`
	Severity    string         `json:"severity,omitempty"`
	Host        string         `json:"host,omitempty"`
	Process     string         `json:"process,omitempty"`
	Destination string         `json:"destination,omitempty"`
	Key         string         `json:"key,omitempty"`
	Value       float64        `json:"value,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
}
type Query struct {
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Types       []string  `json:"types,omitempty"`
	Severity    []string  `json:"severity,omitempty"`
	Process     string    `json:"process,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Limit       int       `json:"limit,omitempty"`
}
type Result struct {
	Events     []Event        `json:"events"`
	ByType     map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
	Count      int            `json:"count"`
}
type Store struct {
	mu   sync.RWMutex
	path string
	max  int
}

func Open(path string, max int) *Store {
	if max <= 0 {
		max = 200000
	}
	return &Store{path: path, max: max}
}
func (s *Store) Append(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	_, err = f.Write(append(b, '\n'))
	return err
}
func (s *Store) Query(q Query) (Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return Result{ByType: map[string]int{}, BySeverity: map[string]int{}}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	if q.Limit <= 0 || q.Limit > 10000 {
		q.Limit = 1000
	}
	typeSet := set(q.Types)
	sevSet := set(q.Severity)
	out := Result{ByType: map[string]int{}, BySeverity: map[string]int{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if !q.Start.IsZero() && e.Time.Before(q.Start) {
			continue
		}
		if !q.End.IsZero() && e.Time.After(q.End) {
			continue
		}
		if len(typeSet) > 0 && !typeSet[strings.ToLower(e.Type)] {
			continue
		}
		if len(sevSet) > 0 && !sevSet[strings.ToLower(e.Severity)] {
			continue
		}
		if q.Process != "" && !strings.Contains(strings.ToLower(e.Process), strings.ToLower(q.Process)) {
			continue
		}
		if q.Destination != "" && !strings.Contains(strings.ToLower(e.Destination), strings.ToLower(q.Destination)) {
			continue
		}
		out.Count++
		out.ByType[e.Type]++
		if e.Severity != "" {
			out.BySeverity[e.Severity]++
		}
		out.Events = append(out.Events, e)
		if len(out.Events) > q.Limit {
			out.Events = out.Events[len(out.Events)-q.Limit:]
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	sort.Slice(out.Events, func(i, j int) bool { return out.Events[i].Time.After(out.Events[j].Time) })
	return out, nil
}
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) <= s.max {
		return nil
	}
	lines = lines[len(lines)-s.max:]
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[strings.ToLower(strings.TrimSpace(x))] = true
	}
	return m
}
func (s *Store) Path() string { return s.path }
func (q Query) Validate() error {
	if !q.End.IsZero() && !q.Start.IsZero() && q.End.Before(q.Start) {
		return fmt.Errorf("end before start")
	}
	return nil
}
