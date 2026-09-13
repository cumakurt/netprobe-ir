package playbook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Mode string

const (
	DryRun           Mode = "dry_run"
	ApprovalRequired Mode = "approval_required"
	Automatic        Mode = "automatic"
)

type Condition struct {
	MinSeverity   string   `json:"min_severity,omitempty"`
	MinConfidence int      `json:"min_confidence,omitempty"`
	Verdicts      []string `json:"verdicts,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	RequireYARA   bool     `json:"require_yara,omitempty"`
	RequireKEV    bool     `json:"require_kev,omitempty"`
}

type Action struct {
	Type       string `json:"type"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
}
type Playbook struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Mode      Mode      `json:"mode"`
	Condition Condition `json:"condition"`
	Actions   []Action  `json:"actions"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Match struct {
	PlaybookID       string   `json:"playbook_id"`
	PlaybookName     string   `json:"playbook_name"`
	Mode             Mode     `json:"mode"`
	FindingID        string   `json:"finding_id"`
	Matched          bool     `json:"matched"`
	Reasons          []string `json:"reasons"`
	Actions          []Action `json:"actions"`
	RequiresApproval bool     `json:"requires_approval"`
	Automatic        bool     `json:"automatic"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	items []Playbook
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) load() error {
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, &s.items)
}
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, e := json.MarshalIndent(s.items, "", "  ")
	if e != nil {
		return e
	}
	tmp := s.path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, s.path)
}
func (s *Store) List() []Playbook {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Playbook(nil), s.items...)
}
func (s *Store) Upsert(p Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = fmt.Sprintf("pb-%d", time.Now().UnixNano())
	}
	if p.Name == "" {
		return fmt.Errorf("name required")
	}
	switch p.Mode {
	case DryRun, ApprovalRequired, Automatic:
	default:
		return fmt.Errorf("invalid mode")
	}
	p.UpdatedAt = time.Now().UTC()
	for i := range s.items {
		if s.items[i].ID == p.ID {
			s.items[i] = p
			return s.saveLocked()
		}
	}
	s.items = append(s.items, p)
	return s.saveLocked()
}
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.items[:0]
	for _, p := range s.items {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.items = out
	return s.saveLocked()
}
func (s *Store) Evaluate(f model.SecurityFinding) []Match {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Match{}
	for _, p := range s.items {
		if !p.Enabled {
			continue
		}
		m := evaluate(p, f)
		if m.Matched {
			out = append(out, m)
		}
	}
	return out
}
func evaluate(p Playbook, f model.SecurityFinding) Match {
	m := Match{PlaybookID: p.ID, PlaybookName: p.Name, Mode: p.Mode, FindingID: f.ID, Matched: true, Actions: append([]Action(nil), p.Actions...), RequiresApproval: p.Mode == ApprovalRequired, Automatic: p.Mode == Automatic}
	c := p.Condition
	if c.MinSeverity != "" && sevRank(f.Severity) < sevRank(c.MinSeverity) {
		m.Matched = false
		m.Reasons = append(m.Reasons, "severity below threshold")
	}
	if c.MinConfidence > 0 && f.Confidence < c.MinConfidence {
		m.Matched = false
		m.Reasons = append(m.Reasons, "confidence below threshold")
	}
	if len(c.Verdicts) > 0 && !containsFold(c.Verdicts, f.Verdict) {
		m.Matched = false
		m.Reasons = append(m.Reasons, "verdict mismatch")
	}
	if len(c.Categories) > 0 && !containsFold(c.Categories, f.Category) {
		m.Matched = false
		m.Reasons = append(m.Reasons, "category mismatch")
	}
	if len(c.Tags) > 0 {
		for _, want := range c.Tags {
			if !containsFold(f.Tags, want) {
				m.Matched = false
				m.Reasons = append(m.Reasons, "missing tag "+want)
			}
		}
	}
	if c.RequireYARA && !evidenceBool(f.Evidence, "yara_match") {
		m.Matched = false
		m.Reasons = append(m.Reasons, "YARA evidence required")
	}
	if c.RequireKEV && !evidenceBool(f.Evidence, "kev") {
		m.Matched = false
		m.Reasons = append(m.Reasons, "KEV evidence required")
	}
	if m.Matched {
		m.Reasons = append(m.Reasons, "conditions matched")
	}
	return m
}
func evidenceBool(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x != ""
	default:
		return true
	}
}
func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
