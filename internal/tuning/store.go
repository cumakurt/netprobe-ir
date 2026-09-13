package tuning

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"netprobe-ir/internal/model"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Enabled   bool      `json:"enabled"`
}
type Store struct {
	mu    sync.Mutex
	path  string
	rules []Rule
}

func New(path string) (*Store, error) {
	s := &Store{path: path}
	if b, e := os.ReadFile(path); e == nil {
		_ = json.Unmarshal(b, &s.rules)
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}
func (s *Store) List() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Rule(nil), s.rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (s *Store) Add(r Rule) (Rule, error) {
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	r.Value = strings.TrimSpace(r.Value)
	switch r.Kind {
	case "rule", "process", "ip", "domain", "application":
	default:
		return Rule{}, fmt.Errorf("unsupported suppression kind")
	}
	if r.Value == "" {
		return Rule{}, fmt.Errorf("suppression value required")
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	r.ID = hex.EncodeToString(b[:])
	r.CreatedAt = time.Now().UTC()
	r.Enabled = true
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, r)
	return r, s.saveLocked()
}
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("suppression not found")
}
func (s *Store) Suppressed(f model.SecurityFinding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, r := range s.rules {
		if !r.Enabled || (!r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)) {
			continue
		}
		v := strings.ToLower(r.Value)
		switch r.Kind {
		case "rule":
			if strings.EqualFold(f.RuleID, r.Value) {
				return true
			}
		case "process":
			if strings.Contains(strings.ToLower(f.Process), v) {
				return true
			}
		case "ip":
			if f.Source.IP == r.Value || f.Destination.IP == r.Value {
				return true
			}
		case "domain":
			if strings.EqualFold(f.Application, r.Value) || strings.Contains(strings.ToLower(fmt.Sprint(f.Evidence)), v) {
				return true
			}
		case "application":
			if strings.EqualFold(f.Application, r.Value) {
				return true
			}
		}
	}
	return false
}
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	b, e := json.MarshalIndent(s.rules, "", "  ")
	if e != nil {
		return e
	}
	tmp := s.path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, s.path)
}
