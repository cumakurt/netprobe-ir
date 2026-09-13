package approvals

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"netprobe-ir/internal/response"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Request struct {
	ID          string           `json:"id"`
	CreatedAt   time.Time        `json:"created_at"`
	RequestedBy string           `json:"requested_by"`
	Status      string           `json:"status"`
	Action      response.Request `json:"action"`
	ApprovedBy  string           `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time       `json:"approved_at,omitempty"`
	Result      *response.Result `json:"result,omitempty"`
	Error       string           `json:"error,omitempty"`
}
type Store struct {
	mu    sync.Mutex
	path  string
	items []Request
}

func New(path string) *Store {
	s := &Store{path: path}
	if b, e := os.ReadFile(path); e == nil {
		_ = json.Unmarshal(b, &s.items)
	}
	return s
}
func (s *Store) Create(user string, a response.Request) (Request, error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	r := Request{ID: hex.EncodeToString(b[:]), CreatedAt: time.Now().UTC(), RequestedBy: user, Status: "pending", Action: a}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, r)
	return r, s.saveLocked()
}
func (s *Store) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Request(nil), s.items...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (s *Store) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.items {
		if x.ID == id {
			return x, true
		}
	}
	return Request{}, false
}
func (s *Store) Approve(id, user string, result response.Result, execErr error) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		r := &s.items[i]
		if r.ID != id {
			continue
		}
		if r.Status != "pending" {
			return Request{}, fmt.Errorf("approval is not pending")
		}
		if r.RequestedBy == user {
			return Request{}, fmt.Errorf("two-person approval requires a different user")
		}
		now := time.Now().UTC()
		r.ApprovedBy = user
		r.ApprovedAt = &now
		r.Result = &result
		if execErr != nil {
			r.Status = "failed"
			r.Error = execErr.Error()
		} else {
			r.Status = "approved"
		}
		return *r, s.saveLocked()
	}
	return Request{}, fmt.Errorf("approval not found")
}
func (s *Store) saveLocked() error {
	if e := os.MkdirAll(filepath.Dir(s.path), 0750); e != nil {
		return e
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
