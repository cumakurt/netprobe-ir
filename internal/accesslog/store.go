package accesslog

import (
	"encoding/json"
	"netprobe-ir/internal/model"
	"strings"
	"sync"
)

const Capacity = 10000

type Entry struct {
	searchable string
	ID         uint64 `json:"id"`
	Kind       string `json:"kind"`
	model.PacketSummary
}
type Page struct {
	Items    []Entry `json:"items"`
	Total    uint64  `json:"total"`
	Retained int     `json:"retained"`
	Matched  int     `json:"matched"`
	Evicted  uint64  `json:"evicted"`
	Next     uint64  `json:"next"`
	Capacity int     `json:"capacity"`
}
type ring struct {
	entries []Entry
	next    int
	total   uint64
}
type Store struct {
	mu  sync.RWMutex
	dns ring
	web ring
}

func New() *Store { return &Store{} }
func (s *Store) Add(kind string, p model.PacketSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &s.web
	if kind == "dns" {
		r = &s.dns
	}
	r.total++
	entry := Entry{ID: r.total, Kind: kind, PacketSummary: p}
	encoded, _ := json.Marshal(entry)
	entry.searchable = strings.ToLower(string(encoded))
	if len(r.entries) < Capacity {
		r.entries = append(r.entries, entry)
	} else {
		r.entries[r.next] = entry
	}
	r.next = (r.next + 1) % Capacity
}
func (s *Store) Query(kind, query string, before uint64, limit int) Page {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := &s.web
	if kind == "dns" {
		r = &s.dns
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	result := Page{Items: []Entry{}, Total: r.total, Retained: len(r.entries), Capacity: Capacity, Evicted: r.total - uint64(len(r.entries))}
	terms := strings.Fields(strings.ToLower(query))
	for i := 0; i < len(r.entries); i++ {
		index := (r.next - 1 - i + len(r.entries)) % len(r.entries)
		entry := r.entries[index]
		if len(terms) > 0 {
			searchable := entry.searchable
			matches := true
			for _, term := range terms {
				if !strings.Contains(searchable, term) {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
		}
		result.Matched++
		if before != 0 && entry.ID >= before {
			continue
		}
		if len(result.Items) < limit {
			result.Items = append(result.Items, entry)
		} else if result.Next == 0 {
			result.Next = result.Items[len(result.Items)-1].ID
		}
	}
	return result
}
