package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	Role     string    `json:"role,omitempty"`
	SourceIP string    `json:"source_ip,omitempty"`
	Action   string    `json:"action"`
	Resource string    `json:"resource,omitempty"`
	Success  bool      `json:"success"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prev_hash,omitempty"`
	Hash     string    `json:"hash"`
}
type Log struct {
	mu            sync.Mutex
	path, keyPath string
	key           []byte
	last          string
}

func New(path string) (*Log, error) {
	l := &Log{path: path, keyPath: path + ".key"}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	if b, e := os.ReadFile(l.keyPath); e == nil && len(b) >= 32 {
		l.key = b
	} else {
		l.key = make([]byte, 32)
		if _, e = rand.Read(l.key); e != nil {
			return nil, e
		}
		if e = os.WriteFile(l.keyPath, l.key, 0600); e != nil {
			return nil, e
		}
	}
	evs, _ := l.readLocked(1 << 30)
	if len(evs) > 0 {
		l.last = evs[len(evs)-1].Hash
	}
	return l, nil
}
func (l *Log) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Time = time.Now().UTC()
	e.PrevHash = l.last
	raw, _ := json.Marshal(struct {
		Time                                       time.Time `json:"time"`
		Username, Role, SourceIP, Action, Resource string
		Success                                    bool
		Detail, PrevHash                           string
	}{e.Time, e.Username, e.Role, e.SourceIP, e.Action, e.Resource, e.Success, e.Detail, e.PrevHash})
	mac := hmac.New(sha256.New, l.key)
	mac.Write(raw)
	e.Hash = hex.EncodeToString(mac.Sum(nil))
	e.ID = e.Hash[:16]
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		l.last = e.Hash
	}
	return err
}
func (l *Log) List(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	evs, _ := l.readLocked(limit)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.After(evs[j].Time) })
	if limit > 0 && len(evs) > limit {
		evs = evs[:limit]
	}
	return evs
}
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	evs, err := l.readLocked(1 << 30)
	if err != nil {
		return err
	}
	prev := ""
	for i, e := range evs {
		if e.PrevHash != prev {
			return fmt.Errorf("audit chain broken at record %d", i)
		}
		raw, _ := json.Marshal(struct {
			Time                                       time.Time `json:"time"`
			Username, Role, SourceIP, Action, Resource string
			Success                                    bool
			Detail, PrevHash                           string
		}{e.Time, e.Username, e.Role, e.SourceIP, e.Action, e.Resource, e.Success, e.Detail, e.PrevHash})
		mac := hmac.New(sha256.New, l.key)
		mac.Write(raw)
		want := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(e.Hash)) {
			return fmt.Errorf("audit event %s failed integrity verification", e.ID)
		}
		prev = e.Hash
	}
	return nil
}
func (l *Log) readLocked(limit int) ([]Event, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 2<<20)
	var out []Event
	line := 0
	for sc.Scan() {
		line++
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("invalid audit record at line %d: %w", line, err)
		}
		out = append(out, e)
		if limit > 0 && len(out) > limit*2 && limit < 100000 {
			out = out[len(out)-limit:]
		}
	}
	return out, sc.Err()
}
