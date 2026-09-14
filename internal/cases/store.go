package cases

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/triage"
)

type Note struct {
	Time   time.Time `json:"time"`
	Author string    `json:"author,omitempty"`
	Text   string    `json:"text"`
}
type Case struct {
	ID              string                  `json:"id"`
	Title           string                  `json:"title"`
	Status          string                  `json:"status"`
	Severity        string                  `json:"severity"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
	FindingIDs      []string                `json:"finding_ids,omitempty"`
	FlowIDs         []string                `json:"flow_ids,omitempty"`
	PacketIDs       []string                `json:"packet_ids,omitempty"`
	Processes       []model.ProcessInfo     `json:"processes,omitempty"`
	Findings        []model.SecurityFinding `json:"findings,omitempty"`
	Flows           []model.Flow            `json:"flows,omitempty"`
	Packets         []model.PacketSummary   `json:"packets,omitempty"`
	PCAPFiles       []string                `json:"pcap_files,omitempty"`
	TriageSnapshots []triage.Snapshot       `json:"triage_snapshots,omitempty"`
	Notes           []Note                  `json:"notes,omitempty"`
	Tags            []string                `json:"tags,omitempty"`
	Locked          bool                    `json:"locked"`
	LockedAt        *time.Time              `json:"locked_at,omitempty"`
}
type Store struct {
	mu        sync.Mutex
	dir       string
	signer    *evidence.Signer
	immutable bool
}

func New(dir string, signer *evidence.Signer) (*Store, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	return &Store{dir: dir, signer: signer}, nil
}
func (s *Store) SetImmutable(v bool) { s.mu.Lock(); s.immutable = v; s.mu.Unlock() }
func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}
func (s *Store) Create(c Case) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == "" {
		c.ID = newID()
	}
	if c.Title == "" {
		c.Title = "Network security investigation"
	}
	if c.Status == "" {
		c.Status = "open"
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if s.immutable {
		c.Locked = true
		t := now
		c.LockedAt = &t
	}
	if err := s.writeLocked(c); err != nil {
		return Case{}, err
	}
	return c, nil
}
func (s *Store) Update(id string, mut func(*Case) error) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, e := s.readLocked(id)
	if e != nil {
		return Case{}, e
	}
	if c.Locked {
		return Case{}, fmt.Errorf("case is locked in forensic immutable mode")
	}
	if e = mut(&c); e != nil {
		return Case{}, e
	}
	c.UpdatedAt = time.Now().UTC()
	if e = s.writeLocked(c); e != nil {
		return Case{}, e
	}
	return c, nil
}
func (s *Store) AddNote(id, author, text string) (Case, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Case{}, fmt.Errorf("note cannot be empty")
	}
	return s.Update(id, func(c *Case) error {
		c.Notes = append(c.Notes, Note{Time: time.Now().UTC(), Author: author, Text: text})
		return nil
	})
}
func (s *Store) AddTriage(id string, snapshot triage.Snapshot) (Case, error) {
	return s.Update(id, func(c *Case) error {
		if len(c.TriageSnapshots) >= triage.MaxSnapshotsPerCase {
			return fmt.Errorf("case triage snapshot limit reached")
		}
		c.TriageSnapshots = append(c.TriageSnapshots, snapshot)
		return nil
	})
}
func (s *Store) Lock(id string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, e := s.readLocked(id)
	if e != nil {
		return Case{}, e
	}
	if c.Locked {
		return c, nil
	}
	now := time.Now().UTC()
	c.Locked = true
	c.LockedAt = &now
	c.UpdatedAt = now
	if e = s.writeLocked(c); e != nil {
		return Case{}, e
	}
	return c, nil
}
func (s *Store) Get(id string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(id)
}
func (s *Store) List() []Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, _ := os.ReadDir(s.dir)
	var out []Case
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, er := s.readLocked(strings.TrimSuffix(e.Name(), ".json"))
		if er == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}
func (s *Store) Count() int { return len(s.List()) }
func (s *Store) path(id string) (string, error) {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid case id")
	}
	return filepath.Join(s.dir, id+".json"), nil
}
func (s *Store) readLocked(id string) (Case, error) {
	p, e := s.path(id)
	if e != nil {
		return Case{}, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return Case{}, e
	}
	var c Case
	e = json.Unmarshal(b, &c)
	return c, e
}
func (s *Store) writeLocked(c Case) error {
	p, e := s.path(c.ID)
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, b, 0640); e != nil {
		return e
	}
	return os.Rename(tmp, p)
}

// Export writes a self-contained forensic ZIP with case JSON, available PCAPs,
// SHA-256 hashes and (when configured) an Ed25519-signed manifest.
func (s *Store) Export(id, dst string) (string, error) {
	c, e := s.Get(id)
	if e != nil {
		return "", e
	}
	tmp, err := os.MkdirTemp("", "netprobe-case-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	cb, _ := json.MarshalIndent(c, "", "  ")
	casePath := filepath.Join(tmp, "case.json")
	if err = os.WriteFile(casePath, cb, 0640); err != nil {
		return "", err
	}
	paths := []string{casePath}
	for i, snapshot := range c.TriageSnapshots {
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return "", err
		}
		path := filepath.Join(tmp, fmt.Sprintf("triage-%03d.json", i+1))
		if err = os.WriteFile(path, b, 0600); err != nil {
			return "", err
		}
		paths = append(paths, path)
	}
	for _, p := range c.PCAPFiles {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			dstp := filepath.Join(tmp, filepath.Base(p))
			if e = copyFile(p, dstp); e == nil {
				paths = append(paths, dstp)
			}
		}
	}
	if s.signer != nil {
		_, mb, e := s.signer.Build(paths)
		if e != nil {
			return "", e
		}
		mp := filepath.Join(tmp, "manifest.json")
		if e = os.WriteFile(mp, mb, 0640); e != nil {
			return "", e
		}
		paths = append(paths, mp)
	}
	if err = os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(out)
	for _, p := range paths {
		if e = zipAdd(zw, p); e != nil {
			zw.Close()
			out.Close()
			return "", e
		}
	}
	if e = zw.Close(); e != nil {
		out.Close()
		return "", e
	}
	if e = out.Close(); e != nil {
		return "", e
	}
	return dst, nil
}
func copyFile(src, dst string) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func zipAdd(z *zip.Writer, path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	w, e := z.Create(filepath.Base(path))
	if e != nil {
		return e
	}
	_, e = io.Copy(w, f)
	return e
}
