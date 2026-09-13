package selfprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"netprobe-ir/internal/model"
)

type Config struct {
	Enabled              bool
	Paths                []string
	DataDir              string
	MinFreeMB            uint64
	ClockRollbackSeconds int
}
type Monitor struct {
	mu       sync.Mutex
	cfg      Config
	hashes   map[string]string
	lastWall time.Time
	seq      uint64
}
type Health struct {
	OK           bool      `json:"ok"`
	CheckedAt    time.Time `json:"checked_at"`
	Watched      int       `json:"watched"`
	Changed      []string  `json:"changed,omitempty"`
	Missing      []string  `json:"missing,omitempty"`
	DiskFreeMB   uint64    `json:"disk_free_mb"`
	ClockHealthy bool      `json:"clock_healthy"`
}

func New(c Config) *Monitor {
	if c.MinFreeMB == 0 {
		c.MinFreeMB = 256
	}
	if c.ClockRollbackSeconds <= 0 {
		c.ClockRollbackSeconds = 5
	}
	m := &Monitor{cfg: c, hashes: map[string]string{}, lastWall: time.Now()}
	for _, p := range c.Paths {
		if h, e := hashFile(p); e == nil {
			m.hashes[filepath.Clean(p)] = h
		}
	}
	return m
}
func hashFile(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (m *Monitor) Check() (Health, []model.SecurityFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	h := Health{CheckedAt: now.UTC(), Watched: len(m.hashes), ClockHealthy: true}
	var fs []model.SecurityFinding
	for p, want := range m.hashes {
		got, e := hashFile(p)
		if e != nil {
			h.Missing = append(h.Missing, p)
			fs = append(fs, m.finding(now, "NP-SENSOR-TAMPER-MISSING", "critical", "Sensor integrity file missing", map[string]any{"path": p, "error": e.Error()}))
			continue
		}
		if got != want {
			h.Changed = append(h.Changed, p)
			fs = append(fs, m.finding(now, "NP-SENSOR-TAMPER-HASH", "critical", "Sensor integrity hash changed", map[string]any{"path": p, "baseline_sha256": want, "current_sha256": got}))
		}
	}
	if !m.lastWall.IsZero() && now.Before(m.lastWall.Add(-time.Duration(m.cfg.ClockRollbackSeconds)*time.Second)) {
		h.ClockHealthy = false
		fs = append(fs, m.finding(now, "NP-SENSOR-CLOCK-ROLLBACK", "high", "System clock moved backwards", map[string]any{"previous": m.lastWall.UTC(), "current": now.UTC()}))
	}
	m.lastWall = now
	if m.cfg.DataDir != "" {
		var st syscall.Statfs_t
		if syscall.Statfs(m.cfg.DataDir, &st) == nil {
			h.DiskFreeMB = st.Bavail * uint64(st.Bsize) / (1 << 20)
			if h.DiskFreeMB < m.cfg.MinFreeMB {
				fs = append(fs, m.finding(now, "NP-SENSOR-DISK-LOW", "high", "Sensor evidence disk space is low", map[string]any{"free_mb": h.DiskFreeMB, "minimum_mb": m.cfg.MinFreeMB}))
			}
		}
	}
	h.OK = len(h.Changed) == 0 && len(h.Missing) == 0 && h.ClockHealthy && (h.DiskFreeMB == 0 || h.DiskFreeMB >= m.cfg.MinFreeMB)
	return h, fs
}
func (m *Monitor) finding(t time.Time, id, sev, title string, ev map[string]any) model.SecurityFinding {
	m.seq++
	return model.SecurityFinding{ID: fmt.Sprintf("self-%d-%d", t.UnixNano(), m.seq), Time: t.UTC(), Severity: sev, Confidence: 100, Verdict: "sensor_integrity", RuleID: id, Title: title, Description: "NetProbe self-protection monitor detected a sensor-integrity condition", Category: "sensor-tampering", Tactic: "Defense Evasion", MITRE: []string{"T1562.001"}, Evidence: ev}
}
func (m *Monitor) Rebaseline(paths []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(paths) == 0 {
		paths = make([]string, 0, len(m.hashes))
		for p := range m.hashes {
			paths = append(paths, p)
		}
	}
	n := map[string]string{}
	for _, p := range paths {
		h, e := hashFile(p)
		if e != nil {
			return e
		}
		n[filepath.Clean(p)] = h
	}
	m.hashes = n
	return nil
}
