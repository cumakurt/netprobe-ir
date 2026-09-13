package detectionquality

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Run struct {
	ID            string         `json:"id"`
	Time          time.Time      `json:"time"`
	Label         string         `json:"label,omitempty"`
	Capture       string         `json:"capture,omitempty"`
	Benign        bool           `json:"benign"`
	ExpectedRules []string       `json:"expected_rules,omitempty"`
	Observed      map[string]int `json:"observed"`
	Frames        uint64         `json:"frames"`
	ElapsedMS     int64          `json:"elapsed_ms"`
}

type RuleMetric struct {
	RuleID        string  `json:"rule_id"`
	Runs          int     `json:"runs"`
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	Observed      int     `json:"observed_findings"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	QualityScore  int     `json:"quality_score"`
	LastSeen      string  `json:"last_seen,omitempty"`
}

type Summary struct {
	Runs                int          `json:"runs"`
	BenignRuns          int          `json:"benign_runs"`
	LabeledPositiveRuns int          `json:"labeled_positive_runs"`
	TotalFrames         uint64       `json:"total_frames"`
	AverageUSPerFrame   float64      `json:"average_us_per_frame"`
	Rules               []RuleMetric `json:"rules"`
	OverallPrecision    float64      `json:"overall_precision"`
	OverallRecall       float64      `json:"overall_recall"`
	OverallQualityScore int          `json:"overall_quality_score"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	runs []Run
}

func New(path string) *Store {
	s := &Store{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.runs)
	}
	return s
}

func (s *Store) Record(r Run) error {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	if r.ID == "" {
		r.ID = fmt.Sprintf("quality-%d", r.Time.UnixNano())
	}
	if r.Observed == nil {
		r.Observed = map[string]int{}
	}
	s.mu.Lock()
	s.runs = append(s.runs, r)
	if len(s.runs) > 1000 {
		s.runs = s.runs[len(s.runs)-1000:]
	}
	err := s.persistLocked()
	s.mu.Unlock()
	return err
}

func (s *Store) Runs(limit int) []Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.runs)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := append([]Run(nil), s.runs[n-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type acc struct {
		RuleMetric
		last time.Time
	}
	m := map[string]*acc{}
	var out Summary
	var totalUS float64
	for _, r := range s.runs {
		out.Runs++
		out.TotalFrames += r.Frames
		totalUS += float64(r.ElapsedMS) * 1000
		if r.Benign {
			out.BenignRuns++
		} else if len(r.ExpectedRules) > 0 {
			out.LabeledPositiveRuns++
		}
		expected := map[string]bool{}
		for _, id := range r.ExpectedRules {
			expected[id] = true
			if m[id] == nil {
				m[id] = &acc{RuleMetric: RuleMetric{RuleID: id}}
			}
		}
		touched := map[string]bool{}
		for id, count := range r.Observed {
			a := m[id]
			if a == nil {
				a = &acc{RuleMetric: RuleMetric{RuleID: id}}
				m[id] = a
			}
			a.Runs++
			a.Observed += count
			touched[id] = true
			if r.Time.After(a.last) {
				a.last = r.Time
			}
			if r.Benign || (!expected[id] && len(expected) > 0) {
				a.FalsePositive += count
			}
			if expected[id] {
				a.TruePositive += count
			}
		}
		for id := range expected {
			if !touched[id] {
				m[id].FalseNegative++
			}
		}
	}
	if out.TotalFrames > 0 {
		out.AverageUSPerFrame = totalUS / float64(out.TotalFrames)
	}
	var tpSum, fpSum, fnSum int
	for _, a := range m {
		tp, fp, fn := a.TruePositive, a.FalsePositive, a.FalseNegative
		if tp+fp > 0 {
			a.Precision = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			a.Recall = float64(tp) / float64(tp+fn)
		}
		a.QualityScore = int(100*((.6*a.Precision)+(.4*a.Recall)) + .5)
		if !a.last.IsZero() {
			a.LastSeen = a.last.UTC().Format(time.RFC3339)
		}
		out.Rules = append(out.Rules, a.RuleMetric)
		tpSum += tp
		fpSum += fp
		fnSum += fn
	}
	if tpSum+fpSum > 0 {
		out.OverallPrecision = float64(tpSum) / float64(tpSum+fpSum)
	}
	if tpSum+fnSum > 0 {
		out.OverallRecall = float64(tpSum) / float64(tpSum+fnSum)
	}
	out.OverallQualityScore = int(100*((.6*out.OverallPrecision)+(.4*out.OverallRecall)) + .5)
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].QualityScore != out.Rules[j].QualityScore {
			return out.Rules[i].QualityScore < out.Rules[j].QualityScore
		}
		return out.Rules[i].RuleID < out.Rules[j].RuleID
	})
	return out
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.runs, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
