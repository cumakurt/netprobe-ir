package stories

import (
	"fmt"
	"netprobe-ir/internal/model"
	"sort"
	"strings"
	"time"
)

type Stage struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	FindingID string    `json:"finding_id,omitempty"`
	FlowID    string    `json:"flow_id,omitempty"`
	FileID    string    `json:"file_id,omitempty"`
	MITRE     []string  `json:"mitre,omitempty"`
}

type RiskPoint struct {
	Time  time.Time `json:"time"`
	Score int       `json:"score"`
	Label string    `json:"label"`
}

type RootCause struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title"`
	Confidence int       `json:"confidence"`
	FindingID  string    `json:"finding_id,omitempty"`
	FlowID     string    `json:"flow_id,omitempty"`
	FileID     string    `json:"file_id,omitempty"`
	Reasons    []string  `json:"reasons"`
	Inference  bool      `json:"inference"`
}

type storyAcc struct {
	s     Story
	mitre map[string]bool
	rules map[string]bool
}

type Story struct {
	ID           string      `json:"id"`
	Title        string      `json:"title"`
	Severity     string      `json:"severity"`
	Confidence   int         `json:"confidence"`
	Process      string      `json:"process,omitempty"`
	PID          int         `json:"pid,omitempty"`
	Remote       string      `json:"remote,omitempty"`
	StartedAt    time.Time   `json:"started_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	Findings     int         `json:"findings"`
	Files        int         `json:"files"`
	Runtime      int         `json:"runtime_events"`
	MITRE        []string    `json:"mitre,omitempty"`
	ScoreReasons []string    `json:"score_reasons"`
	Stages       []Stage     `json:"stages"`
	RiskTimeline []RiskPoint `json:"risk_timeline,omitempty"`
	RootCause    *RootCause  `json:"root_cause,omitempty"`
}

func Build(findings []model.SecurityFinding, flows []model.Flow, limit int) []Story {
	return BuildExtended(findings, flows, nil, nil, limit)
}

func BuildExtended(findings []model.SecurityFinding, flows []model.Flow, files []model.FileArtifact, runtime []model.RuntimeEvent, limit int) []Story {
	m := map[string]*storyAcc{}
	for _, f := range findings {
		key := storyKey(f.PID, f.Process, f.Destination.IP, f.ID)
		a := m[key]
		if a == nil {
			a = &storyAcc{s: Story{ID: key, Title: "Correlated security activity", Severity: f.Severity, Confidence: f.Confidence, Process: f.Process, PID: f.PID, Remote: f.Destination.IP, StartedAt: f.Time, UpdatedAt: f.Time}, mitre: map[string]bool{}, rules: map[string]bool{}}
			m[key] = a
		}
		mergeFinding(a, f)
	}
	flowByID := map[string]model.Flow{}
	for _, f := range flows {
		flowByID[f.ID] = f
		if f.Process == nil {
			continue
		}
		key := storyKey(f.Process.PID, f.Process.Comm, f.Remote.IP, f.ID)
		a := m[key]
		if a == nil {
			continue
		}
		if f.LastSeen.Before(a.s.StartedAt.Add(-10*time.Minute)) || f.FirstSeen.After(a.s.UpdatedAt.Add(10*time.Minute)) {
			continue
		}
		if a.s.Remote == "" {
			a.s.Remote = f.Remote.IP
		}
		title := strings.TrimSpace(f.DPI.Application + " " + f.Remote.IP)
		if title == "" {
			title = f.NetworkProtocol + " network activity"
		}
		a.s.Stages = append(a.s.Stages, Stage{Time: f.FirstSeen, Kind: "network", Title: title, FlowID: f.ID})
	}
	for _, art := range files {
		f, ok := flowByID[art.FlowID]
		if !ok || f.Process == nil {
			continue
		}
		key := storyKey(f.Process.PID, f.Process.Comm, f.Remote.IP, art.ID)
		a := m[key]
		if a == nil {
			continue
		}
		if art.Time.Before(a.s.StartedAt.Add(-10*time.Minute)) || art.Time.After(a.s.UpdatedAt.Add(10*time.Minute)) {
			continue
		}
		title := "File observed: " + art.Name
		if len(art.Yara) > 0 {
			title = "YARA-matched file: " + art.Name
			a.s.Confidence = min(100, a.s.Confidence+12)
			a.s.ScoreReasons = append(a.s.ScoreReasons, "YARA-matched reconstructed file correlated")
		}
		a.s.Files++
		a.s.Stages = append(a.s.Stages, Stage{Time: art.Time, Kind: "file", Title: title, FlowID: art.FlowID, FileID: art.ID})
	}
	for _, ev := range runtime {
		if ev.PID <= 0 {
			continue
		}
		key := fmt.Sprintf("pid:%d", ev.PID)
		a := m[key]
		if a == nil {
			continue
		}
		if ev.Time.Before(a.s.StartedAt.Add(-10*time.Minute)) || ev.Time.After(a.s.UpdatedAt.Add(10*time.Minute)) {
			continue
		}
		title := strings.TrimSpace(ev.Kind + " " + ev.Path)
		if title == "" {
			title = ev.Kind
		}
		a.s.Runtime++
		a.s.Stages = append(a.s.Stages, Stage{Time: ev.Time, Kind: "runtime", Title: title})
	}
	out := make([]Story, 0, len(m))
	for _, a := range m {
		finalize(a)
		out = append(out, a.s)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) > rank(out[j].Severity)
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func mergeFinding(a *storyAcc, f model.SecurityFinding) {
	if rank(f.Severity) > rank(a.s.Severity) {
		a.s.Severity = f.Severity
	}
	if f.Confidence > a.s.Confidence {
		a.s.Confidence = f.Confidence
	}
	if f.Time.Before(a.s.StartedAt) {
		a.s.StartedAt = f.Time
	}
	if f.Time.After(a.s.UpdatedAt) {
		a.s.UpdatedAt = f.Time
	}
	a.s.Findings++
	a.rules[f.RuleID] = true
	for _, x := range f.MITRE {
		a.mitre[x] = true
	}
	a.s.Stages = append(a.s.Stages, Stage{Time: f.Time, Kind: "finding", Title: f.RuleID + " · " + f.Title, FindingID: f.ID, FlowID: f.FlowID, MITRE: f.MITRE})
}

func finalize(a *storyAcc) {
	for x := range a.mitre {
		a.s.MITRE = append(a.s.MITRE, x)
	}
	sort.Strings(a.s.MITRE)
	sort.Slice(a.s.Stages, func(i, j int) bool { return a.s.Stages[i].Time.Before(a.s.Stages[j].Time) })
	if len(a.rules) > 1 {
		a.s.Confidence = min(100, a.s.Confidence+5*(len(a.rules)-1))
		a.s.ScoreReasons = append(a.s.ScoreReasons, fmt.Sprintf("%d distinct detection rules correlated", len(a.rules)))
	}
	if len(a.s.MITRE) > 1 {
		a.s.ScoreReasons = append(a.s.ScoreReasons, fmt.Sprintf("%d ATT&CK techniques observed", len(a.s.MITRE)))
	}
	if a.s.Runtime > 0 {
		a.s.Confidence = min(100, a.s.Confidence+5)
		a.s.ScoreReasons = append(a.s.ScoreReasons, fmt.Sprintf("%d kernel/runtime events correlated", a.s.Runtime))
	}
	if a.s.Findings >= 3 || len(a.s.Stages) >= 5 {
		a.s.Title = "Possible host compromise / multi-stage attack"
	}
	a.s.RiskTimeline = riskTimeline(a.s.Stages)
	a.s.RootCause = inferRootCause(a.s.Stages, a.s.Confidence)
}

func inferRootCause(stages []Stage, storyConfidence int) *RootCause {
	if len(stages) == 0 {
		return nil
	}
	candidates := make([]Stage, 0, len(stages))
	for _, st := range stages {
		if st.Kind == "runtime" {
			low := strings.ToLower(st.Title)
			if strings.HasPrefix(low, "execve ") || strings.HasPrefix(low, "memfd_create ") || strings.HasPrefix(low, "ptrace ") || strings.HasPrefix(low, "setuid ") || strings.HasPrefix(low, "setgid ") || strings.HasPrefix(low, "mount ") || strings.HasPrefix(low, "setns ") {
				candidates = append(candidates, st)
			}
			continue
		}
		if st.Kind == "file" || st.Kind == "finding" {
			candidates = append(candidates, st)
		}
	}
	if len(candidates) == 0 {
		candidates = stages
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Time.Before(candidates[j].Time) })
	st := candidates[0]
	conf := 55
	reasons := []string{"earliest suspicious evidence in the correlated story"}
	if st.Kind == "runtime" {
		conf += 15
		reasons = append(reasons, "kernel/runtime evidence precedes later network detections")
	}
	if st.Kind == "file" {
		conf += 10
		reasons = append(reasons, "file evidence appears before later stages")
	}
	if len(stages) >= 4 {
		conf += 10
		reasons = append(reasons, "multiple later stages support temporal causality")
	}
	if storyConfidence >= 90 {
		conf += 5
	}
	if conf > 95 {
		conf = 95
	}
	return &RootCause{Time: st.Time, Kind: st.Kind, Title: st.Title, Confidence: conf, FindingID: st.FindingID, FlowID: st.FlowID, FileID: st.FileID, Reasons: reasons, Inference: true}
}

func riskTimeline(stages []Stage) []RiskPoint {
	var out []RiskPoint
	score := 0
	for _, st := range stages {
		delta := 5
		switch st.Kind {
		case "finding":
			delta = 18
		case "file":
			delta = 15
		case "runtime":
			delta = 12
		case "network":
			delta = 7
		}
		score += delta
		if score > 100 {
			score = 100
		}
		out = append(out, RiskPoint{Time: st.Time, Score: score, Label: st.Title})
	}
	return out
}

func storyKey(pid int, process, remote, fallback string) string {
	if pid > 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	if process != "" {
		return "proc:" + process
	}
	if remote != "" {
		return "remote:" + remote
	}
	return "finding:" + fallback
}

func rank(s string) int {
	return map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[strings.ToLower(s)]
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
