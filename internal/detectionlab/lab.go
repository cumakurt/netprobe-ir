package detectionlab

import (
	"os"
	"time"

	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/replay"
)

type Result struct {
	Capture   string         `json:"capture"`
	Frames    uint64         `json:"frames"`
	Bytes     uint64         `json:"bytes"`
	Findings  int            `json:"findings"`
	ByRule    map[string]int `json:"by_rule"`
	Critical  int            `json:"critical"`
	High      int            `json:"high"`
	ElapsedMS int64          `json:"elapsed_ms"`
	FPS       float64        `json:"frames_per_second"`
}

func Run(c config.Config, path, rulesFile, iocFile string) (Result, error) {
	if _, e := os.Stat(path); e != nil {
		return Result{}, e
	}
	tmp, e := os.MkdirTemp("", "netprobe-lab-")
	if e != nil {
		return Result{}, e
	}
	defer os.RemoveAll(tmp)
	c.DataDir = tmp
	c.Interfaces = nil
	c.Recorder.Enabled = false
	c.Anomaly.Enabled = false
	c.Baseline.Enabled = false
	c.ThreatIntel.Enabled = false
	c.IDS.Enabled = true
	if rulesFile != "" {
		c.IDS.RulesFile = rulesFile
		c.IDS.RuleLabMode = true
	}
	if iocFile != "" {
		c.IDS.IOCFile = iocFile
	}
	if e = c.Prepare(); e != nil {
		return Result{}, e
	}
	eng := pipeline.New(c)
	start := time.Now()
	st, e := replay.Stream(path, func(fr capture.Frame) error { eng.ProcessReplayFrame(fr); return nil })
	if e != nil {
		return Result{}, e
	}
	fs := eng.Findings(0)
	r := Result{Capture: path, Frames: st.Frames, Bytes: st.Bytes, Findings: len(fs), ByRule: map[string]int{}, ElapsedMS: time.Since(start).Milliseconds()}
	for _, f := range fs {
		r.ByRule[f.RuleID]++
		if f.Severity == "critical" {
			r.Critical++
		}
		if f.Severity == "high" {
			r.High++
		}
	}
	sec := time.Since(start).Seconds()
	if sec > 0 {
		r.FPS = float64(st.Frames) / sec
	}
	return r, nil
}
