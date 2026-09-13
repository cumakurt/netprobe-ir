package fileextract

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"netprobe-ir/internal/model"
)

// Scanner scans a reconstructed artifact. Implementations must never modify the file.
type Scanner interface {
	Scan(path string) ([]model.YaraMatch, error)
	Available() bool
}

type YaraXScanner struct {
	Binary, Rules string
	Timeout       time.Duration
}

func (s *YaraXScanner) Available() bool {
	if strings.TrimSpace(s.Rules) == "" {
		return false
	}
	b := s.Binary
	if b == "" {
		b = "yr"
	}
	_, err := exec.LookPath(b)
	return err == nil
}
func (s *YaraXScanner) Scan(path string) ([]model.YaraMatch, error) {
	if strings.TrimSpace(s.Rules) == "" {
		return nil, nil
	}
	b := s.Binary
	if b == "" {
		b = "yr"
	}
	if _, err := exec.LookPath(b); err != nil {
		return nil, fmt.Errorf("YARA-X binary %q not found: %w", b, err)
	}
	to := s.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	cmd := exec.CommandContext(ctx, b, "scan", "--output-format=ndjson", "-m", "-g", s.Rules, path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("YARA-X scan timeout")
	}
	// yr uses successful empty output for no matches. Some versions may return a
	// non-zero status for diagnostics; preserve stderr so operators can act on it.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("YARA-X scan: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	type yrRule struct {
		Namespace  string         `json:"namespace"`
		Identifier string         `json:"identifier"`
		Tags       []string       `json:"tags"`
		Meta       map[string]any `json:"metadata"`
	}
	type yrLine struct {
		Path  string   `json:"path"`
		Rules []yrRule `json:"rules"`
	}
	var out []model.YaraMatch
	sc := bufio.NewScanner(&stdout)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 2<<20)
	for sc.Scan() {
		var v yrLine
		if json.Unmarshal(sc.Bytes(), &v) != nil {
			continue
		}
		for _, r := range v.Rules {
			out = append(out, model.YaraMatch{Rule: r.Identifier, Namespace: r.Namespace, Tags: r.Tags, Meta: r.Meta})
		}
	}
	if e := sc.Err(); e != nil {
		return out, e
	}
	return out, nil
}
