package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"netprobe-ir/internal/model"
)

type EvidencePack struct {
	Query    string                  `json:"query"`
	Flows    []model.Flow            `json:"flows,omitempty"`
	Findings []model.SecurityFinding `json:"findings,omitempty"`
	Files    []model.FileArtifact    `json:"files,omitempty"`
	Packets  []model.PacketSummary   `json:"packets,omitempty"`
}
type Answer struct {
	Text        string   `json:"text"`
	EvidenceIDs []string `json:"evidence_ids"`
	Provider    string   `json:"provider"`
	Warning     string   `json:"warning,omitempty"`
}
type Config struct {
	Enabled        bool   `json:"enabled"`
	Endpoint       string `json:"endpoint,omitempty"`
	Model          string `json:"model,omitempty"`
	APIKeyEnv      string `json:"api_key_env,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	RemoteEnabled  bool   `json:"remote_enabled,omitempty"`
}
type Analyst struct {
	cfg    Config
	client *http.Client
}

func New(c Config) *Analyst {
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 20
	}
	return &Analyst{cfg: c, client: &http.Client{Timeout: time.Duration(c.TimeoutSeconds) * time.Second}}
}
func (a *Analyst) Ask(ctx context.Context, p EvidencePack) (Answer, error) {
	if !a.cfg.Enabled {
		return Answer{}, fmt.Errorf("analyst disabled")
	}
	local := localAnswer(p)
	if !a.cfg.RemoteEnabled || strings.TrimSpace(a.cfg.Endpoint) == "" {
		return local, nil
	}
	remote, err := a.remote(ctx, p)
	if err != nil {
		local.Warning = "remote analyst unavailable: " + err.Error()
		return local, nil
	}
	remote.EvidenceIDs = local.EvidenceIDs
	return remote, nil
}
func localAnswer(p EvidencePack) Answer {
	q := strings.ToLower(p.Query)
	ids := make([]string, 0, 32)
	for _, f := range p.Findings {
		ids = append(ids, "finding:"+f.ID)
	}
	for _, f := range p.Flows {
		ids = append(ids, "flow:"+f.ID)
	}
	for _, f := range p.Files {
		ids = append(ids, "file:"+f.ID)
	}
	if len(ids) > 50 {
		ids = ids[:50]
	}
	sort.Slice(p.Findings, func(i, j int) bool { return risk(p.Findings[i]) > risk(p.Findings[j]) })
	var b strings.Builder
	if strings.Contains(q, "destination") || strings.Contains(q, "remote") {
		seen := map[string]bool{}
		b.WriteString("Observed remote destinations: ")
		var x []string
		for _, f := range p.Flows {
			if f.Remote.IP != "" && !seen[f.Remote.IP] {
				seen[f.Remote.IP] = true
				x = append(x, fmt.Sprintf("%s:%d", f.Remote.IP, f.Remote.Port))
			}
		}
		b.WriteString(strings.Join(x, ", "))
	} else if strings.Contains(q, "why") || strings.Contains(q, "neden") || strings.Contains(q, "critical") {
		if len(p.Findings) == 0 {
			b.WriteString("No security findings are present in the supplied evidence window.")
		} else {
			top := p.Findings[0]
			b.WriteString(fmt.Sprintf("Highest-priority evidence is %s (%s, confidence %d%%): %s", top.RuleID, top.Severity, top.Confidence, top.Description))
			if len(top.MITRE) > 0 {
				b.WriteString(" ATT&CK: " + strings.Join(top.MITRE, ", ") + ".")
			}
			if top.FlowID != "" {
				b.WriteString(" Related flow: " + top.FlowID + ".")
			}
		}
	} else {
		b.WriteString(fmt.Sprintf("Evidence summary: %d flows, %d findings, %d reconstructed files and %d packet metadata records.", len(p.Flows), len(p.Findings), len(p.Files), len(p.Packets)))
		if len(p.Findings) > 0 {
			b.WriteString(" Top detections: ")
			n := len(p.Findings)
			if n > 5 {
				n = 5
			}
			for i := 0; i < n; i++ {
				if i > 0 {
					b.WriteString("; ")
				}
				b.WriteString(p.Findings[i].RuleID + " " + p.Findings[i].Title)
			}
		}
	}
	return Answer{Text: b.String(), EvidenceIDs: ids, Provider: "local-evidence"}
}
func risk(f model.SecurityFinding) int {
	base := map[string]int{"critical": 100, "high": 80, "medium": 60, "low": 30, "info": 10}[strings.ToLower(f.Severity)]
	if f.Confidence > base {
		return f.Confidence
	}
	return base
}
func (a *Analyst) remote(ctx context.Context, p EvidencePack) (Answer, error) {
	key := ""
	if a.cfg.APIKeyEnv != "" {
		key = os.Getenv(a.cfg.APIKeyEnv)
	}
	if key == "" {
		return Answer{}, fmt.Errorf("API key environment variable is empty")
	}
	system := "You are a defensive network-forensics analyst. Use only the supplied evidence. Never invent telemetry. State uncertainty. Do not provide offensive instructions."
	evidence, _ := json.Marshal(p)
	reqBody := map[string]any{"model": a.cfg.Model, "messages": []any{map[string]any{"role": "system", "content": system}, map[string]any{"role": "user", "content": "Question: " + p.Query + "\nEvidence JSON:\n" + string(evidence)}}, "temperature": 0}
	b, _ := json.Marshal(reqBody)
	url := strings.TrimRight(a.cfg.Endpoint, "/")
	if !strings.HasSuffix(url, "/chat/completions") {
		url += "/chat/completions"
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if e != nil {
		return Answer{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, e := a.client.Do(req)
	if e != nil {
		return Answer{}, e
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode/100 != 2 {
		return Answer{}, fmt.Errorf("analyst HTTP %s", resp.Status)
	}
	var v struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		return Answer{}, e
	}
	if len(v.Choices) == 0 {
		return Answer{}, fmt.Errorf("analyst returned no choices")
	}
	return Answer{Text: strings.TrimSpace(v.Choices[0].Message.Content), Provider: "remote-evidence"}, nil
}
