package vulnintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}
type KEV struct {
	CVEID             string `json:"cve_id"`
	Vendor            string `json:"vendor"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerability_name"`
	DateAdded         string `json:"date_added"`
	DueDate           string `json:"due_date"`
	Ransomware        string `json:"known_ransomware_campaign_use"`
	Notes             string `json:"notes"`
}
type Exposure struct {
	Package          Package `json:"package"`
	KEV              KEV     `json:"kev"`
	Match            string  `json:"match"`
	Confidence       int     `json:"confidence"`
	ProvenVulnerable bool    `json:"proven_vulnerable"`
	Explanation      string  `json:"explanation"`
}
type Hub struct {
	mu          sync.RWMutex
	kev         []KEV
	packages    []Package
	exposures   []Exposure
	lastRefresh time.Time
	errors      []string
}

type cisaCatalog struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		Vendor            string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		DueDate           string `json:"dueDate"`
		Ransomware        string `json:"knownRansomwareCampaignUse"`
		Notes             string `json:"notes"`
	} `json:"vulnerabilities"`
}

func New() *Hub { return &Hub{} }
func (h *Hub) LoadKEV(data []byte) error {
	var c cisaCatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	x := make([]KEV, 0, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		x = append(x, KEV{CVEID: v.CVEID, Vendor: v.Vendor, Product: v.Product, VulnerabilityName: v.VulnerabilityName, DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware, Notes: v.Notes})
	}
	h.mu.Lock()
	h.kev = x
	h.lastRefresh = time.Now().UTC()
	h.recomputeLocked()
	h.mu.Unlock()
	return nil
}
func (h *Hub) LoadKEVFile(path string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return h.LoadKEV(b)
}
func (h *Hub) FetchKEV(ctx context.Context, url string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("KEV HTTP %s", resp.Status)
	}
	var c cisaCatalog
	if e = json.NewDecoder(resp.Body).Decode(&c); e != nil {
		return e
	}
	b, _ := json.Marshal(c)
	return h.LoadKEV(b)
}
func (h *Hub) SetPackages(p []Package) {
	h.mu.Lock()
	h.packages = append([]Package(nil), p...)
	h.recomputeLocked()
	h.mu.Unlock()
}
func (h *Hub) Inventory() []Package {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]Package(nil), h.packages...)
}
func (h *Hub) Exposures() []Exposure {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]Exposure(nil), h.exposures...)
}
func (h *Hub) KEVCount() int          { h.mu.RLock(); defer h.mu.RUnlock(); return len(h.kev) }
func (h *Hub) LastRefresh() time.Time { h.mu.RLock(); defer h.mu.RUnlock(); return h.lastRefresh }
func (h *Hub) Errors() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string(nil), h.errors...)
}
func norm(s string) string {
	s = strings.ToLower(s)
	r := strings.NewReplacer("-", "", "_", "", " ", "", ".", "")
	return r.Replace(s)
}
func (h *Hub) recomputeLocked() {
	var out []Exposure
	for _, p := range h.packages {
		pn := norm(p.Name)
		if len(pn) < 3 {
			continue
		}
		for _, k := range h.kev {
			prod := norm(k.Product)
			vendor := norm(k.Vendor)
			match := ""
			conf := 0
			if prod != "" && (strings.Contains(pn, prod) || strings.Contains(prod, pn)) {
				match = "product-name"
				conf = 70
			} else if vendor != "" && strings.Contains(pn, vendor) && len(vendor) > 4 {
				match = "vendor-name"
				conf = 45
			}
			if match != "" {
				out = append(out, Exposure{Package: p, KEV: k, Match: match, Confidence: conf, ProvenVulnerable: false, Explanation: "Installed package/product name overlaps a CISA KEV catalog product. KEV does not provide affected-version ranges, so this is exposure context, not proof that this installed version is vulnerable."})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].KEV.CVEID < out[j].KEV.CVEID
	})
	h.exposures = out
}

func DiscoverPackages() ([]Package, error) {
	if p, e := exec.LookPath("dpkg-query"); e == nil {
		return parseCommand(p, []string{"-W", "-f=${Package}\t${Version}\n"}, "dpkg")
	}
	if p, e := exec.LookPath("rpm"); e == nil {
		return parseCommand(p, []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}, "rpm")
	}
	if p, e := exec.LookPath("apk"); e == nil {
		return parseAPK(p)
	}
	return nil, fmt.Errorf("no supported package manager found (dpkg-query/rpm/apk)")
}
func parseCommand(bin string, args []string, source string) ([]Package, error) {
	cmd := exec.Command(bin, args...)
	b, e := cmd.Output()
	if e != nil {
		return nil, e
	}
	var out []Package
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 2)
		if len(f) == 2 && strings.TrimSpace(f[0]) != "" {
			out = append(out, Package{Name: strings.TrimSpace(f[0]), Version: strings.TrimSpace(f[1]), Source: source})
		}
	}
	return out, sc.Err()
}
func parseAPK(bin string) ([]Package, error) {
	cmd := exec.Command(bin, "info", "-v")
	b, e := cmd.Output()
	if e != nil {
		return nil, e
	}
	var out []Package
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		x := strings.TrimSpace(sc.Text())
		if x == "" {
			continue
		}
		i := strings.LastIndex(x, "-")
		if i > 0 {
			out = append(out, Package{Name: x[:i], Version: x[i+1:], Source: "apk"})
		}
	}
	return out, sc.Err()
}

// ExploitChain correlates KEV exposure context with live detection/runtime
// evidence. It never upgrades a name-only package overlap into version proof.
type ExploitChain struct {
	CVEID             string               `json:"cve_id"`
	Package           Package              `json:"package"`
	Product           string               `json:"product"`
	FindingID         string               `json:"finding_id,omitempty"`
	FlowID            string               `json:"flow_id,omitempty"`
	PID               int                  `json:"pid,omitempty"`
	Process           string               `json:"process,omitempty"`
	Score             int                  `json:"score"`
	Assessment        string               `json:"assessment"`
	RuntimeCorrelated bool                 `json:"runtime_correlated"`
	VersionProven     bool                 `json:"version_proven"`
	Reasons           []string             `json:"reasons"`
	RuntimeEvidence   []model.RuntimeEvent `json:"runtime_evidence,omitempty"`
}

// CorrelateRuntime joins exposure context to security findings and optional
// runtime events. A result can be high confidence even when VersionProven is
// false, but the API explicitly preserves that distinction.
func (h *Hub) CorrelateRuntime(findings []model.SecurityFinding, runtime []model.RuntimeEvent) []ExploitChain {
	h.mu.RLock()
	exposures := append([]Exposure(nil), h.exposures...)
	h.mu.RUnlock()
	var out []ExploitChain
	for _, ex := range exposures {
		pkg := norm(ex.Package.Name)
		prod := norm(ex.KEV.Product)
		for _, f := range findings {
			hay := norm(strings.Join([]string{f.Process, f.Application, f.Title, f.Description, f.RuleID, f.Category}, " "))
			if pkg != "" && !strings.Contains(hay, pkg) && prod != "" && !strings.Contains(hay, prod) {
				continue
			}
			score := 20
			reasons := []string{"installed package/product overlaps CISA KEV context"}
			strong := f.Verdict == "signature_match" || f.Verdict == "confirmed_ioc" || strings.Contains(strings.ToLower(f.Category), "exploit")
			if strong {
				score += 30
				reasons = append(reasons, "strong exploit/IOC detection correlated")
			} else if f.Confidence >= 80 {
				score += 18
				reasons = append(reasons, "high-confidence security finding correlated")
			}
			if f.Severity == "critical" || f.Severity == "high" {
				score += 10
			}
			var rt []model.RuntimeEvent
			for _, ev := range runtime {
				if f.PID > 0 && ev.PID != f.PID {
					continue
				}
				if ev.Time.Before(f.Time.Add(-30*time.Second)) || ev.Time.After(f.Time.Add(5*time.Minute)) {
					continue
				}
				if ev.Kind == "execve" || ev.Kind == "memfd_create" || ev.Kind == "setuid" || ev.Kind == "ptrace" {
					rt = append(rt, ev)
				}
			}
			if len(rt) > 0 {
				score += 25
				reasons = append(reasons, "kernel/runtime execution signal follows the detection")
			}
			if score > 100 {
				score = 100
			}
			assessment := "exposure-context correlation"
			if strong && len(rt) > 0 {
				assessment = "probable runtime exploitation chain"
			}
			out = append(out, ExploitChain{CVEID: ex.KEV.CVEID, Package: ex.Package, Product: ex.KEV.Product, FindingID: f.ID, FlowID: f.FlowID, PID: f.PID, Process: f.Process, Score: score, Assessment: assessment, RuntimeCorrelated: len(rt) > 0, VersionProven: ex.ProvenVulnerable, Reasons: reasons, RuntimeEvidence: rt})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].CVEID < out[j].CVEID
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out
}
