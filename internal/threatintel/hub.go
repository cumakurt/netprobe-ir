package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type Indicator struct {
	ID          string    `json:"id,omitempty"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  int       `json:"confidence"`
	Source      string    `json:"source"`
	Description string    `json:"description,omitempty"`
	ValidFrom   time.Time `json:"valid_from,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
}

type TAXIIFeed struct {
	Name       string `json:"name"`
	ObjectsURL string `json:"objects_url"`
	Token      string `json:"token,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

type Match struct {
	Indicator Indicator `json:"indicator"`
	Field     string    `json:"field"`
	Observed  string    `json:"observed"`
}

type Hub struct {
	mu         sync.RWMutex
	indicators map[string]Indicator
	errors     []string
	client     *http.Client
}

func New() *Hub {
	return &Hub{indicators: map[string]Indicator{}, client: &http.Client{Timeout: 15 * time.Second}}
}
func (h *Hub) SetHTTPClient(c *http.Client) {
	if c != nil {
		h.client = c
	}
}
func key(t, v string) string { return strings.ToLower(strings.TrimSpace(t)) + "|" + normalize(t, v) }
func normalize(t, v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToLower(t) {
	case "domain", "sni", "url", "ja3", "ja4":
		return strings.ToLower(strings.TrimSuffix(v, "."))
	default:
		return v
	}
}
func (h *Hub) Add(i Indicator) {
	i.Type = strings.ToLower(strings.TrimSpace(i.Type))
	i.Value = normalize(i.Type, i.Value)
	if i.Type == "" || i.Value == "" {
		return
	}
	if i.Confidence <= 0 {
		i.Confidence = 80
	}
	if i.Confidence > 100 {
		i.Confidence = 100
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.indicators[key(i.Type, i.Value)] = i
}
func (h *Hub) Count() int { h.mu.RLock(); defer h.mu.RUnlock(); return len(h.indicators) }
func (h *Hub) Indicators() []Indicator {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Indicator, 0, len(h.indicators))
	now := time.Now()
	for _, i := range h.indicators {
		if i.Expires.IsZero() || i.Expires.After(now) {
			out = append(out, i)
		}
	}
	return out
}
func (h *Hub) Errors() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string(nil), h.errors...)
}
func (h *Hub) addErr(s string) {
	h.mu.Lock()
	h.errors = append(h.errors, s)
	if len(h.errors) > 100 {
		h.errors = h.errors[len(h.errors)-100:]
	}
	h.mu.Unlock()
}

func (h *Hub) MatchFlow(f model.Flow) []Match {
	vals := []struct{ t, v, field string }{{"ip", f.Local.IP, "local.ip"}, {"ip", f.Remote.IP, "remote.ip"}, {"domain", "", "dns.query"}, {"sni", "", "tls.sni"}, {"ja3", "", "tls.ja3"}, {"ja4", "", "tls.ja4"}}
	if f.DPI.DNS != nil {
		vals[2].v = f.DPI.DNS.Query
	}
	if f.DPI.TLS != nil {
		vals[3].v = f.DPI.TLS.SNI
		vals[4].v = f.DPI.TLS.JA3
		vals[5].v = f.DPI.TLS.JA4
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	now := time.Now()
	var out []Match
	for _, x := range vals {
		if x.v == "" {
			continue
		}
		if i, ok := h.indicators[key(x.t, x.v)]; ok && (i.Expires.IsZero() || i.Expires.After(now)) {
			out = append(out, Match{Indicator: i, Field: x.field, Observed: x.v})
		}
	}
	return out
}

var stixPattern = regexp.MustCompile(`(?i)^\s*\[(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\s*\]\s*$`)

type stixBundle struct {
	Type    string            `json:"type"`
	Objects []json.RawMessage `json:"objects"`
}
type stixIndicator struct {
	Type, ID, Pattern, Name, Description string
	Confidence                           int
	Labels                               []string
	ValidFrom                            string `json:"valid_from"`
	ValidUntil                           string `json:"valid_until"`
}

func (h *Hub) ImportSTIXBytes(b []byte, source string) (int, error) {
	var bundle stixBundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return 0, err
	}
	if bundle.Type != "bundle" && len(bundle.Objects) == 0 {
		return 0, fmt.Errorf("not a STIX bundle")
	}
	n := 0
	for _, raw := range bundle.Objects {
		var base map[string]any
		if json.Unmarshal(raw, &base) != nil || base["type"] != "indicator" {
			continue
		}
		var si stixIndicator
		if json.Unmarshal(raw, &si) != nil {
			continue
		}
		m := stixPattern.FindStringSubmatch(si.Pattern)
		if len(m) != 3 {
			continue
		}
		typ := map[string]string{"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}[strings.ToLower(m[1])]
		ind := Indicator{ID: si.ID, Type: typ, Value: m[2], Confidence: si.Confidence, Source: source, Description: si.Description, Labels: si.Labels}
		if t, e := time.Parse(time.RFC3339, si.ValidFrom); e == nil {
			ind.ValidFrom = t
		}
		if t, e := time.Parse(time.RFC3339, si.ValidUntil); e == nil {
			ind.Expires = t
		}
		h.Add(ind)
		n++
	}
	return n, nil
}
func (h *Hub) LoadSTIXFile(path string) (int, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0, e
	}
	return h.ImportSTIXBytes(b, "stix:"+path)
}

func (h *Hub) FetchTAXII(ctx context.Context, feed TAXIIFeed) (int, error) {
	base, err := url.Parse(feed.ObjectsURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return 0, fmt.Errorf("invalid TAXII objects URL")
	}
	src := "taxii:" + feed.Name
	if feed.Name == "" {
		src = "taxii:" + base.Host
	}
	total := 0
	next := ""
	for page := 0; page < 100; page++ {
		u := *base
		q := u.Query()
		if next != "" {
			q.Set("next", next)
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return total, err
		}
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		if feed.Token != "" {
			req.Header.Set("Authorization", "Bearer "+feed.Token)
		} else if feed.Username != "" {
			req.SetBasicAuth(feed.Username, feed.Password)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return total, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return total, fmt.Errorf("TAXII HTTP %s", resp.Status)
		}
		if readErr != nil {
			return total, readErr
		}
		var env struct {
			Objects []json.RawMessage `json:"objects"`
			More    bool              `json:"more"`
			Next    string            `json:"next"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return total, err
		}
		bundle, _ := json.Marshal(stixBundle{Type: "bundle", Objects: env.Objects})
		n, err := h.ImportSTIXBytes(bundle, src)
		if err != nil {
			return total, err
		}
		total += n
		if !env.More {
			return total, nil
		}
		if strings.TrimSpace(env.Next) == "" || env.Next == next {
			return total, fmt.Errorf("TAXII pagination advertised more objects without a usable next token")
		}
		next = env.Next
	}
	return total, fmt.Errorf("TAXII pagination exceeded 100 pages")
}

func (h *Hub) Run(ctx context.Context, files []string, feeds []TAXIIFeed, refresh time.Duration) {
	load := func() {
		for _, p := range files {
			if _, e := h.LoadSTIXFile(p); e != nil {
				h.addErr("STIX " + p + ": " + e.Error())
			}
		}
		for _, f := range feeds {
			if _, e := h.FetchTAXII(ctx, f); e != nil {
				h.addErr("TAXII " + f.Name + ": " + e.Error())
			}
		}
	}
	load()
	if refresh <= 0 {
		return
	}
	t := time.NewTicker(refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			load()
		}
	}
}
