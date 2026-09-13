package netbaseline

import (
	"bufio"
	"encoding/json"
	"netprobe-ir/internal/model"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Time        time.Time `json:"time"`
	RemoteIP    string    `json:"remote_ip,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Application string    `json:"application,omitempty"`
	Process     string    `json:"process,omitempty"`
}
type Item struct {
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	Recent     int       `json:"recent"`
	Historical int       `json:"historical"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}
type Diff struct {
	At               time.Time `json:"at"`
	RecentWindow     string    `json:"recent_window"`
	HistoricalWindow string    `json:"historical_window"`
	New              []Item    `json:"new"`
	Recurring        []Item    `json:"recurring"`
}
type Store struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Store { return &Store{path: path} }
func (s *Store) Observe(f model.Flow) error {
	domain := ""
	if f.DPI.DNS != nil {
		domain = f.DPI.DNS.Query
	}
	if domain == "" && f.DPI.HTTP != nil {
		domain = f.DPI.HTTP.Host
	}
	if domain == "" && f.DPI.TLS != nil {
		domain = f.DPI.TLS.SNI
	}
	e := Event{Time: f.LastSeen, RemoteIP: f.Remote.IP, Domain: domain, Protocol: f.NetworkProtocol, Application: f.DPI.Application}
	if f.Process != nil {
		e.Process = f.Process.Comm
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	b, _ := json.Marshal(e)
	fh, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	_, err = fh.Write(append(b, '\n'))
	ce := fh.Close()
	if err == nil {
		err = ce
	}
	return err
}
func (s *Store) Compare(at time.Time, recent, historical time.Duration) (Diff, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if recent <= 0 {
		recent = time.Hour
	}
	if historical <= recent {
		historical = 7 * 24 * time.Hour
	}
	cutRecent := at.Add(-recent)
	cutHist := at.Add(-historical)
	type a struct{ item Item }
	m := map[string]*a{}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return Diff{At: at, RecentWindow: recent.String(), HistoricalWindow: historical.String()}, nil
	}
	if err != nil {
		return Diff{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Time.Before(cutHist) || e.Time.After(at) {
			continue
		}
		vals := map[string]string{"ip": e.RemoteIP, "domain": e.Domain, "protocol": e.Protocol, "application": e.Application, "process": e.Process}
		for kind, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			k := kind + ":" + v
			x := m[k]
			if x == nil {
				x = &a{item: Item{Kind: kind, Value: v, FirstSeen: e.Time, LastSeen: e.Time}}
				m[k] = x
			}
			if e.Time.Before(x.item.FirstSeen) {
				x.item.FirstSeen = e.Time
			}
			if e.Time.After(x.item.LastSeen) {
				x.item.LastSeen = e.Time
			}
			if !e.Time.Before(cutRecent) {
				x.item.Recent++
			} else {
				x.item.Historical++
			}
		}
	}
	if err = sc.Err(); err != nil {
		return Diff{}, err
	}
	d := Diff{At: at, RecentWindow: recent.String(), HistoricalWindow: historical.String()}
	for _, x := range m {
		if x.item.Recent == 0 {
			continue
		}
		if x.item.Historical == 0 {
			d.New = append(d.New, x.item)
		} else {
			d.Recurring = append(d.Recurring, x.item)
		}
	}
	sort.Slice(d.New, func(i, j int) bool {
		if d.New[i].Recent != d.New[j].Recent {
			return d.New[i].Recent > d.New[j].Recent
		}
		return d.New[i].Kind < d.New[j].Kind
	})
	sort.Slice(d.Recurring, func(i, j int) bool { return d.Recurring[i].Recent > d.Recurring[j].Recent })
	return d, nil
}
