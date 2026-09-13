package enrichment

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
)

type Record struct {
	CIDR         string `json:"cidr"`
	ASN          int    `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	Source       string `json:"source,omitempty"`
}
type Hit struct {
	IP           string `json:"ip"`
	ASN          int    `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	Source       string `json:"source,omitempty"`
	MatchedCIDR  string `json:"matched_cidr,omitempty"`
}
type entry struct {
	net *net.IPNet
	r   Record
}
type Cache struct{ entries []entry }

func Load(path string) (*Cache, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var rs []Record
	if e = json.Unmarshal(b, &rs); e != nil {
		return nil, e
	}
	c := &Cache{}
	for _, r := range rs {
		_, n, e := net.ParseCIDR(strings.TrimSpace(r.CIDR))
		if e != nil {
			continue
		}
		c.entries = append(c.entries, entry{n, r})
	}
	sort.Slice(c.entries, func(i, j int) bool {
		oi, _ := c.entries[i].net.Mask.Size()
		oj, _ := c.entries[j].net.Mask.Size()
		return oi > oj
	})
	return c, nil
}
func (c *Cache) Lookup(ip string) (Hit, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return Hit{}, false
	}
	for _, e := range c.entries {
		if e.net.Contains(p) {
			return Hit{IP: ip, ASN: e.r.ASN, Organization: e.r.Organization, Country: e.r.Country, Source: e.r.Source, MatchedCIDR: e.r.CIDR}, true
		}
	}
	return Hit{}, false
}
