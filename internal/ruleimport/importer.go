package ruleimport

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Rule struct {
	Engine          string    `json:"engine"`
	Action          string    `json:"action"`
	Protocol        string    `json:"protocol"`
	Source          string    `json:"source"`
	SourcePort      string    `json:"source_port"`
	Direction       string    `json:"direction"`
	Destination     string    `json:"destination"`
	DestinationPort string    `json:"destination_port"`
	SID             int       `json:"sid,omitempty"`
	Rev             int       `json:"rev,omitempty"`
	Message         string    `json:"message,omitempty"`
	Classtype       string    `json:"classtype,omitempty"`
	Contents        []Content `json:"contents,omitempty"`
	PCRE            []string  `json:"pcre,omitempty"`
	Flow            []string  `json:"flow,omitempty"`
	Threshold       string    `json:"threshold,omitempty"`
	References      []string  `json:"references,omitempty"`
	Unsupported     []string  `json:"unsupported,omitempty"`
	Coverage        int       `json:"coverage"`
}

type Content struct {
	Value    string `json:"value"`
	NoCase   bool   `json:"nocase,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Depth    int    `json:"depth,omitempty"`
	Distance int    `json:"distance,omitempty"`
	Within   int    `json:"within,omitempty"`
}

var headerRE = regexp.MustCompile(`^\s*(alert|drop|reject|pass)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$`)

func ParseLine(line string) (Rule, error) {
	m := headerRE.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Rule{}, fmt.Errorf("unsupported rule header")
	}
	r := Rule{Engine: "suricata/snort-subset", Action: m[1], Protocol: m[2], Source: m[3], SourcePort: m[4], Direction: m[5], Destination: m[6], DestinationPort: m[7]}
	var last *Content
	supported, total := 0, 0
	for _, raw := range splitOptions(m[8]) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		total++
		kv := strings.SplitN(raw, ":", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := ""
		if len(kv) == 2 {
			val = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
		switch key {
		case "msg":
			r.Message = val
			supported++
		case "sid":
			r.SID, _ = strconv.Atoi(val)
			supported++
		case "rev":
			r.Rev, _ = strconv.Atoi(val)
			supported++
		case "classtype":
			r.Classtype = val
			supported++
		case "flow":
			r.Flow = splitCSV(val)
			supported++
		case "content":
			r.Contents = append(r.Contents, Content{Value: unescapeContent(val)})
			last = &r.Contents[len(r.Contents)-1]
			supported++
		case "nocase":
			if last != nil {
				last.NoCase = true
				supported++
			} else {
				r.Unsupported = append(r.Unsupported, key)
			}
		case "offset", "depth", "distance", "within":
			if last != nil {
				v, _ := strconv.Atoi(val)
				switch key {
				case "offset":
					last.Offset = v
				case "depth":
					last.Depth = v
				case "distance":
					last.Distance = v
				case "within":
					last.Within = v
				}
				supported++
			} else {
				r.Unsupported = append(r.Unsupported, key)
			}
		case "pcre":
			r.PCRE = append(r.PCRE, val)
			supported++
		case "threshold", "detection_filter":
			r.Threshold = val
			supported++
		case "reference":
			r.References = append(r.References, val)
			supported++
		default:
			r.Unsupported = append(r.Unsupported, key)
		}
	}
	if total > 0 {
		r.Coverage = supported * 100 / total
	}
	return r, nil
}

func Translate(r Rule) map[string]any {
	query := []string{"proto:" + r.Protocol}
	if r.Source != "$HOME_NET" && r.Source != "any" {
		query = append(query, "src:"+r.Source)
	}
	if r.Destination != "$HOME_NET" && r.Destination != "any" {
		query = append(query, "dst:"+r.Destination)
	}
	if r.SourcePort != "any" {
		query = append(query, "sport:"+r.SourcePort)
	}
	if r.DestinationPort != "any" {
		query = append(query, "dport:"+r.DestinationPort)
	}
	for _, c := range r.Contents {
		if c.Value != "" {
			query = append(query, `text:"`+strings.ReplaceAll(c.Value, `"`, ``)+`"`)
		}
	}
	return map[string]any{"rule_id": fmt.Sprintf("SURICATA-%d", r.SID), "title": first(r.Message, fmt.Sprintf("Imported rule %d", r.SID)), "query": strings.Join(query, " "), "coverage": r.Coverage, "unsupported": r.Unsupported, "source_engine": r.Engine, "requires_review": len(r.Unsupported) > 0}
}

func splitOptions(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	esc := false
	for _, r := range s {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			b.WriteRune(r)
			esc = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			b.WriteRune(r)
			continue
		}
		if r == ';' && !quoted {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, b.String())
	}
	return out
}
func splitCSV(s string) []string {
	xs := strings.Split(s, ",")
	out := xs[:0]
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func unescapeContent(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\|`, `|`), `\"`, `"`)
}
func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
