package sigma

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Rule struct {
	Title      string                         `json:"title"`
	ID         string                         `json:"id,omitempty"`
	Status     string                         `json:"status,omitempty"`
	Level      string                         `json:"level,omitempty"`
	Product    string                         `json:"product,omitempty"`
	Service    string                         `json:"service,omitempty"`
	Category   string                         `json:"category,omitempty"`
	Condition  string                         `json:"condition"`
	Selection  map[string][]string            `json:"selection"`
	Detections map[string]map[string][]string `json:"detections"`
}

type Compiled struct {
	Query          string   `json:"query"`
	Summary        string   `json:"summary"`
	Coverage       int      `json:"coverage"`
	Warnings       []string `json:"warnings,omitempty"`
	RuntimeReady   bool     `json:"runtime_ready"`
	DetectionNames []string `json:"detection_names"`
}

func ParseFile(path string) (Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return Rule{}, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (Rule, error) {
	rule := Rule{Selection: map[string][]string{}, Detections: map[string]map[string][]string{}}
	sc := bufio.NewScanner(r)
	section, block, field := "", "", ""
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimRight(sc.Text(), " \t\r\n")
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := countIndent(raw)
		switch {
		case indent == 0 && strings.HasSuffix(line, ":"):
			section = strings.TrimSuffix(line, ":")
			block = ""
			field = ""
		case indent == 0:
			k, v, ok := splitKV(line)
			if !ok {
				return Rule{}, fmt.Errorf("line %d: invalid top-level syntax", lineNo)
			}
			switch k {
			case "title":
				rule.Title = v
			case "id":
				rule.ID = v
			case "status":
				rule.Status = v
			case "level":
				rule.Level = v
			}
		case section == "logsource" && indent >= 2:
			k, v, ok := splitKV(line)
			if !ok {
				return Rule{}, fmt.Errorf("line %d: invalid logsource field", lineNo)
			}
			switch k {
			case "product":
				rule.Product = v
			case "service":
				rule.Service = v
			case "category":
				rule.Category = v
			}
		case section == "detection":
			if indent == 2 && strings.HasSuffix(line, ":") {
				block = strings.TrimSuffix(line, ":")
				field = ""
				if rule.Detections[block] == nil {
					rule.Detections[block] = map[string][]string{}
				}
				continue
			}
			if indent == 2 {
				k, v, ok := splitKV(line)
				if !ok {
					return Rule{}, fmt.Errorf("line %d: invalid detection field", lineNo)
				}
				if k == "condition" {
					rule.Condition = v
				}
				continue
			}
			if indent >= 4 && block != "" {
				if strings.HasPrefix(line, "-") {
					if field != "" {
						rule.Detections[block][field] = append(rule.Detections[block][field], strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "-")), `"'`))
					}
					continue
				}
				if strings.HasSuffix(line, ":") {
					field = strings.TrimSuffix(line, ":")
					if _, ok := rule.Detections[block][field]; !ok {
						rule.Detections[block][field] = nil
					}
					continue
				}
				k, v, ok := splitKV(line)
				if !ok {
					return Rule{}, fmt.Errorf("line %d: invalid selection field", lineNo)
				}
				field = k
				rule.Detections[block][k] = append(rule.Detections[block][k], v)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Rule{}, err
	}
	if rule.Title == "" {
		return Rule{}, fmt.Errorf("missing title")
	}
	if len(rule.Detections) == 0 {
		return Rule{}, fmt.Errorf("missing detection selection")
	}
	if rule.Condition == "" {
		if _, ok := rule.Detections["selection"]; ok {
			rule.Condition = "selection"
		} else {
			for k := range rule.Detections {
				rule.Condition = k
				break
			}
		}
	}
	if sel := rule.Detections["selection"]; sel != nil {
		rule.Selection = copySelection(sel)
	} else {
		for _, sel := range rule.Detections {
			rule.Selection = copySelection(sel)
			break
		}
	}
	return rule, nil
}

func CompileQuery(rule Rule) Compiled {
	names := make([]string, 0, len(rule.Detections))
	for k := range rule.Detections {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := map[string]string{}
	supported, total := 0, 0
	var warnings []string
	for _, name := range names {
		q, s, t, w := compileSelection(rule.Detections[name])
		parts[name] = q
		supported += s
		total += t
		warnings = append(warnings, w...)
	}
	query, condWarnings := compileCondition(rule.Condition, parts, names)
	warnings = append(warnings, condWarnings...)
	coverage := 100
	if total > 0 {
		coverage = int(float64(supported)*100/float64(total) + .5)
	}
	summary := rule.Title
	if rule.Level != "" {
		summary += " [" + rule.Level + "]"
	}
	if rule.Product != "" || rule.Service != "" || rule.Category != "" {
		ctx := strings.Trim(strings.Join([]string{rule.Product, rule.Service, rule.Category}, "/"), "/")
		if ctx != "" {
			summary += " — " + ctx
		}
	}
	return Compiled{Query: query, Summary: summary, Coverage: coverage, Warnings: dedupe(warnings), RuntimeReady: coverage == 100, DetectionNames: names}
}

func Match(rule Rule, fields map[string]string) (bool, error) {
	results := map[string]bool{}
	for name, sel := range rule.Detections {
		ok, err := matchSelection(sel, fields)
		if err != nil {
			return false, err
		}
		results[name] = ok
	}
	return evalCondition(strings.TrimSpace(rule.Condition), results)
}

func compileSelection(sel map[string][]string) (string, int, int, []string) {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts, warnings []string
	supported, total := 0, 0
	for _, raw := range keys {
		total++
		base, mod := splitFieldModifier(raw)
		field := fieldMap[base]
		if field == "" {
			field = strings.ToLower(base)
		}
		vals := sel[raw]
		if len(vals) == 0 {
			continue
		}
		var terms []string
		switch mod {
		case "", "contains":
			supported++
			for _, v := range vals {
				terms = append(terms, token(field, v))
			}
		case "startswith":
			supported++
			for _, v := range vals {
				terms = append(terms, token(field, v)+"*")
			}
		case "endswith":
			supported++
			for _, v := range vals {
				terms = append(terms, "*"+token(field, v))
			}
		case "exists", "re", "cidr":
			supported++
			for _, v := range vals {
				terms = append(terms, field+"|"+mod+":"+quote(v))
			}
		default:
			warnings = append(warnings, "unsupported Sigma modifier: "+mod+" on "+base)
			continue
		}
		if len(terms) == 1 {
			parts = append(parts, terms[0])
		} else if len(terms) > 1 {
			parts = append(parts, "("+strings.Join(terms, " OR ")+")")
		}
	}
	return strings.Join(parts, " AND "), supported, total, warnings
}

func compileCondition(cond string, blocks map[string]string, names []string) (string, []string) {
	c := strings.TrimSpace(cond)
	lc := strings.ToLower(c)
	if q, ok := blocks[c]; ok {
		return q, nil
	}
	if strings.HasPrefix(lc, "1 of ") || strings.HasPrefix(lc, "all of ") {
		all := strings.HasPrefix(lc, "all of ")
		pat := strings.TrimSpace(c[strings.Index(c, "of")+2:])
		prefix := strings.TrimSuffix(pat, "*")
		var qs []string
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				if blocks[n] != "" {
					qs = append(qs, "("+blocks[n]+")")
				}
			}
		}
		if len(qs) == 0 {
			return "", []string{"condition matched no detection blocks: " + cond}
		}
		sep := " OR "
		if all {
			sep = " AND "
		}
		return strings.Join(qs, sep), nil
	}
	// Common Sigma boolean expressions. Replace longer names first.
	q := c
	ordered := append([]string(nil), names...)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, n := range ordered {
		q = regexp.MustCompile(`\b`+regexp.QuoteMeta(n)+`\b`).ReplaceAllString(q, "("+blocks[n]+")")
	}
	if strings.Contains(strings.ToLower(q), " not ") {
		return q, []string{"NOT translation is exact in Sigma evaluator; Hunt-query display may require manual review"}
	}
	return q, nil
}

func evalCondition(cond string, results map[string]bool) (bool, error) {
	c := strings.TrimSpace(cond)
	lc := strings.ToLower(c)
	if v, ok := results[c]; ok {
		return v, nil
	}
	if strings.HasPrefix(lc, "1 of ") || strings.HasPrefix(lc, "all of ") {
		all := strings.HasPrefix(lc, "all of ")
		pat := strings.TrimSpace(c[strings.Index(c, "of")+2:])
		prefix := strings.TrimSuffix(pat, "*")
		matched := 0
		truth := 0
		for n, v := range results {
			if strings.HasPrefix(n, prefix) {
				matched++
				if v {
					truth++
				}
			}
		}
		if matched == 0 {
			return false, fmt.Errorf("condition matched no detection blocks")
		}
		if all {
			return truth == matched, nil
		}
		return truth > 0, nil
	}
	// Small boolean grammar: OR of AND terms, with optional NOT prefix.
	for _, orPart := range regexp.MustCompile(`(?i)\s+or\s+`).Split(c, -1) {
		andOK := true
		for _, andPart := range regexp.MustCompile(`(?i)\s+and\s+`).Split(orPart, -1) {
			t := strings.TrimSpace(andPart)
			neg := false
			if strings.HasPrefix(strings.ToLower(t), "not ") {
				neg = true
				t = strings.TrimSpace(t[4:])
			}
			v, ok := results[t]
			if !ok {
				return false, fmt.Errorf("unsupported condition term %q", t)
			}
			if neg {
				v = !v
			}
			andOK = andOK && v
		}
		if andOK {
			return true, nil
		}
	}
	return false, nil
}

func matchSelection(sel map[string][]string, fields map[string]string) (bool, error) {
	for raw, vals := range sel {
		base, mod := splitFieldModifier(raw)
		field := fieldMap[base]
		if field == "" {
			field = strings.ToLower(base)
		}
		actual := fields[field]
		any := false
		for _, want := range vals {
			ok, err := matchValue(actual, want, mod)
			if err != nil {
				return false, fmt.Errorf("%s: %w", raw, err)
			}
			if ok {
				any = true
				break
			}
		}
		if !any {
			return false, nil
		}
	}
	return true, nil
}

func matchValue(actual, want, mod string) (bool, error) {
	a := strings.ToLower(actual)
	w := strings.ToLower(want)
	switch mod {
	case "":
		return strings.EqualFold(actual, want), nil
	case "contains":
		return strings.Contains(a, w), nil
	case "startswith":
		return strings.HasPrefix(a, w), nil
	case "endswith":
		return strings.HasSuffix(a, w), nil
	case "exists":
		x := strings.EqualFold(want, "true") || want == "1"
		return (actual != "") == x, nil
	case "re":
		r, err := regexp.Compile(want)
		if err != nil {
			return false, err
		}
		return r.MatchString(actual), nil
	case "cidr":
		ip := net.ParseIP(actual)
		_, n, err := net.ParseCIDR(want)
		if err != nil {
			return false, err
		}
		return ip != nil && n.Contains(ip), nil
	default:
		return false, fmt.Errorf("unsupported modifier %q", mod)
	}
}

func splitFieldModifier(raw string) (string, string) {
	p := strings.Split(raw, "|")
	if len(p) == 1 {
		return p[0], ""
	}
	return p[0], strings.ToLower(p[1])
}
func copySelection(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
func countIndent(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}
func splitKV(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.Trim(strings.TrimSpace(parts[1]), `"'`), true
}

var fieldMap = map[string]string{"SourceIp": "src", "DestinationIp": "dst", "SourcePort": "sport", "DestinationPort": "dport", "Protocol": "proto", "Image": "process", "CommandLine": "process", "ParentImage": "parent_process", "User": "user", "RuleName": "rule", "Severity": "severity", "Interface": "iface"}

func token(field, value string) string { return field + ":" + quote(value) }
func quote(value string) string {
	if strings.ContainsAny(value, " \t") {
		value = strings.ReplaceAll(value, `"`, "")
		return `"` + value + `"`
	}
	return value
}
func RenderNPDL(rule Rule) string {
	id := rule.ID
	if id == "" {
		id = slug(rule.Title)
	}
	sev := strings.ToLower(rule.Level)
	if sev == "" {
		sev = "medium"
	}
	lines := []string{"# Generated from Sigma by NetProbe IR. Review before enabling.", "rule " + id, "title " + rule.Title, "severity " + sev, "confidence 80"}
	sel, ok := rule.Detections[strings.TrimSpace(rule.Condition)]
	enabled := ok
	var conds []string
	if ok {
		keys := make([]string, 0, len(sel))
		for k := range sel {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, raw := range keys {
			base, mod := splitFieldModifier(raw)
			field := npdlField(base)
			vals := sel[raw]
			if field == "" || len(vals) != 1 || (mod != "" && mod != "contains") {
				enabled = false
				break
			}
			op := "="
			if mod == "contains" {
				op = "~"
			}
			conds = append(conds, fmt.Sprintf("%s %s %s", field, op, quoteNPDL(vals[0])))
		}
	}
	if !enabled || len(conds) == 0 {
		lines = append(lines, "# Complex Sigma boolean/modifier semantics require manual translation.", "enabled false", "when finding_rule = __sigma_manual_review__", "end", "")
		return strings.Join(lines, "\n")
	}
	lines = append(lines, "enabled true", "when "+strings.Join(conds, " AND "), "end", "")
	return strings.Join(lines, "\n")
}

func npdlField(base string) string {
	switch base {
	case "Image", "CommandLine":
		return "process"
	case "SourceIp":
		return "src_ip"
	case "DestinationIp":
		return "dst_ip"
	case "DestinationPort":
		return "dst_port"
	case "Protocol":
		return "protocol"
	case "RuleName":
		return "finding_rule"
	default:
		return ""
	}
}
func quoteNPDL(v string) string {
	if strings.ContainsAny(v, " \t") {
		return `"` + strings.ReplaceAll(v, `"`, "") + `"`
	}
	return v
}

func escape(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	out = strings.Trim(out, "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if out == "" {
		return "sigma-rule"
	}
	return out
}
func dedupe(a []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range a {
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}

// CorrelationRule represents the Sigma correlation subset supported by NetProbe IR.
// Supported types are event_count, value_count, temporal and temporal_ordered.
type CorrelationRule struct {
	Title    string   `json:"title"`
	ID       string   `json:"id,omitempty"`
	Type     string   `json:"type"`
	Rules    []string `json:"rules"`
	GroupBy  []string `json:"group_by,omitempty"`
	Timespan string   `json:"timespan,omitempty"`
	Field    string   `json:"field,omitempty"`
	GTE      int      `json:"gte,omitempty"`
	LTE      int      `json:"lte,omitempty"`
	Ordered  bool     `json:"ordered,omitempty"`
}

type CorrelationPlan struct {
	Type         string   `json:"type"`
	RuleIDs      []string `json:"rule_ids"`
	GroupBy      []string `json:"group_by,omitempty"`
	Timespan     string   `json:"timespan,omitempty"`
	ValueField   string   `json:"value_field,omitempty"`
	MinCount     int      `json:"min_count,omitempty"`
	MaxCount     int      `json:"max_count,omitempty"`
	Ordered      bool     `json:"ordered,omitempty"`
	RuntimeReady bool     `json:"runtime_ready"`
	Warnings     []string `json:"warnings,omitempty"`
}

// ParseCorrelation parses a conservative Sigma correlation-rule subset.
func ParseCorrelation(r io.Reader) (CorrelationRule, error) {
	sc := bufio.NewScanner(r)
	var c CorrelationRule
	section := ""
	list := ""
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), " \t\r\n")
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := countIndent(raw)
		if indent == 0 {
			if strings.HasSuffix(line, ":") {
				section = strings.TrimSuffix(line, ":")
				list = ""
				continue
			}
			k, v, ok := splitKV(line)
			if !ok {
				continue
			}
			switch k {
			case "title":
				c.Title = v
			case "id":
				c.ID = v
			}
			continue
		}
		if section != "correlation" {
			continue
		}
		if indent == 2 && strings.HasSuffix(line, ":") {
			list = strings.TrimSuffix(line, ":")
			continue
		}
		if strings.HasPrefix(line, "-") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "-")), `"'`)
			switch list {
			case "rules":
				c.Rules = append(c.Rules, v)
			case "group-by", "group_by":
				c.GroupBy = append(c.GroupBy, v)
			}
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "type":
			c.Type = strings.ToLower(v)
			c.Ordered = c.Type == "temporal_ordered"
		case "timespan":
			c.Timespan = v
		case "field":
			c.Field = v
		case "gte":
			fmt.Sscanf(v, "%d", &c.GTE)
		case "lte":
			fmt.Sscanf(v, "%d", &c.LTE)
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	if c.Title == "" {
		return c, fmt.Errorf("missing title")
	}
	if c.Type == "" {
		return c, fmt.Errorf("missing correlation.type")
	}
	if len(c.Rules) == 0 {
		return c, fmt.Errorf("missing correlation.rules")
	}
	return c, nil
}

func CompileCorrelation(c CorrelationRule) CorrelationPlan {
	p := CorrelationPlan{Type: c.Type, RuleIDs: append([]string(nil), c.Rules...), GroupBy: append([]string(nil), c.GroupBy...), Timespan: c.Timespan, ValueField: c.Field, MinCount: c.GTE, MaxCount: c.LTE, Ordered: c.Ordered, RuntimeReady: true}
	switch c.Type {
	case "event_count", "value_count", "temporal", "temporal_ordered":
	default:
		p.RuntimeReady = false
		p.Warnings = append(p.Warnings, "unsupported correlation type: "+c.Type)
	}
	if c.Type == "value_count" && strings.TrimSpace(c.Field) == "" {
		p.RuntimeReady = false
		p.Warnings = append(p.Warnings, "value_count requires field")
	}
	if (c.Type == "event_count" || c.Type == "value_count") && c.GTE == 0 && c.LTE == 0 {
		p.MinCount = 1
		p.Warnings = append(p.Warnings, "no count condition supplied; defaulting to >=1")
	}
	return p
}
