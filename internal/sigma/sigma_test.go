package sigma

import (
	"strings"
	"testing"
)

func TestParseCompileAndEvaluateV2(t *testing.T) {
	in := `title: Suspicious Python TLS
id: NP-SIGMA-1001
level: high
logsource:
  product: linux
  service: network
detection:
  selection_main:
    Image|endswith: python3
    DestinationIp|cidr: 203.0.113.0/24
    Protocol: tls
  filter_local:
    DestinationIp: 203.0.113.9
  condition: selection_main and not filter_local
`
	r, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	c := CompileQuery(r)
	if c.Coverage != 100 || !c.RuntimeReady || !strings.Contains(c.Query, "NOT") && !strings.Contains(strings.ToLower(c.Query), "not") {
		t.Fatalf("compiled=%#v", c)
	}
	ok, err := Match(r, map[string]string{"process": "/usr/bin/python3", "dst": "203.0.113.10", "proto": "tls"})
	if err != nil || !ok {
		t.Fatalf("match=%v err=%v", ok, err)
	}
	ok, err = Match(r, map[string]string{"process": "/usr/bin/python3", "dst": "203.0.113.9", "proto": "tls"})
	if err != nil || ok {
		t.Fatalf("filter match=%v err=%v", ok, err)
	}
}

func TestOneOfCondition(t *testing.T) {
	in := `title: one of
level: medium
detection:
  selection_a:
    Image|contains: curl
  selection_b:
    Image|contains: wget
  condition: 1 of selection_*
`
	r, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Match(r, map[string]string{"process": "/usr/bin/wget"})
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
}

func TestParseRejectsMissingSelection(t *testing.T) {
	_, err := Parse(strings.NewReader("title: x\ndetection:\n  condition: selection\n"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderNPDLProducesLoadableSafeSubset(t *testing.T) {
	r, err := Parse(strings.NewReader("title: curl\nid: S1\nlevel: high\ndetection:\n  selection:\n    Image|contains: curl\n    Protocol: tcp\n  condition: selection\n"))
	if err != nil {
		t.Fatal(err)
	}
	n := RenderNPDL(r)
	if !strings.Contains(n, "enabled true") || !strings.Contains(n, "when process ~ curl AND protocol = tcp") {
		t.Fatalf("npdl=%s", n)
	}
}

func TestCorrelationParseCompile(t *testing.T) {
	in := `title: Brute force followed by success
id: NP-CORR-1
correlation:
  type: temporal_ordered
  rules:
    - failed_login
    - successful_login
  group-by:
    - User
    - SourceIp
  timespan: 10m
`
	c, err := ParseCorrelation(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	p := CompileCorrelation(c)
	if !p.RuntimeReady || !p.Ordered || len(p.RuleIDs) != 2 || p.Timespan != "10m" {
		t.Fatalf("bad %#v", p)
	}
}
