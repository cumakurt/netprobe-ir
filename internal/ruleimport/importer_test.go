package ruleimport

import (
	"strings"
	"testing"
)

func TestParseTranslate(t *testing.T) {
	r, e := ParseLine(`alert tcp $HOME_NET any -> 1.2.3.4 443 (msg:"Test"; flow:to_server,established; content:"evil"; nocase; sid:1001; rev:2; classtype:trojan-activity;)`)
	if e != nil {
		t.Fatal(e)
	}
	if r.SID != 1001 || len(r.Contents) != 1 || !r.Contents[0].NoCase || r.Coverage != 100 {
		t.Fatalf("bad %#v", r)
	}
	m := Translate(r)
	if !strings.Contains(m["query"].(string), "dst:1.2.3.4") {
		t.Fatalf("bad %#v", m)
	}
}
func TestUnsupportedVisible(t *testing.T) {
	r, e := ParseLine(`alert tcp any any -> any any (msg:"X"; byte_test:1,=,1,0; sid:1;)`)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Unsupported) != 1 || r.Coverage >= 100 {
		t.Fatalf("bad %#v", r)
	}
}
