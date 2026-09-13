package enrichment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(p, []byte(`[{"cidr":"8.8.8.0/24","asn":15169,"organization":"Example","country":"US"}]`), 0600)
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	h, ok := c.Lookup("8.8.8.8")
	if !ok || h.ASN != 15169 {
		t.Fatalf("bad %#v", h)
	}
}
