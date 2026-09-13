package assetintel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAndSBOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status")
	_ = os.WriteFile(p, []byte("Package: curl\nVersion: 8.0\nArchitecture: amd64\n\nPackage: bash\nVersion: 5\nArchitecture: amd64\n"), 0600)
	xs, e := ParseDPKGStatus(p)
	if e != nil || len(xs) != 2 {
		t.Fatalf("%v %#v", e, xs)
	}
	inv := Current()
	inv.Packages = xs
	if len(CycloneDX(inv)["components"].([]map[string]any)) != 2 {
		t.Fatal("bad cdx")
	}
}
