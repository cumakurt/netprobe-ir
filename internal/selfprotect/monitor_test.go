package selfprotect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashChange(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x")
	os.WriteFile(p, []byte("a"), 0600)
	m := New(Config{Enabled: true, Paths: []string{p}, DataDir: d, MinFreeMB: 1})
	os.WriteFile(p, []byte("b"), 0600)
	h, f := m.Check()
	if len(h.Changed) != 1 || len(f) == 0 {
		t.Fatalf("%#v %#v", h, f)
	}
}

func TestRebaselineWithoutExplicitPathsRetainsWatchSet(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x")
	if err := os.WriteFile(p, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(Config{Enabled: true, Paths: []string{p}, DataDir: d, MinFreeMB: 1})
	if err := os.WriteFile(p, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Rebaseline(nil); err != nil {
		t.Fatal(err)
	}
	h, f := m.Check()
	if h.Watched != 1 || len(h.Changed) != 0 || len(h.Missing) != 0 || len(f) != 0 {
		t.Fatalf("unexpected health after rebaseline: %#v findings=%#v", h, f)
	}
}
