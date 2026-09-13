package wasmplugin

import (
	"netprobe-ir/internal/eventbus"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalRunner(t *testing.T) {
	d := t.TempDir()
	bin := filepath.Join(d, "wasmtime")
	mod := filepath.Join(d, "x.wasm")
	os.WriteFile(mod, []byte("x"), 0600)
	script := "#!/bin/sh\ncat >/dev/null\necho '{\"enrichment\":{\"ok\":true}}'\n"
	if e := os.WriteFile(bin, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	r := New(bin, []Plugin{{Name: "p", Module: mod, Enabled: true}})
	x := r.Process(eventbus.Event{Type: "x"})
	if len(x) != 1 || x[0].Enrichment["ok"] != true {
		t.Fatalf("%#v", x)
	}
}
