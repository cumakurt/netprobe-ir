package cases

import (
	"archive/zip"
	"io"
	"netprobe-ir/internal/evidence"
	"netprobe-ir/internal/triage"
	"os"
	"path/filepath"
	"testing"
)

func TestCaseLifecycleAndExport(t *testing.T) {
	d := t.TempDir()
	sgr, e := evidence.NewSigner(filepath.Join(d, "evidence", "key"), true)
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(filepath.Join(d, "cases"), sgr)
	if e != nil {
		t.Fatal(e)
	}
	pc := filepath.Join(d, "x.pcapng")
	os.WriteFile(pc, []byte("pcap"), 0600)
	c, e := s.Create(Case{Title: "Test", Severity: "high", PCAPFiles: []string{pc}})
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.AddNote(c.ID, "analyst", "checked")
	if e != nil || len(c.Notes) != 1 {
		t.Fatal(e, c)
	}
	c, e = s.AddTriage(c.ID, triage.Snapshot{CollectedBy: "analyst", FindingID: "finding-1", Process: triage.Process{PID: 4242, Comm: "worker"}})
	if e != nil || len(c.TriageSnapshots) != 1 {
		t.Fatal(e, c)
	}
	dst := filepath.Join(d, "exports", c.ID+".zip")
	if _, e = s.Export(c.ID, dst); e != nil {
		t.Fatal(e)
	}
	zr, e := zip.OpenReader(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["case.json"] || !names["manifest.json"] || !names["x.pcapng"] || !names["triage-001.json"] {
		t.Fatal(names)
	}
	verifyDir := filepath.Join(d, "verify")
	os.MkdirAll(verifyDir, 0750)
	for _, zf := range zr.File {
		in, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(in)
		in.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(verifyDir, zf.Name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mb, err := os.ReadFile(filepath.Join(verifyDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = evidence.VerifyManifestFiles(verifyDir, mb); err != nil {
		t.Fatalf("bundle evidence verify: %v", err)
	}
	if s.Count() != 1 {
		t.Fatal("case count")
	}
}
