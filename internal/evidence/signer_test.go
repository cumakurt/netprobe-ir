package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignedManifest(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.txt")
	os.WriteFile(p, []byte("evidence"), 0600)
	s, e := NewSigner(filepath.Join(d, "key"), true)
	if e != nil {
		t.Fatal(e)
	}
	m, b, e := s.Build([]string{p})
	if e != nil || m.Signature == "" {
		t.Fatal(e, m)
	}
	if e = VerifyManifest(b); e != nil {
		t.Fatal(e)
	}
	b[len(b)-2] ^= 1
	if VerifyManifest(b) == nil {
		t.Fatal("tamper accepted")
	}
}

func TestDetachedFileSignature(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "rules.json")
	os.WriteFile(p, []byte("[]"), 0600)
	s, err := NewSigner(filepath.Join(d, "key"), true)
	if err != nil {
		t.Fatal(err)
	}
	det, b, err := s.SignFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetachedFile(p, b, det.PublicKey); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("[{}]"), 0600)
	if err := VerifyDetachedFile(p, b, det.PublicKey); err == nil {
		t.Fatal("tamper not detected")
	}
}

func TestManifestFileHashes(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.txt")
	os.WriteFile(p, []byte("evidence"), 0600)
	s, _ := NewSigner(filepath.Join(d, "key"), true)
	_, b, err := s.Build([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifestFiles(d, b); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("tampered"), 0600)
	if VerifyManifestFiles(d, b) == nil {
		t.Fatal("tampered evidence accepted")
	}
}
