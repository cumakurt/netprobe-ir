package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupVerifyRestore(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	_ = os.MkdirAll(filepath.Join(src, "auth"), 0750)
	_ = os.WriteFile(filepath.Join(src, "auth", "users.json"), []byte("hello"), 0600)
	z := filepath.Join(t.TempDir(), "b.zip")
	if _, e := Create(src, z); e != nil {
		t.Fatal(e)
	}
	if e := Verify(z); e != nil {
		t.Fatal(e)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if e := Restore(z, dst); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dst, "auth", "users.json"))
	if e != nil || string(b) != "hello" {
		t.Fatalf("%s %v", b, e)
	}
}

func TestEncryptedBackupRoundTripAndTamper(t *testing.T) {
	oldIterations := encryptedIterations
	encryptedIterations = 50000
	defer func() { encryptedIterations = oldIterations }()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "auth"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "auth", "users.json"), []byte(`{"users":["a"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(t.TempDir(), "backup.npbackup")
	if _, err := CreateEncrypted(d, enc, "Strong!BackupPass2026"); err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) {
		t.Fatal("encrypted envelope not detected")
	}
	if err := VerifyEncrypted(enc, "Strong!BackupPass2026"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncrypted(enc, "wrong-password"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	r := t.TempDir()
	if err := RestoreEncrypted(enc, r, "Strong!BackupPass2026"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, "auth", "users.json")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x40
	if err = os.WriteFile(enc, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncrypted(enc, "Strong!BackupPass2026"); err == nil {
		t.Fatal("tampered backup verified")
	}
}
