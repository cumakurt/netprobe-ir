//go:build linux

package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectPersistenceIncludesTargetUnitAndCronWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/systemd/system/worker.service":                 "[Service]\nExecStart=/usr/bin/worker\n",
		"etc/systemd/system/worker.service.d/override.conf": "[Service]\nRestart=always\n",
		"etc/cron.d/health":                                 "0 * * * * root /usr/bin/true\n",
	}
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/private/secret", filepath.Join(root, "etc/crontab")); err != nil {
		t.Fatal(err)
	}
	artifacts, warnings := collectPersistence(context.Background(), root, "0::/system.slice/worker.service", nil)
	if len(warnings) != 0 || len(artifacts) != 4 {
		t.Fatalf("artifacts=%+v warnings=%v", artifacts, warnings)
	}
	byPath := map[string]PersistenceArtifact{}
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact
	}
	unit := byPath[filepath.Join(root, "etc/systemd/system/worker.service")]
	wantHash := sha256.Sum256([]byte(files["etc/systemd/system/worker.service"]))
	if unit.Scope != "target_systemd_unit" || unit.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("unexpected unit artifact: %+v", unit)
	}
	link := byPath[filepath.Join(root, "etc/crontab")]
	if link.Kind != "symlink" || link.LinkTarget != "/private/secret" || link.SHA256 != "" {
		t.Fatalf("symlink was followed or lost: %+v", link)
	}
	if got := systemdUnit("0::/system.slice/../../worker.service"); got != "worker.service" {
		t.Fatalf("unexpected safe unit name: %q", got)
	}
	if got := systemdUnit("0::/user.slice/user@1000.service/app.slice/browser.scope"); got != "" {
		t.Fatalf("ancestor service was treated as the process unit: %q", got)
	}
}

func TestJournalMetadataDoesNotStoreMessageContent(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","_BOOT_ID":"boot-1","_SYSTEMD_UNIT":"worker.service","SYSLOG_IDENTIFIER":"worker","PRIORITY":"3","MESSAGE":"credential=value"}` + "\n"
	entries, warnings := parseJournal([]byte(line))
	if len(warnings) != 0 || len(entries) != 1 {
		t.Fatalf("entries=%+v warnings=%v", entries, warnings)
	}
	want := sha256.Sum256([]byte("credential=value"))
	if entries[0].MessageSHA256 != hex.EncodeToString(want[:]) || entries[0].MessageBytes != len("credential=value") {
		t.Fatalf("unexpected journal digest: %+v", entries[0])
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "credential=value") {
		t.Fatal("journal message leaked into snapshot")
	}
	writer := &boundedWriter{limit: 4}
	if n, err := writer.Write([]byte("123456789")); err != nil || n != 9 || string(writer.bytes) != "1234" || !writer.truncated {
		t.Fatalf("bounded writer: %+v n=%d err=%v", writer, n, err)
	}
}
