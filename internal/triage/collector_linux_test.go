//go:build linux

package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectMatchesProcessSocketsAndRejectsIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "4242")
	for _, dir := range []string{filepath.Join(base, "fd"), filepath.Join(base, "net")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "4242 (worker) S 1 "+strings.Repeat("0 ", 17)+"42\n")
	write("status", "Name:\tworker\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")
	write("cgroup", "0::/system.slice/worker.service\n")
	write("loginuid", "1001\n")
	write("sessionid", "77\n")
	write("net/tcp", "header\n0: 0100007F:1F90 0200007F:0050 01 0:0 00:00000000 00000000 1000 0 123 1\n0: 0100007F:1F91 0200007F:0050 01 0:0 00:00000000 00000000 1000 0 456 1\n")
	executable := filepath.Join(root, "worker.bin")
	if err := os.WriteFile(executable, []byte("test binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[123]", filepath.Join(base, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(base, "fd", "4")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := collectAt(context.Background(), root, 4242, 42, "worker", executable, "analyst", "finding-1")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Process.PID != 4242 || snapshot.Process.StartTimeTicks != 42 || snapshot.Process.UID != 1000 {
		t.Fatalf("unexpected process: %+v", snapshot.Process)
	}
	if snapshot.Process.LoginUID == nil || *snapshot.Process.LoginUID != 1001 || snapshot.Process.SessionID == nil || *snapshot.Process.SessionID != 77 {
		t.Fatalf("unexpected audit identity: %+v", snapshot.Process)
	}
	wantHash := sha256.Sum256([]byte("test binary"))
	if snapshot.Process.ExeSHA256 != hex.EncodeToString(wantHash[:]) || snapshot.Process.ExeSize != int64(len("test binary")) {
		t.Fatalf("unexpected executable hash: %+v", snapshot.Process)
	}
	if len(snapshot.Connections) != 1 || snapshot.Connections[0].Local != "127.0.0.1:8080" || snapshot.Connections[0].SocketInode != "123" {
		t.Fatalf("unexpected connections: %+v", snapshot.Connections)
	}
	if len(snapshot.OpenFiles) != 1 || snapshot.OpenFiles[0].FD != 4 || snapshot.OpenFiles[0].Path != executable || snapshot.OpenFiles[0].Size != int64(len("test binary")) || snapshot.OpenFiles[0].Inode == "" {
		t.Fatalf("unexpected open files: %+v", snapshot.OpenFiles)
	}
	if _, err := collectAt(context.Background(), root, 4242, 42, "other", "", "analyst", "finding-1"); err == nil {
		t.Fatal("expected process identity mismatch")
	}
	if _, err := collectAt(context.Background(), root, 4242, 99, "worker", "", "analyst", "finding-1"); err == nil {
		t.Fatal("expected PID reuse rejection")
	}
}
