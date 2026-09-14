//go:build linux

package triage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxPersistenceArtifacts = 40
	maxPersistenceBytes     = 1 << 20
	maxDropInFiles          = 16
	maxCronFiles            = 24
	maxJournalBytes         = 1 << 20
	maxJournalEntries       = 100
)

func hashExecutable(ctx context.Context, procRoot string, pid int) (string, int64, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxExecutableBytes {
		return "", 0, fmt.Errorf("executable is unavailable or too large")
	}
	hash := sha256.New()
	buf := make([]byte, 32<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, err := f.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > maxExecutableBytes {
				return "", 0, fmt.Errorf("executable exceeded the hash size limit")
			}
			if _, writeErr := hash.Write(buf[:n]); writeErr != nil {
				return "", 0, writeErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, err
		}
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, fmt.Errorf("executable changed during hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func collectPersistence(ctx context.Context, root, cgroup string, warnings []string) ([]PersistenceArtifact, []string) {
	var paths []struct{ scope, path string }
	if unit := systemdUnit(cgroup); unit != "" {
		for _, dir := range []string{"etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"} {
			paths = append(paths, struct{ scope, path string }{"target_systemd_unit", filepath.Join(root, dir, unit)})
		}
		for _, dir := range []string{"etc/systemd/system", "run/systemd/system"} {
			files, truncated, err := listRegularNames(filepath.Join(root, dir, unit+".d"), maxDropInFiles)
			if err != nil && !os.IsNotExist(err) {
				warnings = append(warnings, "Systemd drop-in directory could not be read")
			}
			if truncated {
				warnings = append(warnings, "Systemd drop-in listing was truncated")
			}
			for _, name := range files {
				if strings.HasSuffix(name, ".conf") {
					paths = append(paths, struct{ scope, path string }{"target_systemd_dropin", filepath.Join(root, dir, unit+".d", name)})
				}
			}
		}
	}
	paths = append(paths, struct{ scope, path string }{"host_cron", filepath.Join(root, "etc/crontab")})
	cron, truncated, err := listRegularNames(filepath.Join(root, "etc/cron.d"), maxCronFiles)
	if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, "Host cron directory could not be read")
	}
	if truncated {
		warnings = append(warnings, "Host cron directory listing was truncated")
	}
	for _, name := range cron {
		paths = append(paths, struct{ scope, path string }{"host_cron", filepath.Join(root, "etc/cron.d", name)})
	}
	var artifacts []PersistenceArtifact
	for _, candidate := range paths {
		if err := ctx.Err(); err != nil {
			return artifacts, append(warnings, "Persistence scan was interrupted")
		}
		if len(artifacts) >= maxPersistenceArtifacts {
			warnings = append(warnings, "Persistence artifact limit reached")
			break
		}
		artifact, present, warning := inspectArtifact(candidate.scope, candidate.path)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if present {
			artifacts = append(artifacts, artifact)
		}
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts, warnings
}

func systemdUnit(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		part := filepath.Base(strings.TrimSpace(line))
		if !strings.HasSuffix(part, ".service") || len(part) > 255 {
			continue
		}
		valid := true
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.@:", r)) {
				valid = false
				break
			}
		}
		if valid {
			return part
		}
	}
	return ""
}

func listRegularNames(path string, limit int) ([]string, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("not a directory")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, truncated, nil
}

func inspectArtifact(scope, path string) (PersistenceArtifact, bool, string) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return PersistenceArtifact{}, false, ""
	}
	if err != nil {
		return PersistenceArtifact{}, false, "Persistence artifact metadata could not be read"
	}
	artifact := PersistenceArtifact{Scope: scope, Path: path, Mode: info.Mode().String(), Size: info.Size(), ModifiedAt: info.ModTime().UTC()}
	if info.Mode()&os.ModeSymlink != 0 {
		artifact.Kind = "symlink"
		artifact.LinkTarget, _ = os.Readlink(path)
		return artifact, true, ""
	}
	if !info.Mode().IsRegular() {
		return PersistenceArtifact{}, false, ""
	}
	artifact.Kind = "regular_file"
	if info.Size() > maxPersistenceBytes {
		return artifact, true, "Persistence artifact exceeded the hash size limit"
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return artifact, true, "Persistence artifact could not be opened without following links"
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return artifact, true, "Persistence artifact changed during collection"
	}
	hash := sha256.New()
	n, err := io.CopyN(hash, f, maxPersistenceBytes+1)
	if err != nil && err != io.EOF {
		return artifact, true, "Persistence artifact could not be hashed"
	}
	if n > maxPersistenceBytes {
		return artifact, true, "Persistence artifact exceeded the hash size limit"
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || n != after.Size() {
		return artifact, true, "Persistence artifact changed during hashing"
	}
	artifact.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return artifact, true, ""
}

type boundedWriter struct {
	bytes     []byte
	limit     int
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if remaining := w.limit - len(w.bytes); remaining > 0 {
		if len(p) > remaining {
			w.bytes = append(w.bytes, p[:remaining]...)
			w.truncated = true
		} else {
			w.bytes = append(w.bytes, p...)
		}
	} else {
		w.truncated = true
	}
	return len(p), nil
}

func collectJournal(ctx context.Context, pid int, findingTime, end time.Time, warnings []string) (*time.Time, *time.Time, []JournalEntry, []string) {
	since := end.Add(-time.Hour)
	if !findingTime.IsZero() {
		candidate := findingTime.Add(-5 * time.Minute)
		if candidate.After(since) && candidate.Before(end) {
			since = candidate
		} else if candidate.Before(since) {
			warnings = append(warnings, "Journal search was limited to the last hour")
		}
	}
	journalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(journalCtx, "/usr/bin/journalctl", "--no-pager", "--quiet", "--all", "--output=json", "--boot", "--lines=100", "--since", fmt.Sprintf("@%d", since.Unix()), "--until", fmt.Sprintf("@%d", end.Unix()), "_PID="+strconv.Itoa(pid))
	output := &boundedWriter{limit: maxJournalBytes}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return &since, &end, nil, append(warnings, "Journal metadata could not be collected")
	}
	entries, parseWarnings := parseJournal(output.bytes)
	warnings = append(warnings, parseWarnings...)
	if output.truncated {
		warnings = append(warnings, "Journal output was truncated")
	}
	return &since, &end, entries, warnings
}

func parseJournal(data []byte) ([]JournalEntry, []string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxJournalBytes)
	var entries []JournalEntry
	var warnings []string
	for scanner.Scan() {
		if len(entries) >= maxJournalEntries {
			warnings = append(warnings, "Journal entry limit reached")
			break
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &fields) != nil {
			warnings = append(warnings, "A journal entry could not be parsed")
			continue
		}
		microseconds, err := strconv.ParseInt(journalValue(fields, "__REALTIME_TIMESTAMP"), 10, 64)
		if err != nil {
			continue
		}
		message := journalValue(fields, "MESSAGE")
		entry := JournalEntry{Time: time.UnixMicro(microseconds).UTC(), BootID: truncateText(journalValue(fields, "_BOOT_ID"), 64), Unit: truncateText(journalValue(fields, "_SYSTEMD_UNIT"), 128), Identifier: truncateText(journalValue(fields, "SYSLOG_IDENTIFIER"), 128), Priority: truncateText(journalValue(fields, "PRIORITY"), 8)}
		if message != "" {
			digest := sha256.Sum256([]byte(message))
			entry.MessageBytes = len(message)
			entry.MessageSHA256 = hex.EncodeToString(digest[:])
		}
		entries = append(entries, entry)
	}
	if scanner.Err() != nil {
		warnings = append(warnings, "Journal output could not be fully parsed")
	}
	return entries, warnings
}

func journalValue(fields map[string]json.RawMessage, name string) string {
	var value string
	if json.Unmarshal(fields[name], &value) == nil {
		return value
	}
	return ""
}

func truncateText(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
