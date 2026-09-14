//go:build linux

package triage

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxProcessFileBytes = 64 << 10
	maxSocketFDs        = 512
	maxOpenFiles        = 128
	maxConnections      = 128
	maxNetEntries       = 10000
	maxAncestors        = 8
	maxExecutableBytes  = 64 << 20
)

func Collect(ctx context.Context, pid int, expectedStart uint64, expectedComm, expectedExe, actor, findingID string, findingTime time.Time) (Snapshot, error) {
	snapshot, err := collectAt(ctx, "/proc", pid, expectedStart, expectedComm, expectedExe, actor, findingID)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Persistence, snapshot.Warnings = collectPersistence(ctx, "/", snapshot.Process.Cgroup, snapshot.Warnings)
	snapshot.JournalWindowStart, snapshot.JournalWindowEnd, snapshot.Journal, snapshot.Warnings = collectJournal(ctx, pid, findingTime, snapshot.CollectedAt, snapshot.Warnings)
	current, err := readProcess("/proc", pid)
	if err != nil || current.StartTimeTicks != snapshot.Process.StartTimeTicks || current.Comm != snapshot.Process.Comm || current.Exe != snapshot.Process.Exe {
		return Snapshot{}, fmt.Errorf("target process changed during collection")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func collectAt(ctx context.Context, procRoot string, pid int, expectedStart uint64, expectedComm, expectedExe, actor, findingID string) (Snapshot, error) {
	if pid <= 1 {
		return Snapshot{}, fmt.Errorf("invalid target PID")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	process, err := readProcess(procRoot, pid)
	if err != nil {
		return Snapshot{}, fmt.Errorf("target process is unavailable: %w", err)
	}
	if expectedComm != "" && process.Comm != expectedComm {
		return Snapshot{}, fmt.Errorf("target PID no longer matches the finding process")
	}
	if expectedStart != 0 && process.StartTimeTicks != expectedStart {
		return Snapshot{}, fmt.Errorf("target PID was reused since the finding")
	}
	if expectedExe != "" && process.Exe != "" && process.Exe != expectedExe {
		return Snapshot{}, fmt.Errorf("target PID executable changed since the finding")
	}
	hostname, _ := os.Hostname()
	snapshot := Snapshot{CollectedAt: time.Now().UTC(), CollectedBy: actor, Hostname: hostname, FindingID: findingID, Process: process}
	if expectedComm == "" && expectedExe == "" {
		snapshot.Warnings = append(snapshot.Warnings, "No recorded process name or executable was available for identity comparison")
	}
	if expectedExe != "" && process.Exe == "" {
		snapshot.Warnings = append(snapshot.Warnings, "Live executable path could not be read for identity comparison")
	}
	if expectedStart == 0 {
		snapshot.Warnings = append(snapshot.Warnings, "The finding did not record process start time; matching PID, name and executable cannot fully exclude PID reuse")
	}
	if process.Exe != "" {
		sha256, size, err := hashExecutable(ctx, procRoot, pid)
		if err != nil {
			snapshot.Warnings = append(snapshot.Warnings, "Target executable could not be hashed within the collection limit")
		} else {
			snapshot.Process.ExeSHA256 = sha256
			snapshot.Process.ExeSize = size
		}
	}
	parent := process.PPID
	for len(snapshot.Ancestors) < maxAncestors && parent > 1 {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		ancestor, err := readProcess(procRoot, parent)
		if err != nil {
			snapshot.Warnings = append(snapshot.Warnings, "An ancestor process exited or could not be read")
			break
		}
		snapshot.Ancestors = append(snapshot.Ancestors, ancestor)
		if ancestor.PPID == parent {
			break
		}
		parent = ancestor.PPID
	}
	inodes, fdTruncated, err := socketInodes(procRoot, pid)
	if err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "Socket file descriptors could not be read")
	} else {
		if fdTruncated {
			snapshot.Warnings = append(snapshot.Warnings, "Socket file descriptor scan was truncated")
		}
		snapshot.Connections, snapshot.Warnings = readConnections(ctx, procRoot, pid, inodes, snapshot.Warnings)
	}
	openFiles, filesTruncated, err := collectOpenFiles(ctx, procRoot, pid)
	if err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "Open file metadata could not be read")
	} else {
		snapshot.OpenFiles = openFiles
		if filesTruncated {
			snapshot.Warnings = append(snapshot.Warnings, "Open file metadata scan was truncated")
		}
	}
	current, err := readProcess(procRoot, pid)
	if err != nil || current.StartTimeTicks != process.StartTimeTicks || current.Comm != process.Comm || current.Exe != process.Exe {
		return Snapshot{}, fmt.Errorf("target process changed during collection")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func readProcess(procRoot string, pid int) (Process, error) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	stat, err := readLimited(filepath.Join(base, "stat"))
	if err != nil {
		return Process{}, err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 || end+2 >= len(stat) {
		return Process{}, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(stat[end+2:]))
	if len(fields) <= 19 {
		return Process{}, fmt.Errorf("incomplete process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return Process{}, fmt.Errorf("invalid process start time")
	}
	status, err := readLimited(filepath.Join(base, "status"))
	if err != nil {
		return Process{}, err
	}
	process := Process{PID: pid, UID: -1, StartTimeTicks: start}
	if comm, err := readLimited(filepath.Join(base, "comm")); err == nil {
		process.Comm = strings.TrimSpace(string(comm))
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Name:":
			if process.Comm == "" {
				process.Comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
		case "PPid:":
			process.PPID, _ = strconv.Atoi(fields[1])
		case "Uid:":
			process.UID, _ = strconv.Atoi(fields[1])
		}
	}
	if process.Comm == "" {
		return Process{}, fmt.Errorf("process name is unavailable")
	}
	process.LoginUID = readAuditID(filepath.Join(base, "loginuid"))
	process.SessionID = readAuditID(filepath.Join(base, "sessionid"))
	process.Exe, _ = os.Readlink(filepath.Join(base, "exe"))
	if cgroup, err := readLimited(filepath.Join(base, "cgroup")); err == nil {
		process.Cgroup = strings.TrimSpace(string(cgroup))
	}
	return process, nil
}

func readAuditID(path string) *uint32 {
	b, err := readLimited(path)
	if err != nil {
		return nil
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || id == uint64(^uint32(0)) {
		return nil
	}
	value := uint32(id)
	return &value
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxProcessFileBytes))
}

func collectOpenFiles(ctx context.Context, procRoot string, pid int) ([]OpenFile, bool, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	dir, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxSocketFDs + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	truncated := len(entries) > maxSocketFDs
	if truncated {
		entries = entries[:maxSocketFDs]
	}
	var files []OpenFile
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdPath := filepath.Join(path, entry.Name())
		target, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		info, err := os.Stat(fdPath)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		currentTarget, err := os.Readlink(fdPath)
		if err != nil || currentTarget != target {
			continue
		}
		file := OpenFile{FD: fd, Path: truncateText(target, 1024), Size: info.Size(), Mode: info.Mode().String(), ModifiedAt: info.ModTime().UTC(), Deleted: strings.HasSuffix(target, " (deleted)")}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			file.Inode = strconv.FormatUint(stat.Ino, 10)
		}
		files = append(files, file)
		if len(files) >= maxOpenFiles {
			truncated = true
			break
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].FD < files[j].FD })
	return files, truncated, nil
}

func socketInodes(procRoot string, pid int) (map[string]bool, bool, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	dir, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxSocketFDs + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	inodes := map[string]bool{}
	truncated := len(entries) > maxSocketFDs
	if truncated {
		entries = entries[:maxSocketFDs]
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(path, entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		inodes[inode] = true
	}
	return inodes, truncated, nil
}

func readConnections(ctx context.Context, procRoot string, pid int, inodes map[string]bool, warnings []string) ([]Connection, []string) {
	if len(inodes) == 0 {
		return nil, warnings
	}
	base := filepath.Join(procRoot, strconv.Itoa(pid), "net")
	var connections []Connection
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if ctx.Err() != nil {
			return connections, append(warnings, "Connection scan was interrupted")
		}
		f, err := os.Open(filepath.Join(base, proto))
		if err != nil {
			warnings = append(warnings, proto+" socket table could not be read")
			continue
		}
		limited := &io.LimitedReader{R: f, N: 4 << 20}
		scanner := bufio.NewScanner(limited)
		line := 0
		for scanner.Scan() {
			line++
			if line%256 == 0 && ctx.Err() != nil {
				warnings = append(warnings, "Connection scan was interrupted")
				break
			}
			if line == 1 {
				continue
			}
			if line > maxNetEntries {
				warnings = append(warnings, proto+" socket table scan was truncated")
				break
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || !inodes[fields[9]] {
				continue
			}
			local, localErr := parseAddress(fields[1])
			remote, remoteErr := parseAddress(fields[2])
			if localErr != nil || remoteErr != nil {
				continue
			}
			connections = append(connections, Connection{Protocol: strings.ToUpper(proto), Local: local, Remote: remote, State: socketState(proto, fields[3]), SocketInode: fields[9]})
			if len(connections) >= maxConnections {
				warnings = append(warnings, "Connection list was truncated")
				break
			}
		}
		if scanner.Err() != nil {
			warnings = append(warnings, proto+" socket table scan failed")
		}
		if limited.N == 0 {
			warnings = append(warnings, proto+" socket table byte limit reached")
		}
		f.Close()
		if len(connections) >= maxConnections {
			break
		}
	}
	sort.Slice(connections, func(i, j int) bool {
		if connections[i].Protocol != connections[j].Protocol {
			return connections[i].Protocol < connections[j].Protocol
		}
		return connections[i].SocketInode < connections[j].SocketInode
	})
	matched := map[string]bool{}
	for _, connection := range connections {
		matched[connection.SocketInode] = true
	}
	if len(matched) < len(inodes) {
		warnings = append(warnings, "Some socket descriptors were not present in the TCP/UDP tables")
	}
	return connections, warnings
}

func socketState(protocol, state string) string {
	if strings.HasPrefix(protocol, "udp") {
		if state == "07" {
			return "UNCONNECTED"
		}
		return state
	}
	switch state {
	case "01":
		return "ESTABLISHED"
	case "06":
		return "TIME_WAIT"
	case "08":
		return "CLOSE_WAIT"
	case "0A":
		return "LISTEN"
	default:
		return state
	}
}

func parseAddress(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid socket address")
	}
	ip, err := hex.DecodeString(parts[0])
	if err != nil || len(ip) != 4 && len(ip) != 16 {
		return "", fmt.Errorf("invalid socket IP")
	}
	for i := 0; i < len(ip); i += 4 {
		ip[i], ip[i+3] = ip[i+3], ip[i]
		ip[i+1], ip[i+2] = ip[i+2], ip[i+1]
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", fmt.Errorf("invalid socket port")
	}
	return net.JoinHostPort(net.IP(ip).String(), strconv.FormatUint(port, 10)), nil
}
