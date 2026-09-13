//go:build linux

package procmap

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/model"
)

type socketEntry struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Inode      string
}

type KernelEvent struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	PID        int
	UID        int
	Comm       string
	Time       time.Time
}

type kernelEntry struct {
	Process model.ProcessInfo
	Time    time.Time
}

type Tracker struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	exact       map[string]model.ProcessInfo
	local       map[string]model.ProcessInfo
	localIPs    map[string]bool
	kernelExact map[string]kernelEntry
	lastRefresh time.Time
	errors      uint64
}

func New() *Tracker {
	return &Tracker{exact: map[string]model.ProcessInfo{}, local: map[string]model.ProcessInfo{}, localIPs: localAddresses(), kernelExact: map[string]kernelEntry{}}
}

func localAddresses() map[string]bool {
	m := map[string]bool{"127.0.0.1": true, "::1": true}
	ifs, _ := net.Interfaces()
	for _, ni := range ifs {
		as, _ := ni.Addrs()
		for _, a := range as {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil {
				m[ip.String()] = true
			}
		}
	}
	return m
}

func (t *Tracker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t.Refresh()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Refresh()
		}
	}
}

func (t *Tracker) Age() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.lastRefresh.IsZero() {
		return 0
	}
	return time.Since(t.lastRefresh)
}

func (t *Tracker) Refresh() {
	t.refreshMu.Lock()
	defer t.refreshMu.Unlock()
	entries := []socketEntry{}
	specs := []struct{ p, proto string }{{"/proc/net/tcp", "TCP"}, {"/proc/net/tcp6", "TCP"}, {"/proc/net/udp", "UDP"}, {"/proc/net/udp6", "UDP"}}
	for _, s := range specs {
		es, err := parseProcNet(s.p, s.proto)
		if err == nil {
			entries = append(entries, es...)
		}
	}
	need := map[string]bool{}
	for _, e := range entries {
		if e.Inode != "0" {
			need[e.Inode] = true
		}
	}
	inodeProc := scanProcessSockets(need)
	exact := map[string]model.ProcessInfo{}
	local := map[string]model.ProcessInfo{}
	for _, e := range entries {
		p, ok := inodeProc[e.Inode]
		if !ok {
			continue
		}
		exact[socketKey(e.Proto, e.LocalIP, e.LocalPort, e.RemoteIP, e.RemotePort)] = p
		lk := localKey(e.Proto, e.LocalIP, e.LocalPort)
		if _, exists := local[lk]; !exists {
			local[lk] = p
		}
		if e.LocalIP == "0.0.0.0" || e.LocalIP == "::" {
			local[localKey(e.Proto, "*", e.LocalPort)] = p
		}
	}
	t.mu.Lock()
	t.exact = exact
	t.local = local
	t.localIPs = localAddresses()
	t.lastRefresh = time.Now()
	t.mu.Unlock()
}

func (t *Tracker) AddKernelEvent(e KernelEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	pi := readProcess(e.PID)
	if pi.PID == 0 {
		pi.PID = e.PID
		pi.UID = e.UID
		pi.Comm = e.Comm
	}
	if pi.Comm == "" {
		pi.Comm = e.Comm
	}
	pi.Attribution = "ebpf-socket"
	t.mu.Lock()
	if len(t.kernelExact) > 32768 {
		cut := time.Now().Add(-2 * time.Minute)
		for k, v := range t.kernelExact {
			if v.Time.Before(cut) {
				delete(t.kernelExact, k)
			}
		}
	}
	t.kernelExact[socketKey(strings.ToUpper(e.Proto), e.LocalIP, e.LocalPort, e.RemoteIP, e.RemotePort)] = kernelEntry{Process: pi, Time: e.Time}
	t.mu.Unlock()
}

func (t *Tracker) KernelEntries() int { t.mu.RLock(); defer t.mu.RUnlock(); return len(t.kernelExact) }

func (t *Tracker) LookupFresh(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16, dir model.Direction) (*model.ProcessInfo, string) {
	p, attr := t.Lookup(proto, srcIP, srcPort, dstIP, dstPort, dir)
	if p != nil || attr == "forwarded" {
		return p, attr
	}
	// Short-lived sockets can appear and disappear between periodic snapshots.
	// On a miss, permit a throttled immediate refresh so the first SYN/datagram
	// has a much better chance of being attributed to its creating process.
	if t.Age() > 200*time.Millisecond {
		t.Refresh()
		return t.Lookup(proto, srcIP, srcPort, dstIP, dstPort, dir)
	}
	return p, attr
}

func (t *Tracker) Lookup(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16, dir model.Direction) (*model.ProcessInfo, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	srcLocal := t.localIPs[srcIP]
	dstLocal := t.localIPs[dstIP]
	proto = strings.ToUpper(proto)
	if ke, ok := t.kernelExact[socketKey(proto, srcIP, srcPort, dstIP, dstPort)]; ok && time.Since(ke.Time) < 10*time.Minute {
		cp := ke.Process
		cp.Attribution = "ebpf-socket"
		return &cp, "ebpf-socket"
	}
	if ke, ok := t.kernelExact[socketKey(proto, dstIP, dstPort, srcIP, srcPort)]; ok && time.Since(ke.Time) < 10*time.Minute {
		cp := ke.Process
		cp.Attribution = "ebpf-socket"
		return &cp, "ebpf-socket"
	}
	if !srcLocal && !dstLocal {
		return nil, "forwarded"
	}
	candidates := [][4]any{}
	if dir == model.DirectionOutbound || (srcLocal && !dstLocal) {
		candidates = append(candidates, [4]any{srcIP, srcPort, dstIP, dstPort})
	}
	if dir == model.DirectionInbound || (dstLocal && !srcLocal) {
		candidates = append(candidates, [4]any{dstIP, dstPort, srcIP, srcPort})
	}
	if srcLocal && dstLocal {
		candidates = append(candidates, [4]any{srcIP, srcPort, dstIP, dstPort}, [4]any{dstIP, dstPort, srcIP, srcPort})
	}
	for _, c := range candidates {
		lip := c[0].(string)
		lp := c[1].(uint16)
		rip := c[2].(string)
		rp := c[3].(uint16)
		if p, ok := t.exact[socketKey(proto, lip, lp, rip, rp)]; ok {
			cp := p
			cp.Attribution = "exact-socket"
			return &cp, "exact-socket"
		}
		if p, ok := t.local[localKey(proto, lip, lp)]; ok {
			cp := p
			cp.Attribution = "local-socket"
			return &cp, "local-socket"
		}
		if p, ok := t.local[localKey(proto, "*", lp)]; ok {
			cp := p
			cp.Attribution = "wildcard-listener"
			return &cp, "wildcard-listener"
		}
	}
	return nil, "socket-not-mapped"
}

func socketKey(proto, lip string, lp uint16, rip string, rp uint16) string {
	return fmt.Sprintf("%s|%s:%d|%s:%d", proto, lip, lp, rip, rp)
}
func localKey(proto, ip string, port uint16) string { return fmt.Sprintf("%s|%s:%d", proto, ip, port) }

func parseProcNet(path, proto string) ([]socketEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	var out []socketEntry
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		lip, lp, err := parseAddr(fs[1])
		if err != nil {
			continue
		}
		rip, rp, err := parseAddr(fs[2])
		if err != nil {
			continue
		}
		out = append(out, socketEntry{Proto: proto, LocalIP: lip, LocalPort: lp, RemoteIP: rip, RemotePort: rp, Inode: fs[9]})
	}
	return out, sc.Err()
}

func parseAddr(s string) (string, uint16, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr")
	}
	hb, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	if len(hb) == 4 {
		for i, j := 0, len(hb)-1; i < j; i, j = i+1, j-1 {
			hb[i], hb[j] = hb[j], hb[i]
		}
	} else if len(hb) == 16 {
		for i := 0; i < 16; i += 4 {
			hb[i], hb[i+3] = hb[i+3], hb[i]
			hb[i+1], hb[i+2] = hb[i+2], hb[i+1]
		}
	} else {
		return "", 0, fmt.Errorf("bad ip bytes")
	}
	pv, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	return net.IP(hb).String(), uint16(pv), nil
}

func scanProcessSockets(need map[string]bool) map[string]model.ProcessInfo {
	out := map[string]model.ProcessInfo{}
	ds, _ := os.ReadDir("/proc")
	for _, d := range ds {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var matched []string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				if need[inode] {
					matched = append(matched, inode)
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		pi := readProcess(pid)
		for _, inode := range matched {
			out[inode] = pi
		}
	}
	return out
}

func readProcess(pid int) model.ProcessInfo {
	base := fmt.Sprintf("/proc/%d", pid)
	p := model.ProcessInfo{PID: pid, UID: -1}
	if b, e := os.ReadFile(filepath.Join(base, "comm")); e == nil {
		p.Comm = strings.TrimSpace(string(b))
	}
	if e, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.Exe = e
	}
	if b, e := os.ReadFile(filepath.Join(base, "cmdline")); e == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	if b, e := os.ReadFile(filepath.Join(base, "status")); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PPid:") {
				fmt.Sscanf(l, "PPid:\t%d", &p.PPID)
			}
			if strings.HasPrefix(l, "Uid:") {
				var u int
				fmt.Sscanf(l, "Uid:\t%d", &u)
				p.UID = u
			}
		}
	}
	if p.UID >= 0 {
		if u, e := user.LookupId(strconv.Itoa(p.UID)); e == nil {
			p.User = u.Username
		}
	}
	if b, e := os.ReadFile(filepath.Join(base, "cgroup")); e == nil {
		p.Cgroup = strings.TrimSpace(string(b))
		enrichContainer(&p)
	}
	return p
}

func enrichContainer(p *model.ProcessInfo) {
	s := p.Cgroup
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ':' || r == '-' || r == '_' }) {
		if len(tok) >= 12 && len(tok) <= 64 && isHex(tok) {
			p.ContainerID = tok
			if strings.Contains(s, "docker") {
				p.ContainerRuntime = "docker"
			} else if strings.Contains(s, "containerd") {
				p.ContainerRuntime = "containerd"
			}
			break
		}
	}
	if strings.Contains(s, "kubepods") {
		if i := strings.Index(s, "pod"); i >= 0 {
			rest := s[i+3:]
			if j := strings.IndexAny(rest, "/.:"); j >= 0 {
				rest = rest[:j]
			}
			rest = strings.Trim(rest, "-_")
			if rest != "" {
				p.KubernetesPod = "uid:" + rest
			}
		}
	}
}
func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
