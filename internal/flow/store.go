package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type Store struct {
	mu    sync.RWMutex
	flows map[string]*model.Flow
	idle  time.Duration
}

func New(idle time.Duration) *Store {
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	return &Store{flows: map[string]*model.Flow{}, idle: idle}
}

func Key(p *decode.Packet, localIP string, localPort uint16, remoteIP string, remotePort uint16) string {
	s := fmt.Sprintf("%s|%s:%d|%s:%d", p.Protocol, localIP, localPort, remoteIP, remotePort)
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func (s *Store) Observe(p *decode.Packet, proc *model.ProcessInfo, attribution string, dpi model.DPIInfo, localIP string, localPort uint16, remoteIP string, remotePort uint16, dir model.Direction) (model.Flow, bool) {
	id := Key(p, localIP, localPort, remoteIP, remotePort)
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[id]
	created := false
	if f == nil {
		created = true
		f = &model.Flow{ID: id, NetworkProtocol: p.Protocol, IPVersion: p.IPVersion, Local: model.Endpoint{IP: localIP, Port: localPort}, Remote: model.Endpoint{IP: remoteIP, Port: remotePort}, Direction: dir, FirstSeen: p.Time, LastSeen: p.Time, Attribution: attribution}
		s.flows[id] = f
	}
	f.LastSeen = p.Time
	if dir != model.DirectionUnknown {
		f.Direction = dir
	}
	if !contains(f.Interfaces, p.Interface) {
		f.Interfaces = append(f.Interfaces, p.Interface)
	}
	if proc != nil {
		cp := *proc
		f.Process = &cp
		f.Attribution = attribution
	}
	if dpi.Protocol != "" {
		f.DPI = dpi
	}
	f.TCPFlags = decode.TCPFlagsString(p.TCPFlags)
	f.ToS = p.ToS
	if p.VLANID != 0 {
		f.VLANID = p.VLANID
	}
	if strings.HasPrefix(p.Protocol, "ICMP") {
		f.ICMPType = p.ICMPType
		f.ICMPCode = p.ICMPCode
	}
	n := uint64(len(p.Raw))
	if dir == model.DirectionOutbound {
		f.PacketsTX++
		f.BytesTX += n
	} else if dir == model.DirectionInbound {
		f.PacketsRX++
		f.BytesRX += n
	} else {
		f.PacketsRX++
		f.BytesRX += n
	}
	if p.Protocol == "TCP" && (p.TCPFlags&0x05) != 0 {
		t := p.Time
		f.ClosedAt = &t
	}
	return *f, created
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
func (s *Store) SetRisk(id string, score int, reasons []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.flows[id]; f != nil {
		f.Risk = score
		f.RiskReasons = append([]string(nil), reasons...)
	}
}
func (s *Store) Snapshot(limit int) []model.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Flow, 0, len(s.flows))
	for _, f := range s.flows {
		cp := *f
		cp.Interfaces = append([]string(nil), f.Interfaces...)
		cp.RiskReasons = append([]string(nil), f.RiskReasons...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func (s *Store) Get(id string) (model.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.flows[id]
	if !ok {
		return model.Flow{}, false
	}
	return *f, true
}
func (s *Store) GC(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []string
	for id, f := range s.flows {
		if now.Sub(f.LastSeen) > s.idle {
			delete(s.flows, id)
			removed = append(removed, id)
		}
	}
	return removed
}
func (s *Store) Counts() (total, active int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.flows)
	cut := time.Now().Add(-s.idle)
	for _, f := range s.flows {
		if f.LastSeen.After(cut) {
			active++
		}
	}
	return
}
func (s *Store) ProcessCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := map[int]bool{}
	for _, f := range s.flows {
		if f.Process != nil && f.Process.PID > 0 {
			m[f.Process.PID] = true
		}
	}
	return len(m)
}
