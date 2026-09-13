package capture

import (
	"context"
	"fmt"
	"netprobe-ir/internal/model"
	"strings"
	"sync"
)

type SourceConfig struct {
	Interface              string
	SnapLen, ReceiveBuffer int
	DirectionFilter        model.Direction
}

func NewSource(backend string, c SourceConfig) (Source, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "auto":
		return &AutoSource{cfg: c}, nil
	case "tpacket_v3", "packet_mmap":
		return &PacketMMap{Interface: c.Interface, SnapLen: c.SnapLen, ReceiveBuffer: c.ReceiveBuffer, DirectionFilter: c.DirectionFilter}, nil
	case "af_packet":
		return &AFPacket{Interface: c.Interface, SnapLen: c.SnapLen, ReceiveBuffer: c.ReceiveBuffer, DirectionFilter: c.DirectionFilter}, nil
	case "af_xdp":
		return nil, fmt.Errorf("AF_XDP passive capture is intentionally disabled: XDP_REDIRECT consumes host traffic; use tpacket_v3 for high-rate passive monitoring")
	default:
		return nil, fmt.Errorf("unknown capture backend %q", backend)
	}
}

type AutoSource struct {
	cfg      SourceConfig
	mu       sync.RWMutex
	active   Source
	fast     *PacketMMap
	slow     *AFPacket
	fallback bool
}

func (a *AutoSource) Run(ctx context.Context, out chan<- Frame) error {
	fast := &PacketMMap{Interface: a.cfg.Interface, SnapLen: a.cfg.SnapLen, ReceiveBuffer: a.cfg.ReceiveBuffer, DirectionFilter: a.cfg.DirectionFilter}
	a.mu.Lock()
	a.fast = fast
	a.active = fast
	a.mu.Unlock()
	if e := fast.Run(ctx, out); e != nil && ctx.Err() == nil {
		slow := &AFPacket{Interface: a.cfg.Interface, SnapLen: a.cfg.SnapLen, ReceiveBuffer: a.cfg.ReceiveBuffer, DirectionFilter: a.cfg.DirectionFilter}
		a.mu.Lock()
		a.slow = slow
		a.active = slow
		a.fallback = true
		a.mu.Unlock()
		return slow.Run(ctx, out)
	}
	return nil
}
func (a *AutoSource) Backend() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.active != nil {
		b := a.active.Backend()
		if a.fallback {
			return b + " (fallback)"
		}
		return b
	}
	return "auto"
}
func (a *AutoSource) StatsView() StatsView {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var v StatsView
	if a.fast != nil {
		x := a.fast.StatsView()
		v.Packets += x.Packets
		v.Bytes += x.Bytes
		v.Errors += x.Errors
		v.Dropped += x.Dropped
	}
	if a.slow != nil {
		x := a.slow.StatsView()
		v.Packets += x.Packets
		v.Bytes += x.Bytes
		v.Errors += x.Errors
		v.Dropped += x.Dropped
	}
	return v
}
