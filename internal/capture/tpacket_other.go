//go:build !linux

package capture

import (
	"context"
	"fmt"
	"netprobe-ir/internal/model"
)

type PacketMMap struct {
	Interface              string
	SnapLen, ReceiveBuffer int
	DirectionFilter        model.Direction
	Stats                  Stats
}

func (p *PacketMMap) Run(context.Context, chan<- Frame) error {
	return fmt.Errorf("TPACKET_V3 is Linux-only")
}
func (p *PacketMMap) Backend() string      { return "tpacket_v3" }
func (p *PacketMMap) StatsView() StatsView { return p.Stats.View() }
func ProbeAFXDP() (bool, string)           { return false, "AF_XDP is Linux-only" }
