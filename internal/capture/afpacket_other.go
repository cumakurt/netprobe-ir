//go:build !linux

package capture

import (
	"context"
	"fmt"
	"netprobe-ir/internal/model"
)

type AFPacket struct {
	Interface       string
	SnapLen         int
	ReceiveBuffer   int
	DirectionFilter model.Direction
	Stats           Stats
}

func (a *AFPacket) Run(ctx context.Context, out chan<- Frame) error {
	return fmt.Errorf("AF_PACKET is Linux-only")
}

func (a *AFPacket) StatsView() StatsView { return a.Stats.View() }
func (a *AFPacket) Backend() string      { return "af_packet" }
