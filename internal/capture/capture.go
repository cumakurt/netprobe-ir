package capture

import (
	"context"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/model"
)

type Frame struct {
	Time      time.Time
	Interface string
	Direction model.Direction
	Data      []byte
}
type Stats struct {
	Packets atomic.Uint64
	Bytes   atomic.Uint64
	Errors  atomic.Uint64
	Dropped atomic.Uint64
}
type StatsView struct{ Packets, Bytes, Errors, Dropped uint64 }

func (s *Stats) View() StatsView {
	return StatsView{Packets: s.Packets.Load(), Bytes: s.Bytes.Load(), Errors: s.Errors.Load(), Dropped: s.Dropped.Load()}
}

type Source interface {
	Run(context.Context, chan<- Frame) error
	StatsView() StatsView
	Backend() string
}
