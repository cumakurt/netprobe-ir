//go:build !linux

package procmap

import (
	"context"
	"netprobe-ir/internal/model"
	"time"
)

type KernelEvent struct {
	Proto, LocalIP, RemoteIP, Comm string
	LocalPort, RemotePort          uint16
	PID, UID                       int
	Time                           time.Time
}
type Tracker struct{}

func New() *Tracker                                         { return &Tracker{} }
func (t *Tracker) Run(ctx context.Context, i time.Duration) {}
func (t *Tracker) Refresh()                                 {}
func (t *Tracker) Age() time.Duration                       { return 0 }
func (t *Tracker) AddKernelEvent(e KernelEvent)             {}
func (t *Tracker) KernelEntries() int                       { return 0 }
func (t *Tracker) LookupFresh(proto, src string, sp uint16, dst string, dp uint16, dir model.Direction) (*model.ProcessInfo, string) {
	return t.Lookup(proto, src, sp, dst, dp, dir)
}
func (t *Tracker) Lookup(proto, src string, sp uint16, dst string, dp uint16, dir model.Direction) (*model.ProcessInfo, string) {
	return nil, "unsupported-platform"
}
func (t *Tracker) OwnsConnection(proto, src string, sp uint16, dst string, dp uint16, pid int) bool {
	return false
}
func (t *Tracker) IsLocalAddress(ip string) bool { return false }
