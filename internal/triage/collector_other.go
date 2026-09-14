//go:build !linux

package triage

import (
	"context"
	"fmt"
	"time"
)

func Collect(context.Context, int, uint64, string, string, string, string, time.Time) (Snapshot, error) {
	return Snapshot{}, fmt.Errorf("host triage is supported on Linux only")
}
