package pipeline

import (
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestLiveTelemetryExcludesReplayAndRetainsObservedDPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	defer e.TrafficSeries.Close()
	now := time.Now()
	frame := capture.Frame{Time: now, Interface: "capture0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")}
	e.ProcessReplayFrame(frame)
	before, _ := e.Telemetry.Snapshot("", now)
	if before.Totals.Bytes != 0 {
		t.Fatal("replay polluted live telemetry")
	}
	e.ProcessFrame(frame)
	e.Telemetry.Tick(now.Add(time.Second), nil)
	after, _ := e.Telemetry.Snapshot("capture0", now.Add(time.Second))
	if after.Totals.Bytes != uint64(len(frame.Data)) || after.Totals.Packets != 1 {
		t.Fatal("live frame not counted exactly once")
	}
	if after.Groups["applications"][0].Key != "GitHub" {
		t.Fatal("DPI metadata not propagated")
	}
}
