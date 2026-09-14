package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netprobe-ir/internal/model"
)

func sample(now time.Time) model.PacketSummary {
	return model.PacketSummary{Time: now, Interface: "eth0", Direction: model.DirectionInbound, NetworkProtocol: "TCP", IPVersion: 4, Source: model.Endpoint{IP: "192.0.2.1", Port: 50000}, Destination: model.Endpoint{IP: "198.51.100.1", Port: 443}, Length: 100, FlowID: "flow", TCPFlags: "SYN"}
}
func TestDirectionsFlowsAndInterfaceIsolation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(now, 2*time.Minute)
	p := sample(now)
	s.Observe(p)
	s.Observe(p) // retransmitted SYN is not a new connection
	p.Source, p.Destination = p.Destination, p.Source
	p.Direction = model.DirectionOutbound
	p.TCPFlags = "ACK"
	s.Observe(p)
	p.Interface = "eth1"
	p.Direction = model.DirectionForwarded
	p.Length = 300
	s.Observe(p)
	s.Tick(now.Add(time.Second), nil)
	global, _ := s.Snapshot("", now.Add(time.Second))
	eth0, _ := s.Snapshot("eth0", now.Add(time.Second))
	eth1, _ := s.Snapshot("eth1", now.Add(time.Second))
	if global.Totals.Bytes != 600 || global.Totals.Packets != 4 || global.Current.Bytes != [4]uint64{200, 100, 300, 0} {
		t.Fatalf("global double-counted or lost traffic: %+v", global)
	}
	if eth0.Totals.Bytes != 300 || eth1.Totals.Bytes != 300 {
		t.Fatal("interface leakage")
	}
	if global.ActiveTCP != 1 || eth0.ActiveTCP != 1 || global.Current.Connections != 1 || global.Current.Flows != 1 {
		t.Fatalf("reverse traffic/retransmits inflated flow counts: %+v", global)
	}
	if global.Groups["applications"][0].Key != "Unknown / Unclassified" {
		t.Fatal("port was treated as application evidence")
	}
	if _, ok := s.Snapshot("missing", now); ok {
		t.Fatal("unknown interface fabricated")
	}
	s.Tick(now.Add(2*time.Second), nil)
	v, _ := s.Snapshot("", now.Add(2*time.Second))
	if v.Current.Bytes != [4]uint64{} || v.Current.Flows != 0 {
		t.Fatal("idle interval retained stale rates")
	}
	s.Tick(now.Add(3*time.Minute), nil)
	v, _ = s.Snapshot("", now.Add(3*time.Minute))
	if v.Active != 0 {
		t.Fatal("idle flow remained active")
	}
}
func TestKernelRXTXResetsAndMissing(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(now, 0)
	s.Tick(now.Add(time.Second), map[string]InterfaceCounters{"eth0": {RX: Count{Bytes: 100, Packets: 10}, TX: Count{Bytes: 500, Packets: 50}}})
	v, _ := s.Snapshot("eth0", now.Add(time.Second))
	if v.Current.RX != nil {
		t.Fatal("first sample invented a rate")
	}
	s.Tick(now.Add(3*time.Second), map[string]InterfaceCounters{"eth0": {RX: Count{Bytes: 300, Packets: 20}, TX: Count{Bytes: 600, Packets: 60}}})
	v, _ = s.Snapshot("eth0", now.Add(3*time.Second))
	if v.Current.RX.Bytes != 200 || v.Current.TX.Bytes != 100 || v.Current.Seconds != 2 {
		t.Fatal("RX/TX delta or elapsed interval incorrect")
	}
	s.Tick(now.Add(4*time.Second), map[string]InterfaceCounters{"eth0": {RX: Count{Bytes: 1}, TX: Count{Bytes: 2}}})
	v, _ = s.Snapshot("eth0", now.Add(4*time.Second))
	if v.Current.RX != nil {
		t.Fatal("counter reset created spike")
	}
	s.Tick(now.Add(5*time.Second), nil)
	v, _ = s.Snapshot("eth0", now.Add(5*time.Second))
	if v.Kernel != nil || v.Current.RX != nil {
		t.Fatal("unavailable device shown as zero")
	}
}
func TestHistoryRetentionAndConservation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(now, 0)
	for i := 1; i <= 90000; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		p := sample(ts)
		p.Length = 1
		s.Observe(p)
		s.Tick(ts, nil)
	}
	if len(s.scopes[""].seconds) != 900 || len(s.scopes[""].minutes) != 1440 {
		t.Fatal("history not bounded")
	}
	for _, d := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour} {
		xs := s.History("", d, now.Add(90000*time.Second))
		if len(xs) == 0 || len(xs) > 360 {
			t.Fatalf("history size %d for %s", len(xs), d)
		}
		for _, p := range xs {
			if p.Bytes[0] != uint64(p.Seconds) {
				t.Fatal("downsampling lost bytes or duration")
			}
		}
	}
}
func TestUnknownEvidenceAndCardinality(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(now, 0)
	for i := 0; i < maxKeys+100; i++ {
		p := sample(now)
		p.Source.IP = fmt.Sprint(i)
		p.DPI = model.DPIInfo{Application: "HTTPS", Confidence: 35, Evidence: "port"}
		s.Observe(p)
	}
	v, _ := s.Snapshot("", now)
	if !v.Limited || len(s.scopes[""].groups["sources"]) > maxKeys+1 || v.Totals.Packets != maxKeys+100 {
		t.Fatal("cardinality cap lost total counters")
	}
	if v.Groups["classification"][0].Key != "Unknown / Unclassified" {
		t.Fatal("weak evidence accepted")
	}
}
func TestConcurrentReadersAndPackets(t *testing.T) {
	now := time.Now()
	s := New(now, 0)
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				s.Observe(sample(now))
				s.Snapshot("", now)
				s.History("", time.Minute, now)
			}
		}()
	}
	wg.Wait()
	v, _ := s.Snapshot("", now.Add(2*time.Second))
	if v.Totals.Packets != 4000 {
		t.Fatal("concurrent packet loss")
	}
}
func TestParseInterfaceCounters(t *testing.T) {
	input := "eth0: 100 2 3 4 0 0 0 0 500 6 7 8 0 0 0 0\nbad: x 2 3 4 0 0 0 0 5 6 7 8 0 0 0 0\n"
	xs := parseInterfaces(bufio.NewScanner(strings.NewReader(input)))
	v := xs["eth0"]
	if len(xs) != 1 || v.RX.Bytes != 100 || v.TX.Bytes != 500 || v.ErrorsRX != 3 || v.DroppedTX != 8 {
		t.Fatal(xs)
	}
}
func BenchmarkObserve10000Flows(b *testing.B) {
	now := time.Now()
	s := New(now, 0)
	packets := make([]model.PacketSummary, 10000)
	for i := range packets {
		p := sample(now)
		p.Source.Port = uint16(i)
		p.FlowID = fmt.Sprint(i)
		packets[i] = p
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Observe(packets[i%len(packets)])
	}
}
func BenchmarkSnapshot10000Flows(b *testing.B) {
	now := time.Now()
	s := New(now, 0)
	for i := 0; i < 10000; i++ {
		p := sample(now)
		p.Source.Port = uint16(i)
		s.Observe(p)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Snapshot("", now.Add(time.Duration(i+1)*time.Second))
	}
}

func TestClosedFlowRestartAndBoundedRankings(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(now, 0)
	p := sample(now)
	s.Observe(p)
	p.TCPFlags = "FIN"
	s.Observe(p)
	s.Tick(now.Add(time.Second), nil)
	v, _ := s.Snapshot("", now.Add(time.Second))
	if v.Active != 0 || len(v.Longest) != 0 {
		t.Fatal("closed flow ranked as open")
	}
	p.Time = now.Add(2 * time.Second)
	p.TCPFlags = "SYN"
	s.Observe(p)
	s.Tick(now.Add(3*time.Second), nil)
	v, _ = s.Snapshot("", now.Add(3*time.Second))
	if v.Totals.Flows != 2 || v.Active != 1 || v.Current.Connections != 1 {
		t.Fatal("reused tuple did not start a new flow")
	}
	for i := 0; i < 20000; i++ {
		p.Source.Port = uint16(i)
		p.Length = i + 1
		p.Time = now.Add(3 * time.Second)
		s.Observe(p)
	}
	v, _ = s.Snapshot("", now.Add(4*time.Second))
	if len(v.Largest) != 20 || v.Largest[0].Bytes != 20000 || len(v.Groups["tcp_ports"]) > 20 {
		t.Fatal("large flow ranking is unbounded or incorrect")
	}
	if !v.Limited || v.FlowLimited || v.Active != 20001 {
		t.Fatal("port label limit invalidated accurate flow counts")
	}
}

func TestHistoryIsDetachedFromConcurrentKernelSampling(t *testing.T) {
	now := time.Now()
	s := New(now, 0)
	s.Tick(now.Add(time.Second), map[string]InterfaceCounters{"eth0": {}})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 2; i < 1000; i++ {
			s.Tick(now.Add(time.Duration(i)*time.Millisecond+time.Second), map[string]InterfaceCounters{"eth0": {RX: Count{Bytes: uint64(i)}, TX: Count{Bytes: uint64(i)}}})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			xs := s.History("eth0", time.Hour, now.Add(3*time.Second))
			if _, err := json.Marshal(xs); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
}
