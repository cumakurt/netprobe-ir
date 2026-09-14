package trafficseries

import (
	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestHistoryRealDirections(t *testing.T) {
	b := eventbus.New()
	s := New(b, 100)
	defer s.Close()
	now := time.Now().UTC()
	b.Publish(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Time: now, Direction: model.DirectionInbound, Length: 100, FlowID: "a"}})
	b.Publish(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Time: now, Direction: model.DirectionOutbound, Length: 200, FlowID: "b"}})
	time.Sleep(1100 * time.Millisecond)
	xs := s.History(time.Minute, time.Now().UTC())
	if len(xs) == 0 {
		t.Fatal("no points")
	}
	var in, out, flows float64
	for _, x := range xs {
		in += x.InBytesSec
		out += x.OutBytesSec
		flows += x.FlowsSec
	}
	if in <= 0 || out <= 0 || flows <= 0 {
		t.Fatalf("bad rates %#v", xs)
	}
}
func TestRanges(t *testing.T) {
	for _, x := range []string{"1m", "5m", "15m", "1h", "24h"} {
		if _, e := ParseRange(x); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := ParseRange("2h"); e == nil {
		t.Fatal("expected error")
	}
}

func TestSensorTrafficDoesNotEnterLiveSeries(t *testing.T) {
	s := New(nil, 10)
	now := time.Now().UTC()
	s.consume(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Direction: model.DirectionOutbound, Length: 100, FlowID: "sensor", SensorTraffic: true}})
	s.consume(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Direction: model.DirectionOutbound, Length: 200, FlowID: "other"}})
	if s.current.OutBytes != 200 || s.current.OutPackets != 1 || s.current.Flows != 1 {
		t.Fatalf("unexpected visible live counters: %+v", s.current)
	}
}

func TestTwentyFourHourHistoryIsDownsampledAndBounded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := New(nil, 90000)
	// One raw point per second for a full day. The 24h API must aggregate these
	// into five-minute buckets rather than returning every raw datapoint.
	s.points = make([]Point, 0, 24*60*60)
	for i := 0; i < 24*60*60; i++ {
		s.points = append(s.points, Point{Time: now.Add(-24*time.Hour + time.Duration(i)*time.Second), InBytes: 100, OutBytes: 200, InPackets: 1, OutPackets: 2, Flows: 1, InFlows: 1})
	}
	xs := s.History(24*time.Hour, now)
	if len(xs) < 280 || len(xs) > 289 {
		t.Fatalf("expected about 288 five-minute buckets, got %d", len(xs))
	}
	// The first/last bucket can be partial because the requested window rarely
	// aligns exactly to a five-minute boundary. Interior buckets must preserve
	// the original per-second rate.
	for _, p := range xs[1 : len(xs)-1] {
		if p.InBytesSec < 99.9 || p.InBytesSec > 100.1 || p.OutBytesSec < 199.9 || p.OutBytesSec > 200.1 {
			t.Fatalf("unexpected aggregate rate: %#v", p)
		}
	}
}
