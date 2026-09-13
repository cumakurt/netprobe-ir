package flowexport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
)

func testFlow(ipv6 bool) model.Flow {
	now := time.Now().UTC()
	a, b := "192.0.2.10", "198.51.100.20"
	if ipv6 {
		a = "2001:db8::10"
		b = "2001:db8::20"
	}
	return model.Flow{ID: "flow1", NetworkProtocol: "TCP", IPVersion: map[bool]int{false: 4, true: 6}[ipv6], Local: model.Endpoint{IP: a, Port: 43210}, Remote: model.Endpoint{IP: b, Port: 443}, Direction: model.DirectionOutbound, FirstSeen: now.Add(-5 * time.Second), LastSeen: now, PacketsTX: 10, PacketsRX: 5, BytesTX: 1000, BytesRX: 2000, TCPFlags: "SYN|ACK", ToS: 0x2e, VLANID: 123, DPI: model.DPIInfo{Protocol: "TLS", Application: "HTTPS"}}
}
func baseCollector(proto string) Collector {
	return Collector{Name: "c", Enabled: true, Host: "127.0.0.1", Port: 9999, Protocol: proto, ObservationDomain: 42, ActiveTimeoutSeconds: 1, InactiveTimeoutSeconds: 1, TemplateRefreshSeconds: 1, SamplingRate: 1, QueueSize: 16, AgentAddress: "127.0.0.1"}
}

func TestProtocolEncodersIPv4IPv6(t *testing.T) {
	now := time.Now()
	e := newEncoder()
	d, err := e.encode(baseCollector("netflow5"), testFlow(false), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 1 || len(d[0]) != 72 || binary.BigEndian.Uint16(d[0][:2]) != 5 {
		t.Fatalf("netflow5 len=%d", len(d[0]))
	}
	if _, err = e.encode(baseCollector("netflow5"), testFlow(true), now, true); err == nil {
		t.Fatal("netflow5 must reject IPv6")
	}
	e = newEncoder()
	d, err = e.encode(baseCollector("netflow9"), testFlow(false), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 2 || binary.BigEndian.Uint16(d[0][:2]) != 9 || binary.BigEndian.Uint16(d[0][20:22]) != 0 || binary.BigEndian.Uint16(d[1][20:22]) != 256 {
		t.Fatal("invalid netflow9 sets")
	}
	e = newEncoder()
	d, err = e.encode(baseCollector("netflow9"), testFlow(true), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(d[1][20:22]) != 257 {
		t.Fatal("nf9 ipv6 template")
	}
	e = newEncoder()
	d, err = e.encode(baseCollector("ipfix"), testFlow(false), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 2 || binary.BigEndian.Uint16(d[0][:2]) != 10 || int(binary.BigEndian.Uint16(d[0][2:4])) != len(d[0]) || binary.BigEndian.Uint16(d[1][16:18]) != 300 {
		t.Fatal("invalid ipfix")
	}
	e = newEncoder()
	d, err = e.encode(baseCollector("ipfix"), testFlow(true), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(d[1][16:18]) != 301 {
		t.Fatal("ipfix ipv6")
	}
	e = newEncoder()
	d, err = e.encode(baseCollector("sflow"), testFlow(false), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(d[0][:4]) != 5 {
		t.Fatal("sflow version")
	}
	e = newEncoder()
	if _, err = e.encode(baseCollector("sflow"), testFlow(true), now, true); err != nil {
		t.Fatal(err)
	}
}

func listenUDP(t *testing.T) (net.PacketConn, int) {
	t.Helper()
	p, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	return p, p.LocalAddr().(*net.UDPAddr).Port
}
func readN(t *testing.T, p net.PacketConn, n int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(out) < n {
		b := make([]byte, 65535)
		k, _, e := p.ReadFrom(b)
		if e != nil {
			t.Fatalf("read %d/%d: %v", len(out), n, e)
		}
		out = append(out, append([]byte(nil), b[:k]...))
	}
	return out
}

func TestManagerMultipleCollectorsTimeoutAndPersistence(t *testing.T) {
	p1, port1 := listenUDP(t)
	defer p1.Close()
	p2, port2 := listenUDP(t)
	defer p2.Close()
	bus := eventbus.New()
	path := filepath.Join(t.TempDir(), "flows.json")
	m, err := New(path, bus)
	if err != nil {
		t.Fatal(err)
	}
	c1 := baseCollector("netflow5")
	c1.Port = port1
	c1.Name = "v5"
	if _, err = m.Upsert(c1); err != nil {
		t.Fatal(err)
	}
	c2 := baseCollector("ipfix")
	c2.Port = port2
	c2.Name = "ipfix"
	if _, err = m.Upsert(c2); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	bus.Publish(eventbus.Event{Category: "flow", Type: "flow_update", Payload: testFlow(false)})
	got1 := readN(t, p1, 1)
	if binary.BigEndian.Uint16(got1[0][:2]) != 5 {
		t.Fatal("v5 not received")
	}
	got2 := readN(t, p2, 2)
	if binary.BigEndian.Uint16(got2[0][:2]) != 10 || binary.BigEndian.Uint16(got2[1][:2]) != 10 {
		t.Fatal("ipfix not received")
	}
	stats := m.Stats()
	if len(stats) != 2 {
		t.Fatal(stats)
	}
	m2, err := New(path, eventbus.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.List()) != 2 {
		t.Fatal("collector persistence")
	}
}

func TestTemplateRefresh(t *testing.T) {
	e := newEncoder()
	c := baseCollector("ipfix")
	f := testFlow(false)
	now := time.Now()
	d, _ := e.encode(c, f, now, false)
	if len(d) != 2 {
		t.Fatal(len(d))
	}
	d, _ = e.encode(c, f, now.Add(100*time.Millisecond), false)
	if len(d) != 1 {
		t.Fatalf("unexpected template refresh %d", len(d))
	}
	d, _ = e.encode(c, f, now.Add(2*time.Second), false)
	if len(d) != 2 {
		t.Fatal("template did not refresh")
	}
}

func TestValidation(t *testing.T) {
	c := baseCollector("ipfix")
	c.Host = "bad host"
	if Validate(c) == nil {
		t.Fatal("host accepted")
	}
	c = baseCollector("bogus")
	if Validate(c) == nil {
		t.Fatal("protocol accepted")
	}
	c = baseCollector("ipfix")
	c.Port = 70000
	if Validate(c) == nil {
		t.Fatal("port accepted")
	}
}

func TestSFlowUsesPacketEventsAndSampling(t *testing.T) {
	p, port := listenUDP(t)
	defer p.Close()
	bus := eventbus.New()
	m, err := New(filepath.Join(t.TempDir(), "flows.json"), bus)
	if err != nil {
		t.Fatal(err)
	}
	c := baseCollector("sflow")
	c.Port = port
	c.SamplingRate = 1
	if _, err = m.Upsert(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	pkt := model.PacketSummary{ID: "pkt-1", Time: time.Now(), Interface: "lo", Direction: model.DirectionOutbound, NetworkProtocol: "TCP", IPVersion: 4, Source: model.Endpoint{IP: "192.0.2.1", Port: 12345}, Destination: model.Endpoint{IP: "198.51.100.1", Port: 443}, Length: 1500, TCPFlags: "SYN", ToS: 0x2e}
	bus.Publish(eventbus.Event{Category: "network", Type: "packet_metadata", PacketID: pkt.ID, Payload: pkt})
	got := readN(t, p, 1)[0]
	if binary.BigEndian.Uint32(got[:4]) != 5 {
		t.Fatal("not sFlow v5")
	}
	// A flow_update alone must not produce an sFlow packet sample.
	_ = p.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	bus.Publish(eventbus.Event{Category: "flow", Type: "flow_update", Payload: testFlow(false)})
	b := make([]byte, 2048)
	if _, _, e := p.ReadFrom(b); e == nil {
		t.Fatal("sFlow incorrectly emitted from aggregated flow")
	}
}

func TestDirectionalRecords(t *testing.T) {
	f := testFlow(false)
	r := directionalFlows(f)
	if len(r) != 2 {
		t.Fatalf("want two unidirectional records, got %d", len(r))
	}
	if r[0].Direction != model.DirectionOutbound || r[0].PacketsTX != 10 || r[0].PacketsRX != 0 {
		t.Fatalf("bad outbound: %+v", r[0])
	}
	if r[1].Direction != model.DirectionInbound || r[1].PacketsRX != 5 || r[1].PacketsTX != 0 {
		t.Fatalf("bad inbound: %+v", r[1])
	}
}

func TestFlowQueueBoundedAndUnavailableCollector(t *testing.T) {
	bus := eventbus.New()
	m, err := New(filepath.Join(t.TempDir(), "flows.json"), bus)
	if err != nil {
		t.Fatal(err)
	}
	c := baseCollector("ipfix")
	c.Host = "does-not-exist.invalid"
	c.QueueSize = 1
	c.InactiveTimeoutSeconds = 1
	if _, err = m.Upsert(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	for i := 0; i < 200; i++ {
		f := testFlow(false)
		f.ID = fmt.Sprintf("f-%d", i)
		bus.Publish(eventbus.Event{Category: "flow", Type: "flow_update", Payload: f})
	}
	time.Sleep(1800 * time.Millisecond)
	st := m.Stats()
	if len(st) != 1 {
		t.Fatal(st)
	}
	if st[0].QueueDepth > 1 {
		t.Fatalf("unbounded queue: %+v", st[0])
	}
	if st[0].DroppedExports == 0 {
		t.Fatalf("expected bounded-queue drops: %+v", st[0])
	}
	if st[0].FailedExports == 0 || st[0].Reconnects == 0 {
		t.Fatalf("expected unreachable collector failure/backoff: %+v", st[0])
	}
}

func TestIPFIXSequenceDoesNotAdvanceForTemplate(t *testing.T) {
	e := newEncoder()
	c := baseCollector("ipfix")
	f := testFlow(false)
	now := time.Now()
	d, err := e.encode(c, f, now, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 2 {
		t.Fatal(len(d))
	}
	templateSeq := binary.BigEndian.Uint32(d[0][8:12])
	dataSeq := binary.BigEndian.Uint32(d[1][8:12])
	if templateSeq != 0 || dataSeq != 0 {
		t.Fatalf("template advanced IPFIX sequence: template=%d data=%d", templateSeq, dataSeq)
	}
	d, err = e.encode(c, f, now.Add(time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	seq := binary.BigEndian.Uint32(d[len(d)-1][8:12])
	if seq != 1 {
		t.Fatalf("next data sequence=%d want 1", seq)
	}
}

func TestActiveTimeoutExportsCounterDeltas(t *testing.T) {
	now := time.Now()
	st := &flowState{flow: testFlow(false), lastExport: now.Add(-time.Second)}
	d, ok := deltaFlow(st)
	if !ok || d.PacketsTX != 10 || d.PacketsRX != 5 || d.BytesTX != 1000 || d.BytesRX != 2000 {
		t.Fatalf("first delta %+v", d)
	}
	st.exportedPacketsTX = st.flow.PacketsTX
	st.exportedPacketsRX = st.flow.PacketsRX
	st.exportedBytesTX = st.flow.BytesTX
	st.exportedBytesRX = st.flow.BytesRX
	st.flow.PacketsTX += 3
	st.flow.PacketsRX += 2
	st.flow.BytesTX += 300
	st.flow.BytesRX += 400
	st.lastExport = now
	d, ok = deltaFlow(st)
	if !ok || d.PacketsTX != 3 || d.PacketsRX != 2 || d.BytesTX != 300 || d.BytesRX != 400 {
		t.Fatalf("second delta %+v", d)
	}
	st.exportedPacketsTX = st.flow.PacketsTX
	st.exportedPacketsRX = st.flow.PacketsRX
	st.exportedBytesTX = st.flow.BytesTX
	st.exportedBytesRX = st.flow.BytesRX
	if _, ok = deltaFlow(st); ok {
		t.Fatal("unchanged counters should not be re-exported")
	}
}

func TestProtocolWireFieldsDecode(t *testing.T) {
	now := time.Now()
	f := testFlow(false)
	f.PacketsRX = 0
	f.BytesRX = 0
	e := newEncoder()
	ds, err := e.encode(baseCollector("netflow5"), f, now, true)
	if err != nil {
		t.Fatal(err)
	}
	b := ds[0]
	if len(b) != 72 {
		t.Fatal(len(b))
	}
	if net.IP(b[24:28]).String() != "192.0.2.10" || net.IP(b[28:32]).String() != "198.51.100.20" {
		t.Fatal("v5 addresses")
	}
	if binary.BigEndian.Uint32(b[40:44]) != 10 || binary.BigEndian.Uint32(b[44:48]) != 1000 {
		t.Fatal("v5 counters")
	}
	if binary.BigEndian.Uint16(b[56:58]) != 43210 || binary.BigEndian.Uint16(b[58:60]) != 443 || b[62] != 6 || b[63] != 0x2e {
		t.Fatal("v5 l4 fields")
	}

	e = newEncoder()
	ds, err = e.encode(baseCollector("ipfix"), f, now, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 {
		t.Fatal(len(ds))
	}
	b = ds[1]
	off := 20
	if binary.BigEndian.Uint64(b[off:off+8]) != 1000 || binary.BigEndian.Uint64(b[off+8:off+16]) != 10 {
		t.Fatal("ipfix counters")
	}
	off += 16
	if b[off] != 6 || b[off+1] != 0x2e {
		t.Fatal("ipfix proto/tos")
	}
	off += 3 // proto,tos,flags
	if binary.BigEndian.Uint16(b[off:off+2]) != 43210 {
		t.Fatal("ipfix src port")
	}
	off += 2
	if net.IP(b[off:off+4]).String() != "192.0.2.10" {
		t.Fatal("ipfix src")
	}
	off += 4
	off += 4 // ingress
	if binary.BigEndian.Uint16(b[off:off+2]) != 443 {
		t.Fatal("ipfix dst port")
	}
	off += 2
	if net.IP(b[off:off+4]).String() != "198.51.100.20" {
		t.Fatal("ipfix dst")
	}
	off += 4
	off += 4 + 8 + 8 + 2 // egress, start, end, icmp
	if binary.BigEndian.Uint16(b[off:off+2]) != 123 {
		t.Fatal("ipfix vlan")
	}
	off += 2
	if b[off] != 0 {
		t.Fatal("ipfix direction")
	}
	off++
	if binary.BigEndian.Uint32(b[off:off+4]) != 1 {
		t.Fatal("ipfix sampling")
	}
	off += 4
	ln := int(b[off])
	off++
	if string(b[off:off+ln]) != "HTTPS" {
		t.Fatalf("ipfix app=%q", b[off:off+ln])
	}

	e = newEncoder()
	p := model.PacketSummary{ID: "p", Time: now, Interface: "lo", Direction: model.DirectionOutbound, NetworkProtocol: "TCP", IPVersion: 4, Source: model.Endpoint{IP: "192.0.2.1", Port: 1111}, Destination: model.Endpoint{IP: "198.51.100.2", Port: 2222}, Length: 1200, TCPFlags: "SYN|ACK", ToS: 0x28}
	b, err = e.sflowPacket(baseCollector("sflow"), p, now)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b[:4]) != 5 || binary.BigEndian.Uint32(b[68:72]) != 3 {
		t.Fatal("sflow format")
	}
	if binary.BigEndian.Uint32(b[76:80]) != 1200 || binary.BigEndian.Uint32(b[80:84]) != 6 {
		t.Fatal("sflow len/proto")
	}
	if net.IP(b[84:88]).String() != "192.0.2.1" || net.IP(b[88:92]).String() != "198.51.100.2" {
		t.Fatal("sflow addresses")
	}
	if binary.BigEndian.Uint32(b[92:96]) != 1111 || binary.BigEndian.Uint32(b[96:100]) != 2222 || binary.BigEndian.Uint32(b[104:108]) != 0x28 {
		t.Fatal("sflow fields")
	}
}

func TestSFlowPacketIPv6Record(t *testing.T) {
	e := newEncoder()
	c := baseCollector("sflow")
	c.AgentAddress = "2001:db8::100"
	p := model.PacketSummary{ID: "p6", Time: time.Now(), NetworkProtocol: "UDP", IPVersion: 6, Source: model.Endpoint{IP: "2001:db8::1", Port: 5353}, Destination: model.Endpoint{IP: "2001:db8::2", Port: 53}, Length: 512, ToS: 0x40}
	b, err := e.sflowPacket(c, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b[:4]) != 5 || binary.BigEndian.Uint32(b[4:8]) != 2 {
		t.Fatal("bad IPv6 agent header")
	}
	// IPv6 agent address grows the datagram header by 12 bytes compared with IPv4.
	if binary.BigEndian.Uint32(b[80:84]) != 4 {
		t.Fatalf("sampled IPv6 record format=%d", binary.BigEndian.Uint32(b[80:84]))
	}
}
