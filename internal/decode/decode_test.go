package decode

import (
	"encoding/binary"
	"net"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestParseIPv4TCP(t *testing.T) {
	p, err := ParseEthernet(testIPv4TCP([]byte("hello")), time.Now(), "eth0", model.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if p.SrcIP != "10.0.0.1" || p.DstIP != "10.0.0.2" || p.SrcPort != 12345 || p.DstPort != 443 || p.Protocol != "TCP" || string(p.Payload) != "hello" {
		t.Fatalf("unexpected packet: %+v", p)
	}
}
func TestParseVLAN(t *testing.T) {
	raw := testIPv4TCP([]byte("x"))
	v := make([]byte, len(raw)+4)
	copy(v[:12], raw[:12])
	binary.BigEndian.PutUint16(v[12:14], 0x8100)
	binary.BigEndian.PutUint16(v[14:16], 100)
	copy(v[16:], raw[12:])
	p, err := ParseEthernet(v, time.Now(), "eth0", model.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if p.DstPort != 443 {
		t.Fatal("vlan offset failed")
	}
}
func TestIPv6UDP(t *testing.T) {
	b := make([]byte, 14+40+8+3)
	binary.BigEndian.PutUint16(b[12:14], 0x86dd)
	o := 14
	b[o] = 0x60
	binary.BigEndian.PutUint16(b[o+4:o+6], 11)
	b[o+6] = 17
	b[o+7] = 64
	copy(b[o+8:o+24], []byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(b[o+24:o+40], []byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	u := o + 40
	binary.BigEndian.PutUint16(b[u:u+2], 5353)
	binary.BigEndian.PutUint16(b[u+2:u+4], 53)
	binary.BigEndian.PutUint16(b[u+4:u+6], 11)
	copy(b[u+8:], []byte{1, 2, 3})
	p, err := ParseEthernet(b, time.Now(), "eth0", model.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if p.IPVersion != 6 || p.Protocol != "UDP" || p.DstPort != 53 || len(p.Payload) != 3 {
		t.Fatalf("unexpected: %+v", p)
	}
}
func TestRejectShort(t *testing.T) {
	if _, e := ParseEthernet([]byte{1, 2}, time.Now(), "x", model.DirectionUnknown); e == nil {
		t.Fatal("expected error")
	}
}
func testIPv4TCP(payload []byte) []byte {
	ipLen := 20 + 20 + len(payload)
	b := make([]byte, 14+ipLen)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	o := 14
	b[o] = 0x45
	binary.BigEndian.PutUint16(b[o+2:o+4], uint16(ipLen))
	b[o+8] = 64
	b[o+9] = 6
	copy(b[o+12:o+16], []byte{10, 0, 0, 1})
	copy(b[o+16:o+20], []byte{10, 0, 0, 2})
	q := o + 20
	binary.BigEndian.PutUint16(b[q:q+2], 12345)
	binary.BigEndian.PutUint16(b[q+2:q+4], 443)
	binary.BigEndian.PutUint32(b[q+4:q+8], 7)
	b[q+12] = 0x50
	b[q+13] = 0x18
	copy(b[q+20:], payload)
	return b
}

func TestParseTrafficClassVLANAndICMP(t *testing.T) {
	// IPv4 ICMP echo with DSCP/ECN byte 0xb8 and VLAN 321.
	b := make([]byte, 14+4+20+8)
	binary.BigEndian.PutUint16(b[12:14], 0x8100)
	binary.BigEndian.PutUint16(b[14:16], 321)
	binary.BigEndian.PutUint16(b[16:18], 0x0800)
	o := 18
	b[o] = 0x45
	b[o+1] = 0xb8
	binary.BigEndian.PutUint16(b[o+2:o+4], 28)
	b[o+8] = 64
	b[o+9] = 1
	copy(b[o+12:o+16], []byte{192, 0, 2, 1})
	copy(b[o+16:o+20], []byte{198, 51, 100, 2})
	b[o+20] = 8
	b[o+21] = 0
	p, err := ParseEthernet(b, time.Now(), "eth0", model.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if p.ToS != 0xb8 || p.VLANID != 321 || p.Protocol != "ICMP" || p.ICMPType != 8 || p.ICMPCode != 0 {
		t.Fatalf("metadata mismatch: %+v", p)
	}
}

func TestIPv6TrafficClass(t *testing.T) {
	b := make([]byte, 14+40+8)
	binary.BigEndian.PutUint16(b[12:14], 0x86dd)
	o := 14
	// Version 6 + traffic class 0xab.
	b[o] = 0x6a
	b[o+1] = 0xb0
	binary.BigEndian.PutUint16(b[o+4:o+6], 8)
	b[o+6] = 58
	b[o+7] = 64
	copy(b[o+8:o+24], net.ParseIP("2001:db8::1").To16())
	copy(b[o+24:o+40], net.ParseIP("2001:db8::2").To16())
	b[o+40] = 128
	b[o+41] = 0
	p, err := ParseEthernet(b, time.Now(), "eth0", model.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if p.ToS != 0xab || p.Protocol != "ICMPv6" || p.ICMPType != 128 {
		t.Fatalf("unexpected: %+v", p)
	}
}
