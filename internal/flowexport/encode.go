package flowexport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"netprobe-ir/internal/model"
)

type encoder struct {
	started       time.Time
	sequence      uint32
	templateLast  map[uint16]time.Time
	templateSends atomic.Uint64
}

func newEncoder() *encoder {
	return &encoder{started: time.Now(), templateLast: map[uint16]time.Time{}}
}

func (e *encoder) encode(c Collector, f model.Flow, now time.Time, forceTemplate bool) ([][]byte, error) {
	switch c.Protocol {
	case "netflow5":
		b, err := e.netflow5(c, f, now)
		return one(b, err)
	case "netflow9":
		return e.netflow9(c, f, now, forceTemplate)
	case "ipfix":
		return e.ipfix(c, f, now, forceTemplate)
	case "sflow":
		b, err := e.sflow(c, f, now)
		return one(b, err)
	default:
		return nil, fmt.Errorf("unsupported flow protocol %q", c.Protocol)
	}
}
func one(b []byte, err error) ([][]byte, error) {
	if err != nil {
		return nil, err
	}
	return [][]byte{b}, nil
}
func endpoints(f model.Flow) (src, dst model.Endpoint) {
	if f.Direction == model.DirectionInbound {
		return f.Remote, f.Local
	}
	return f.Local, f.Remote
}
func protoNumber(s string) uint8 {
	switch strings.ToUpper(s) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPV6":
		return 58
	}
	return 0
}
func flagsBits(s string) uint8 {
	var x uint8
	for _, p := range strings.Split(s, "|") {
		switch p {
		case "FIN":
			x |= 1
		case "SYN":
			x |= 2
		case "RST":
			x |= 4
		case "PSH":
			x |= 8
		case "ACK":
			x |= 16
		case "URG":
			x |= 32
		case "ECE":
			x |= 64
		case "CWR":
			x |= 128
		}
	}
	return x
}
func counters(f model.Flow) (pkts, octets uint64) {
	return f.PacketsTX + f.PacketsRX, f.BytesTX + f.BytesRX
}
func ifindex(f model.Flow, preferred string) uint32 {
	name := preferred
	if name == "" && len(f.Interfaces) > 0 {
		name = f.Interfaces[0]
	}
	if name == "" {
		return 0
	}
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return uint32(i.Index)
}
func directionByte(d model.Direction) uint8 {
	if d == model.DirectionInbound {
		return 1
	}
	return 0
}
func uptimeMS(start, t time.Time) uint32 {
	if t.Before(start) {
		return 0
	}
	d := t.Sub(start) / time.Millisecond
	if d > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(d)
}
func putIP4(buf *bytes.Buffer, s string) error {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return fmt.Errorf("IPv4 required: %s", s)
	}
	_, _ = buf.Write(ip)
	return nil
}
func putIP16(buf *bytes.Buffer, s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", s)
	}
	ip = ip.To16()
	if ip == nil {
		return fmt.Errorf("invalid IPv6: %s", s)
	}
	_, _ = buf.Write(ip)
	return nil
}
func writeBE(buf *bytes.Buffer, v any) { _ = binary.Write(buf, binary.BigEndian, v) }

func (e *encoder) netflow5(c Collector, f model.Flow, now time.Time) ([]byte, error) {
	src, dst := endpoints(f)
	if net.ParseIP(src.IP).To4() == nil || net.ParseIP(dst.IP).To4() == nil {
		return nil, fmt.Errorf("NetFlow v5 supports IPv4 flows only")
	}
	pkts, octets := counters(f)
	buf := new(bytes.Buffer)
	writeBE(buf, uint16(5))
	writeBE(buf, uint16(1))
	writeBE(buf, uptimeMS(e.started, now))
	writeBE(buf, uint32(now.Unix()))
	writeBE(buf, uint32(now.Nanosecond()))
	writeBE(buf, e.sequence)
	e.sequence++
	buf.WriteByte(0)
	buf.WriteByte(byte(c.ObservationDomain & 0xff))
	sampling := uint16(c.SamplingRate)
	if sampling > 0x3fff {
		sampling = 0x3fff
	}
	if sampling > 1 {
		sampling |= 1 << 14
	} // mode 1: deterministic sampling
	writeBE(buf, sampling)
	if err := putIP4(buf, src.IP); err != nil {
		return nil, err
	}
	if err := putIP4(buf, dst.IP); err != nil {
		return nil, err
	}
	writeBE(buf, uint32(0))
	idx := ifindex(f, c.SourceInterface)
	writeBE(buf, uint16(idx))
	writeBE(buf, uint16(0))
	writeBE(buf, uint32(min64(pkts, ^uint32(0))))
	writeBE(buf, uint32(min64(octets, ^uint32(0))))
	writeBE(buf, uptimeMS(e.started, f.FirstSeen))
	writeBE(buf, uptimeMS(e.started, f.LastSeen))
	writeBE(buf, src.Port)
	writeBE(buf, dst.Port)
	buf.WriteByte(0)
	buf.WriteByte(flagsBits(f.TCPFlags))
	buf.WriteByte(protoNumber(f.NetworkProtocol))
	buf.WriteByte(f.ToS)
	writeBE(buf, uint16(0))
	writeBE(buf, uint16(0))
	buf.WriteByte(0)
	buf.WriteByte(0)
	writeBE(buf, uint16(0))
	return buf.Bytes(), nil
}
func min64(v uint64, max uint32) uint64 {
	if v > uint64(max) {
		return uint64(max)
	}
	return v
}

type field struct{ typ, length uint16 }

func nfFields(ipv6 bool) []field {
	fs := []field{{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}}
	if ipv6 {
		fs = append(fs, field{27, 16})
	} else {
		fs = append(fs, field{8, 4})
	}
	fs = append(fs, field{10, 4}, field{11, 2})
	if ipv6 {
		fs = append(fs, field{28, 16})
	} else {
		fs = append(fs, field{12, 4})
	}
	return append(fs, field{14, 4}, field{21, 4}, field{22, 4}, field{32, 2}, field{58, 2}, field{61, 1}, field{34, 4})
}
func templateID(ipv6 bool) uint16 {
	if ipv6 {
		return 257
	}
	return 256
}
func (e *encoder) netflow9(c Collector, f model.Flow, now time.Time, force bool) ([][]byte, error) {
	src, dst := endpoints(f)
	ipv6 := net.ParseIP(src.IP).To4() == nil || net.ParseIP(dst.IP).To4() == nil
	tid := templateID(ipv6)
	var out [][]byte
	refresh := time.Duration(c.TemplateRefreshSeconds) * time.Second
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	if force || e.templateLast[tid].IsZero() || now.Sub(e.templateLast[tid]) >= refresh {
		out = append(out, e.nf9Template(c, tid, ipv6, now))
		e.templateLast[tid] = now
		e.templateSends.Add(1)
	}
	b, err := e.nf9Data(c, tid, ipv6, f, now)
	if err != nil {
		return nil, err
	}
	out = append(out, b)
	return out, nil
}
func (e *encoder) nf9Header(c Collector, now time.Time, count uint16) *bytes.Buffer {
	b := new(bytes.Buffer)
	writeBE(b, uint16(9))
	writeBE(b, count)
	writeBE(b, uptimeMS(e.started, now))
	writeBE(b, uint32(now.Unix()))
	writeBE(b, e.sequence)
	e.sequence++
	writeBE(b, c.ObservationDomain)
	return b
}
func (e *encoder) nf9Template(c Collector, tid uint16, ipv6 bool, now time.Time) []byte {
	b := e.nf9Header(c, now, 1)
	set := new(bytes.Buffer)
	writeBE(set, uint16(0))
	writeBE(set, uint16(0))
	writeBE(set, tid)
	fs := nfFields(ipv6)
	writeBE(set, uint16(len(fs)))
	for _, f := range fs {
		writeBE(set, f.typ)
		writeBE(set, f.length)
	}
	raw := set.Bytes()
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	b.Write(raw)
	pad4(b)
	return b.Bytes()
}
func (e *encoder) nf9Data(c Collector, tid uint16, ipv6 bool, f model.Flow, now time.Time) ([]byte, error) {
	b := e.nf9Header(c, now, 1)
	set := new(bytes.Buffer)
	writeBE(set, tid)
	writeBE(set, uint16(0))
	if err := writeFlowData(set, c, f, ipv6, false, e.started); err != nil {
		return nil, err
	}
	raw := set.Bytes()
	padBytes4(&raw)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	b.Write(raw)
	return b.Bytes(), nil
}

func ipfixFields(ipv6 bool) []field {
	fs := []field{{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 1}, {7, 2}}
	if ipv6 {
		fs = append(fs, field{27, 16})
	} else {
		fs = append(fs, field{8, 4})
	}
	fs = append(fs, field{10, 4}, field{11, 2})
	if ipv6 {
		fs = append(fs, field{28, 16})
	} else {
		fs = append(fs, field{12, 4})
	}
	icmp := uint16(32)
	if ipv6 {
		icmp = 139
	}
	return append(fs, field{14, 4}, field{152, 8}, field{153, 8}, field{icmp, 2}, field{58, 2}, field{61, 1}, field{34, 4}, field{96, 65535})
}
func ipfixTemplateID(ipv6 bool) uint16 {
	if ipv6 {
		return 301
	}
	return 300
}
func (e *encoder) ipfix(c Collector, f model.Flow, now time.Time, force bool) ([][]byte, error) {
	src, dst := endpoints(f)
	ipv6 := net.ParseIP(src.IP).To4() == nil || net.ParseIP(dst.IP).To4() == nil
	tid := ipfixTemplateID(ipv6)
	var out [][]byte
	refresh := time.Duration(c.TemplateRefreshSeconds) * time.Second
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	if force || e.templateLast[tid].IsZero() || now.Sub(e.templateLast[tid]) >= refresh {
		out = append(out, e.ipfixTemplate(c, tid, ipv6, now))
		e.templateLast[tid] = now
		e.templateSends.Add(1)
	}
	b, err := e.ipfixData(c, tid, ipv6, f, now)
	if err != nil {
		return nil, err
	}
	out = append(out, b)
	return out, nil
}
func (e *encoder) ipfixHeader(c Collector, now time.Time) *bytes.Buffer {
	b := new(bytes.Buffer)
	writeBE(b, uint16(10))
	writeBE(b, uint16(0))
	writeBE(b, uint32(now.Unix()))
	writeBE(b, e.sequence)
	writeBE(b, c.ObservationDomain)
	return b
}
func (e *encoder) finishIPFIX(b *bytes.Buffer) []byte {
	raw := b.Bytes()
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	return raw
}
func (e *encoder) ipfixTemplate(c Collector, tid uint16, ipv6 bool, now time.Time) []byte {
	b := e.ipfixHeader(c, now)
	set := new(bytes.Buffer)
	writeBE(set, uint16(2))
	writeBE(set, uint16(0))
	writeBE(set, tid)
	fs := ipfixFields(ipv6)
	writeBE(set, uint16(len(fs)))
	for _, f := range fs {
		writeBE(set, f.typ)
		writeBE(set, f.length)
	}
	raw := set.Bytes()
	padBytes4(&raw)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	b.Write(raw)
	return e.finishIPFIX(b)
}
func (e *encoder) ipfixData(c Collector, tid uint16, ipv6 bool, f model.Flow, now time.Time) ([]byte, error) {
	b := e.ipfixHeader(c, now)
	set := new(bytes.Buffer)
	writeBE(set, tid)
	writeBE(set, uint16(0))
	if err := writeFlowData(set, c, f, ipv6, true, e.started); err != nil {
		return nil, err
	}
	app := f.DPI.Application
	if app == "" {
		app = f.DPI.Protocol
	}
	writeVar(set, []byte(app))
	raw := set.Bytes()
	padBytes4(&raw)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	b.Write(raw)
	e.sequence++
	return e.finishIPFIX(b), nil
}

func writeFlowData(b *bytes.Buffer, c Collector, f model.Flow, ipv6, ipfix bool, start time.Time) error {
	src, dst := endpoints(f)
	pkts, octets := counters(f)
	writeBE(b, octets)
	writeBE(b, pkts)
	b.WriteByte(protoNumber(f.NetworkProtocol))
	b.WriteByte(f.ToS)
	b.WriteByte(flagsBits(f.TCPFlags))
	writeBE(b, src.Port)
	if ipv6 {
		if err := putIP16(b, src.IP); err != nil {
			return err
		}
	} else {
		if err := putIP4(b, src.IP); err != nil {
			return err
		}
	}
	writeBE(b, ifindex(f, c.SourceInterface))
	writeBE(b, dst.Port)
	if ipv6 {
		if err := putIP16(b, dst.IP); err != nil {
			return err
		}
	} else {
		if err := putIP4(b, dst.IP); err != nil {
			return err
		}
	}
	writeBE(b, uint32(0))
	if ipfix {
		writeBE(b, uint64(f.FirstSeen.UnixMilli()))
		writeBE(b, uint64(f.LastSeen.UnixMilli()))
	} else {
		writeBE(b, uptimeMS(start, f.LastSeen))
		writeBE(b, uptimeMS(start, f.FirstSeen))
	}
	writeBE(b, uint16(f.ICMPType)<<8|uint16(f.ICMPCode))
	writeBE(b, f.VLANID)
	b.WriteByte(directionByte(f.Direction))
	writeBE(b, uint32(c.SamplingRate))
	return nil
}
func writeVar(b *bytes.Buffer, v []byte) {
	if len(v) < 255 {
		b.WriteByte(byte(len(v)))
	} else {
		b.WriteByte(255)
		writeBE(b, uint16(len(v)))
	}
	b.Write(v)
}
func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}
func padBytes4(p *[]byte) {
	for len(*p)%4 != 0 {
		*p = append(*p, 0)
	}
}

func (e *encoder) sflowPacket(c Collector, p model.PacketSummary, now time.Time) ([]byte, error) {
	if net.ParseIP(p.Source.IP) == nil || net.ParseIP(p.Destination.IP) == nil {
		return nil, fmt.Errorf("invalid packet IP")
	}
	ipv6 := p.IPVersion == 6 || net.ParseIP(p.Source.IP).To4() == nil || net.ParseIP(p.Destination.IP).To4() == nil
	b := new(bytes.Buffer)
	writeBE(b, uint32(5))
	agent := net.ParseIP(c.AgentAddress)
	if agent == nil {
		agent = net.ParseIP("127.0.0.1")
	}
	if a4 := agent.To4(); a4 != nil {
		writeBE(b, uint32(1))
		b.Write(a4)
	} else {
		writeBE(b, uint32(2))
		b.Write(agent.To16())
	}
	writeBE(b, c.ObservationDomain)
	e.sequence++
	writeBE(b, e.sequence)
	writeBE(b, uptimeMS(e.started, now))
	writeBE(b, uint32(1))
	writeBE(b, uint32(1)) // enterprise 0, flow sample format 1
	sample := new(bytes.Buffer)
	writeBE(sample, e.sequence)
	idx := uint32(0)
	if p.Interface != "" {
		if i, err := net.InterfaceByName(p.Interface); err == nil {
			idx = uint32(i.Index)
		}
	}
	writeBE(sample, idx&0x00ffffff)
	rate := c.SamplingRate
	if rate == 0 {
		rate = 1
	}
	writeBE(sample, rate)
	// sample_pool represents the running population estimate. Sequence * sampling rate is monotonic.
	writeBE(sample, e.sequence*rate)
	writeBE(sample, uint32(0))
	writeBE(sample, idx)
	writeBE(sample, uint32(0))
	writeBE(sample, uint32(1))
	rec := new(bytes.Buffer)
	if ipv6 {
		writeBE(sample, uint32(4))
		writeBE(rec, uint32(p.Length))
		writeBE(rec, uint32(protoNumber(p.NetworkProtocol)))
		if err := putIP16(rec, p.Source.IP); err != nil {
			return nil, err
		}
		if err := putIP16(rec, p.Destination.IP); err != nil {
			return nil, err
		}
	} else {
		writeBE(sample, uint32(3))
		writeBE(rec, uint32(p.Length))
		writeBE(rec, uint32(protoNumber(p.NetworkProtocol)))
		if err := putIP4(rec, p.Source.IP); err != nil {
			return nil, err
		}
		if err := putIP4(rec, p.Destination.IP); err != nil {
			return nil, err
		}
	}
	writeBE(rec, uint32(p.Source.Port))
	writeBE(rec, uint32(p.Destination.Port))
	writeBE(rec, uint32(flagsBits(p.TCPFlags)))
	writeBE(rec, uint32(p.ToS))
	writeBE(sample, uint32(rec.Len()))
	sample.Write(rec.Bytes())
	writeBE(b, uint32(sample.Len()))
	b.Write(sample.Bytes())
	return b.Bytes(), nil
}

func (e *encoder) sflow(c Collector, f model.Flow, now time.Time) ([]byte, error) {
	src, dst := endpoints(f)
	srcIP := net.ParseIP(src.IP)
	dstIP := net.ParseIP(dst.IP)
	if srcIP == nil || dstIP == nil {
		return nil, fmt.Errorf("invalid flow IP")
	}
	ipv6 := srcIP.To4() == nil || dstIP.To4() == nil
	b := new(bytes.Buffer)
	writeBE(b, uint32(5))
	agent := net.ParseIP(c.AgentAddress)
	if agent == nil {
		agent = net.ParseIP("127.0.0.1")
	}
	if a4 := agent.To4(); a4 != nil {
		writeBE(b, uint32(1))
		b.Write(a4)
	} else {
		writeBE(b, uint32(2))
		b.Write(agent.To16())
	}
	writeBE(b, c.ObservationDomain)
	writeBE(b, e.sequence)
	e.sequence++
	writeBE(b, uptimeMS(e.started, now))
	writeBE(b, uint32(1))
	// Flow sample (enterprise=0, format=1)
	writeBE(b, uint32(1))
	sample := new(bytes.Buffer)
	writeBE(sample, e.sequence)
	writeBE(sample, uint32(ifindex(f, c.SourceInterface)&0x00ffffff))
	rate := c.SamplingRate
	if rate == 0 {
		rate = 1
	}
	writeBE(sample, rate)
	writeBE(sample, rate)
	writeBE(sample, uint32(0))
	writeBE(sample, ifindex(f, c.SourceInterface))
	writeBE(sample, uint32(0))
	writeBE(sample, uint32(1))
	rec := new(bytes.Buffer)
	if ipv6 {
		writeBE(sample, uint32(4))
		writeBE(rec, uint32(flowLength(f)))
		writeBE(rec, uint32(protoNumber(f.NetworkProtocol)))
		if err := putIP16(rec, src.IP); err != nil {
			return nil, err
		}
		if err := putIP16(rec, dst.IP); err != nil {
			return nil, err
		}
	} else {
		writeBE(sample, uint32(3))
		writeBE(rec, uint32(flowLength(f)))
		writeBE(rec, uint32(protoNumber(f.NetworkProtocol)))
		if err := putIP4(rec, src.IP); err != nil {
			return nil, err
		}
		if err := putIP4(rec, dst.IP); err != nil {
			return nil, err
		}
	}
	writeBE(rec, uint32(src.Port))
	writeBE(rec, uint32(dst.Port))
	writeBE(rec, uint32(flagsBits(f.TCPFlags)))
	writeBE(rec, uint32(f.ToS))
	writeBE(sample, uint32(rec.Len()))
	sample.Write(rec.Bytes())
	writeBE(b, uint32(sample.Len()))
	b.Write(sample.Bytes())
	return b.Bytes(), nil
}
func flowLength(f model.Flow) uint64 { _, o := counters(f); return o }
func sampled(id string, n uint32) bool {
	if n <= 1 {
		return true
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32()%n == 0
}
