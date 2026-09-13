package decode

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"netprobe-ir/internal/model"
)

type Packet struct {
	Time      time.Time
	Interface string
	Direction model.Direction
	Raw       []byte
	IPVersion int
	Protocol  string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	TCPSeq    uint32
	TCPAck    uint32
	TCPFlags  uint8
	ToS       uint8
	VLANID    uint16
	ICMPType  uint8
	ICMPCode  uint8
	Payload   []byte
}

func ParseEthernet(raw []byte, ts time.Time, iface string, dir model.Direction) (*Packet, error) {
	if len(raw) < 14 {
		return nil, fmt.Errorf("short ethernet frame")
	}
	off := 14
	et := binary.BigEndian.Uint16(raw[12:14])
	p := &Packet{Time: ts, Interface: iface, Direction: dir, Raw: raw}
	for et == 0x8100 || et == 0x88a8 {
		if len(raw) < off+4 {
			return nil, fmt.Errorf("short vlan frame")
		}
		tci := binary.BigEndian.Uint16(raw[off : off+2])
		if p.VLANID == 0 {
			p.VLANID = tci & 0x0fff
		}
		et = binary.BigEndian.Uint16(raw[off+2 : off+4])
		off += 4
	}
	switch et {
	case 0x0800:
		if err := parseIPv4(raw, off, p); err != nil {
			return nil, err
		}
	case 0x86dd:
		if err := parseIPv6(raw, off, p); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported ethertype 0x%04x", et)
	}
	return p, nil
}

func parseIPv4(b []byte, off int, p *Packet) error {
	if len(b) < off+20 {
		return fmt.Errorf("short ipv4 packet")
	}
	vihl := b[off]
	if vihl>>4 != 4 {
		return fmt.Errorf("invalid ipv4 version")
	}
	ihl := int(vihl&0x0f) * 4
	if ihl < 20 || len(b) < off+ihl {
		return fmt.Errorf("invalid ipv4 ihl")
	}
	total := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	if total < ihl {
		return fmt.Errorf("invalid ipv4 length")
	}
	end := off + total
	if end > len(b) {
		end = len(b)
	}
	p.IPVersion = 4
	p.ToS = b[off+1]
	p.SrcIP = net.IP(b[off+12 : off+16]).String()
	p.DstIP = net.IP(b[off+16 : off+20]).String()
	proto := b[off+9]
	return parseTransport(b[:end], off+ihl, proto, p)
}

func parseIPv6(b []byte, off int, p *Packet) error {
	if len(b) < off+40 {
		return fmt.Errorf("short ipv6 packet")
	}
	if b[off]>>4 != 6 {
		return fmt.Errorf("invalid ipv6 version")
	}
	p.IPVersion = 6
	p.ToS = (b[off]&0x0f)<<4 | (b[off+1] >> 4)
	p.SrcIP = net.IP(b[off+8 : off+24]).String()
	p.DstIP = net.IP(b[off+24 : off+40]).String()
	next := b[off+6]
	pos := off + 40
	// Safely skip common extension headers. Fragmented non-first packets are not L4 decoded.
	for {
		switch next {
		case 0, 43, 60:
			if len(b) < pos+2 {
				return fmt.Errorf("short ipv6 extension")
			}
			n := b[pos]
			l := (int(b[pos+1]) + 1) * 8
			if len(b) < pos+l {
				return fmt.Errorf("short ipv6 extension payload")
			}
			next = n
			pos += l
		case 44:
			if len(b) < pos+8 {
				return fmt.Errorf("short ipv6 fragment")
			}
			frag := binary.BigEndian.Uint16(b[pos+2 : pos+4])
			next = b[pos]
			pos += 8
			if frag>>3 != 0 {
				p.Protocol = "IPv6-FRAG"
				p.Payload = b[pos:]
				return nil
			}
		case 51:
			if len(b) < pos+2 {
				return fmt.Errorf("short ah")
			}
			n := b[pos]
			l := (int(b[pos+1]) + 2) * 4
			if len(b) < pos+l {
				return fmt.Errorf("short ah payload")
			}
			next = n
			pos += l
		default:
			return parseTransport(b, pos, next, p)
		}
	}
}

func parseTransport(b []byte, off int, proto uint8, p *Packet) error {
	switch proto {
	case 6:
		p.Protocol = "TCP"
		if len(b) < off+20 {
			return fmt.Errorf("short tcp")
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.TCPSeq = binary.BigEndian.Uint32(b[off+4 : off+8])
		p.TCPAck = binary.BigEndian.Uint32(b[off+8 : off+12])
		hlen := int((b[off+12] >> 4) * 4)
		if hlen < 20 || len(b) < off+hlen {
			return fmt.Errorf("invalid tcp header length")
		}
		p.TCPFlags = b[off+13]
		p.Payload = b[off+hlen:]
	case 17:
		p.Protocol = "UDP"
		if len(b) < off+8 {
			return fmt.Errorf("short udp")
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.Payload = b[off+8:]
	case 1:
		p.Protocol = "ICMP"
		if len(b) >= off+2 {
			p.ICMPType = b[off]
			p.ICMPCode = b[off+1]
			p.Payload = b[off:]
		}
	case 58:
		p.Protocol = "ICMPv6"
		if len(b) >= off+2 {
			p.ICMPType = b[off]
			p.ICMPCode = b[off+1]
			p.Payload = b[off:]
		}
	default:
		p.Protocol = fmt.Sprintf("IP-%d", proto)
		if len(b) > off {
			p.Payload = b[off:]
		}
	}
	return nil
}

func TCPFlagsString(f uint8) string {
	names := []struct {
		b uint8
		s string
	}{{0x80, "CWR"}, {0x40, "ECE"}, {0x20, "URG"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x04, "RST"}, {0x02, "SYN"}, {0x01, "FIN"}}
	var out []string
	for _, n := range names {
		if f&n.b != 0 {
			out = append(out, n.s)
		}
	}
	return strings.Join(out, "|")
}
