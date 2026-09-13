package dpi

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
)

type stream struct {
	init    bool
	next    uint32
	buf     []byte
	pending map[uint32][]byte
}

type flowState struct {
	tx   stream
	rx   stream
	info model.DPIInfo
}

type Engine struct {
	mu     sync.Mutex
	max    int
	states map[string]*flowState
	packs  map[string]bool
}

func New(max int) *Engine {
	if max <= 0 {
		max = 128 * 1024
	}
	return &Engine{max: max, states: map[string]*flowState{}, packs: map[string]bool{"core": true, "enterprise": true, "database": true, "devops": true, "ics": true}}
}

func (e *Engine) Forget(id string) { e.mu.Lock(); delete(e.states, id); e.mu.Unlock() }
func (e *Engine) SetProtocolPacks(packs []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.packs = map[string]bool{}
	for _, p := range packs {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			e.packs[p] = true
		}
	}
	if len(e.packs) == 0 {
		e.packs["core"] = true
	}
}
func (e *Engine) packEnabled(pack string) bool {
	if pack == "" {
		return true
	}
	return e.packs[strings.ToLower(pack)]
}
func (e *Engine) filterPack(i *model.DPIInfo) {
	if i.ProtocolPack != "" && !e.packEnabled(i.ProtocolPack) {
		*i = model.DPIInfo{}
	}
}

func (e *Engine) Inspect(flowID string, dir model.Direction, p *decode.Packet) model.DPIInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.states[flowID]
	if st == nil {
		st = &flowState{}
		e.states[flowID] = st
	}
	// Stateless/packet-level recognizers first.
	if p.Protocol == "UDP" && (p.SrcPort == 53 || p.DstPort == 53) {
		if d, ok := parseDNS(p.Payload); ok {
			st.info.Protocol = "DNS"
			st.info.Application = "DNS"
			st.info.Confidence = 100
			st.info.DNS = &d
		}
	}
	if p.Protocol == "UDP" && (p.SrcPort == 443 || p.DstPort == 443) && st.info.Protocol == "" {
		st.info.Protocol = "QUIC"
		st.info.Application = "QUIC/HTTP3"
		st.info.Confidence = 55
		st.info.Encrypted = true
		if q, ok := parseQUICHeader(p.Payload); ok {
			st.info.QUIC = &q
			st.info.Confidence = 90
		}
	}
	if p.Protocol != "TCP" || len(p.Payload) == 0 {
		if st.info.Protocol == "" {
			applyPortHint(&st.info, p)
		}
		e.filterPack(&st.info)
		return clone(st.info)
	}
	var s *stream
	if dir == model.DirectionOutbound {
		s = &st.tx
	} else {
		s = &st.rx
	}
	appendSegment(s, p.TCPSeq, p.Payload, e.max)
	b := s.buf
	if len(b) > 0 {
		h2Found := false
		if h2, ok := parseHTTP2(b); ok {
			h2Found = true
			st.info.Protocol = "HTTP/2"
			st.info.Application = "HTTP/2"
			st.info.ProtocolPack = "core"
			st.info.Confidence = 100
			st.info.HTTP2 = &h2
		}
		if d, ok := parseDNSOverTCP(b, p.SrcPort, p.DstPort); ok {
			st.info.Protocol = "DNS"
			st.info.Application = "DNS over TCP"
			st.info.Confidence = 100
			st.info.DNS = &d
		}
		if h, ok := parseHTTP(b); ok && !h2Found {
			st.info.Protocol = "HTTP"
			st.info.Application = "HTTP"
			st.info.Confidence = 100
			mergeHTTP(&st.info, h)
		}
		if t, ok := parseTLSClientHello(b); ok {
			st.info.Protocol = "TLS"
			st.info.Application = "HTTPS/TLS"
			st.info.Confidence = 100
			st.info.Encrypted = true
			if st.info.TLS != nil {
				t.ServerVersion = st.info.TLS.ServerVersion
				t.ServerCipher = st.info.TLS.ServerCipher
				t.ServerFingerprint = st.info.TLS.ServerFingerprint
				t.Certificate = st.info.TLS.Certificate
			}
			st.info.TLS = &t
		}
		if sv, cipher, fp, ok := parseTLSServerHello(b); ok {
			st.info.Protocol = "TLS"
			st.info.Application = "HTTPS/TLS"
			st.info.Confidence = 100
			st.info.Encrypted = true
			if st.info.TLS == nil {
				st.info.TLS = &model.TLSInfo{}
			}
			st.info.TLS.ServerVersion = sv
			st.info.TLS.ServerCipher = cipher
			st.info.TLS.ServerFingerprint = fp
		}
		if cert, ok := parseTLS12Certificate(b); ok {
			if st.info.TLS == nil {
				st.info.TLS = &model.TLSInfo{}
			}
			st.info.TLS.Certificate = &cert
		}
		if proto, app, pack, conf := detectProtocolPack(p, b); proto != "" && e.packEnabled(pack) && conf >= st.info.Confidence {
			st.info.Protocol = proto
			st.info.Application = app
			st.info.ProtocolPack = pack
			st.info.Confidence = conf
		}
		if bytes.HasPrefix(b, []byte("SSH-")) {
			line := string(b)
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			if len(line) > 160 {
				line = line[:160]
			}
			st.info.Protocol = "SSH"
			st.info.Application = "SSH"
			st.info.Confidence = 100
			st.info.Encrypted = true
			st.info.ProtocolPack = "core"
			st.info.SSHBanner = strings.TrimSpace(line)
		}
	}
	if st.info.Protocol == "" {
		applyPortHint(&st.info, p)
	}
	e.filterPack(&st.info)
	return clone(st.info)
}

func clone(in model.DPIInfo) model.DPIInfo { return in }

func appendSegment(s *stream, seq uint32, data []byte, max int) {
	if len(data) == 0 || len(s.buf) >= max {
		return
	}
	if !s.init {
		s.init = true
		s.next = seq
		s.pending = map[uint32][]byte{}
	}
	if seq < s.next {
		overlap := int(s.next - seq)
		if overlap >= len(data) {
			return
		}
		data = data[overlap:]
		seq = s.next
	}
	if seq > s.next {
		if len(s.pending) < 64 {
			cp := append([]byte(nil), data...)
			s.pending[seq] = cp
		}
		return
	}
	n := max - len(s.buf)
	if len(data) > n {
		data = data[:n]
	}
	s.buf = append(s.buf, data...)
	s.next += uint32(len(data))
	for {
		d, ok := s.pending[s.next]
		if !ok {
			break
		}
		delete(s.pending, s.next)
		n = max - len(s.buf)
		if n <= 0 {
			break
		}
		if len(d) > n {
			d = d[:n]
		}
		s.buf = append(s.buf, d...)
		s.next += uint32(len(d))
	}
}

func applyPortHint(i *model.DPIInfo, p *decode.Packet) {
	port := p.DstPort
	if port == 0 {
		port = p.SrcPort
	}
	set := func(proto, app, pack string, conf int, enc bool) {
		i.Protocol = proto
		i.Application = app
		i.ProtocolPack = pack
		i.Confidence = conf
		i.Encrypted = enc
	}
	switch {
	case p.SrcPort == 53 || p.DstPort == 53:
		set("DNS", "DNS", "core", 45, false)
	case p.SrcPort == 443 || p.DstPort == 443:
		set("TLS/QUIC", "HTTPS", "core", 35, true)
	case p.SrcPort == 22 || p.DstPort == 22:
		set("SSH", "SSH", "core", 40, true)
	case p.SrcPort == 80 || p.DstPort == 80:
		set("HTTP", "HTTP", "core", 40, false)
	case port == 25 || p.SrcPort == 25 || port == 587 || p.SrcPort == 587:
		set("SMTP", "SMTP", "core", 35, false)
	case port == 21 || p.SrcPort == 21:
		set("FTP", "FTP", "core", 35, false)
	case port == 445 || p.SrcPort == 445:
		set("SMB", "SMB", "enterprise", 45, false)
	case port == 88 || p.SrcPort == 88:
		set("Kerberos", "Kerberos", "enterprise", 45, false)
	case port == 389 || p.SrcPort == 389 || port == 636 || p.SrcPort == 636:
		set("LDAP", "LDAP", "enterprise", 40, port == 636 || p.SrcPort == 636)
	case port == 3389 || p.SrcPort == 3389:
		set("RDP", "RDP", "enterprise", 35, true)
	case port == 5985 || p.SrcPort == 5985 || port == 5986 || p.SrcPort == 5986:
		set("HTTP", "WinRM", "enterprise", 40, port == 5986 || p.SrcPort == 5986)
	case port == 3306 || p.SrcPort == 3306:
		set("MySQL", "MySQL", "database", 35, false)
	case port == 5432 || p.SrcPort == 5432:
		set("PostgreSQL", "PostgreSQL", "database", 35, false)
	case port == 1433 || p.SrcPort == 1433:
		set("TDS", "Microsoft SQL Server", "database", 35, false)
	case port == 6379 || p.SrcPort == 6379:
		set("RESP", "Redis", "database", 35, false)
	case port == 2375 || p.SrcPort == 2375 || port == 2376 || p.SrcPort == 2376:
		set("HTTP", "Docker API", "devops", 40, port == 2376 || p.SrcPort == 2376)
	case port == 6443 || p.SrcPort == 6443:
		set("TLS", "Kubernetes API", "devops", 40, true)
	case port == 2379 || p.SrcPort == 2379 || port == 2380 || p.SrcPort == 2380:
		set("HTTP/2", "etcd", "devops", 35, true)
	case port == 502 || p.SrcPort == 502:
		set("Modbus/TCP", "Modbus", "ics", 40, false)
	case port == 20000 || p.SrcPort == 20000:
		set("DNP3", "DNP3", "ics", 40, false)
	case port == 102 || p.SrcPort == 102:
		set("ISO-on-TCP", "Siemens S7", "ics", 40, false)
	case port == 47808 || p.SrcPort == 47808:
		set("BACnet/IP", "BACnet", "ics", 40, false)
	}
}

func detectProtocolPack(p *decode.Packet, b []byte) (proto, app, pack string, confidence int) {
	if len(b) >= 4 && (bytes.Equal(b[:4], []byte{0xff, 'S', 'M', 'B'}) || bytes.Equal(b[:4], []byte{0xfe, 'S', 'M', 'B'})) {
		return "SMB", "SMB", "enterprise", 100
	}
	if len(b) >= 8 && bytes.Equal(b[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		return "SMB2", "SMB2/3", "enterprise", 100
	}
	if len(b) >= 4 && b[0] == 3 && b[1] == 0 && (p.SrcPort == 3389 || p.DstPort == 3389) {
		return "RDP", "RDP", "enterprise", 95
	}
	if (p.SrcPort == 389 || p.DstPort == 389) && len(b) > 2 && b[0] == 0x30 {
		return "LDAP", "LDAP", "enterprise", 85
	}
	if (p.SrcPort == 88 || p.DstPort == 88) && len(b) > 2 && (b[0] == 0x6a || b[0] == 0x6b || b[0] == 0x7e) {
		return "Kerberos", "Kerberos", "enterprise", 85
	}
	up := bytes.ToUpper(bytes.TrimSpace(b))
	if bytes.HasPrefix(up, []byte("PING")) || bytes.HasPrefix(up, []byte("GET ")) || bytes.HasPrefix(up, []byte("SET ")) || bytes.HasPrefix(up, []byte("*")) && (p.SrcPort == 6379 || p.DstPort == 6379) {
		return "RESP", "Redis", "database", 90
	}
	if (p.SrcPort == 5432 || p.DstPort == 5432) && len(b) >= 8 && binary.BigEndian.Uint32(b[4:8]) == 196608 {
		return "PostgreSQL", "PostgreSQL", "database", 95
	}
	if (p.SrcPort == 3306 || p.DstPort == 3306) && len(b) > 5 && b[4] == 0x0a {
		return "MySQL", "MySQL", "database", 90
	}
	if (p.SrcPort == 502 || p.DstPort == 502) && len(b) >= 8 && binary.BigEndian.Uint16(b[2:4]) == 0 {
		return "Modbus/TCP", "Modbus", "ics", 98
	}
	if len(b) >= 2 && b[0] == 0x05 && b[1] == 0x64 {
		return "DNP3", "DNP3", "ics", 98
	}
	if (p.SrcPort == 102 || p.DstPort == 102) && len(b) >= 7 && b[0] == 3 && b[1] == 0 {
		return "ISO-on-TCP", "Siemens S7", "ics", 92
	}
	if p.Protocol == "UDP" && len(b) >= 4 && b[0] == 0x81 {
		return "BACnet/IP", "BACnet", "ics", 95
	}
	if bytes.Contains(b, []byte("/containers/")) || bytes.Contains(b, []byte("Docker-Experimental")) {
		return "HTTP", "Docker API", "devops", 90
	}
	return "", "", "", 0
}

func parseHTTP2(b []byte) (model.HTTP2Info, bool) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	pos := 0
	h := model.HTTP2Info{Settings: map[uint16]uint32{}}
	if bytes.HasPrefix(b, []byte(preface)) {
		h.PrefaceSeen = true
		pos = len(preface)
	}
	if !h.PrefaceSeen && len(b) < 9 {
		return model.HTTP2Info{}, false
	}
	seen := map[uint32]bool{}
	for pos+9 <= len(b) && h.Frames < 128 {
		ln := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
		typ, flags := b[pos+3], b[pos+4]
		streamID := binary.BigEndian.Uint32(b[pos+5:pos+9]) & 0x7fffffff
		if ln < 0 || pos+9+ln > len(b) {
			break
		}
		payload := b[pos+9 : pos+9+ln]
		h.Frames++
		h.LastType = typ
		h.LastFlags = flags
		if streamID != 0 && !seen[streamID] {
			seen[streamID] = true
			h.Streams = append(h.Streams, streamID)
		}
		if typ == 4 && streamID == 0 && flags&0x1 == 0 {
			for i := 0; i+6 <= len(payload); i += 6 {
				h.Settings[binary.BigEndian.Uint16(payload[i:i+2])] = binary.BigEndian.Uint32(payload[i+2 : i+6])
			}
		}
		pos += 9 + ln
	}
	if !h.PrefaceSeen && h.Frames == 0 {
		return model.HTTP2Info{}, false
	}
	return h, true
}

func mergeHTTP(i *model.DPIInfo, h model.HTTPInfo) {
	if i.HTTP == nil {
		i.HTTP = &h
		return
	}
	if h.Method != "" {
		i.HTTP.Method = h.Method
		i.HTTP.Path = h.Path
		i.HTTP.Host = h.Host
		i.HTTP.UserAgent = h.UserAgent
	}
	if h.Status != 0 {
		i.HTTP.Status = h.Status
	}
	if h.ContentType != "" {
		i.HTTP.ContentType = h.ContentType
	}
}

func parseHTTP(b []byte) (model.HTTPInfo, bool) {
	if len(b) < 5 {
		return model.HTTPInfo{}, false
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 || end > 32768 {
		return model.HTTPInfo{}, false
	}
	lines := strings.Split(string(b[:end]), "\r\n")
	if len(lines) == 0 {
		return model.HTTPInfo{}, false
	}
	h := model.HTTPInfo{}
	first := strings.Fields(lines[0])
	if len(first) >= 3 && strings.HasPrefix(first[2], "HTTP/") {
		h.Method = first[0]
		h.Path = first[1]
	} else if len(first) >= 2 && strings.HasPrefix(first[0], "HTTP/") {
		h.Status, _ = strconv.Atoi(first[1])
	} else {
		return model.HTTPInfo{}, false
	}
	for _, l := range lines[1:] {
		i := strings.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(l[:i]))
		v := strings.TrimSpace(l[i+1:])
		switch k {
		case "host":
			h.Host = v
		case "user-agent":
			h.UserAgent = v
		case "content-type":
			h.ContentType = v
		}
	}
	return h, true
}

func parseDNSOverTCP(b []byte, sp, dp uint16) (model.DNSInfo, bool) {
	if sp != 53 && dp != 53 {
		return model.DNSInfo{}, false
	}
	if len(b) < 2 {
		return model.DNSInfo{}, false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return model.DNSInfo{}, false
	}
	return parseDNS(b[2 : 2+n])
}
func parseDNS(b []byte) (model.DNSInfo, bool) {
	if len(b) < 12 {
		return model.DNSInfo{}, false
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	flags := binary.BigEndian.Uint16(b[2:4])
	d := model.DNSInfo{ResponseCode: uint8(flags & 0x0f)}
	pos := 12
	if qd > 0 {
		name, npos, ok := dnsName(b, pos, 0)
		if !ok || npos+4 > len(b) {
			return model.DNSInfo{}, false
		}
		d.Query = name
		d.QType = binary.BigEndian.Uint16(b[npos : npos+2])
		pos = npos + 4
		for q := 1; q < qd; q++ {
			_, npos, ok = dnsName(b, pos, 0)
			if !ok || npos+4 > len(b) {
				return d, false
			}
			pos = npos + 4
		}
	}
	for i := 0; i < an && i < 16; i++ {
		_, npos, ok := dnsName(b, pos, 0)
		if !ok || npos+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[npos : npos+2])
		rdl := int(binary.BigEndian.Uint16(b[npos+8 : npos+10]))
		rpos := npos + 10
		if rpos+rdl > len(b) {
			break
		}
		if typ == 1 && rdl == 4 {
			d.Answers = append(d.Answers, fmt.Sprintf("%d.%d.%d.%d", b[rpos], b[rpos+1], b[rpos+2], b[rpos+3]))
		} else if typ == 28 && rdl == 16 {
			d.Answers = append(d.Answers, fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", binary.BigEndian.Uint16(b[rpos:]), binary.BigEndian.Uint16(b[rpos+2:]), binary.BigEndian.Uint16(b[rpos+4:]), binary.BigEndian.Uint16(b[rpos+6:]), binary.BigEndian.Uint16(b[rpos+8:]), binary.BigEndian.Uint16(b[rpos+10:]), binary.BigEndian.Uint16(b[rpos+12:]), binary.BigEndian.Uint16(b[rpos+14:])))
		}
		pos = rpos + rdl
	}
	return d, d.Query != "" || an > 0
}
func dnsName(b []byte, pos, depth int) (string, int, bool) {
	if depth > 8 || pos >= len(b) {
		return "", pos, false
	}
	var labels []string
	orig := pos
	jumped := false
	next := pos
	for {
		if pos >= len(b) {
			return "", next, false
		}
		l := int(b[pos])
		if l == 0 {
			pos++
			if !jumped {
				next = pos
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(b) {
				return "", next, false
			}
			ptr := int(binary.BigEndian.Uint16(b[pos:pos+2]) & 0x3fff)
			n, _, ok := dnsName(b, ptr, depth+1)
			if !ok {
				return "", next, false
			}
			labels = append(labels, n)
			if !jumped {
				next = pos + 2
			}
			jumped = true
			break
		}
		pos++
		if l > 63 || pos+l > len(b) {
			return "", next, false
		}
		labels = append(labels, string(b[pos:pos+l]))
		pos += l
		if !jumped {
			next = pos
		}
	}
	_ = orig
	return strings.Join(labels, "."), next, true
}

func parseTLSClientHello(b []byte) (model.TLSInfo, bool) {
	if len(b) < 9 || b[0] != 22 || b[1] != 3 {
		return model.TLSInfo{}, false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return model.TLSInfo{}, false
	}
	if b[5] != 1 {
		return model.TLSInfo{}, false
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if hsLen+9 > len(b) {
		return model.TLSInfo{}, false
	}
	p := 9
	if p+34 > len(b) {
		return model.TLSInfo{}, false
	}
	legacy := binary.BigEndian.Uint16(b[p : p+2])
	ja3Version := legacy
	p += 34
	if p >= len(b) {
		return model.TLSInfo{}, false
	}
	sid := int(b[p])
	p++
	if p+sid+2 > len(b) {
		return model.TLSInfo{}, false
	}
	p += sid
	cLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if cLen%2 != 0 || p+cLen > len(b) {
		return model.TLSInfo{}, false
	}
	var ciphers []uint16
	for x := p; x < p+cLen; x += 2 {
		v := binary.BigEndian.Uint16(b[x : x+2])
		if !grease(v) {
			ciphers = append(ciphers, v)
		}
	}
	p += cLen
	if p >= len(b) {
		return model.TLSInfo{}, false
	}
	comp := int(b[p])
	p++
	if p+comp > len(b) {
		return model.TLSInfo{}, false
	}
	p += comp
	t := model.TLSInfo{Version: tlsVersion(legacy), CipherCount: len(ciphers)}
	var exts, groups []uint16
	var ecpf []uint8
	var supported, sigAlgs []uint16
	if p+2 <= len(b) {
		el := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		end := p + el
		if end > len(b) {
			end = len(b)
		}
		for p+4 <= end {
			typ := binary.BigEndian.Uint16(b[p : p+2])
			l := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+l > end {
				break
			}
			d := b[p : p+l]
			if !grease(typ) {
				exts = append(exts, typ)
			}
			switch typ {
			case 0:
				if len(d) >= 5 {
					n := int(binary.BigEndian.Uint16(d[3:5]))
					if 5+n <= len(d) {
						t.SNI = string(d[5 : 5+n])
					}
				}
			case 16:
				if len(d) >= 2 {
					q := 2
					for q < len(d) {
						n := int(d[q])
						q++
						if q+n > len(d) {
							break
						}
						t.ALPN = append(t.ALPN, string(d[q:q+n]))
						q += n
					}
				}
			case 10:
				if len(d) >= 2 {
					n := int(binary.BigEndian.Uint16(d[:2]))
					for q := 2; q+1 < 2+n && q+1 < len(d); q += 2 {
						v := binary.BigEndian.Uint16(d[q : q+2])
						if !grease(v) {
							groups = append(groups, v)
						}
					}
				}
			case 11:
				if len(d) >= 1 {
					n := int(d[0])
					for q := 1; q < 1+n && q < len(d); q++ {
						ecpf = append(ecpf, d[q])
					}
				}
			case 13:
				if len(d) >= 2 {
					n := int(binary.BigEndian.Uint16(d[:2]))
					for q := 2; q+1 < 2+n && q+1 < len(d); q += 2 {
						v := binary.BigEndian.Uint16(d[q : q+2])
						if !grease(v) {
							sigAlgs = append(sigAlgs, v)
						}
					}
				}
			case 43:
				if len(d) >= 1 {
					n := int(d[0])
					for q := 1; q+1 < 1+n && q+1 < len(d); q += 2 {
						supported = append(supported, binary.BigEndian.Uint16(d[q:q+2]))
					}
				}
			}
			p += l
		}
		t.ExtensionCount = len(exts)
	}
	for _, v := range supported {
		if v > legacy && !grease(v) {
			legacy = v
			t.Version = tlsVersion(v)
		}
	}
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", ja3Version, join16(ciphers), join16(exts), join16(groups), join8(ecpf))
	m := md5.Sum([]byte(ja3))
	t.JA3 = hex.EncodeToString(m[:])
	t.JA4 = ja4Fingerprint(legacy, t.SNI != "", t.ALPN, ciphers, exts, sigAlgs)
	fp := sha256.Sum256([]byte(ja3 + "|" + t.JA4 + "|" + t.SNI + "|" + strings.Join(t.ALPN, ",")))
	t.Fingerprint = hex.EncodeToString(fp[:8])
	return t, true
}
func ja4Fingerprint(version uint16, hasSNI bool, alpn []string, ciphers, exts, sigAlgs []uint16) string {
	v := "00"
	switch version {
	case 0x0301:
		v = "10"
	case 0x0302:
		v = "11"
	case 0x0303:
		v = "12"
	case 0x0304:
		v = "13"
	}
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	ap := "00"
	if len(alpn) > 0 && len(alpn[0]) > 0 {
		a := alpn[0]
		ap = string([]byte{a[0], a[len(a)-1]})
	}
	cs := append([]uint16(nil), ciphers...)
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	es := make([]uint16, 0, len(exts))
	for _, x := range exts {
		if x != 0 && x != 16 && !grease(x) {
			es = append(es, x)
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i] < es[j] })
	// JA4 preserves signature-algorithm order; only extension codes are sorted.
	ss := append([]uint16(nil), sigAlgs...)
	hexList := func(vs []uint16) string {
		a := make([]string, len(vs))
		for i, x := range vs {
			a[i] = fmt.Sprintf("%04x", x)
		}
		return strings.Join(a, ",")
	}
	h12 := func(x string) string { h := sha256.Sum256([]byte(x)); return hex.EncodeToString(h[:])[:12] }
	a := fmt.Sprintf("t%s%s%02d%02d%s", v, sni, min99(len(cs)), min99(len(exts)), ap)
	b := "000000000000"
	if len(cs) > 0 {
		b = h12(hexList(cs))
	}
	c := "000000000000"
	if len(es) > 0 {
		input := hexList(es)
		if len(ss) > 0 {
			input += "_" + hexList(ss)
		}
		c = h12(input)
	}
	return a + "_" + b + "_" + c
}

func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// parseTLS12Certificate extracts the first certificate from plaintext TLS
// handshake records. TLS 1.3 encrypts Certificate after ServerHello, so this
// intentionally does not claim visibility where session keys are unavailable.
func parseTLS12Certificate(b []byte) (model.TLSCertificateInfo, bool) {
	for rec := 0; rec+5 <= len(b); {
		if b[rec] != 22 {
			rec++
			continue
		}
		rl := int(binary.BigEndian.Uint16(b[rec+3 : rec+5]))
		end := rec + 5 + rl
		if end > len(b) {
			return model.TLSCertificateInfo{}, false
		}
		p := rec + 5
		for p+4 <= end {
			typ := b[p]
			hl := int(b[p+1])<<16 | int(b[p+2])<<8 | int(b[p+3])
			p += 4
			if p+hl > end {
				break
			}
			if typ == 11 && hl >= 6 {
				d := b[p : p+hl]
				total := int(d[0])<<16 | int(d[1])<<8 | int(d[2])
				if total+3 > len(d) || total < 3 {
					return model.TLSCertificateInfo{}, false
				}
				cl := int(d[3])<<16 | int(d[4])<<8 | int(d[5])
				if cl <= 0 || 6+cl > len(d) {
					return model.TLSCertificateInfo{}, false
				}
				der := d[6 : 6+cl]
				h := sha256.Sum256(der)
				ci := model.TLSCertificateInfo{SHA256: hex.EncodeToString(h[:])}
				if cert, err := x509.ParseCertificate(der); err == nil {
					ci.SubjectCN = cert.Subject.CommonName
					ci.IssuerCN = cert.Issuer.CommonName
					ci.Serial = cert.SerialNumber.Text(16)
					ci.NotBefore = cert.NotBefore
					ci.NotAfter = cert.NotAfter
					ci.SANs = append([]string(nil), cert.DNSNames...)
					ci.SelfSigned = cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil
					if len(cert.RawSubjectPublicKeyInfo) > 0 {
						spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
						ci.SPKISHA256 = hex.EncodeToString(spki[:])
					}
				}
				return ci, true
			}
			p += hl
		}
		rec = end
	}
	return model.TLSCertificateInfo{}, false
}

// parseTLSServerHello produces a NetProbe-owned TLS server fingerprint (NPSH),
// deliberately not branded as JA4S because JA4S has separate licensing terms.
func parseTLSServerHello(b []byte) (version, cipher, fingerprint string, ok bool) {
	if len(b) < 9 || b[0] != 22 || b[1] != 3 || b[5] != 2 {
		return "", "", "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return "", "", "", false
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if 9+hsLen > len(b) || hsLen < 38 {
		return "", "", "", false
	}
	p := 9
	legacy := binary.BigEndian.Uint16(b[p : p+2])
	p += 34
	if p >= len(b) {
		return "", "", "", false
	}
	sid := int(b[p])
	p++
	if p+sid+3 > len(b) {
		return "", "", "", false
	}
	p += sid
	cv := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	p++ // compression
	var exts []uint16
	selected := legacy
	if p+2 <= 9+hsLen {
		el := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		end := p + el
		if end > 9+hsLen {
			end = 9 + hsLen
		}
		for p+4 <= end {
			typ := binary.BigEndian.Uint16(b[p : p+2])
			l := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+l > end {
				break
			}
			if !grease(typ) {
				exts = append(exts, typ)
			}
			if typ == 43 && l >= 2 {
				selected = binary.BigEndian.Uint16(b[p : p+2])
			}
			p += l
		}
	}
	es := append([]uint16(nil), exts...)
	sort.Slice(es, func(i, j int) bool { return es[i] < es[j] })
	parts := make([]string, len(es))
	for i, x := range es {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	raw := fmt.Sprintf("%04x|%04x|%s", selected, cv, strings.Join(parts, ","))
	h := sha256.Sum256([]byte(raw))
	return tlsVersion(selected), fmt.Sprintf("%04x", cv), "npsh1_" + hex.EncodeToString(h[:])[:16], true
}

func quicVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << ((b[0] >> 6) & 0x03)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, n, true
}
func parseQUICHeader(b []byte) (model.QUICInfo, bool) {
	if len(b) < 7 || b[0]&0x80 == 0 || b[0]&0x40 == 0 {
		return model.QUICInfo{}, false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	pos := 5
	dl := int(b[pos])
	pos++
	if dl > 20 || pos+dl+1 > len(b) {
		return model.QUICInfo{}, false
	}
	dcid := b[pos : pos+dl]
	pos += dl
	sl := int(b[pos])
	pos++
	if sl > 20 || pos+sl > len(b) {
		return model.QUICInfo{}, false
	}
	scid := b[pos : pos+sl]
	pos += sl
	ptype := "long-header"
	vn := v == 0
	retry := false
	tokenLen := uint64(0)
	if vn {
		ptype = "version-negotiation"
	} else {
		switch (b[0] >> 4) & 0x03 {
		case 0:
			ptype = "initial"
			if tv, n, ok := quicVarint(b[pos:]); ok {
				tokenLen = tv
				pos += n
				if tokenLen > uint64(len(b)-pos) {
					return model.QUICInfo{}, false
				}
			}
		case 1:
			ptype = "0-rtt"
		case 2:
			ptype = "handshake"
		case 3:
			ptype = "retry"
			retry = true
		}
	}
	raw := fmt.Sprintf("%08x|%d|%d|%02x|%s", v, dl, sl, b[0]&0x30, ptype)
	h := sha256.Sum256([]byte(raw))
	return model.QUICInfo{VersionHex: fmt.Sprintf("0x%08x", v), PacketType: ptype, DCID: hex.EncodeToString(dcid), SCID: hex.EncodeToString(scid), TokenLength: tokenLen, LongHeader: true, VersionNegotiation: vn, Retry: retry, Fingerprint: "npq1_" + hex.EncodeToString(h[:])[:16]}, true
}

func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }
func join16(v []uint16) string {
	a := make([]string, len(v))
	for i, x := range v {
		a[i] = strconv.Itoa(int(x))
	}
	return strings.Join(a, "-")
}
func join8(v []uint8) string {
	a := make([]string, len(v))
	for i, x := range v {
		a[i] = strconv.Itoa(int(x))
	}
	return strings.Join(a, "-")
}
func tlsVersion(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
