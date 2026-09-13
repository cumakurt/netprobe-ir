package dpi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func pkt(payload []byte, sp, dp uint16, proto string) *decode.Packet {
	return &decode.Packet{Time: time.Now(), Protocol: proto, SrcPort: sp, DstPort: dp, TCPSeq: 100, Payload: payload}
}
func TestHTTP(t *testing.T) {
	e := New(65536)
	x := e.Inspect("f", model.DirectionOutbound, pkt([]byte("GET /x HTTP/1.1\r\nHost: example.test\r\nUser-Agent: test\r\n\r\n"), 4444, 80, "TCP"))
	if x.HTTP == nil || x.HTTP.Host != "example.test" || x.HTTP.Path != "/x" || x.Protocol != "HTTP" {
		t.Fatalf("bad HTTP: %+v", x)
	}
}
func TestDNS(t *testing.T) {
	q := dnsQuery("example.com")
	x := New(1024).Inspect("d", model.DirectionOutbound, pkt(q, 5555, 53, "UDP"))
	if x.DNS == nil || x.DNS.Query != "example.com" || x.DNS.QType != 1 {
		t.Fatalf("bad dns: %+v", x)
	}
}
func TestTLSClientHello(t *testing.T) {
	hello := clientHello("example.com", []string{"h2", "http/1.1"})
	x := New(65536).Inspect("t", model.DirectionOutbound, pkt(hello, 50000, 443, "TCP"))
	if x.TLS == nil {
		t.Fatalf("no tls: %+v", x)
	}
	if x.TLS.SNI != "example.com" || len(x.TLS.ALPN) != 2 || x.TLS.JA3 == "" || x.TLS.JA4 == "" || x.TLS.Fingerprint == "" {
		t.Fatalf("bad tls: %+v", x.TLS)
	}
}
func TestOutOfOrderReassembly(t *testing.T) {
	e := New(65536)
	full := []byte("GET /abc HTTP/1.1\r\nHost: reorder.test\r\n\r\n")
	a := &decode.Packet{Protocol: "TCP", SrcPort: 1, DstPort: 80, TCPSeq: 100, Payload: full[:10]}
	b := &decode.Packet{Protocol: "TCP", SrcPort: 1, DstPort: 80, TCPSeq: 120, Payload: full[20:]}
	c := &decode.Packet{Protocol: "TCP", SrcPort: 1, DstPort: 80, TCPSeq: 110, Payload: full[10:20]}
	e.Inspect("o", model.DirectionOutbound, a)
	e.Inspect("o", model.DirectionOutbound, b)
	x := e.Inspect("o", model.DirectionOutbound, c)
	if x.HTTP == nil || x.HTTP.Host != "reorder.test" {
		t.Fatalf("reassembly failed: %+v", x)
	}
}
func dnsQuery(name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 1)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, l := range split(name) {
		b = append(b, byte(len(l)))
		b = append(b, []byte(l)...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}
func split(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
func clientHello(sni string, alpns []string) []byte {
	var ex []byte
	s := []byte(sni)
	sn := make([]byte, 5+len(s))
	binary.BigEndian.PutUint16(sn[0:2], uint16(3+len(s)))
	sn[2] = 0
	binary.BigEndian.PutUint16(sn[3:5], uint16(len(s)))
	copy(sn[5:], s)
	ex = appendExt(ex, 0, sn)
	var ap []byte
	for _, a := range alpns {
		ap = append(ap, byte(len(a)))
		ap = append(ap, []byte(a)...)
	}
	ad := make([]byte, 2+len(ap))
	binary.BigEndian.PutUint16(ad[:2], uint16(len(ap)))
	copy(ad[2:], ap)
	ex = appendExt(ex, 16, ad)
	sv := []byte{2, 0x03, 0x04}
	ex = appendExt(ex, 43, sv)
	body := make([]byte, 0)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 4, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 1, 0)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(ex)))
	body = append(body, tmp...)
	body = append(body, ex...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	return append(rec, hs...)
}
func appendExt(ex []byte, t uint16, d []byte) []byte {
	x := make([]byte, 4)
	binary.BigEndian.PutUint16(x[:2], t)
	binary.BigEndian.PutUint16(x[2:4], uint16(len(d)))
	ex = append(ex, x...)
	return append(ex, d...)
}

func TestQUICLongHeaderMetadata(t *testing.T) {
	// v1 Initial-like long header with 4-byte DCID and 4-byte SCID.
	b := []byte{0xc0, 0, 0, 0, 1, 4, 0xde, 0xad, 0xbe, 0xef, 4, 1, 2, 3, 4, 0}
	x := New(4096).Inspect("q", model.DirectionOutbound, pkt(b, 55000, 443, "UDP"))
	if x.QUIC == nil || x.QUIC.VersionHex != "0x00000001" || x.QUIC.DCID != "deadbeef" || x.QUIC.Fingerprint == "" {
		t.Fatalf("bad quic: %+v", x)
	}
}

func TestTLSServerHelloFingerprint(t *testing.T) {
	sh := serverHello()
	e := New(65536)
	x := e.Inspect("s", model.DirectionInbound, pkt(sh, 443, 50000, "TCP"))
	if x.TLS == nil || x.TLS.ServerVersion != "TLS 1.3" || x.TLS.ServerCipher != "1301" || x.TLS.ServerFingerprint == "" {
		t.Fatalf("bad server hello: %+v", x.TLS)
	}
}

func serverHello() []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0x13, 0x01, 0)
	ex := appendExt(nil, 43, []byte{0x03, 0x04})
	t := make([]byte, 2)
	binary.BigEndian.PutUint16(t, uint16(len(ex)))
	body = append(body, t...)
	body = append(body, ex...)
	hs := []byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	return append(rec, hs...)
}

func TestTLS12CertificateMetadata(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "netprobe.test"}, Issuer: pkix.Name{CommonName: "NetProbe Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"netprobe.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{byte((len(der) + 3) >> 16), byte((len(der) + 3) >> 8), byte(len(der) + 3), byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	body = append(body, der...)
	hs := []byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	ci, ok := parseTLS12Certificate(rec)
	if !ok {
		t.Fatal("certificate not parsed")
	}
	if ci.SubjectCN != "netprobe.test" || ci.Serial != "2a" || ci.SHA256 == "" {
		t.Fatalf("bad cert info: %+v", ci)
	}
}

func TestJA4OfficialExample(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	exts := []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	sig := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	got := ja4Fingerprint(0x0304, true, []string{"h2"}, ciphers, exts, sig)
	want := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Fatalf("JA4 mismatch got=%s want=%s", got, want)
	}
}

func TestHTTP2H2CSettings(t *testing.T) {
	pre := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	frame := []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 100}
	x := New(65536).Inspect("h2", model.DirectionOutbound, pkt(append(pre, frame...), 51000, 8080, "TCP"))
	if x.HTTP2 == nil || !x.HTTP2.PrefaceSeen || x.HTTP2.Settings[1] != 100 || x.Application != "HTTP/2" {
		t.Fatalf("bad h2 %+v", x)
	}
}

func TestProtocolPacks(t *testing.T) {
	cases := []struct {
		name              string
		p                 []byte
		sp, dp            uint16
		proto, want, pack string
	}{
		{"smb2", append([]byte{0, 0, 0, 64}, append([]byte{0xfe, 'S', 'M', 'B'}, make([]byte, 60)...)...), 50000, 445, "TCP", "SMB2/3", "enterprise"},
		{"redis", []byte("PING\r\n"), 50000, 6379, "TCP", "Redis", "database"},
		{"postgres", []byte{0, 0, 0, 8, 0, 3, 0, 0}, 50000, 5432, "TCP", "PostgreSQL", "database"},
		{"modbus", []byte{0, 1, 0, 0, 0, 2, 1, 3}, 50000, 502, "TCP", "Modbus", "ics"},
		{"dnp3", []byte{0x05, 0x64, 5, 0, 0, 0}, 50000, 20000, "TCP", "DNP3", "ics"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(65536)
			e.SetProtocolPacks([]string{"core", "enterprise", "database", "devops", "ics"})
			x := e.Inspect(tc.name, model.DirectionOutbound, pkt(tc.p, tc.sp, tc.dp, tc.proto))
			if x.Application != tc.want || x.ProtocolPack != tc.pack {
				t.Fatalf("got app=%s pack=%s dpi=%+v", x.Application, x.ProtocolPack, x)
			}
		})
	}
}

func TestProtocolPackCanBeDisabled(t *testing.T) {
	e := New(65536)
	e.SetProtocolPacks([]string{"core"})
	x := e.Inspect("m", model.DirectionOutbound, pkt([]byte{0, 1, 0, 0, 0, 2, 1, 3}, 50000, 502, "TCP"))
	if x.ProtocolPack == "ics" || x.Application == "Modbus" {
		t.Fatalf("disabled pack detected %+v", x)
	}
}
