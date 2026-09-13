package dpi

import (
	"encoding/binary"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/model"
	"testing"
)

func dnsMessage(response bool) []byte {
	b := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if response {
		b[2] = 0x81
		b[3] = 0x83
	}
	return b
}
func TestDNSObservationsAreMessagesNotCachedPackets(t *testing.T) {
	e := New(4096)
	p := &decode.Packet{Protocol: "UDP", SrcPort: 1234, DstPort: 53, Payload: dnsMessage(false)}
	_, obs := e.InspectObserved("dns", model.DirectionOutbound, p)
	if len(obs) != 1 || obs[0].DNS.TransactionID != 0x1234 || obs[0].DNS.IsResponse {
		t.Fatalf("query: %+v", obs)
	}
	p.Payload = nil
	_, obs = e.InspectObserved("dns", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("cached query emitted on empty packet")
	}
	p.Payload = dnsMessage(true)
	_, obs = e.InspectObserved("dns", model.DirectionInbound, p)
	if len(obs) != 1 || !obs[0].DNS.IsResponse || obs[0].DNS.ResponseCode != 3 {
		t.Fatal("response metadata missing")
	}
}
func TestTCPDNSFramingAndRetransmission(t *testing.T) {
	e := New(4096)
	msg := dnsMessage(false)
	framed := make([]byte, 2)
	binary.BigEndian.PutUint16(framed, uint16(len(msg)))
	framed = append(framed, msg...)
	all := append(append([]byte{}, framed...), framed...)
	p := &decode.Packet{Protocol: "TCP", SrcIP: "10.0.0.1", SrcPort: 1234, DstPort: 53, TCPSeq: 100, Payload: all[:10]}
	_, obs := e.InspectObserved("dns", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("partial DNS emitted")
	}
	p.TCPSeq = 110
	p.Payload = all[10:]
	_, obs = e.InspectObserved("dns", model.DirectionOutbound, p)
	if len(obs) != 2 {
		t.Fatalf("want two messages, got %d", len(obs))
	}
	_, obs = e.InspectObserved("dns", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("retransmission duplicated DNS")
	}
}
func TestHTTPKeepAliveBodiesSegmentationAndRetransmission(t *testing.T) {
	e := New(4096)
	request := "POST /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbodyGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
	p := &decode.Packet{Protocol: "TCP", SrcIP: "10.0.0.1", SrcPort: 1234, DstPort: 80, TCPSeq: 100, Payload: []byte(request[:20])}
	_, obs := e.InspectObserved("http", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("partial HTTP emitted")
	}
	p.TCPSeq += 20
	p.Payload = []byte(request[20:])
	_, obs = e.InspectObserved("http", model.DirectionOutbound, p)
	if len(obs) != 2 || obs[0].HTTP.Path != "/first" || obs[1].HTTP.Path != "/second" {
		t.Fatalf("requests: %+v", obs)
	}
	_, obs = e.InspectObserved("http", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("retransmission duplicated HTTP")
	}
	p.TCPSeq += uint32(len(p.Payload))
	p.Payload = []byte("GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, obs = e.InspectObserved("http", model.DirectionOutbound, p)
	if len(obs) != 1 {
		t.Fatal("identical new request must be retained")
	}
}

func TestTLSObservationAfterFragmentedHello(t *testing.T) {
	e := New(65536)
	hello := clientHello("example.com", []string{"h2", "http/1.1"})
	p := pkt(hello[:12], 50000, 443, "TCP")
	_, obs := e.InspectObserved("tls", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("partial hello emitted")
	}
	p.TCPSeq += 12
	p.Payload = hello[12:]
	_, obs = e.InspectObserved("tls", model.DirectionOutbound, p)
	if len(obs) != 1 || obs[0].TLS == nil || obs[0].TLS.SNI != "example.com" {
		t.Fatalf("TLS observation missing: %+v", obs)
	}
	p.TCPSeq += uint32(len(p.Payload))
	p.Payload = nil
	_, obs = e.InspectObserved("tls", model.DirectionOutbound, p)
	if len(obs) != 0 {
		t.Fatal("TLS repeated on ACK")
	}
}

func TestHTTPHeadersRecordedBeforeBodyAndChunkedFraming(t *testing.T) {
	e := New(4096)
	p := pkt([]byte("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"), 50000, 80, "TCP")
	_, obs := e.InspectObserved("chunked", model.DirectionOutbound, p)
	if len(obs) != 1 || obs[0].HTTP.Path != "/upload" {
		t.Fatal("headers delayed until body completion")
	}
	p.TCPSeq += uint32(len(p.Payload))
	p.Payload = []byte("4\r\ndata\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, obs = e.InspectObserved("chunked", model.DirectionOutbound, p)
	if len(obs) != 1 || obs[0].HTTP.Path != "/next" {
		t.Fatalf("chunked framing failed: %+v", obs)
	}
}
