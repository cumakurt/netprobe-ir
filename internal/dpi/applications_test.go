package dpi

import (
	"bytes"
	"testing"

	"netprobe-ir/internal/model"
)

func TestApplicationHostEvidence(t *testing.T) {
	for _, tc := range []struct{ host, app string }{{"api.github.com", "GitHub"}, {"GITHUB.COM.", "GitHub"}, {"evilgithub.com", "HTTP"}, {"github.com.attacker.test", "HTTP"}, {"github.com@attacker.test", "HTTP"}, {"drive.google.com", "Google Drive"}, {"docs.google.com", "HTTP"}, {"cdn.unknown.test", "HTTP"}, {"teams.microsoft.com:443", "Microsoft Teams"}} {
		t.Run(tc.host, func(t *testing.T) {
			x := New(4096).Inspect("f", model.DirectionOutbound, pkt([]byte("GET / HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n"), 45000, 80, "TCP"))
			if x.Application != tc.app {
				t.Fatalf("%q: %+v", tc.host, x)
			}
			if tc.app != "HTTP" && (x.Evidence != "http_host" || x.MatchedHost == "") {
				t.Fatal("missing observed evidence")
			}
		})
	}
	x := New(4096).Inspect("f", model.DirectionOutbound, pkt(clientHello("www.youtube.com", []string{"h2"}), 45000, 443, "TCP"))
	if x.Application != "YouTube" || x.Evidence != "tls_sni" {
		t.Fatalf("TLS identity missing: %+v", x)
	}
}
func TestNoPortOrRandomPayloadApplicationGuess(t *testing.T) {
	for _, proto := range []string{"TCP", "UDP"} {
		for _, port := range []uint16{22, 25, 53, 80, 443, 3389, 51820, 6379} {
			for _, payload := range [][]byte{nil, []byte("unrecognized payload"), make([]byte, 32)} {
				x := New(4096).Inspect("f", model.DirectionOutbound, pkt(payload, 45000, port, proto))
				if x.Application != "" {
					t.Fatalf("%s/%d guessed %+v", proto, port, x)
				}
			}
		}
	}
	x := New(4096).Inspect("f", model.DirectionOutbound, pkt(dnsQuery("youtube.com"), 45000, 53, "UDP"))
	if x.Application != "DNS" {
		t.Fatal("DNS lookup inferred app traffic")
	}
}
func TestAdditionalSignatures(t *testing.T) {
	wg := make([]byte, 148)
	wg[0] = 1
	wg[12] = 42
	bt := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)
	for _, tc := range []struct {
		app, proto string
		port       uint16
		payload    []byte
	}{{"WireGuard", "UDP", 45000, wg}, {"BitTorrent", "TCP", 45000, bt}, {"SIP", "UDP", 5060, []byte("INVITE sip:alice@example.test SIP/2.0\r\n")}, {"SMTP", "TCP", 25, []byte("220 mail.example.test ESMTP\r\n")}, {"FTP", "TCP", 21, []byte("220 FTP ready\r\n")}, {"IMAP", "TCP", 143, []byte("* OK IMAP4 ready\r\n")}, {"POP3", "TCP", 110, []byte("+OK POP3 ready\r\n")}} {
		t.Run(tc.app, func(t *testing.T) {
			x := New(4096).Inspect("f", model.DirectionOutbound, pkt(tc.payload, 45001, tc.port, tc.proto))
			if x.Application != tc.app {
				t.Fatalf("signature not recognized: %+v", x)
			}
		})
	}
	x := New(4096).Inspect("f", model.DirectionOutbound, pkt(bytes.Repeat([]byte{0}, 148), 45001, 51820, "UDP"))
	if x.Application != "" {
		t.Fatal("invalid WireGuard classified")
	}
}

func TestHTTPPersistentConnectionChangesApplication(t *testing.T) {
	e := New(4096)
	first := []byte("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
	second := []byte("GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n")
	p := pkt(first, 45000, 80, "TCP")
	x := e.Inspect("f", model.DirectionOutbound, p)
	if x.Application != "GitHub" {
		t.Fatal(x)
	}
	p.TCPSeq += uint32(len(first))
	p.Payload = second
	x = e.Inspect("f", model.DirectionOutbound, p)
	if x.Application != "HTTP" || x.MatchedHost != "" {
		t.Fatalf("stale hostname classification: %+v", x)
	}
	p.Payload = nil
	x = e.Inspect("f", model.DirectionOutbound, p)
	if x.Application != "HTTP" {
		t.Fatal("ACK restored stale application")
	}
}

func TestTruncatedQUICHeadersStayUnknown(t *testing.T) {
	for _, kind := range []byte{0xc0, 0xd0, 0xe0, 0xf0} {
		x := New(4096).Inspect("f", model.DirectionOutbound, pkt([]byte{kind, 0, 0, 0, 1, 0, 0}, 45000, 443, "UDP"))
		if x.Application != "" {
			t.Fatalf("truncated QUIC %x classified: %+v", kind, x)
		}
	}
}
