package syslogexport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/eventbus"
)

func baseDest(host string, port int) Destination {
	return Destination{Name: "test", Enabled: true, Host: host, Port: port, Transport: "udp", Format: "rfc5424", Facility: 16, Severity: 6, Categories: []string{"all"}, QueueSize: 8}
}

func TestRFCFormatsAndFraming(t *testing.T) {
	e := eventbus.Event{Time: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC), Category: "security", Type: "finding", FlowID: "f1", Payload: map[string]any{"src": "1.2.3.4"}}
	d := baseDest("127.0.0.1", 514)
	d.Hostname = "sensor1"
	b, err := Format(d, e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "<134>1 2026-09-12T10:00:00Z sensor1 netprobe-ir") || !strings.Contains(string(b), `category="security"`) {
		t.Fatalf("rfc5424=%s", b)
	}
	d.Format = "rfc3164"
	b, _ = Format(d, e)
	if !strings.HasPrefix(string(b), "<134>Sep 12 10:00:00 sensor1 netprobe-ir:") {
		t.Fatalf("rfc3164=%s", b)
	}
	d.Transport = "tcp"
	d.Framing = "octet-counting"
	fr := frame(d, []byte("abc"))
	if string(fr) != "3 abc" {
		t.Fatalf("octet=%q", fr)
	}
	d.Framing = "non-transparent"
	if string(frame(d, []byte("abc"))) != "abc\n" {
		t.Fatal("newline framing")
	}
}

func TestUDPDeliveryPersistenceAndCategories(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	bus := eventbus.New()
	path := filepath.Join(t.TempDir(), "syslog.json")
	m, err := New(path, bus)
	if err != nil {
		t.Fatal(err)
	}
	d := baseDest("127.0.0.1", addr.Port)
	d.Categories = []string{"security"}
	pub, err := m.Upsert(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	bus.Publish(eventbus.Event{Category: "network", Type: "packet", Payload: map[string]any{"x": 1}})
	bus.Publish(eventbus.Event{Category: "security", Type: "finding", Payload: map[string]any{"x": 2}})
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 8192)
	n, _, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b[:n]), `"category":"security"`) {
		t.Fatalf("message=%s", b[:n])
	}
	m2, err := New(path, eventbus.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.List()) != 1 || m2.List()[0].ID != pub.ID {
		t.Fatal("persistence")
	}
}

func TestTCPDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := make(chan string, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		got <- line
	}()
	bus := eventbus.New()
	m, _ := New(filepath.Join(t.TempDir(), "x.json"), bus)
	d := baseDest("127.0.0.1", port)
	d.Transport = "tcp"
	d.Framing = "non-transparent"
	_, err = m.Upsert(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	bus.Publish(eventbus.Event{Category: "system", Type: "tcp_test"})
	select {
	case s := <-got:
		if !strings.Contains(s, "tcp_test") {
			t.Fatal(s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no tcp")
	}
}

func TestTLSValidationAndDelivery(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := selfSigned(t, dir)
	pair, err := tlsPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tlsListen(pair)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := make(chan []byte, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(io.LimitReader(c, 8192))
		got <- b
	}()
	d := baseDest("127.0.0.1", port)
	d.Transport = "tls"
	d.Framing = "octet-counting"
	d.TLS.CAFile = certFile
	d.TLS.ServerName = "localhost"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dial(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := Format(d, eventbus.Event{Time: time.Now(), Category: "system", Type: "tls_test"})
	_, err = c.Write(frame(d, msg))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case b := <-got:
		if !strings.Contains(string(b), "tls_test") {
			t.Fatalf("got=%q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no TLS data")
	}
	d.TLS.ServerName = "wrong.invalid"
	if c, err := dial(context.Background(), d); err == nil {
		_ = c.Close()
		t.Fatal("expected certificate validation failure")
	}
}

// Tiny test-only TLS helpers kept local so production never generates certs.
func selfSigned(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cf := filepath.Join(dir, "cert.pem")
	kf := filepath.Join(dir, "key.pem")
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = os.WriteFile(cf, cb, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kf, kb, 0600); err != nil {
		t.Fatal(err)
	}
	return cf, kf
}

// Wrappers avoid importing crypto/tls in the main test list above as helper names are explicit.
type tlsCertificate = tls.Certificate

func tlsPair(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}
func tlsListen(pair tls.Certificate) (net.Listener, error) {
	return tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
}

func TestTCPReconnectAndQueueOverflow(t *testing.T) {
	// Reserve a TCP port but do not listen yet so the first connection attempt fails.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	bus := eventbus.New()
	m, _ := New(filepath.Join(t.TempDir(), "x.json"), bus)
	d := baseDest("127.0.0.1", port)
	d.Transport = "tcp"
	d.Framing = "non-transparent"
	d.QueueSize = 1
	pub, err := m.Upsert(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	for i := 0; i < 20; i++ {
		bus.Publish(eventbus.Event{Category: "system", Type: "before_listener"})
	}
	time.Sleep(150 * time.Millisecond)
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		got <- line
	}()
	// Wait past the worker's first one-second reconnect backoff, then enqueue a fresh event.
	time.Sleep(1200 * time.Millisecond)
	bus.Publish(eventbus.Event{Category: "system", Type: "after_listener"})
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not reconnect")
	}
	st := m.Stats()
	var x Stats
	for _, s := range st {
		if s.ID == pub.ID {
			x = s
		}
	}
	if x.Reconnects == 0 {
		t.Fatal("reconnect not counted")
	}
	if x.Dropped == 0 {
		t.Fatal("bounded queue did not report drops")
	}
}

func TestMutualTLSClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPEM := makeCA(t)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey := makeSigned(t, caCert, caKey, "server", true)
	cliCert, cliKey := makeSigned(t, caCert, caKey, "client", false)
	sf := filepath.Join(dir, "server.crt")
	sk := filepath.Join(dir, "server.key")
	cf := filepath.Join(dir, "client.crt")
	ck := filepath.Join(dir, "client.key")
	writePEM(t, sf, "CERTIFICATE", srvCert)
	writePEM(t, sk, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey))
	writePEM(t, cf, "CERTIFICATE", cliCert)
	writePEM(t, ck, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cliKey))
	pair, err := tls.LoadX509KeyPair(sf, sk)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ok := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			_, e = io.ReadAll(io.LimitReader(c, 4096))
			c.Close()
		}
		ok <- e
	}()
	d := baseDest("127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
	d.Transport = "tls"
	d.Framing = "octet-counting"
	d.TLS.CAFile = caFile
	d.TLS.ServerName = "localhost"
	d.TLS.ClientCertFile = cf
	d.TLS.ClientKeyFile = ck
	c, err := dial(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := Format(d, eventbus.Event{Time: time.Now(), Category: "system", Type: "mtls_test"})
	_, err = c.Write(frame(d, msg))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case e := <-ok:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mTLS server did not complete")
	}
}

func makeCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "NetProbe Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	c, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func makeSigned(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, server bool) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	eku := x509.ExtKeyUsageClientAuth
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	if server {
		eku = x509.ExtKeyUsageServerAuth
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{eku}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	return der, k
}
func writePEM(t *testing.T, path, typ string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestUDPIPv6Delivery(t *testing.T) {
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	bus := eventbus.New()
	m, err := New(filepath.Join(t.TempDir(), "syslog.json"), bus)
	if err != nil {
		t.Fatal(err)
	}
	d := baseDest("::1", port)
	if _, err = m.Upsert(d); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	bus.Publish(eventbus.Event{Category: "security", Type: "ipv6_test", Payload: map[string]any{"src": "2001:db8::1"}})
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 8192)
	n, _, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b[:n]), "ipv6_test") {
		t.Fatalf("message=%s", b[:n])
	}
}

func TestMultipleSyslogDestinationsConcurrent(t *testing.T) {
	p1, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p1.Close()
	p2, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p2.Close()
	bus := eventbus.New()
	m, e := New(filepath.Join(t.TempDir(), "syslog.json"), bus)
	if e != nil {
		t.Fatal(e)
	}
	d1 := baseDest("127.0.0.1", p1.LocalAddr().(*net.UDPAddr).Port)
	d1.Name = "one"
	d2 := baseDest("127.0.0.1", p2.LocalAddr().(*net.UDPAddr).Port)
	d2.Name = "two"
	d2.Format = "rfc3164"
	if _, e = m.Upsert(d1); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Upsert(d2); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	bus.Publish(eventbus.Event{Time: time.Now(), Category: "security", Type: "multi_target_test"})
	for i, p := range []net.PacketConn{p1, p2} {
		_ = p.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 4096)
		n, _, e := p.ReadFrom(b)
		if e != nil {
			t.Fatalf("target %d: %v", i, e)
		}
		if !strings.Contains(string(b[:n]), "multi_target_test") {
			t.Fatalf("target %d data=%q", i, b[:n])
		}
	}
}
