//go:build linux

package procmap

import (
	"net"
	"netprobe-ir/internal/model"
	"os"
	"testing"
	"time"
)

func TestParseProcAddr(t *testing.T) {
	ip, p, e := parseAddr("0100007F:1F90")
	if e != nil || ip != "127.0.0.1" || p != 8080 {
		t.Fatalf("%s %d %v", ip, p, e)
	}
	ip, p, e = parseAddr("00000000000000000000000001000000:0035")
	if e != nil || ip != "::1" || p != 53 {
		t.Fatalf("ipv6 %s %d %v", ip, p, e)
	}
}

func TestLiveSocketAttribution(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	tr := New()
	tr.Refresh()
	la := client.LocalAddr().(*net.TCPAddr)
	ra := client.RemoteAddr().(*net.TCPAddr)
	p, attr := tr.Lookup("TCP", la.IP.String(), uint16(la.Port), ra.IP.String(), uint16(ra.Port), model.DirectionOutbound)
	if p == nil {
		t.Fatalf("no process attribution, attr=%s", attr)
	}
	if p.PID != os.Getpid() {
		t.Fatalf("pid=%d want=%d attr=%s", p.PID, os.Getpid(), attr)
	}
	if p.StartTimeTicks == 0 {
		t.Fatal("attributed process is missing start time ticks")
	}
	if !tr.OwnsConnection("TCP", la.IP.String(), uint16(la.Port), ra.IP.String(), uint16(ra.Port), os.Getpid()) {
		t.Fatal("sensor-owned socket was not identified")
	}
}

func TestOwnsConnectionChecksBothLocalEndpointsWithoutNameMatching(t *testing.T) {
	tr := New()
	tr.mu.Lock()
	tr.lastRefresh = time.Now()
	tr.local[localKey("TCP", "127.0.0.1", 8443)] = model.ProcessInfo{PID: 4242, Comm: "netprobe-ir"}
	tr.mu.Unlock()
	if !tr.OwnsConnection("TCP", "127.0.0.1", 50000, "127.0.0.1", 8443, 4242) {
		t.Fatal("traffic to the sensor listener was not identified")
	}
	if tr.OwnsConnection("TCP", "192.0.2.20", 8443, "198.51.100.30", 443, 4242) {
		t.Fatal("unrelated remote port was treated as the sensor listener")
	}
	if tr.OwnsConnection("TCP", "127.0.0.1", 50000, "127.0.0.1", 8443, 5151) {
		t.Fatal("process name caused another PID to be excluded")
	}
}
