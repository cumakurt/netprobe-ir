package anomaly

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestExfilAlert(t *testing.T) {
	e := New(Config{ExfiltrationBytes: 100})
	f := model.Flow{ID: "x", LastSeen: time.Now(), Local: model.Endpoint{IP: "10.0.0.1"}, Remote: model.Endpoint{IP: "8.8.8.8", Port: 443}, BytesTX: 101}
	score, rs, as := e.Observe(f, false)
	if score < 35 || len(rs) == 0 || len(as) != 1 || as[0].Rule != "exfil-volume" {
		t.Fatalf("score=%d reasons=%v alerts=%v", score, rs, as)
	}
}
func TestBeaconAlert(t *testing.T) {
	e := New(Config{BeaconMinSamples: 4, BeaconMaxJitter: .05, ExfiltrationBytes: 1 << 60, FanoutDestinations: 999, PortScanPorts: 999, BurstConnections: 999})
	base := time.Now()
	found := false
	for i := 0; i < 5; i++ {
		f := model.Flow{ID: string(rune('a' + i)), LastSeen: base.Add(time.Duration(i) * 10 * time.Second), Local: model.Endpoint{IP: "10.0.0.1"}, Remote: model.Endpoint{IP: "1.2.3.4", Port: 443}, Process: &model.ProcessInfo{PID: 42, Exe: "/tmp/x"}}
		_, _, as := e.Observe(f, true)
		for _, a := range as {
			if a.Rule == "beacon" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("beacon alert not detected")
	}
}
func TestDNSEntropy(t *testing.T) {
	e := New(Config{DNSEntropyThreshold: 3.5, ExfiltrationBytes: 1 << 60, FanoutDestinations: 999, PortScanPorts: 999, BurstConnections: 999})
	f := model.Flow{ID: "dns", LastSeen: time.Now(), Local: model.Endpoint{IP: "x"}, Remote: model.Endpoint{IP: "y"}, DPI: model.DPIInfo{DNS: &model.DNSInfo{Query: "a9x2k7m4q8z1v6n3p5t0r2s7.example"}}}
	score, _, _ := e.Observe(f, false)
	if score == 0 {
		t.Fatal("expected entropy risk")
	}
}
