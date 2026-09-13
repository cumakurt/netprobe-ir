package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/config"
	"netprobe-ir/internal/decode"
	"netprobe-ir/internal/eventbus"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
)

func TestV10LiveTrafficAPIUsesRealEventBusTelemetry(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	defer e.TrafficSeries.Close()
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	now := time.Now().UTC()
	e.EventBus.Publish(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Time: now, Direction: model.DirectionInbound, Length: 100, FlowID: "in-1"}})
	e.EventBus.Publish(eventbus.Event{Time: now, Type: "packet_metadata", Payload: model.PacketSummary{Time: now, Direction: model.DirectionOutbound, Length: 250, FlowID: "out-1"}})
	// The store intentionally flushes one bounded bucket per second.
	time.Sleep(1150 * time.Millisecond)
	for _, path := range []string{"/api/v1/traffic/live", "/api/v1/traffic/history?range=1m"} {
		r, err := s.Client().Get(s.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != http.StatusOK {
			r.Body.Close()
			t.Fatalf("%s=%d", path, r.StatusCode)
		}
		var v map[string]any
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			r.Body.Close()
			t.Fatal(err)
		}
		r.Body.Close()
		if path == "/api/v1/traffic/live" {
			if v["in_bytes_sec"].(float64) <= 0 || v["out_bytes_sec"].(float64) <= 0 {
				t.Fatalf("live telemetry not populated: %#v", v)
			}
		} else if len(v["points"].([]any)) == 0 {
			t.Fatalf("history empty: %#v", v)
		}
	}
	r, err := s.Client().Get(s.URL + "/api/v1/traffic/history?range=99d")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid range=%d", r.StatusCode)
	}
}

func TestV10NotificationAdminRBACAndSecretMasking(t *testing.T) {
	s, am, cl, pw := secureServer(t)
	defer s.Close()
	authenticatedAdmin(t, s, cl, pw)
	cfg := map[string]any{
		"email":            map[string]any{"enabled": false, "smtp_server": "smtp.example.test", "smtp_port": 587, "username": "soc", "password": "smtp-super-secret", "sender": "netprobe@example.test", "recipients": []string{"soc@example.test"}, "starttls": true, "timeout_seconds": 5, "severities": []string{"high", "critical"}},
		"telegram":         map[string]any{"enabled": false, "bot_token": "123456:abcdefghijklmnopqrstuvwxyzABCDE12345", "chat_id": "42", "timeout_seconds": 5, "severities": []string{"critical"}},
		"cooldown_seconds": 60,
		"max_retries":      2,
	}
	b, _ := json.Marshal(cfg)
	req, _ := http.NewRequest(http.MethodPut, s.URL+"/api/v1/notifications", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	_, _ = raw.ReadFrom(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("save=%d %s", r.StatusCode, raw.String())
	}
	if strings.Contains(raw.String(), "smtp-super-secret") || strings.Contains(raw.String(), "abcdefghijklmnopqrstuvwxyzABCDE12345") {
		t.Fatal("secret exposed in settings response")
	}
	if !strings.Contains(raw.String(), `"password_set":true`) || !strings.Contains(raw.String(), `"bot_token_set":true`) {
		t.Fatalf("masked secret flags missing: %s", raw.String())
	}

	_, err = am.CreateUser("view-notify", "Viewer", "viewer", "Viewer!Secure2026", false)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	vc := s.Client()
	vc.Jar = jar
	code, _ := loginClient(t, vc, s.URL, "view-notify", "Viewer!Secure2026", "")
	if code != http.StatusOK {
		t.Fatalf("viewer login=%d", code)
	}
	r, err = vc.Get(s.URL + "/api/v1/notifications")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer secret settings read=%d", r.StatusCode)
	}
}

func TestV10NotificationMutationRejectsCrossOrigin(t *testing.T) {
	s, _, cl, pw := secureServer(t)
	defer s.Close()
	authenticatedAdmin(t, s, cl, pw)
	b := []byte(`{"email":{"enabled":false},"telegram":{"enabled":false},"cooldown_seconds":60,"max_retries":1}`)
	req, _ := http.NewRequest(http.MethodPut, s.URL+"/api/v1/notifications", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	r, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin notification mutation=%d", r.StatusCode)
	}
}

func TestV10AssetsAreObservedAndDetailAddressable(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	defer e.TrafficSeries.Close()
	now := time.Now().UTC()
	pkt := &decode.Packet{Time: now, Interface: "eth-test", Protocol: "TCP", IPVersion: 4, Raw: make([]byte, 300)}
	proc := &model.ProcessInfo{PID: 4242, Comm: "curl", User: "alice"}
	dpi := model.DPIInfo{Protocol: "TLS", Application: "HTTPS"}
	f, _ := e.Store.Observe(pkt, proc, "test", dpi, "10.0.0.10", 51000, "203.0.113.9", 443, model.DirectionOutbound)
	e.Store.SetRisk(f.ID, 81, []string{"test"})

	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	r, err := s.Client().Get(s.URL + "/api/v1/assets")
	if err != nil {
		t.Fatal(err)
	}
	var assets []assetView
	if err := json.NewDecoder(r.Body).Decode(&assets); err != nil {
		r.Body.Close()
		t.Fatal(err)
	}
	r.Body.Close()
	var remote *assetView
	for i := range assets {
		if assets[i].ID == "remote_ip:203.0.113.9" {
			remote = &assets[i]
			break
		}
	}
	if remote == nil || remote.OutTraffic != 300 || remote.Flows != 1 || remote.Risk != 81 {
		t.Fatalf("unexpected remote asset: %#v", remote)
	}
	r, err = s.Client().Get(s.URL + "/api/v1/assets/remote_ip%3A203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("asset detail=%d", r.StatusCode)
	}
}

func TestV10WebAssetsExposeInteractiveGraphTrafficAndNotifications(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	s := httptest.NewServer(New(e, "").Handler())
	defer s.Close()
	for path, need := range map[string][]string{
		"/":       {"v1.0.0", "Investigation Graph", "System Settings"},
		"/app.js": {"initGraphCanvas", "graphHitNode", "graphHitEdge", "Area Select", "renderAssetDetail", "renderNotificationSettings", "Live IN / OUT Traffic", "trafficRange", "Pause Live"},
	} {
		r, err := s.Client().Get(s.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s=%d", path, r.StatusCode)
		}
		for _, x := range need {
			if !bytes.Contains(b.Bytes(), []byte(x)) {
				t.Fatalf("%s missing %q", path, x)
			}
		}
		if path == "/app.js" && bytes.Contains(b.Bytes(), []byte("Interface Acquisition")) {
			t.Fatal("legacy Interface Acquisition section still exposed")
		}
	}
}
