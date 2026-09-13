package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netprobe-ir/internal/model"
)

func TestHubAndClient(t *testing.T) {
	h := NewHub()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NetProbe-Sensor-Token") != "secret" {
			http.Error(w, "no", 401)
			return
		}
		var s Snapshot
		if json.NewDecoder(r.Body).Decode(&s) != nil {
			http.Error(w, "bad", 400)
			return
		}
		if e := h.Ingest(s); e != nil {
			http.Error(w, e.Error(), 400)
		}
	}))
	defer srv.Close()
	c := Client{URL: srv.URL, Token: "secret", SensorID: "node-a", Snapshot: func() Snapshot { return Snapshot{Time: time.Now()} }}
	if e := c.Send(context.Background()); e != nil {
		t.Fatal(e)
	}
	if h.Count() != 1 || h.List()[0].SensorID != "node-a" {
		t.Fatal(h.List())
	}
}

func TestFleetCommands(t *testing.T) {
	h := NewHub()
	if e := h.Ingest(Snapshot{SensorID: "s1"}); e != nil {
		t.Fatal(e)
	}
	c, e := h.QueueCommand("s1", "reload_rules", map[string]any{"sha256": "abc"}, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if len(h.Commands("s1", true)) != 1 {
		t.Fatal("missing command")
	}
	if e = h.AckCommand("s1", c.ID, "completed", "ok"); e != nil {
		t.Fatal(e)
	}
	if len(h.Commands("s1", true)) != 0 {
		t.Fatal("still pending")
	}
	h.SetDesired("s1", "c", "r", "0.8.0")
	if len(h.Fleet()) != 1 || h.Fleet()[0].DesiredVersion != "0.8.0" {
		t.Fatal(h.Fleet())
	}
}

func TestPersistentFleetState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fleet.json")
	h := NewHubPersistent(p)
	if err := h.Ingest(Snapshot{SensorID: "s1", Hostname: "host1"}); err != nil {
		t.Fatal(err)
	}
	c, err := h.QueueCommand("s1", "capture_stop", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h.SetDesired("s1", "cfg", "rules", "0.8.0")
	h2 := NewHubPersistent(p)
	if len(h2.List()) != 1 || len(h2.Commands("s1", true)) != 1 {
		t.Fatalf("state not restored")
	}
	if h2.Commands("s1", true)[0].ID != c.ID {
		t.Fatal("command mismatch")
	}
	if h2.Fleet()[0].DesiredVersion != "0.8.0" {
		t.Fatal("desired state missing")
	}
}

func TestFleetHealthDetectsStalenessAndDrift(t *testing.T) {
	h := NewHub()
	now := time.Now().UTC()
	_ = h.Ingest(Snapshot{SensorID: "s1", Version: "0.8.0", ConfigSHA256: "a", RulesSHA256: "b", Time: now.Add(-45 * time.Second), Status: model.Status{CaptureRunning: true}})
	h.SetDesired("s1", "x", "b", "0.9.0")
	x := h.FleetHealth(now)
	if len(x) != 1 || x[0].State != "stale" || len(x[0].Drift) != 2 || x[0].HealthScore >= 100 {
		t.Fatalf("health=%#v", x)
	}
}
