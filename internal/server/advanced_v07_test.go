package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"netprobe-ir/internal/config"
	"netprobe-ir/internal/pipeline"
)

func TestV07ReadAPIsAndAnalyst(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Federation.IngestToken = "sensor-secret"
	e := pipeline.New(c)
	srv := httptest.NewServer(New(e, "").Handler())
	defer srv.Close()
	paths := []string{"/api/v1/files", "/api/v1/c2/beacons", "/api/v1/encrypted-dns", "/api/v1/identity-profiles", "/api/v1/vulnerabilities", "/api/v1/protocol-packs", "/api/v1/streaming", "/api/v1/plugins", "/api/v1/self-protection", "/api/v1/fleet"}
	for _, p := range paths {
		r, err := srv.Client().Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 200 {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			t.Fatalf("%s status=%d body=%s", p, r.StatusCode, b)
		}
		r.Body.Close()
	}
	b, _ := json.Marshal(map[string]any{"query": "summarize evidence"})
	r, err := srv.Client().Post(srv.URL+"/api/v1/analyst", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		bb, _ := io.ReadAll(r.Body)
		t.Fatalf("analyst status=%d %s", r.StatusCode, bb)
	}
	r.Body.Close()
}

func TestFleetCommandPollAck(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Federation.IngestToken = "sensor-secret"
	e := pipeline.New(c)
	srv := httptest.NewServer(New(e, "").Handler())
	defer srv.Close()
	body := bytes.NewBufferString(`{"sensor_id":"sensor-1","type":"version_report","ttl_seconds":60}`)
	r, err := srv.Client().Post(srv.URL+"/api/v1/fleet/commands", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		bb, _ := io.ReadAll(r.Body)
		t.Fatalf("queue %d %s", r.StatusCode, bb)
	}
	var cmd map[string]any
	_ = json.NewDecoder(r.Body).Decode(&cmd)
	r.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/sensors/commands/poll?sensor_id=sensor-1", nil)
	req.Header.Set("X-NetProbe-Sensor-Token", "sensor-secret")
	r, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Commands []map[string]any `json:"commands"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	if len(out.Commands) != 1 {
		t.Fatalf("commands=%v", out.Commands)
	}
	ack, _ := json.Marshal(map[string]any{"sensor_id": "sensor-1", "id": cmd["id"], "state": "completed", "result": "ok"})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sensors/commands/ack", bytes.NewReader(ack))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NetProbe-Sensor-Token", "sensor-secret")
	r, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		bb, _ := io.ReadAll(r.Body)
		t.Fatalf("ack %d %s", r.StatusCode, bb)
	}
	r.Body.Close()
}
