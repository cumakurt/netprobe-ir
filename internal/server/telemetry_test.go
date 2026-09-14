package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
)

func TestTelemetryAPIAndLiveStream(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	defer e.TrafficSeries.Close()
	now := time.Now()
	e.Telemetry.Observe(model.PacketSummary{Time: now, Interface: "eth0", Direction: model.DirectionInbound, NetworkProtocol: "UDP", Length: 321})
	e.Telemetry.Tick(now.Add(time.Second), nil)
	srv := httptest.NewServer(New(e, "test-token").Handler())
	defer srv.Close()
	for _, tc := range []struct {
		path   string
		status int
	}{{"/api/v1/telemetry", 401}, {"/api/v1/telemetry?token=test-token", 200}, {"/api/v1/telemetry?token=test-token&range=6h", 200}, {"/api/v1/telemetry?token=test-token&interface=absent", 404}, {"/api/v1/telemetry?token=test-token&range=99h", 400}} {
		res, err := srv.Client().Get(srv.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s = %d", tc.path, res.StatusCode)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/telemetry/stream?token=test-token&interface=eth0", nil)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("not SSE")
	}
	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	found := false
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: ") {
			var v struct {
				Snapshot struct {
					Totals struct {
						Bytes uint64 `json:"bytes"`
					} `json:"totals"`
				} `json:"snapshot"`
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "data: ")), &v); err != nil {
				t.Fatal(err)
			}
			if v.Snapshot.Totals.Bytes != 321 {
				t.Fatal("stream has wrong interface telemetry")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no stream frame", scanner.Err())
	}
	cancel()
}
