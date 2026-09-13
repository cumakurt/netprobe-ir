package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netprobe-ir/internal/config"
	"netprobe-ir/internal/detectionquality"
	"netprobe-ir/internal/federation"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
	"netprobe-ir/internal/vulnintel"
)

func TestV081ReadAPIsAndSigmaTranslate(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	_ = e.RecordDetectionQuality(detectionquality.Run{Label: "benign", Benign: true, Observed: map[string]int{"R1": 1}, Frames: 10, ElapsedMS: 1})
	_ = e.Federation.Ingest(federation.Snapshot{SensorID: "s1", Version: "0.9.0", Time: time.Now(), Status: model.Status{CaptureRunning: true}})
	srv := httptest.NewServer(New(e, "").Handler())
	defer srv.Close()
	for _, p := range []string{"/api/v1/detection-quality", "/api/v1/runtime-events", "/api/v1/exploit-correlations", "/api/v1/fleet/health"} {
		r, err := srv.Client().Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 200 {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			t.Fatalf("%s=%d %s", p, r.StatusCode, b)
		}
		r.Body.Close()
	}
	payload, _ := json.Marshal(map[string]any{"rule": "title: test\nlevel: high\ndetection:\n  selection:\n    Image|contains: curl\n  condition: selection\n"})
	r, err := srv.Client().Post(srv.URL+"/api/v1/sigma/translate", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("sigma=%d %s", r.StatusCode, b)
	}
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	if out["compiled"] == nil {
		t.Fatalf("missing compiled: %#v", out)
	}
}

func TestExploitCorrelationAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	e := pipeline.New(c)
	_ = e.VulnIntel.LoadKEV([]byte(`{"vulnerabilities":[{"cveID":"CVE-X","vendorProject":"Acme","product":"apache","vulnerabilityName":"x"}]}`))
	e.VulnIntel.SetPackages([]vulnintel.Package{{Name: "apache", Version: "1"}})
	// The correlation implementation itself is package-tested. Here we verify API stability.
	srv := httptest.NewServer(New(e, "").Handler())
	defer srv.Close()
	r, err := http.Get(srv.URL + "/api/v1/exploit-correlations")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("status=%d", r.StatusCode)
	}
}
