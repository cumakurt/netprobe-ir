//go:build linux

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netprobe-ir/internal/cases"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
)

func TestCaseTriageAPICollectsAndRejectsLockedCase(t *testing.T) {
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Recorder.Enabled = false
	engine := pipeline.New(cfg)
	c, err := engine.Cases.Create(cases.Case{Findings: []model.SecurityFinding{{ID: "finding-1", PID: os.Getpid(), Process: strings.TrimSpace(string(comm))}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(engine, "").Handler())
	defer srv.Close()
	endpoint := srv.URL + "/api/v1/cases/" + c.ID + "/triage"
	crossOrigin, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	crossOrigin.Header.Set("Origin", "https://other.example")
	blocked, err := srv.Client().Do(crossOrigin)
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", blocked.StatusCode)
	}
	res, err := srv.Client().Post(endpoint, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var captured cases.Case
	if err := json.NewDecoder(res.Body).Decode(&captured); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || len(captured.TriageSnapshots) != 1 || captured.TriageSnapshots[0].CollectedBy != "local" {
		t.Fatalf("status=%d case=%+v", res.StatusCode, captured)
	}
	if _, err := engine.Cases.Lock(c.ID); err != nil {
		t.Fatal(err)
	}
	res, err = srv.Client().Post(endpoint, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("locked case status=%d", res.StatusCode)
	}
}
