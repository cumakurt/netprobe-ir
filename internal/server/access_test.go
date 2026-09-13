package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netprobe-ir/internal/accesslog"
	"netprobe-ir/internal/capture"
	"netprobe-ir/internal/config"
	"netprobe-ir/internal/model"
	"netprobe-ir/internal/pipeline"
	"testing"
	"time"
)

func TestAccessAPI(t *testing.T) {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Recorder.Enabled = false
	c.Security.ConsoleAllowedCIDRs = []string{"0.0.0.0/0", "::/0"}
	e := pipeline.New(c)
	e.ProcessFrame(capture.Frame{Time: time.Now(), Interface: "test0", Direction: model.DirectionOutbound, Data: httpFrame()})
	handler := New(e, "").Handler()
	for _, test := range []struct {
		path string
		code int
	}{{"/api/v1/access/web", 200}, {"/api/v1/access/dns", 200}, {"/api/v1/access/web?before=bad", 400}, {"/api/v1/access/web?limit=501", 400}, {"/api/v1/access/other", 404}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", test.path, nil))
		if w.Code != test.code {
			t.Fatalf("%s: %d %s", test.path, w.Code, w.Body.String())
		}
		if test.path == "/api/v1/access/web" {
			var page accesslog.Page
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 || page.Items[0].DPI.HTTP == nil {
				t.Fatalf("HTTP capture not retained: %s", w.Body.String())
			}
		}
	}
	w := httptest.NewRecorder()
	New(e, "secret").Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/access/dns", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unguarded access API: %d", w.Code)
	}
}
