package otelprofiles

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExport(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatal("method")
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	e := Exporter{Endpoint: s.URL}
	if err := e.Export(context.Background(), Envelope{Resource: map[string]string{"service.name": "netprobe"}, Samples: []Sample{{Time: time.Now(), PID: 1, Value: 1, Unit: "samples"}}}); err != nil {
		t.Fatal(err)
	}
}
