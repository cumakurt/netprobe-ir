package integrations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestWebhook(t *testing.T) {
	ch := make(chan model.SecurityFinding, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Finding model.SecurityFinding `json:"finding"`
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		ch <- v.Finding
		w.WriteHeader(204)
	}))
	defer s.Close()
	m := New(Config{Webhooks: []Webhook{{Name: "soc", URL: s.URL, Enabled: true, MinSeverity: "high"}}})
	m.Publish(model.SecurityFinding{ID: "f1", Severity: "critical", RuleID: "X"})
	select {
	case f := <-ch:
		if f.ID != "f1" {
			t.Fatal(f.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
}
