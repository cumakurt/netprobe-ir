package threatintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"netprobe-ir/internal/model"
	"testing"
)

func bundle() string {
	return `{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","id":"indicator--1","pattern_type":"stix","pattern":"[ipv4-addr:value = '203.0.113.9']","confidence":95},{"type":"indicator","id":"indicator--2","pattern_type":"stix","pattern":"[domain-name:value = 'evil.example']","confidence":90}]}`
}
func TestSTIXAndMatch(t *testing.T) {
	h := New()
	n, e := h.ImportSTIXBytes([]byte(bundle()), "test")
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	f := model.Flow{Remote: model.Endpoint{IP: "203.0.113.9"}}
	if len(h.MatchFlow(f)) != 1 {
		t.Fatal("IP IOC not matched")
	}
}
func TestTAXII(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/taxii+json;version=2.1" {
			t.Error("accept")
		}
		fmt.Fprint(w, `{"objects":[{"type":"indicator","id":"indicator--x","pattern":"[domain-name:value = 'c2.example']","confidence":99}]}`)
	}))
	defer srv.Close()
	h := New()
	n, e := h.FetchTAXII(context.Background(), TAXIIFeed{Name: "lab", ObjectsURL: srv.URL})
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	f := model.Flow{DPI: model.DPIInfo{DNS: &model.DNSInfo{Query: "c2.example"}}}
	if len(h.MatchFlow(f)) != 1 {
		t.Fatal("domain IOC not matched")
	}
}

func TestTAXIIPagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprint(w, `{"objects":[{"type":"indicator","id":"indicator--a","pattern":"[ipv4-addr:value = '203.0.113.10']","confidence":91}],"more":true,"next":"page2"}`)
			return
		}
		if r.URL.Query().Get("next") != "page2" {
			t.Errorf("missing next token")
		}
		fmt.Fprint(w, `{"objects":[{"type":"indicator","id":"indicator--b","pattern":"[domain-name:value = 'paged.example']","confidence":92}],"more":false}`)
	}))
	defer srv.Close()
	h := New()
	n, err := h.FetchTAXII(context.Background(), TAXIIFeed{Name: "paged", ObjectsURL: srv.URL})
	if err != nil || n != 2 || calls != 2 {
		t.Fatalf("n=%d calls=%d err=%v", n, calls, err)
	}
}
