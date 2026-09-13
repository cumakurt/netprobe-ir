package streaming

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"netprobe-ir/internal/eventbus"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOTLP(t *testing.T) {
	ch := make(chan bool, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			t.Error("bad json")
		}
		ch <- true
		w.WriteHeader(200)
	}))
	defer s.Close()
	b := eventbus.New()
	m := New(b, []Target{{Name: "otel", Type: "otlp", Enabled: true, Address: s.URL}})
	ctx, c := context.WithCancel(context.Background())
	defer c()
	m.Start(ctx)
	b.Publish(eventbus.Event{Time: time.Now(), Category: "security", Type: "x"})
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no otlp")
	}
}
func TestNATS(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, _ := ln.Accept()
		defer c.Close()
		c.Write([]byte("INFO {}\r\n"))
		r := bufio.NewReader(c)
		r.ReadString('\n')
		h, _ := r.ReadString('\n')
		got <- h
	}()
	b := eventbus.New()
	m := New(b, []Target{{Name: "n", Type: "nats", Enabled: true, Address: ln.Addr().String(), Topic: "np.test"}})
	ctx, c := context.WithCancel(context.Background())
	defer c()
	m.Start(ctx)
	b.Publish(eventbus.Event{Time: time.Now(), Category: "x", Type: "y"})
	select {
	case x := <-got:
		if !strings.HasPrefix(x, "PUB np.test ") {
			t.Fatal(x)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no nats")
	}
}

func TestClickHouseJSONEachRow(t *testing.T) {
	got := make(chan map[string]any, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "JSONEachRow") {
			t.Errorf("query=%s", r.URL.RawQuery)
		}
		var v map[string]any
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			t.Error("bad row")
		}
		got <- v
		w.WriteHeader(200)
	}))
	defer s.Close()
	b := eventbus.New()
	m := New(b, []Target{{Name: "ch", Type: "clickhouse", Enabled: true, Address: s.URL, Topic: "netprobe_events"}})
	ctx, c := context.WithCancel(context.Background())
	defer c()
	m.Start(ctx)
	b.Publish(eventbus.Event{Time: time.Now(), Category: "security", Type: "finding", FlowID: "f1"})
	select {
	case v := <-got:
		if v["flow_id"] != "f1" {
			t.Fatalf("%+v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no clickhouse")
	}
}

func TestKafkaKcatAdapter(t *testing.T) {
	dir := t.TempDir()
	out := dir + "/out"
	bin := dir + "/kcat"
	script := "#!/bin/sh\ncat > '" + out + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	b := eventbus.New()
	m := New(b, []Target{{Name: "k", Type: "kafka", Enabled: true, Address: "broker:9092", Topic: "netprobe.events", Binary: bin}})
	ctx, c := context.WithCancel(context.Background())
	defer c()
	m.Start(ctx)
	b.Publish(eventbus.Event{Time: time.Now(), Category: "network", Type: "flow"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if x, err := os.ReadFile(out); err == nil && strings.Contains(string(x), "network") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("kcat adapter did not receive event")
}
