package investigation

import (
	"fmt"
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestGraph(t *testing.T) {
	f := model.Flow{ID: "x", NetworkProtocol: "TCP", Local: model.Endpoint{IP: "10.0.0.2", Port: 1234}, Remote: model.Endpoint{IP: "203.0.113.8", Port: 443}, Interfaces: []string{"eth0"}, Process: &model.ProcessInfo{PID: 7, Comm: "curl"}, DPI: model.DPIInfo{TLS: &model.TLSInfo{SNI: "example.com", JA4: "t13d..."}}, Risk: 80}
	g := Build([]model.Flow{f}, nil, 10)
	types := map[string]bool{}
	for _, n := range g.Nodes {
		types[n.Type] = true
	}
	for _, x := range []string{"flow", "ip", "process", "interface", "domain", "tls"} {
		if !types[x] {
			t.Fatalf("missing %s: %+v", x, g.Nodes)
		}
	}
}

func TestBuildQueryFiltersNeighborhoodAndClusters(t *testing.T) {
	flows := []model.Flow{}
	for i := 0; i < 60; i++ {
		flows = append(flows, model.Flow{ID: fmt.Sprintf("f%d", i), NetworkProtocol: "TCP", Local: model.Endpoint{IP: "10.0.0.2", Port: 1000 + uint16(i)}, Remote: model.Endpoint{IP: fmt.Sprintf("203.0.113.%d", i+1), Port: 443}, Direction: model.DirectionOutbound, DPI: model.DPIInfo{Application: "HTTPS"}, Risk: i % 5})
	}
	g := BuildQuery(flows, nil, nil, Query{Protocol: "tcp", Application: "https", EnableClustering: true, MaxNodes: 20, MaxEdges: 40})
	if !g.Meta.Clustered || len(g.Nodes) > 20 || len(g.Edges) > 40 {
		t.Fatalf("bad clustered graph meta=%+v nodes=%d edges=%d", g.Meta, len(g.Nodes), len(g.Edges))
	}
	g2 := BuildQuery(flows, nil, nil, Query{SourceIP: "10.0.0.2", FocusID: "ip:10.0.0.2", Neighborhood: 1, MaxNodes: 100, MaxEdges: 200})
	if len(g2.Nodes) == 0 {
		t.Fatal("expected neighborhood")
	}
}

func TestBuildQueryLargeGraphRemainsBounded(t *testing.T) {
	flows := make([]model.Flow, 0, 5000)
	now := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		flows = append(flows, model.Flow{
			ID: fmt.Sprintf("large-%d", i), NetworkProtocol: "TCP",
			Local:     model.Endpoint{IP: fmt.Sprintf("10.%d.%d.%d", (i/65536)%250, (i/256)%250, i%250+1), Port: uint16(10000 + i%40000)},
			Remote:    model.Endpoint{IP: fmt.Sprintf("198.51.%d.%d", (i/250)%250, i%250+1), Port: 443},
			Direction: model.DirectionOutbound, FirstSeen: now, LastSeen: now,
			DPI: model.DPIInfo{Application: "HTTPS", Protocol: "TLS"}, Risk: i % 100,
		})
	}
	start := time.Now()
	g := BuildQuery(flows, nil, nil, Query{EnableClustering: true, MaxNodes: 500, MaxEdges: 1200})
	if time.Since(start) > 5*time.Second {
		t.Fatalf("large graph build too slow: %v", time.Since(start))
	}
	if len(g.Nodes) > 500 || len(g.Edges) > 1200 || !g.Meta.Clustered {
		t.Fatalf("graph safeguards failed: nodes=%d edges=%d meta=%+v", len(g.Nodes), len(g.Edges), g.Meta)
	}
}

func TestFindingFiltersAreAppliedServerSide(t *testing.T) {
	now := time.Now().UTC()
	findings := []model.SecurityFinding{
		{ID: "a", Time: now, Severity: "critical", Source: model.Endpoint{IP: "10.0.0.1", Port: 1234}, Destination: model.Endpoint{IP: "203.0.113.9", Port: 443}, Protocol: "TCP", Application: "TLS", Process: "curl"},
		{ID: "b", Time: now, Severity: "low", Source: model.Endpoint{IP: "10.0.0.2", Port: 3333}, Destination: model.Endpoint{IP: "192.0.2.9", Port: 53}, Protocol: "UDP", Application: "DNS", Process: "dig"},
	}
	g := BuildQuery(nil, findings, nil, Query{SourceIP: "10.0.0.1", DestinationIP: "203.0.113.9", Port: 443, Protocol: "tcp", Application: "tls", Severity: "critical", Asset: "curl", MaxNodes: 100, MaxEdges: 100})
	if g.Meta.FilteredFindings != 1 {
		t.Fatalf("filtered findings=%d", g.Meta.FilteredFindings)
	}
}
