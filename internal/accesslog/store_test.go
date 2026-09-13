package accesslog

import (
	"netprobe-ir/internal/model"
	"testing"
)

func TestRetentionPaginationAndSearch(t *testing.T) {
	s := New()
	for i := 0; i < Capacity+10; i++ {
		s.Add("dns", model.PacketSummary{Interface: "eth0", DPI: model.DPIInfo{DNS: &model.DNSInfo{Query: "example.com"}}})
	}
	s.Add("http", model.PacketSummary{Interface: "eth1"})
	p := s.Query("dns", "example.com eth0", 0, 100)
	if p.Retained != Capacity || p.Total != Capacity+10 || p.Evicted != 10 || len(p.Items) != 100 || p.Items[0].ID != Capacity+10 {
		t.Fatalf("bad page: %+v", p)
	}
	next := s.Query("dns", "", p.Next, 100)
	if next.Items[0].ID != p.Items[99].ID-1 {
		t.Fatal("pagination overlaps or skips")
	}
	if s.Query("dns", "missing", 0, 100).Matched != 0 {
		t.Fatal("search ignored")
	}
	if s.Query("web", "", 0, 100).Total != 1 {
		t.Fatal("category retention not independent")
	}
}
