package tlsintel

import (
	"netprobe-ir/internal/model"
	"testing"
	"time"
)

func TestReuseCluster(t *testing.T) {
	s := New(100)
	for i := 0; i < 6; i++ {
		c := &model.TLSCertificateInfo{SHA256: "abc", SubjectCN: "x", IssuerCN: "y"}
		f := model.Flow{LastSeen: time.Now(), Remote: model.Endpoint{IP: string(rune('a' + i))}, DPI: model.DPIInfo{TLS: &model.TLSInfo{SNI: string(rune('x' + i)), Certificate: c}}}
		s.Observe(f)
	}
	cs := s.Clusters()
	if len(cs) != 1 || !cs[0].Suspicious {
		t.Fatalf("bad %#v", cs)
	}
}
