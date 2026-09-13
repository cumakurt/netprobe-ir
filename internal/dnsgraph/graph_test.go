package dnsgraph

import (
	"fmt"
	"testing"
	"time"
)

func TestFastFlux(t *testing.T) {
	g := New()
	now := time.Now()
	for i := 0; i < 9; i++ {
		g.Observe("x.test", []string{fmt.Sprintf("10.0.0.%d", i)}, now.Add(time.Duration(i)*time.Minute))
	}
	d := g.Domains()
	if len(d) != 1 || !d[0].FastFlux {
		t.Fatalf("bad %#v", d)
	}
}
