package perflab

import (
	"context"
	"testing"
)

func TestRun(t *testing.T) {
	r := Run(context.Background(), "x", 100, func(i int) { _ = i * i })
	if r.Iterations != 100 || r.OpsPerSecond <= 0 {
		t.Fatalf("bad %#v", r)
	}
}
