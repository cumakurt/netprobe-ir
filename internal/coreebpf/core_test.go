package coreebpf

import "testing"

func TestProbeDoesNotClaimReadyWithoutObject(t *testing.T) {
	c := Probe("/definitely/missing/netprobe.bpf.o")
	if c.Ready {
		t.Fatal("unexpected ready")
	}
	if c.ObjectPresent {
		t.Fatal("unexpected object")
	}
}
