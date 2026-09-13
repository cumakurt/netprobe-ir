package capture

import "testing"

func TestAFXDPPassiveIsExplicitlyRejected(t *testing.T) {
	if _, err := NewSource("af_xdp", SourceConfig{Interface: "lo"}); err == nil {
		t.Fatal("passive AF_XDP must not silently redirect host traffic")
	}
}
func TestUnknownBackendRejected(t *testing.T) {
	if _, err := NewSource("wat", SourceConfig{}); err == nil {
		t.Fatal("unknown backend accepted")
	}
}
