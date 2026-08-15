package cidr

import "testing"

// TestParseCIDRAcceptsPrefix32 verifies that /32 is a valid CIDR prefix
// representing a single host address.
func TestParseCIDRAcceptsPrefix32(t *testing.T) {
	b, orig, err := ParseCIDR("10.0.0.5/32")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.5/32) should succeed, got error: %v", err)
	}
	if b.Prefix != 32 {
		t.Fatalf("prefix = %d, want 32", b.Prefix)
	}
	if b.Network != orig {
		t.Fatalf("network %#x != orig %#x for /32", b.Network, orig)
	}
	if b.HostCount() != 1 {
		t.Fatalf("host count = %d, want 1", b.HostCount())
	}
}
