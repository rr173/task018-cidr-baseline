package cidr

import "testing"

// TestContainsBlockSelf verifies that a CIDR block contains itself.
// A block B should satisfy B.ContainsBlock(B) == true since Prefix <= Prefix
// and the network addresses are equal.
func TestContainsBlockSelf(t *testing.T) {
	b, _, err := ParseCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !b.ContainsBlock(b) {
		t.Fatal("a block should contain itself: 192.168.0.0/24.ContainsBlock(192.168.0.0/24) = false")
	}

	// Also test with /28
	b28, _, err := ParseCIDR("10.0.0.0/28")
	if err != nil {
		t.Fatal(err)
	}
	if !b28.ContainsBlock(b28) {
		t.Fatal("a /28 block should contain itself")
	}
}
