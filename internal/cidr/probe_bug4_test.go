package cidr

import "testing"

// TestSplitN1ReturnsOriginal verifies that splitting a block into 1 subnet
// returns a slice containing the original block (not nil or empty).
func TestSplitN1ReturnsOriginal(t *testing.T) {
	b, _, err := ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	subs, err := Split(b, 1)
	if err != nil {
		t.Fatalf("Split(n=1) should succeed, got error: %v", err)
	}
	if subs == nil {
		t.Fatal("Split(n=1) returned nil, want slice with original block")
	}
	if len(subs) != 1 {
		t.Fatalf("Split(n=1) returned %d blocks, want 1", len(subs))
	}
	if subs[0] != b {
		t.Fatalf("Split(n=1)[0] = %v, want %v", subs[0], b)
	}
}
