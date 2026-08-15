package cidr

import "testing"

// TestFormatIPv4OctetOrder verifies that FormatIPv4 produces the correct
// dotted-decimal representation with octets in the right order.
func TestFormatIPv4OctetOrder(t *testing.T) {
	// 192.168.1.2 = 0xC0A80102
	ip := uint32(0xC0A80102)
	got := FormatIPv4(ip)
	if got != "192.168.1.2" {
		t.Fatalf("FormatIPv4(0xC0A80102) = %q, want %q", got, "192.168.1.2")
	}

	// Verify round-trip: parse then format should be identity for canonical form
	parsed, err := ParseIPv4("10.20.30.40")
	if err != nil {
		t.Fatal(err)
	}
	if s := FormatIPv4(parsed); s != "10.20.30.40" {
		t.Fatalf("round-trip 10.20.30.40 -> %#x -> %q", parsed, s)
	}
}
