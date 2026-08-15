package cidr

import "testing"

// TestAggregateDedupKeepsDistinctPrefixes verifies that two CIDRs with the
// same network address but different prefix lengths are both considered
// during aggregation (the larger block should absorb the smaller one).
func TestAggregateDedupKeepsDistinctPrefixes(t *testing.T) {
	// Input order: /25 first, then /24. Both have network 10.0.0.0.
	// Correct: /24 contains /25, so result = [10.0.0.0/24].
	// If dedup incorrectly treats them as same (keyed only on network),
	// /24 gets dropped, leaving only /25.
	got, err := Aggregate([]string{"10.0.0.0/25", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 block, got %d: %v", len(got), blocksToStrings(got))
	}
	if got[0].String() != "10.0.0.0/24" {
		t.Fatalf("expected 10.0.0.0/24, got %s", got[0].String())
	}
}

func blocksToStrings(bs []Block) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.String()
	}
	return out
}
