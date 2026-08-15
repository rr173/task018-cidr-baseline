package cidr

import (
	"errors"
	"testing"
)

// TestParseIPv4Valid 合法地址解析为正确的 uint32。
func TestParseIPv4Valid(t *testing.T) {
	cases := map[string]uint32{
		"0.0.0.0":           0x00000000,
		"255.255.255.255":   0xFFFFFFFF,
		"192.168.1.1":       0xC0A80101,
		"10.0.0.1":          0x0A000001,
		"1.2.3.4":           0x01020304,
		"192.168.0.0":       0xC0A80000,
		"8.8.8.8":           0x08080808,
		"127.0.0.1":         0x7F000001,
	}
	for s, want := range cases {
		got, err := ParseIPv4(s)
		if err != nil {
			t.Errorf("ParseIPv4(%q) unexpected error: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("ParseIPv4(%q) = %#x, want %#x", s, got, want)
		}
	}
}

// TestParseIPv4Invalid 各类非法地址必须拒绝：空段、段数不对、非数字、前导零、越界。
func TestParseIPv4Invalid(t *testing.T) {
	bad := []string{
		"",                 // 空
		"1.2.3",            // 段数不足
		"1.2.3.4.5",        // 段数过多
		"192..1.1",         // 空段
		"192.168.a.1",      // 非数字
		"192.168.1.1 ",     // 含空格
		" 192.168.1.1",     // 前导空格
		"01.2.3.4",         // 前导零
		"192.168.001.1",    // 前导零
		"192.168.0.00",     // 前导零
		"010.0.0.0",        // 前导零
		"256.1.1.1",        // 越界
		"1.256.1.1",        // 越界
		"1.1.1.256",        // 越界
		"1.1.1.300",        // 越界
		"1.-1.1.1",         // 负号
		"1.1.1.1.1.1",      // 段数过多
		"abc.def.ghi.jkl",  // 全非数字
	}
	for _, s := range bad {
		if _, err := ParseIPv4(s); err == nil {
			t.Errorf("ParseIPv4(%q) expected error, got nil", s)
		} else if !errors.Is(err, ErrInvalidIP) {
			t.Errorf("ParseIPv4(%q) want ErrInvalidIP, got %v", s, err)
		}
	}
}

// TestFormatIPv4 uint32 与点分十进制互为逆运算。
func TestFormatIPv4(t *testing.T) {
	cases := []uint32{0, 0xFFFFFFFF, 0xC0A80101, 0x0A000001, 0x7F000001}
	for _, ip := range cases {
		s := FormatIPv4(ip)
		got, err := ParseIPv4(s)
		if err != nil {
			t.Fatalf("FormatIPv4(%#x) -> %q parse error: %v", ip, s, err)
		}
		if got != ip {
			t.Errorf("round trip %#x -> %q -> %#x", ip, s, got)
		}
	}
}

// TestMask 各前缀对应的掩码。
func TestMask(t *testing.T) {
	cases := map[int]uint32{
		0:  0x00000000,
		1:  0x80000000,
		8:  0xFF000000,
		16: 0xFFFF0000,
		24: 0xFFFFFF00,
		31: 0xFFFFFFFE,
		32: 0xFFFFFFFF,
	}
	for p, want := range cases {
		if got := Mask(p); got != want {
			t.Errorf("Mask(%d) = %#x, want %#x", p, got, want)
		}
	}
}

// TestParseCIDRValid 合法 CIDR 解析与主机位规整。
func TestParseCIDRValid(t *testing.T) {
	cases := []struct {
		s        string
		network  uint32
		prefix   int
		orig     uint32
	}{
		{"192.168.0.0/24", 0xC0A80000, 24, 0xC0A80000},
		{"192.168.1.10/24", 0xC0A80100, 24, 0xC0A8010A}, // 主机位规整
		{"10.0.0.0/8", 0x0A000000, 8, 0x0A000000},
		{"0.0.0.0/0", 0x00000000, 0, 0x00000000},
		{"255.255.255.255/32", 0xFFFFFFFF, 32, 0xFFFFFFFF},
		{"10.255.255.255/8", 0x0A000000, 8, 0x0AFFFFFF}, // 主机位规整
		{"192.168.0.129/25", 0xC0A80080, 25, 0xC0A80081}, // 主机位规整
	}
	for _, tc := range cases {
		b, orig, err := ParseCIDR(tc.s)
		if err != nil {
			t.Errorf("ParseCIDR(%q) unexpected error: %v", tc.s, err)
			continue
		}
		if b.Network != tc.network {
			t.Errorf("ParseCIDR(%q) network = %#x, want %#x", tc.s, b.Network, tc.network)
		}
		if b.Prefix != tc.prefix {
			t.Errorf("ParseCIDR(%q) prefix = %d, want %d", tc.s, b.Prefix, tc.prefix)
		}
		if orig != tc.orig {
			t.Errorf("ParseCIDR(%q) orig = %#x, want %#x", tc.s, orig, tc.orig)
		}
	}
}

// TestParseCIDRInvalid 各类非法 CIDR 必须拒绝。
func TestParseCIDRInvalid(t *testing.T) {
	type want struct{ err error }
	cases := map[string]want{
		"192.168.0.0":       {ErrInvalidCIDR},  // 缺斜杠
		"192.168.0.0/":      {ErrInvalidPrefix}, // 空前缀
		"192.168.0.0/abc":   {ErrInvalidPrefix}, // 非数字前缀
		"192.168.0.0/33":    {ErrInvalidPrefix}, // 越界
		"192.168.0.0/-1":    {ErrInvalidPrefix}, // 负前缀
		"192.168.0.0/24/":   {ErrInvalidPrefix}, // 多斜杠尾部
		"256.1.1.1/24":      {ErrInvalidIP},     // 非法 IP
		"192.168.0.0/ 24":   {ErrInvalidPrefix}, // 前缀含空格
		"192.168..0/24":     {ErrInvalidIP},     // 空段
	}
	for s, w := range cases {
		_, _, err := ParseCIDR(s)
		if err == nil {
			t.Errorf("ParseCIDR(%q) expected error, got nil", s)
			continue
		}
		if !errors.Is(err, w.err) {
			t.Errorf("ParseCIDR(%q) want %v, got %v", s, w.err, err)
		}
	}
}

// TestBlockBroadcastHostCount 广播地址与主机数，含 /0 与 /32 边界。
func TestBlockBroadcastHostCount(t *testing.T) {
	cases := []struct {
		cidr      string
		broadcast uint32
		hostCount uint64
	}{
		{"192.168.0.0/24", 0xC0A800FF, 256},
		{"10.0.0.0/8", 0x0AFFFFFF, 16777216},
		{"0.0.0.0/0", 0xFFFFFFFF, 4294967296},
		{"192.168.1.1/32", 0xC0A80101, 1},
		{"10.0.0.0/30", 0x0A000003, 4},
	}
	for _, tc := range cases {
		b, _, err := ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q) error: %v", tc.cidr, err)
		}
		if got := b.Broadcast(); got != tc.broadcast {
			t.Errorf("%s broadcast = %#x, want %#x", tc.cidr, got, tc.broadcast)
		}
		if got := b.HostCount(); got != tc.hostCount {
			t.Errorf("%s host count = %d, want %d", tc.cidr, got, tc.hostCount)
		}
	}
}

// TestBlockContains 归属判断基于规整网络地址与掩码。
func TestBlockContains(t *testing.T) {
	b, _, _ := ParseCIDR("192.168.0.0/24")
	contains := []uint32{0xC0A80000, 0xC0A80064, 0xC0A800FF} // .0.0, .0.100, .0.255
	notContains := []uint32{0xC0A80100, 0xC0A7FFFF, 0x0A000001} // .1.0, .255.255, 10.0.0.1
	for _, ip := range contains {
		if !b.Contains(ip) {
			t.Errorf("192.168.0.0/24 should contain %#x", ip)
		}
	}
	for _, ip := range notContains {
		if b.Contains(ip) {
			t.Errorf("192.168.0.0/24 should not contain %#x", ip)
		}
	}
	// /0 包含一切。
	zero, _, _ := ParseCIDR("0.0.0.0/0")
	if !zero.Contains(0xFFFFFFFF) || !zero.Contains(0) {
		t.Errorf("0.0.0.0/0 should contain all addresses")
	}
}

// TestContainsBlock 包含关系判断：A 包含 B 当且仅当前缀更小且 B 网络落在 A 内。
func TestContainsBlock(t *testing.T) {
	a, _, _ := ParseCIDR("10.0.0.0/8")
	b, _, _ := ParseCIDR("10.1.0.0/16")
	c, _, _ := ParseCIDR("11.0.0.0/8")
	d, _, _ := ParseCIDR("192.168.0.128/25")
	e, _, _ := ParseCIDR("192.168.0.0/24")
	if !a.ContainsBlock(b) {
		t.Error("10.0.0.0/8 should contain 10.1.0.0/16")
	}
	if a.ContainsBlock(c) {
		t.Error("10.0.0.0/8 should not contain 11.0.0.0/8")
	}
	if !e.ContainsBlock(d) {
		t.Error("192.168.0.0/24 should contain 192.168.0.128/25")
	}
	if d.ContainsBlock(e) {
		t.Error("192.168.0.128/25 should not contain 192.168.0.0/24 (smaller prefix)")
	}
	if !a.ContainsBlock(a) {
		t.Error("a block should contain itself")
	}
}

// TestLongestContains 最长前缀匹配：多个命中取最具体者。
func TestLongestContains(t *testing.T) {
	// /24 与 /25 同时命中 .0.200，应返回更具体的 /25。
	m, err := LongestContains([]string{"192.168.0.0/24", "192.168.0.128/25"}, "192.168.0.200")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Contained || m.Matched != "192.168.0.128/25" {
		t.Fatalf("got %+v, want matched 192.168.0.128/25", m)
	}
	// /8 与 /16 命中 10.1.2.3，返回 /16。
	m, _ = LongestContains([]string{"10.0.0.0/8", "10.1.0.0/16"}, "10.1.2.3")
	if !m.Contained || m.Matched != "10.1.0.0/16" {
		t.Fatalf("got %+v, want matched 10.1.0.0/16", m)
	}
	// 不命中。
	m, _ = LongestContains([]string{"192.168.0.0/24"}, "192.168.1.1")
	if m.Contained || m.Matched != "" {
		t.Fatalf("got %+v, want not contained", m)
	}
	// 空列表不命中。
	m, _ = LongestContains(nil, "1.2.3.4")
	if m.Contained {
		t.Fatalf("empty list should not contain, got %+v", m)
	}
	// 查询 IP 非法返回错误。
	if _, err := LongestContains([]string{"10.0.0.0/8"}, "999.1.1.1"); !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("want ErrInvalidIP, got %v", err)
	}
	// 列表中网段非法返回错误。
	if _, err := LongestContains([]string{"10.0.0.0/8", "bad"}, "10.0.0.1"); err == nil {
		t.Fatalf("want error for invalid cidr in list")
	}
}

// TestAggregateMergeAdjacent 两个相邻等长段合并为超网。
func TestAggregateMergeAdjacent(t *testing.T) {
	got, err := Aggregate([]string{"192.168.0.0/24", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.0.0/23"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestAggregateNotAdjacentNotMerged 不相邻的等长段不可合并。
func TestAggregateNotAdjacentNotMerged(t *testing.T) {
	got, _ := Aggregate([]string{"192.168.0.0/24", "192.168.2.0/24"})
	want := []string{"192.168.0.0/24", "192.168.2.0/24"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestAggregateContainedDropped 被包含的子段被丢弃。
func TestAggregateContainedDropped(t *testing.T) {
	got, _ := Aggregate([]string{"10.0.0.0/8", "10.1.0.0/16"})
	want := []string{"10.0.0.0/8"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// /25 被 /24 包含。
	got, _ = Aggregate([]string{"192.168.0.0/24", "192.168.0.128/25"})
	if !sameStrings(got, []string{"192.168.0.0/24"}) {
		t.Fatalf("got %v, want [192.168.0.0/24]", got)
	}
}

// TestAggregateChainMerge 四个连续 /24 链式合并为 /22，且输入乱序。
func TestAggregateChainMerge(t *testing.T) {
	got, err := Aggregate([]string{"10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24", "10.0.1.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.0/22"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestAggregatePartialMerge 部分可合并：.0+.1 合并，.4 单独保留。
func TestAggregatePartialMerge(t *testing.T) {
	got, _ := Aggregate([]string{"10.0.0.0/24", "10.0.1.0/24", "10.0.4.0/24"})
	want := []string{"10.0.0.0/23", "10.0.4.0/24"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestAggregateAdjacentButNotSupernet 相邻但不构成超网的等长段不可合并。
// 192.168.0.128/25 与 192.168.1.0/25 相邻，但低块是 .0/24 的上半段，不构成 /24。
func TestAggregateAdjacentButNotSupernet(t *testing.T) {
	got, _ := Aggregate([]string{"192.168.0.128/25", "192.168.1.0/25"})
	want := []string{"192.168.0.128/25", "192.168.1.0/25"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v (not mergeable)", got, want)
	}
}

// TestAggregateDedupAndEmpty 去重与空输入。
func TestAggregateDedupAndEmpty(t *testing.T) {
	got, _ := Aggregate([]string{"192.168.0.0/24", "192.168.0.0/24"})
	if !sameStrings(got, []string{"192.168.0.0/24"}) {
		t.Fatalf("dedup got %v", got)
	}
	got, _ = Aggregate(nil)
	if len(got) != 0 {
		t.Fatalf("empty input got %v", got)
	}
}

// TestAggregateZeroCoversAll 0.0.0.0/0 吸收一切。
func TestAggregateZeroCoversAll(t *testing.T) {
	got, _ := Aggregate([]string{"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"})
	if !sameStrings(got, []string{"0.0.0.0/0"}) {
		t.Fatalf("got %v, want [0.0.0.0/0]", got)
	}
}

// TestAggregateSorted 结果按网络地址升序。
func TestAggregateSorted(t *testing.T) {
	got, _ := Aggregate([]string{"192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"})
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/24"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v (sorted)", got, want)
	}
}

// TestAggregateInvalidReturnsError 非法网段导致整体返回错误。
func TestAggregateInvalidReturnsError(t *testing.T) {
	if _, err := Aggregate([]string{"10.0.0.0/8", "bad"}); err == nil {
		t.Fatal("want error for invalid cidr")
	}
}

// TestSplitValid 合法子网划分：N=2/4，按网络地址升序、并集等于原网段。
func TestSplitValid(t *testing.T) {
	b, _, _ := ParseCIDR("192.168.0.0/24")
	got, err := Split(b, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.0.0/25", "192.168.0.128/25"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	got, _ = Split(b, 4)
	want = []string{"192.168.0.0/26", "192.168.0.64/26", "192.168.0.128/26", "192.168.0.192/26"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestSplitN1 N=1 返回原网段。
func TestSplitN1(t *testing.T) {
	b, _, _ := ParseCIDR("10.0.0.0/24")
	got, _ := Split(b, 1)
	if !sameStrings(got, []string{"10.0.0.0/24"}) {
		t.Fatalf("N=1 got %v", got)
	}
}

// TestSplitBoundary /30 分 4 个 /32；/0 分 2 个 /1。
func TestSplitBoundary(t *testing.T) {
	b, _, _ := ParseCIDR("10.0.0.0/30")
	got, _ := Split(b, 4)
	want := []string{"10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"}
	if !sameStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	zero, _, _ := ParseCIDR("0.0.0.0/0")
	got, _ = Split(zero, 2)
	if !sameStrings(got, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
		t.Fatalf("got %v, want [0.0.0.0/1 128.0.0.0/1]", got)
	}
}

// TestSplitUnionEqualsOriginal 子网并集等于原网段且两两不相交。
func TestSplitUnionEqualsOriginal(t *testing.T) {
	b, _, _ := ParseCIDR("10.0.0.0/22")
	subs, err := Split(b, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var sumHost uint64
	var prevBroadcast uint32
	for i, s := range subs {
		sumHost += s.HostCount()
		if i == 0 {
			if s.Network != b.Network {
				t.Fatalf("first subnet network %#x != base %#x", s.Network, b.Network)
			}
		} else {
			if s.Network != prevBroadcast+1 {
				t.Fatalf("subnet %d not contiguous: %#x != %#x+1", i, s.Network, prevBroadcast)
			}
		}
		prevBroadcast = s.Broadcast()
	}
	if sumHost != b.HostCount() {
		t.Fatalf("sum host %d != base host %d", sumHost, b.HostCount())
	}
	if prevBroadcast != b.Broadcast() {
		t.Fatalf("last broadcast %#x != base broadcast %#x", prevBroadcast, b.Broadcast())
	}
}

// TestSplitInvalidCount N 非正或非 2 的幂必须拒绝。
func TestSplitInvalidCount(t *testing.T) {
	b, _, _ := ParseCIDR("10.0.0.0/24")
	for _, n := range []int{0, -1, 3, 5, 6, 7, 9} {
		if _, err := Split(b, n); !errors.Is(err, ErrSplitCountNotPow2) {
			t.Errorf("Split(n=%d) want ErrSplitCountNotPow2, got %v", n, err)
		}
	}
}

// TestSplitPrefixOverflow 子网前缀超过 32 必须拒绝。
func TestSplitPrefixOverflow(t *testing.T) {
	b30, _, _ := ParseCIDR("10.0.0.0/30")
	if _, err := Split(b30, 8); !errors.Is(err, ErrSplitPrefixOverflow) {
		t.Fatalf("Split(/30,8) want ErrSplitPrefixOverflow, got %v", err)
	}
	b32, _, _ := ParseCIDR("10.0.0.0/32")
	if _, err := Split(b32, 2); !errors.Is(err, ErrSplitPrefixOverflow) {
		t.Fatalf("Split(/32,2) want ErrSplitPrefixOverflow, got %v", err)
	}
}

// TestInfoOf 单网段信息：规整网络地址、广播地址、前缀、主机数。
func TestInfoOf(t *testing.T) {
	b, _, _ := ParseCIDR("192.168.1.10/24")
	info := InfoOf(b)
	want := Info{
		Network:   "192.168.1.0",
		Broadcast: "192.168.1.255",
		Prefix:    24,
		HostCount: 256,
	}
	if info != want {
		t.Fatalf("got %+v, want %+v", info, want)
	}
	// /0 边界。
	zero, _, _ := ParseCIDR("0.0.0.0/0")
	info = InfoOf(zero)
	if info.Network != "0.0.0.0" || info.Broadcast != "255.255.255.255" || info.Prefix != 0 || info.HostCount != 4294967296 {
		t.Fatalf("/0 info = %+v", info)
	}
	// /32 边界。
	b32, _, _ := ParseCIDR("10.0.0.5/32")
	info = InfoOf(b32)
	if info.Network != "10.0.0.5" || info.Broadcast != "10.0.0.5" || info.Prefix != 32 || info.HostCount != 1 {
		t.Fatalf("/32 info = %+v", info)
	}
}

// sameStrings 比较网段切片与期望字符串切片（顺序敏感）。
func sameStrings(blocks []Block, want []string) bool {
	if len(blocks) != len(want) {
		return false
	}
	for i, b := range blocks {
		if b.String() != want[i] {
			return false
		}
	}
	return true
}
