package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"task018-cidr/internal/httpapi"
)

// Run 执行无需外部依赖的自检：通过 httptest 启动真实 HTTP 服务，
// 覆盖网段信息、归属判断、聚合、子网划分与各类边界约束。成功返回 0，任一失败返回 1。
func Run() int {
	passed, failed := 0, 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL %-36s %v\n", name, err)
		} else {
			passed++
			fmt.Printf("PASS %s\n", name)
		}
	}

	api := httpapi.New()
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	do := func(method, path, body string) (*http.Response, []byte, error) {
		var r io.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, srv.URL+path, r)
		if err != nil {
			return nil, nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data, readErr
	}

	postJSON := func(path string, v any) (int, []byte, error) {
		b, _ := json.Marshal(v)
		resp, body, err := do(http.MethodPost, path, string(b))
		if err != nil {
			return 0, nil, err
		}
		return resp.StatusCode, body, nil
	}

	postRaw := func(path, raw string) (int, []byte, error) {
		resp, b, err := do(http.MethodPost, path, raw)
		if err != nil {
			return 0, nil, err
		}
		return resp.StatusCode, b, nil
	}

	check("健康检查", func() error {
		resp, _, err := do(http.MethodGet, "/healthz", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	check("网段信息主机位规整", func() error {
		status, body, err := postJSON("/info", map[string]string{"cidr": "192.168.1.10/24"})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Network   string `json:"network"`
			Broadcast string `json:"broadcast"`
			Prefix    int    `json:"prefix"`
			HostCount uint64 `json:"host_count"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if out.Network != "192.168.1.0" || out.Broadcast != "192.168.1.255" || out.Prefix != 24 || out.HostCount != 256 {
			return fmt.Errorf("info=%+v", out)
		}
		return nil
	})

	check("网段信息 /0 边界", func() error {
		status, body, err := postJSON("/info", map[string]string{"cidr": "0.0.0.0/0"})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Network   string `json:"network"`
			Broadcast string `json:"broadcast"`
			Prefix    int    `json:"prefix"`
			HostCount uint64 `json:"host_count"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if out.Network != "0.0.0.0" || out.Broadcast != "255.255.255.255" || out.Prefix != 0 || out.HostCount != 4294967296 {
			return fmt.Errorf("/0 info=%+v", out)
		}
		return nil
	})

	check("网段信息 /32 边界", func() error {
		status, body, err := postJSON("/info", map[string]string{"cidr": "10.0.0.5/32"})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Network   string `json:"network"`
			Broadcast string `json:"broadcast"`
			Prefix    int    `json:"prefix"`
			HostCount uint64 `json:"host_count"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if out.Network != "10.0.0.5" || out.Broadcast != "10.0.0.5" || out.Prefix != 32 || out.HostCount != 1 {
			return fmt.Errorf("/32 info=%+v", out)
		}
		return nil
	})

	check("归属判断最长前缀匹配", func() error {
		status, body, err := postJSON("/contains", map[string]any{
			"cidrs": []string{"192.168.0.0/24", "192.168.0.128/25"},
			"ip":    "192.168.0.200",
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Contained bool   `json:"contained"`
			Matched   string `json:"matched"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if !out.Contained || out.Matched != "192.168.0.128/25" {
			return fmt.Errorf("contained=%v matched=%q", out.Contained, out.Matched)
		}
		return nil
	})

	check("归属判断不命中", func() error {
		status, body, err := postJSON("/contains", map[string]any{
			"cidrs": []string{"192.168.0.0/24"},
			"ip":    "192.168.1.1",
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Contained bool   `json:"contained"`
			Matched   string `json:"matched"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if out.Contained || out.Matched != "" {
			return fmt.Errorf("contained=%v matched=%q", out.Contained, out.Matched)
		}
		return nil
	})

	check("归属判断空网段列表", func() error {
		status, body, err := postJSON("/contains", map[string]any{
			"cidrs": []string{},
			"ip":    "1.2.3.4",
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Contained bool `json:"contained"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if out.Contained {
			return fmt.Errorf("empty list should not contain")
		}
		return nil
	})

	check("聚合相邻合并为超网", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"192.168.0.0/24", "192.168.1.0/24"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"192.168.0.0/23"}
		if len(out.Result) != 1 || out.Result[0] != want[0] {
			return fmt.Errorf("result=%v want %v", out.Result, want)
		}
		return nil
	})

	check("聚合被包含子段丢弃", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24", "192.168.0.128/25"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"10.0.0.0/8", "192.168.0.0/24"}
		if len(out.Result) != len(want) {
			return fmt.Errorf("result=%v want %v", out.Result, want)
		}
		for i, w := range want {
			if out.Result[i] != w {
				return fmt.Errorf("result[%d]=%q want %q", i, out.Result[i], w)
			}
		}
		return nil
	})

	check("聚合链式合并乱序输入", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24", "10.0.1.0/24"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"10.0.0.0/22"}
		if len(out.Result) != 1 || out.Result[0] != want[0] {
			return fmt.Errorf("result=%v want %v", out.Result, want)
		}
		return nil
	})

	check("聚合不相邻不合并", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"192.168.0.0/24", "192.168.2.0/24"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"192.168.0.0/24", "192.168.2.0/24"}
		if len(out.Result) != 2 || out.Result[0] != want[0] || out.Result[1] != want[1] {
			return fmt.Errorf("result=%v want %v", out.Result, want)
		}
		return nil
	})

	check("聚合相邻但不构成超网不合并", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"192.168.0.128/25", "192.168.1.0/25"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"192.168.0.128/25", "192.168.1.0/25"}
		if len(out.Result) != 2 || out.Result[0] != want[0] || out.Result[1] != want[1] {
			return fmt.Errorf("result=%v want %v", out.Result, want)
		}
		return nil
	})

	check("聚合空列表返回空", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{"cidrs": []string{}})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if len(out.Result) != 0 {
			return fmt.Errorf("result=%v want empty", out.Result)
		}
		return nil
	})

	check("子网划分 N=2", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "192.168.0.0/24", "n": 2})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Subnets []string `json:"subnets"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"192.168.0.0/25", "192.168.0.128/25"}
		if len(out.Subnets) != 2 || out.Subnets[0] != want[0] || out.Subnets[1] != want[1] {
			return fmt.Errorf("subnets=%v want %v", out.Subnets, want)
		}
		return nil
	})

	check("子网划分 N=1 返回原网段", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "10.0.0.0/24", "n": 1})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Subnets []string `json:"subnets"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if len(out.Subnets) != 1 || out.Subnets[0] != "10.0.0.0/24" {
			return fmt.Errorf("subnets=%v want [10.0.0.0/24]", out.Subnets)
		}
		return nil
	})

	check("子网划分 /0 分 2", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "0.0.0.0/0", "n": 2})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Subnets []string `json:"subnets"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		want := []string{"0.0.0.0/1", "128.0.0.0/1"}
		if len(out.Subnets) != 2 || out.Subnets[0] != want[0] || out.Subnets[1] != want[1] {
			return fmt.Errorf("subnets=%v want %v", out.Subnets, want)
		}
		return nil
	})

	check("子网划分并集等于原网段", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "10.0.0.0/22", "n": 4})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out struct {
			Subnets []string `json:"subnets"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if len(out.Subnets) != 4 {
			return fmt.Errorf("want 4 subnets, got %d", len(out.Subnets))
		}
		// 10.0.0.0/22 分 4 个子网，前缀 22+log2(4)=24，首尾与原网段一致、地址连续。
		want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}
		for i, w := range want {
			if out.Subnets[i] != w {
				return fmt.Errorf("subnets[%d]=%q want %q (subnets=%v)", i, out.Subnets[i], w, out.Subnets)
			}
		}
		return nil
	})

	check("非法 IP 查询被拒绝", func() error {
		status, body, err := postJSON("/contains", map[string]any{
			"cidrs": []string{"10.0.0.0/8"},
			"ip":    "256.1.1.1",
		})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("前导零 IP 被拒绝", func() error {
		status, body, err := postJSON("/contains", map[string]any{
			"cidrs": []string{"10.0.0.0/8"},
			"ip":    "01.2.3.4",
		})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("聚合含非法网段被拒绝", func() error {
		status, body, err := postJSON("/aggregate", map[string]any{
			"cidrs": []string{"10.0.0.0/8", "bad"},
		})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("前缀越界被拒绝", func() error {
		status, body, err := postJSON("/info", map[string]string{"cidr": "192.168.0.0/33"})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("子网数非 2 的幂被拒绝", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "10.0.0.0/24", "n": 3})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		if !strings.Contains(string(body), "2 的正整数次幂") {
			return fmt.Errorf("error should mention power of 2: %s", body)
		}
		return nil
	})

	check("子网前缀越界被拒绝", func() error {
		status, body, err := postJSON("/split", map[string]any{"cidr": "10.0.0.0/30", "n": 8})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("非法 JSON 被拒绝", func() error {
		status, _, err := postRaw("/info", "{not json")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("多段 JSON 被拒绝", func() error {
		status, _, err := postRaw("/info", `{"cidr":"10.0.0.0/8"}{"cidr":"10.0.0.0/8"}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("未知字段被拒绝", func() error {
		status, _, err := postRaw("/info", `{"cidr":"10.0.0.0/8","extra":1}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("缺少 ip 字段被拒绝", func() error {
		status, body, err := postJSON("/contains", map[string]any{"cidrs": []string{"10.0.0.0/8"}})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("缺少 cidr 字段被拒绝", func() error {
		status, body, err := postJSON("/split", map[string]any{"n": 2})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("未知路由返回 404", func() error {
		resp, _, err := do(http.MethodGet, "/nope", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("status=%d want 404", resp.StatusCode)
		}
		return nil
	})

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
