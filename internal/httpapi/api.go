// Package httpapi 提供 IPv4 网段（CIDR）计算与归属判断服务的 HTTP 接口。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"task018-cidr/internal/cidr"
)

// ErrBadJSON 表示请求体不是单个合法 JSON 对象。
var ErrBadJSON = errors.New("请求体不是合法的单个 JSON 对象")

// API 是 CIDR 服务的 HTTP 接口实现。服务无状态：每个请求自带所需输入。
type API struct{}

// New 创建服务实例。
func New() *API { return &API{} }

// Handler 返回 HTTP 路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /contains", a.contains)
	mux.HandleFunc("POST /aggregate", a.aggregate)
	mux.HandleFunc("POST /split", a.split)
	mux.HandleFunc("POST /info", a.info)
	return mux
}

// decodeJSON 解码单个 JSON 对象，拒绝多段 JSON 与未知字段。
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return ErrBadJSON
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// containsReq 归属判断请求：网段列表与待查 IP。
type containsReq struct {
	Cidrs []string `json:"cidrs"`
	IP    string   `json:"ip"`
}

// containsResp 归属判断响应。
type containsResp struct {
	Contained bool   `json:"contained"`
	Matched   string `json:"matched"`
}

func (a *API) contains(w http.ResponseWriter, r *http.Request) {
	var req containsReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 ip 字段", "status": http.StatusBadRequest})
		return
	}
	m, err := cidr.LongestContains(req.Cidrs, req.IP)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	writeJSON(w, http.StatusOK, containsResp{Contained: m.Contained, Matched: m.Matched})
}

// aggregateReq 聚合请求：网段列表。
type aggregateReq struct {
	Cidrs []string `json:"cidrs"`
}

func (a *API) aggregate(w http.ResponseWriter, r *http.Request) {
	var req aggregateReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	blocks, err := cidr.Aggregate(req.Cidrs)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	result := make([]string, len(blocks))
	for i, b := range blocks {
		result[i] = b.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result})
}

// splitReq 子网划分请求：单个 CIDR 与子网数 N。
type splitReq struct {
	Cidr string `json:"cidr"`
	N    int    `json:"n"`
}

func (a *API) split(w http.ResponseWriter, r *http.Request) {
	var req splitReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	if req.Cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 cidr 字段", "status": http.StatusBadRequest})
		return
	}
	b, _, err := cidr.ParseCIDR(req.Cidr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	subs, err := cidr.Split(b, req.N)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	out := make([]string, len(subs))
	for i, s := range subs {
		out[i] = s.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"subnets": out})
}

// infoReq 单网段信息请求。
type infoReq struct {
	Cidr string `json:"cidr"`
}

func (a *API) info(w http.ResponseWriter, r *http.Request) {
	var req infoReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	if req.Cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 cidr 字段", "status": http.StatusBadRequest})
		return
	}
	b, _, err := cidr.ParseCIDR(req.Cidr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	writeJSON(w, http.StatusOK, cidr.InfoOf(b))
}
