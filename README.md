# task018-cidr

IPv4 网段（CIDR）计算与归属判断服务。

## 功能

- 网段信息：返回单个 CIDR 的规整网络地址、广播地址、前缀长度与主机数
- 归属判断：最长前缀匹配，返回命中网段
- 聚合：把一组 CIDR 合并为最小不相交集合（丢弃被包含段、合并可构成超网的相邻等长段）
- 子网划分：把单个 CIDR 等分为 N（2 的幂）个子网

## 运行

```bash
# 启动 HTTP 服务
go run . server --addr :8080

# 自检（无需外部依赖，执行后退出）
go run . --smoke-test
```

## 端点

- `GET /healthz` 健康检查
- `POST /info` 单网段信息
- `POST /contains` 归属判断
- `POST /aggregate` 最小不相交聚合
- `POST /split` 子网划分

仅使用标准库，无第三方依赖。
