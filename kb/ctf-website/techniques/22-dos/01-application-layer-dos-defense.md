---
id: "ctf-website/22-dos/01-application-layer-dos-defense"
title: "应用层拒绝服务防御与协议弹性加固"
title_en: "Application-Layer DoS Defense and Protocol Resilience Hardening"
summary: >
  针对 HTTP/1.1 Slowloris 与 RUDY 慢速攻击、HTTP/2 Rapid Reset（CVE-2023-44487）、WebSocket 长连接与分片帧洪泛、GraphQL 别名与深度放大，以及 TOCTOU 竞争窗口耗尽配额的系统性蓝队防御方案。涵盖反向代理超时收紧、HTTP/2 流控与版本升级、查询复杂度预算、Redis 原子限流及可运行弹性校验脚本。
summary_en: >
  Blue-team defense guide countering HTTP/1.1 Slowloris and RUDY slow attacks, HTTP/2 Rapid Reset (CVE-2023-44487), WebSocket connection and fragmented-frame floods, GraphQL alias/depth amplification, and TOCTOU race-condition quota exhaustion. Covers reverse-proxy timeout hardening, HTTP/2 stream caps, query complexity budgets, atomic Redis rate limiting, and runnable resilience verification code.
board: "ctf-website"
category: "22-dos"
signals:
  - "Slowloris 半开连接拦截 408"
  - "RUDY 慢速 POST 超时断开"
  - "HTTP/2 RST_STREAM 速率限制与 GOAWAY"
  - "WebSocket 并发连接配额与帧超时"
  - "GraphQL 别名与深度复杂度拦截"
  - "TOCTOU 原子令牌桶限流 429"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "Slowloris 防御"
  - "RUDY 防护"
  - "CVE-2023-44487 缓解"
  - "HTTP/2 Rapid Reset 加固"
  - "WebSocket 连接限制"
  - "GraphQL 查询复杂度限制"
  - "原子限流"
  - "application layer DoS defense"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "http2"
  - "websocket"
  - "graphql"
  - "rate-limiting"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/01-application-layer-dos"
track: "blue"
defends: "ctf-website/22-dos/01-application-layer-dos"
---
# 应用层拒绝服务防御与协议弹性加固

## 防御目标与对抗矩阵

应用层拒绝服务（对应攻击面见 [01-application-layer-dos.md](./01-application-layer-dos.md)）利用合法协议语义，以极低带宽占满连接池、事件循环或后端 Worker。蓝队防御必须在网关、协议解析层和业务逻辑层同步建立硬边界：

| 攻击向量 | 协议瓶颈 | 核心防御机制 | 关键阈值 / 策略 |
|---|---|---|---|
| Slowloris 不完全请求 | Header 读取等待占满 `worker_connections` | 收紧请求头读取超时与最小传输速率 | `client_header_timeout 5s` + 单 IP 并发上限 |
| RUDY 慢速 POST Body | 声明大 `Content-Length` 后逐字节慢发 | 收紧请求体间隔超时、最小吞吐速率与体上限 | `client_body_timeout 10s` + Envoy `min_rate` |
| HTTP/2 Rapid Reset (CVE-2023-44487) | 高频 `HEADERS + RST_STREAM` 创建销毁竞争 | 升级内核/代理版本并限制单连接流重置速率 | Nginx `>=1.25.3` / Envoy `>=1.27.0` + `max_concurrent_streams` |
| WebSocket 连接洪泛与分片帧 | 长连接占用 FD、不完整分片帧挂起、超大帧预分配 | 连接数/握手速率限制、分片组装超时与最大帧长 | 单 IP WS 并发限制、最大帧 `64KB`、Ping/Pong 限频 |
| GraphQL 别名与嵌套轰炸 | 单 HTTP 请求放大为数千次解析与 DB 查询 | 静态 AST 别名/深度/节点复杂度预算与 DataLoader | `max_depth <= 6`、`max_aliases <= 15`、禁用生产 Introspection |
| TOCTOU 竞争窗口绕过 | 并发请求穿透非原子配额校验 | Redis Lua 单线程原子令牌桶 / 分布式锁 | `EVALSHA` 原子扣减，消除 Read-Check-Write 竞态 |

---

## 防御工作流

### 阶段一：网关与反向代理协议超时收紧（Slowloris / RUDY）

1. **采用事件驱动反向代理隔离后端进程**：禁止将 Apache `mpm_prefork` 等每连接一进程模型直接暴露公网，统一由 Nginx 或 Envoy 缓冲完整请求头与请求体后再转发至上游应用。
2. **设置严格的请求头/体读写超时与并发连接上限**：对未在规定窗口内发送完整 `\r\n\r\n` 的 Slowloris 连接快速返回 `408 Request Timeout` 并回收套接字；对 RUDY 慢速请求体设置每次读操作间隔超时与最小字节速率要求。
3. **关闭不必要的大请求体缓冲与长 Keep-Alive 空闲窗**：按业务端点精细配置 `client_max_body_size` 与 `keepalive_timeout`。

#### Nginx 生产级加固配置（对抗 Slowloris、RUDY、WebSocket 洪泛与泛化 UA/IP 绕过）

```nginx
# /etc/nginx/conf.d/app_dos_hardening.conf
# 1. 连接与请求速率限制区（在真实代理链路下使用可信代理还原真实客户端 IP）
limit_conn_zone $binary_remote_addr zone=per_ip_conn:20m;
limit_req_zone  $binary_remote_addr zone=per_ip_req:20m rate=30r/s;
limit_req_zone  $binary_remote_addr zone=ws_handshake:10m rate=5r/s;

# 2. HTTP/1.1 与 HTTP/2 慢速连接收紧
server {
    listen 443 ssl http2;
    server_name app.example.internal;

    # Slowloris 防护：5 秒内必须完成请求头传输
    client_header_timeout 5s;
    # RUDY 防护：两次请求体读操作间隔不超过 10 秒，且发送超时 10 秒
    client_body_timeout 10s;
    send_timeout 10s;
    # 限制请求头与请求体尺寸
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    client_max_body_size 10m;

    # 限制 Keep-Alive 复用上限，防止长连接长期滞留
    keepalive_timeout 15s;
    keepalive_requests 200;
    reset_timedout_connection on;

    # HTTP/2 Rapid Reset (CVE-2023-44487) 加固（需 Nginx >= 1.25.3）
    http2_max_concurrent_streams 64;
    http2_recv_timeout 10s;

    # 通用并发与速率保护
    limit_conn per_ip_conn 30;
    limit_conn_status 429;
    limit_req zone=per_ip_req burst=60 nodelay;
    limit_req_status 429;

    location / {
        proxy_pass http://app_backend;
        proxy_request_buffering on;   # 缓冲完整请求后再唤醒后端 Worker
        proxy_connect_timeout 3s;
        proxy_read_timeout 30s;
        proxy_send_timeout 15s;
    }

    # WebSocket 端点专项隔离
    location /ws {
        limit_req zone=ws_handshake burst=10 nodelay;
        limit_conn per_ip_conn 5;     # 单 IP 严格限制长连接数量

        proxy_pass http://ws_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        # 未在 60 秒内完成有效数据交换则回收空闲连接
        proxy_read_timeout 60s;
        proxy_send_timeout 15s;
    }
}
```

### 阶段二：HTTP/2 Rapid Reset（CVE-2023-44487）缓解

1. **升级已打补丁的 HTTP/2 实现**：Nginx `>= 1.25.3`、Apache `>= 2.4.58`、Envoy `>= 1.27.0`、Go `>= 1.21.4`、Node.js `>= 20.8.0 / 18.19.0`。
2. **启用无效流重置计数与 GOAWAY 强制断连**：在 Envoy 中启用流空闲超时、请求头超时及单连接流总数上限，并对短时间内发送大量 `RST_STREAM` 的连接返回 `GOAWAY(ENHANCE_YOUR_CALM)` 立即关闭 TCP 连接。

#### Envoy 网关抗 Rapid Reset 与慢速流配置

```yaml
# envoy-http2-hardening.yaml
static_resources:
  listeners:
    - name: https_listener
      address:
        socket_address: { address: 0.0.0.0, port_value: 443 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                request_headers_timeout: 5s
                stream_idle_timeout: 30s
                common_http_protocol_options:
                  idle_timeout: 60s
                  max_requests_per_connection: 1000
                  max_headers_count: 64
                http2_protocol_options:
                  max_concurrent_streams: 64
                  initial_stream_window_size: 65536
                  initial_connection_window_size: 1048576
                  max_outbound_frames: 10000
                  max_outbound_control_frames: 1000
                  max_consecutive_inbound_frames_with_empty_payload: 1
                  max_inbound_priority_frames_per_stream: 10
                  max_inbound_window_update_frames_per_data_frame_sent: 10
```

### 阶段三：WebSocket 与 GraphQL 应用协议层硬限

1. **WebSocket 防护**：
   - 在握手阶段校验证书/Origin 与认证 Token（拒绝未认证匿名建连）；
   - 设置最大帧负载（如 `max_size=65536`）与分片组装超时（如 `fragment_timeout=5s`），防止帧碎片挂起和声明 `2^63` 长度时的预分配 OOM；
   - 对客户端控制帧（Ping）做令牌桶限流（例如每秒最多 2 次 Ping）。
2. **GraphQL 防护**：
   - 解析执行前进行静态 AST 预算检查：限制最大嵌套深度（`<= 6`）、最大别名数（`<= 15`）、总查询复杂度分值（Cost Analysis）；
   - 启用 Persisted Queries（白名单哈希查询），在生产环境仅放行预注册查询语句；
   - 结合 DataLoader 批处理合并相同实体查询，消除 `N+1` 放大。

### 阶段四：消除 TOCTOU 竞争窗口与对抗检测规避

1. **原子化配额校验**：将“读取余额/配额 -> 判断 -> 扣减”合并为单次 Redis Lua 脚本或数据库行级乐观锁（`UPDATE quotas SET remaining = remaining - 1 WHERE user_id = $1 AND remaining > 0`），彻底封死并发窗口穿透。
2. **对抗 UA / IP / JA3 轮换**：限流键禁止仅依赖 `User-Agent` 或客户端可伪造头；对认证 API 绑定 `user_id / tenant_id` 维度限流，对匿名边缘接口结合 ASN/CIDR 聚合速率控制与 TLS 指纹异常基线。

```lua
-- atomic_rate_limit.lua : Redis 原子滑动窗口限流（消除 TOCTOU 竞态）
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
local current = redis.call('ZCARD', key)
if current >= limit then
    return {0, current}
end
redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms)
return {1, current + 1}
```

---

## 弹性校验代码（可运行 Python 自检）

以下脚本用于在 CI 或预发布环境本地校验三类核心应用层防护机制：GraphQL 别名/深度复杂度守卫、WebSocket 帧长/分片限制检查，以及线程并发下的原子配额器与 HTTP 网关超时配置检查。

```python
#!/usr/bin/env python3
"""Application-layer DoS defense verifier (GraphQL, WebSocket frame guard, atomic quota)."""

import re
import threading
import time
from dataclasses import dataclass


@dataclass
class GraphQLBudget:
    max_depth: int = 6
    max_aliases: int = 15
    max_fields: int = 80


def validate_graphql_query(query: str, budget: GraphQLBudget = GraphQLBudget()) -> tuple[bool, str]:
    """Static complexity guard against GraphQL alias bombing and deep nesting."""
    stripped = re.sub(r"#.*", "", query)
    depth = 0
    max_seen_depth = 0
    for ch in stripped:
        if ch == "{":
            depth += 1
            max_seen_depth = max(max_seen_depth, depth)
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False, "unbalanced braces"
    if depth != 0:
        return False, "unclosed braces"
    if max_seen_depth > budget.max_depth:
        return False, f"depth {max_seen_depth} exceeds limit {budget.max_depth}"

    aliases = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_]*", stripped)
    if len(aliases) > budget.max_aliases:
        return False, f"aliases {len(aliases)} exceeds limit {budget.max_aliases}"

    tokens = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
    if len(tokens) > budget.max_fields:
        return False, f"field tokens {len(tokens)} exceeds limit {budget.max_fields}"
    return True, "ok"


def validate_ws_frame_header(fin: bool, opcode: int, payload_len: int,
                             pending_fragments: int, max_frame_bytes: int = 65536,
                             max_fragments: int = 8) -> tuple[bool, str]:
    """Reject oversized WebSocket frames and unbounded fragmentation chains."""
    if payload_len < 0 or payload_len > max_frame_bytes:
        return False, f"payload_len {payload_len} exceeds {max_frame_bytes}"
    if opcode == 0x0 or not fin:
        if pending_fragments + 1 > max_fragments:
            return False, f"fragment count {pending_fragments + 1} exceeds {max_fragments}"
    return True, "ok"


class AtomicQuota:
    """Thread-safe quota counter eliminating TOCTOU race windows."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    def try_consume(self) -> bool:
        with self._lock:
            if self._used >= self._limit:
                return False
            self._used += 1
            return True


def run_self_checks() -> None:
    # 1. GraphQL 别名轰炸拦截校验
    alias_bomb = "query { " + " ".join(f"a{i}: user(id:{i}) {{ name }}" for i in range(50)) + " }"
    ok, reason = validate_graphql_query(alias_bomb)
    assert not ok and "aliases" in reason, f"Expected alias block, got {ok}, {reason}"

    deep_query = "query { " + "a { " * 8 + "id " + "} " * 8 + "}"
    ok, reason = validate_graphql_query(deep_query)
    assert not ok and "depth" in reason, f"Expected depth block, got {ok}, {reason}"

    normal_query = "query { me: user(id:1) { id name } }"
    ok, reason = validate_graphql_query(normal_query)
    assert ok, f"Normal query rejected: {reason}"

    # 2. WebSocket 帧长与分片数量边界校验
    ok, _ = validate_ws_frame_header(fin=False, opcode=0x1, payload_len=1024, pending_fragments=8)
    assert not ok, "Excessive fragments should be rejected"
    ok, _ = validate_ws_frame_header(fin=True, opcode=0x2, payload_len=10_000_000, pending_fragments=0)
    assert not ok, "Oversized frame should be rejected"

    # 3. 高并发 TOCTOU 配额压测校验（50 线程同时抢占 10 个配额）
    quota = AtomicQuota(limit=10)
    granted = []
    barrier = threading.Barrier(50)

    def worker() -> None:
        barrier.wait(timeout=2)
        if quota.try_consume():
            granted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(granted) == 10, f"TOCTOU leak detected: granted {len(granted)} != 10"
    print("[PASS] All application-layer DoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| Slowloris / RUDY 慢速连接 | 不完整 Header 在 `<= 5s` 返回 `408`；逐字节慢 POST 在 `<= 10s` 被断连回收 | `worker_connections` 占用率维持 `< 20%`，正常 `/health` P99 `< 100ms` |
| HTTP/2 Rapid Reset | 发送批量 `HEADERS + RST_STREAM` 后被网关发送 `GOAWAY` 断开且 CPU 无毛刺 | 单连接 `RST_STREAM/s` 被限流，代理进程 CPU `< 30%` |
| WebSocket 帧与连接保护 | 超出单 IP 并发限制返回 `429`；分片超限或超长帧被服务端立即 `Close(1009)` | FD 数量稳定在阈值内，无 OOM 增长 |
| GraphQL 复杂度拦截 | 别名 `> 15` 或深度 `> 6` 的查询在 AST 解析阶段直接返回 `400` 且未触发 DB 查询 | 后端数据库 QPS 无伴随放大 |
| 原子配额防并发穿透 | 并发突发请求严格受限于单窗口配额上限，无超额放行 | `429` 准确计数，资源扣减与配额记录零偏差 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 网关响应与超时核验 | `http_probe` | 检查目标端点 HTTP/2 ALPN、限流响应码（408/429）与延迟基线 |
| 防御方案检索 | `kb_router` | 以 `track="blue"` 检索应用层 DoS、HTTP/2、GraphQL 防护条目 |
| 攻防对照查阅 | `kb_read_file` | 读取本防御文档及配对攻击文档 `ctf-website/22-dos/01-application-layer-dos` |
| 目录清单查询 | `kb_catalog` | 列举 `22-dos` 分类下全部蓝队与红队条目 |
