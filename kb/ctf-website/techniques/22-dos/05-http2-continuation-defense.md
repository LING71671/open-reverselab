---
id: "ctf-website/22-dos/05-http2-continuation-defense"
title: "HTTP/2 CONTINUATION Flood 与 H2/H3 协议弹性防御"
title_en: "HTTP/2 CONTINUATION Flood and H2/H3 Resilience Defense"
summary: >
  针对 HTTP/2 CONTINUATION Flood（CVE-2024-27316）、HPACK 动态表解压炸弹、Stream 优先级带宽饥饿以及 HTTP/3 QUIC Connection ID 耗尽、0-RTT 重放和版本协商风暴的系统防御方案。提供主流代理修复版本基线、Nginx/Envoy 帧预算与缓冲区配置，以及 Python 帧状态机校验代码。
summary_en: >
  Defense guide against HTTP/2 CONTINUATION Flood (CVE-2024-27316), HPACK dynamic table bombs, Stream Priority starvation, and HTTP/3 QUIC CID exhaustion, 0-RTT replay, and Version Negotiation floods. Includes patched version baselines, Nginx/Envoy frame budget configs, and Python frame state-machine checks.
board: "ctf-website"
category: "22-dos"
signals:
  - "CONTINUATION 帧数与头部总字节上限"
  - "SETTINGS_HEADER_TABLE_SIZE 限制"
  - "RFC 9218 可扩展优先级替旧优先级"
  - "QUIC Retry 地址验证与 0-RTT 反重放"
  - "CVE-2024-27316 补丁版本核验"
  - "GOAWAY ENHANCE_YOUR_CALM 断连"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "CONTINUATION Flood 防御"
  - "CVE-2024-27316 修复"
  - "HPACK Bomb 防护"
  - "HTTP/2 帧限制"
  - "QUIC 防护"
  - "HTTP/3 抗重放"
  - "Envoy HTTP/2 加固"
  - "http2 continuation defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "http2"
  - "http3"
  - "quic"
  - "hpack"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/05-http2-continuation"
track: "blue"
defends: "ctf-website/22-dos/05-http2-continuation"
---
# HTTP/2 CONTINUATION Flood 与 H2/H3 协议弹性防御

## 防御目标与对抗矩阵

HTTP/2 与 HTTP/3 的底层多路复用和压缩机制（对应攻击技术见 [05-http2-continuation.md](./05-http2-continuation.md)）常在边缘网关层造成内存 OOM 或合法流饥饿。蓝队需通过**版本升级补齐状态机缺陷 + 帧级/头部硬上限 + QUIC 无状态校验**建立全面防线。

| 攻击向量 | 底层弱点 | 核心防御措施 | 关键配置 / 补丁版本 |
|---|---|---|---|
| CONTINUATION Flood (CVE-2024-27316) | 未收齐 `END_HEADERS` 前持续堆叠帧导致 OOM | 升级修复版本并限定单流最大头部字节与连续帧数量 | Nginx `>=1.26.0`、Apache `>=2.4.60`、Envoy `>=1.29.3`、Go `>=1.22.1` |
| HPACK Bomb 动态表放大 | 极小索引帧反复引用动态表内 4KB 条目 | 下调 `SETTINGS_HEADER_TABLE_SIZE` 并限制解压后总头部字节 | `HEADER_TABLE_SIZE <= 4096`、`MAX_HEADER_LIST_SIZE <= 16384` |
| Stream 优先级饥饿 | 旧版依赖树权重可被大量高权重挂起流占满调度 | 禁用 RFC 7540 旧优先级树调度，升级至 RFC 9218 可扩展优先级 | 配置并发流上限 `<= 64` 与每流空闲超时 |
| QUIC CID / 0-RTT / VN 风暴 | 伪造 CID 建表耗尽、0-RTT 重放放大、无校验回包 | 强制启用 QUIC Retry Token、限制单 IP CID 表容量与 0-RTT 幂等白名单 | 开启 `Retry`、限制单连接 CID 数量（`active_connection_id_limit=2`） |

---

## 防御工作流

### 阶段一：强制升级受影响 HTTP/2 运行时

针对 CVE-2024-27316，旧版本即使配置常规超时仍可能因单连接内高密度 `CONTINUATION` 帧触发 OOM，必须优先完成以下基线版本升级：

| 组件 | 最低已修复版本 |
|---|---|
| Nginx | `1.26.0`（或 `1.25.5` 主线及以上） |
| Apache httpd | `2.4.60` |
| Envoy | `1.29.3` / `1.28.2` |
| Go `net/http` (`x/net/http2`) | Go `1.22.1` / `1.21.8`（`x/net v0.23.0`） |
| Node.js | `21.6.2` / `20.12.1` / `18.20.1` |
| Netty / Tomcat / Jetty | Netty `4.1.108.Final` / Tomcat `10.1.20` / Jetty `12.0.8` |

### 阶段二：HTTP/2 帧预算、HPACK 解压上限与流隔离配置

1. **Nginx HTTP/2 头部与流控收紧**：限制单连接并发流、请求头缓冲区和读超时，避免 `CONTINUATION` 与 `HPACK` 解压后内存失控。

```nginx
# /etc/nginx/conf.d/h2_hardening.conf (Nginx >= 1.26.0)
server {
    listen 443 ssl;
    http2 on;
    server_name api.example.internal;

    # 限制单连接并发流，阻断海量挂起流与流饥饿
    http2_max_concurrent_streams 64;
    # 严格限制完整请求头读取超时与单帧后缓冲区上限
    client_header_timeout 5s;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    # 限制连接总体生命周期及最大请求数，强制周期性重建干净状态
    keepalive_requests 500;
    keepalive_timeout 20s;
    reset_timedout_connection on;
}
```

2. **Envoy HTTP/2 与 HTTP/3 (QUIC) 帧预算加固**：使用 Envoy 原生帧限制字段阻止 `CONTINUATION` 泛滥、HPACK 膨胀和无载荷控制帧风暴。

```yaml
# envoy-h2-h3-hardening.yaml
common_http_protocol_options:
  idle_timeout: 30s
  max_headers_count: 64
  max_requests_per_connection: 1000
max_request_headers_kb: 16
request_headers_timeout: 5s
stream_idle_timeout: 20s
http2_protocol_options:
  max_concurrent_streams: 64
  hpack_table_size: 4096
  max_outbound_frames: 5000
  max_outbound_control_frames: 500
  max_consecutive_inbound_frames_with_empty_payload: 1
  max_inbound_priority_frames_per_stream: 4
http3_protocol_options:
  allow_extended_connect: false
  quic_protocol_options:
    max_concurrent_streams: 64
    initial_stream_window_size: 65536
    initial_connection_window_size: 1048576
```

### 阶段三：HTTP/3 QUIC 地址校验与 0-RTT 反重放

1. **高并发下开启 QUIC Retry Token**：当未知源地址的 `Initial` 包速率超过阈值时，边缘节点通过无状态加密 Retry Token 强制验证源 IP 可达性后再分配服务端连接状态与 CID 映射表项，防止随机 CID 耗尽连接表。
2. **抑制 0-RTT 重放放大**：
   - 非绝对幂等端点（特别是涉及计算或数据库写入的 POST/查询）**严禁接受 TLS 1.3 / QUIC 0-RTT early data**，或强制服务端返回 `425 Too Early`；
   - 部署跨边缘节点共享的 Anti-Replay Bloom Filter（按时间窗口轮转），阻断同一 `ClientHello` 0-RTT 载荷的多重重放。
3. **版本协商（Version Negotiation）限速**：对连续发送无效 QUIC 版本号的同一源 IP/网段执行令牌桶限流，避免上行链路被 VN 包填充。

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 代码模拟并验证服务端 HTTP/2 帧状态机守卫：针对 `HEADERS` + `CONTINUATION` 未收齐 `END_HEADERS`、单流连续 `CONTINUATION` 帧数超限、HPACK 解压后字节膨胀与单连接无休止重置流给出明确拒绝判定，同时提供组件版本合规检查。

```python
#!/usr/bin/env python3
"""HTTP/2 CONTINUATION flood, HPACK bomb, and patched-version compliance verifier."""

from dataclasses import dataclass


@dataclass
class H2Limits:
    max_header_list_bytes: int = 16384
    max_continuation_frames: int = 4
    max_hpack_table_size: int = 4096
    max_concurrent_streams: int = 64
    max_resets_per_window: int = 20


class H2FrameGuard:
    """Simulated HTTP/2 connection frame budget guard."""

    def __init__(self, limits: H2Limits = H2Limits()) -> None:
        self.limits = limits
        self.open_streams: dict[int, dict[str, int | bool]] = {}
        self.reset_count = 0

    def on_headers(self, stream_id: int, end_headers: bool, inflated_bytes: int) -> tuple[bool, str]:
        if len(self.open_streams) >= self.limits.max_concurrent_streams:
            return False, "GOAWAY:MAX_CONCURRENT_STREAMS"
        if inflated_bytes > self.limits.max_header_list_bytes:
            return False, "GOAWAY:ENHANCE_YOUR_CALM(HPACK_BOMB)"
        self.open_streams[stream_id] = {
            "header_bytes": inflated_bytes,
            "cont_frames": 0,
            "headers_done": end_headers,
        }
        return True, "ok"

    def on_continuation(self, stream_id: int, end_headers: bool, inflated_bytes: int) -> tuple[bool, str]:
        st = self.open_streams.get(stream_id)
        if not st or st["headers_done"]:
            return False, "GOAWAY:PROTOCOL_ERROR"
        st["cont_frames"] = int(st["cont_frames"]) + 1
        st["header_bytes"] = int(st["header_bytes"]) + inflated_bytes
        if int(st["cont_frames"]) > self.limits.max_continuation_frames:
            return False, "GOAWAY:ENHANCE_YOUR_CALM(CONTINUATION_FLOOD)"
        if int(st["header_bytes"]) > self.limits.max_header_list_bytes:
            return False, "GOAWAY:ENHANCE_YOUR_CALM(HEADER_SIZE)"
        if end_headers:
            st["headers_done"] = True
        return True, "ok"

    def on_rst_stream(self, stream_id: int) -> tuple[bool, str]:
        self.open_streams.pop(stream_id, None)
        self.reset_count += 1
        if self.reset_count > self.limits.max_resets_per_window:
            return False, "GOAWAY:ENHANCE_YOUR_CALM(RAPID_RESET)"
        return True, "ok"


PATCHED_MIN_VERSIONS = {
    "nginx": (1, 26, 0),
    "apache_httpd": (2, 4, 60),
    "envoy": (1, 29, 3),
    "nodejs": (21, 6, 2),
}


def check_version_patched(product: str, version_tuple: tuple[int, int, int]) -> bool:
    min_ver = PATCHED_MIN_VERSIONS[product]
    return version_tuple >= min_ver


def run_self_checks() -> None:
    # 1. CONTINUATION Flood 拦截校验
    guard = H2FrameGuard()
    ok, _ = guard.on_headers(stream_id=1, end_headers=False, inflated_bytes=512)
    assert ok
    for i in range(4):
        ok, _ = guard.on_continuation(stream_id=1, end_headers=False, inflated_bytes=512)
        assert ok
    ok, reason = guard.on_continuation(stream_id=1, end_headers=False, inflated_bytes=512)
    assert not ok and "CONTINUATION_FLOOD" in reason

    # 2. HPACK 解压炸弹拦截校验
    guard2 = H2FrameGuard()
    ok, reason = guard2.on_headers(stream_id=3, end_headers=True, inflated_bytes=65536)
    assert not ok and "HPACK_BOMB" in reason

    # 3. 版本补丁合规校验
    assert check_version_patched("nginx", (1, 26, 1))
    assert not check_version_patched("nginx", (1, 25, 2))
    assert check_version_patched("envoy", (1, 29, 3))
    print("[PASS] All HTTP/2 CONTINUATION & H2/H3 defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| CVE-2024-27316 版本合规 | 全网网关与后端 HTTP/2 运行时均处于已修复版本基线之上 | 版本盘点零高危滞后节点 |
| CONTINUATION 帧拦截 | 超过 `max_continuation_frames` 或未收齐 `END_HEADERS` 超时即发送 `GOAWAY` 断连 | 代理进程 RSS 内存平缓，无线性飙升 |
| HPACK 解压上限 | 解压后头部总字节超过 `16KB` 立即返回 `431` 或断连 | 内存分配峰值受控在配置缓冲区内 |
| QUIC 抗放大与 0-RTT 防护 | 启用 Retry Token；非幂等路由对 0-RTT 返回 `425 Too Early` | CID 映射表占用率 `< 40%`，无重放放大 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| ALPN 与 H2/H3 协议核验 | `http_probe` | 检验目标端点是否通告 h2/h3、并发流与 431/GOAWAY 行为 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 检索 `continuation` / `http2` / `quic` 防御指南 |
| 攻防对照查阅 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/05-http2-continuation` |
| 分类清单查询 | `kb_catalog` | 列举 `22-dos` 全部可用防御文档 |
