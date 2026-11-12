---
id: "ctf-website/02-auth/jwt/01-alg-none-defense"
title: "JWT alg:none 无签名绕过防御"
title_en: "JWT alg:none Signature Bypass Defense"
summary: >
  针对 JWT alg:none 无签名绕过攻击及其大小写混淆（None/NONE/nOnE）、空算法（alg=""）、缺失 alg 字段、算法数组（["none","HS256"]）及双点空签名绕过，提供严格服务端算法白名单校验、多语言安全解码配置、网关与后端双解析器一致化策略，以及可运行的 Python 验证测试脚本。
summary_en: >
  Defensive guide against JWT alg:none signature bypass and variants including case-mixing, empty alg, missing alg, array alg injection, and trailing empty signatures. Provides strict server-side algorithm allowlisting, multi-language safe decoder settings, and runnable Python verification checks.
board: "ctf-website"
category: "02-auth"
signals: ["alg:none", "none算法", "无签名防御", "算法白名单", "JWT", "InvalidAlgorithmError"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["alg:none防御", "禁用none算法", "JWT算法白名单", "无签名拦截", "PyJWT algorithms"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "signature-verification"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/01-alg-none", "ctf-website/02-auth/jwt/00-overview-defense", "ctf-website/02-auth/jwt/02-algorithm-confusion-defense"]
track: "blue"
defends: "ctf-website/02-auth/jwt/01-alg-none"
---

# JWT `alg: none` 无签名绕过防御

`alg: none` 绕过的核心漏洞在于**把“选择用什么算法验证”的决定权交给未受信任的 Token Header**，或服务端允许缺省/空签名路径通过。防线不仅要拒绝小写 `"none"`，还要覆盖大小写变体、空字符串、数组类型以及网关与后端之间的双解析差异。

## 变体向量与防御控制

| 攻击变体 | 绕过机制 | 强制防御控制 |
|---|---|---|
| 标准 `{"alg":"none"}` | 验签库启用了调试模式或允许不安全算法 | 验证函数强制传入单元素或固定非 `none` 算法白名单（如 `["RS256"]`） |
| 大小写混淆 (`None`, `NONE`, `nOnE`) | 黑名单只过滤精确小写 `"none"` | 严禁使用黑名单；必须先校验 `isinstance(alg, str)` 再做精确白名单成员匹配 |
| 空算法 / 缺失 `alg` (`""`, `{}`) | 条件分支 `if alg == "none"` 未命中却 fallback 到无验签 | 显式拒绝非字符串或不在 `ALLOWED_ALGORITHMS` 中的任何 `alg` 值 |
| 算法数组 (`{"alg":["none","HS256"]}`) | 解析逻辑与验签逻辑读取不同下标或受类型混淆影响 | 强类型校验 `header["alg"]` 必须为非空 `str`，否则直接拒绝 |
| 空签名双点 Token (`H.P.`) 或非法字符 | 仅检查 `.split(".")` 长度为 3 而不检查签名段非空 | 解码前预检第 3 段长度必须大于最小签名字节数（如 HS256 至少 32 字节 Base64URL 编码即 43 字符） |
| 网关与后端双解析窗口 | 网关只验非 `none` 或跳过空签名，后端信任网关透传 payload | 网关与业务服务共用同一套强算法白名单；后端独立验签或强制校验内部 mTLS 签名断言 |

## 防御工作流

```text
1. 预处理结构与类型校验
   └─ 验证 Token 恰有 3 段，且 Header/Payload 为 JSON 对象、Signature 段非空且达到最低字节长度
2. 算法参数强白名单（Allowlist Only）
   └─ 显式配置 ALLOWED_ALGORITHMS（如 {"RS256"} 或 {"HS256"}），绝不使用黑名单排除 "none"
3. 禁用高危库调用方式
   └─ 禁止调用 decode(..., verify=False) / options={"verify_signature": False} / parseClaimsJwt()（无签名解析方法）
4. 网关与微服务一致性锁定
   └─ API 网关（Kong/Envoy/Nginx）与上游服务同时执行算法白名单，防止其中一层放行无签名 Token
5. 错误输出归一化
   └─ 不向客户端回显 "Algorithm none is not allowed" 等具体分支文本，统一返回 401 Unauthorized
```

### 多语言安全配置参考

```python
# Python (PyJWT >= 2.x)：显式传入固定算法白名单并开启 require 校验
import jwt

ALLOWED_ALGORITHMS = ["RS256"]  # 严禁同时混入对称与非对称算法，更不能包含 none


def verify_jwt_strict(token: str, public_key: str) -> dict:
    return jwt.decode(
        token,
        key=public_key,
        algorithms=ALLOWED_ALGORITHMS,
        options={
            "verify_signature": True,
            "require": ["exp", "iss", "sub"],
        },
        issuer="https://auth.example.com",
    )
```

```javascript
// Node.js (jsonwebtoken)：强制 algorithms 白名单且禁止空密钥回调
const jwt = require("jsonwebtoken");

function verifyTokenStrict(token, publicKeyPem) {
  return jwt.verify(token, publicKeyPem, {
    algorithms: ["RS256"], // 显式白名单，自动拒绝 none 与 HS256
    issuer: "https://auth.example.com",
  });
}
```

```java
// Java (jjwt >= 0.12)：使用 parseSignedClaims 而非允许无签名 Token 的 parseClaimsJwt
Claims claims = Jwts.parser()
    .verifyWith(publicKey)
    .requireIssuer("https://auth.example.com")
    .build()
    .parseSignedClaims(token)
    .getPayload();
```

### 自包含 Python 预处理与白名单验证器

```python
import base64
import hashlib
import hmac
import json

ALLOWED_ALGS = frozenset({"HS256"})
MIN_SIG_BYTES = {"HS256": 32}


def _b64u_decode(seg: str) -> bytes:
    if not seg:
        raise ValueError("empty segment")
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_and_verify_no_none(token: str, secret: bytes) -> dict:
    """严格拒绝任何 alg:none、大小写变体、空算法、数组算法及空签名 Token。"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT segment count")
    h_b64, p_b64, s_b64 = parts
    if not s_b64:
        raise ValueError("empty signature rejected")

    header = json.loads(_b64u_decode(h_b64))
    if not isinstance(header, dict):
        raise ValueError("header must be JSON object")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
        raise ValueError("algorithm not in allowlist")

    sig_bytes = _b64u_decode(s_b64)
    if len(sig_bytes) < MIN_SIG_BYTES[alg]:
        raise ValueError("signature too short")

    expected = hmac.new(secret, f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig_bytes):
        raise ValueError("invalid signature")

    payload = json.loads(_b64u_decode(p_b64))
    if not isinstance(payload, dict):
        raise ValueError("payload must be JSON object")
    return payload
```

## 验证与判定标准

运行下方脚本验证 [01-alg-none.md](01-alg-none.md) 中列出的全部无签名与算法变体均被拦截：

```python
def run_alg_none_defense_checks() -> None:
    def b64u(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    secret = b"S" * 32
    payload = {"sub": "admin", "role": "admin"}
    attack_headers = [
        {"alg": "none", "typ": "JWT"},
        {"alg": "None", "typ": "JWT"},
        {"alg": "NONE", "typ": "JWT"},
        {"alg": "NoNe", "typ": "JWT"},
        {"alg": ["none", "HS256"], "typ": "JWT"},
        {"alg": "", "typ": "JWT"},
        {"typ": "JWT"},
        {"alg": "FAKE", "typ": "JWT"},
    ]
    for h in attack_headers:
        forged_empty_sig = f"{b64u(h)}.{b64u(payload)}."
        forged_fake_sig = f"{b64u(h)}.{b64u(payload)}.AA"
        for tok in (forged_empty_sig, forged_fake_sig):
            try:
                decode_and_verify_no_none(tok, secret)
            except ValueError:
                pass
            else:
                raise AssertionError(f"alg:none variant bypassed defense: {h}")

    msg = f"{b64u({'alg': 'HS256', 'typ': 'JWT'})}.{b64u(payload)}"
    sig = base64.urlsafe_b64encode(hmac.new(secret, msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert decode_and_verify_no_none(f"{msg}.{sig}", secret)["sub"] == "admin"
    print("PASS: all alg:none defense checks passed")


if __name__ == "__main__":
    run_alg_none_defense_checks()
```

判定标准：
1. **全变体阻断**：`none`、`None`、`NONE`、`nOnE`、`""`、缺失 `alg`、`["none","HS256"]` 与 `FAKE` 无论是否带尾部签名字符均返回 `401`。
2. **源码扫描无危险模式**：代码库中不存在 `verify_signature=False`、`verify=False` 或 JJWT `parseClaimsJwt()` 调用（除非紧接独立签名阶段且被明确隔离在非认证场景）。
3. **跨层一致**：边缘网关与后端业务服务返回的拒绝状态码和错误响应体哈希完全一致。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `alg:none`、`算法白名单`、`无签名` 检索相关防护文档 |
| 规程读取 | `kb_read_file` | 读取 `01-alg-none-defense` 与 `08-cve-library-defense` |
| 目录索引核查 | `kb_catalog` | 检查 `02-auth/jwt/` 中算法与签名类防御文档清单 |
