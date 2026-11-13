---
id: "ctf-website/02-auth/jwt/02-algorithm-confusion-defense"
title: "JWT 非对称/对称算法混淆防御"
title_en: "JWT Algorithm Confusion (RS/ES to HS) Defense"
summary: >
  针对 JWT 算法混淆攻击（攻击者获取公开的 RS256/ES256 公钥或 JWKS/TLS 证书字节并将其作为 HS256 HMAC 对称密钥重签伪造 Token），提供算法族单向锁定、密钥对象类型强绑定（RSAPublicKey/ECPublicKey 拒绝进入 HMAC 验签）、JWK kty/alg 一致性校验与公钥格式隔离策略，并附可运行的 Python 验证代码。
summary_en: >
  Defensive guide against JWT algorithm confusion (reusing RS256/ES256 public keys or JWKS/TLS certs as HS256 HMAC secrets). Covers single-family algorithm pinning, strict key-type binding, JWK kty/alg validation, and runnable Python verification checks.
board: "ctf-website"
category: "02-auth"
signals: ["算法混淆", "RS256", "HS256", "JWKS", "HMAC", "密钥类型绑定", "PublicKey"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["算法混淆防御", "RS256转HS256防御", "JWT公钥安全", "密钥类型绑定", "algorithm confusion defense"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "cryptography", "algorithm-confusion"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/02-algorithm-confusion", "ctf-website/02-auth/jwt/01-alg-none-defense", "ctf-website/02-auth/jwt/05-jku-x5u-abuse-defense"]
track: "blue"
defends: "ctf-website/02-auth/jwt/02-algorithm-confusion"
---

# JWT 非对称/对称算法混淆防御

算法混淆（Algorithm Confusion）能够成立有两个缺一不可的前提：**第一，验签函数同时接受对称（`HS*`）和非对称（`RS*`/`ES*`/`PS*`）算法；第二，底层验签 API 允许把“公钥字节串/PEM 文本”直接当作 HMAC 原始字节密钥传入**。只要切断任一前提——更规范地应同时切断两者——公钥无论多公开（JWKS、OIDC、TLS 证书复用）都无法用于伪造签名。

## 攻击路径与防御控制映射

| 攻击向量 | 漏洞根因 | 强制防御措施 |
|---|---|---|
| RS256/ES256 → HS256 切换 | `algorithms=["RS256", "HS256"]` 混用，且共传同一个 `public_key` | 按业务线锁死**单一算法族**：对外验签仅允许 `["RS256"]` 或 `["ES256"]`，绝不混放 `HS*` |
| PEM / DER / JWK JSON / n 坐标当 HMAC secret | 旧版库对传入的 `str`/`bytes` 不区分是否为公钥结构，直接喂给 `hmac.new` | 使用强类型密钥对象（如 `cryptography` 的 `RSAPublicKey`、`ECPublicKey`），并在 HMAC 分支显式拒绝含 `BEGIN PUBLIC KEY` 或 JWK 非 `oct` 类型的密钥 |
| JWKS 端点返回密钥未校验 `kty` 与 `alg` | 只按 `kid` 从 JWKS 取键，未核对 JWK 的 `kty`（`RSA`/`EC`）与 `use="sig"` | 从 JWKS 构造验证器时强制检查 `jwk["kty"]`、`jwk["alg"] == EXPECTED_ALG` 与 `jwk["use"] == "sig"` |
| 多 Token 公钥恢复 + TLS 证书共用密钥 | JWT 与 HTTPS TLS 证书共用同一 RSA 密钥对 | 将 JWT 签名密钥对与 TLS 证书密钥对物理分离，定期轮换独立 JWKS 密钥 |

## 防御工作流

```text
1. 锁定服务端验证算法族
   └─ 明确区分：对外验证一律采用非对称签名（RS256 / ES256 / EdDSA），禁用 HS* 分支
2. 密钥对象强类型化（Type-Safe Key Loading）
   └─ 启动加载公钥时即解析为 RSAPublicKey / ECPublicKey 实例，不在运行时保留原始 PEM 字节流给通用接口
3. JWK 元数据一致性检查
   └─ 解析 JWKS 时校验 kty 与预期算法匹配（RSA -> RS256/PS256，EC -> ES256），拒绝 kty=oct 混入公钥集
4. 升级高版本安全验签库
   └─ 升级 PyJWT (>=2.4+)、jsonwebtoken (>=9.0.0) 等自带公钥 PEM 拒入 HMAC 检测的版本，并仍保持单算法白名单
5. 密钥用途隔离
   └─ JWT 签名私钥不与 TLS 证书私钥共用，即使证书公钥可被 openssl s_client 提取也与 JWT 无关
```

### 类型安全算法锁定与防混淆验证器（Python）

```python
import base64
import json
from typing import Any


class AlgorithmConfusionError(Exception):
    """拒绝算法混淆、密钥类型不匹配与混用分支。"""


def _b64u_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class StrictAsymmetricVerifier:
    """仅接受固定非对称算法与强类型公钥描述符，彻底封闭 HMAC 分支。"""

    EXPECTED_KTY_BY_ALG = {
        "RS256": "RSA",
        "PS256": "RSA",
        "ES256": "EC",
    }

    def __init__(self, expected_alg: str, jwk_keyset: dict[str, dict[str, Any]]) -> None:
        if expected_alg not in self.EXPECTED_KTY_BY_ALG:
            raise ValueError(f"unsupported or symmetric algorithm disallowed: {expected_alg}")
        self.expected_alg = expected_alg
        self.expected_kty = self.EXPECTED_KTY_BY_ALG[expected_alg]
        self.keyset = self._validate_keyset(jwk_keyset)

    def _validate_keyset(self, raw_keys: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        validated: dict[str, dict[str, Any]] = {}
        for kid, jwk in raw_keys.items():
            if jwk.get("kty") != self.expected_kty:
                raise AlgorithmConfusionError(f"key {kid} kty mismatch: {jwk.get('kty')}")
            if jwk.get("use", "sig") != "sig":
                raise AlgorithmConfusionError(f"key {kid} not marked for signature")
            if "alg" in jwk and jwk["alg"] != self.expected_alg:
                raise AlgorithmConfusionError(f"key {kid} alg mismatch: {jwk['alg']}")
            validated[kid] = jwk
        return validated

    def preflight_verify(self, token: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise AlgorithmConfusionError("invalid JWT structure")
        header = json.loads(_b64u_decode(parts[0]))
        if not isinstance(header, dict):
            raise AlgorithmConfusionError("header must be object")

        alg = header.get("alg")
        # 关键防线：任何 HS*、大小写变体或非预期算法直接拒绝，绝不进入 HMAC 路径
        if not isinstance(alg, str) or alg != self.expected_alg:
            raise AlgorithmConfusionError(f"algorithm {alg!r} rejected; expected {self.expected_alg}")

        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self.keyset:
            raise AlgorithmConfusionError("unknown kid")

        payload = json.loads(_b64u_decode(parts[1]))
        return header, payload, self.keyset[kid]


def guard_hmac_key_material(key_bytes: bytes) -> None:
    """若内部服务确实使用 HS256，防止误传入公钥 PEM/DER/JWK 字节。"""
    if b"BEGIN PUBLIC KEY" in key_bytes or b"BEGIN RSA PUBLIC KEY" in key_bytes or b"BEGIN CERTIFICATE" in key_bytes:
        raise AlgorithmConfusionError("public PEM/certificate material cannot be used as HMAC secret")
    if key_bytes.lstrip().startswith(b"{") and b'"kty"' in key_bytes:
        raise AlgorithmConfusionError("JWK JSON material cannot be used as raw HMAC secret")
```

## 验证与判定标准

运行以下自检脚本验证 [02-algorithm-confusion.md](../../../../../red/ctf-website/techniques/02-auth/jwt/02-algorithm-confusion.md) 中的 RS→HS、大小写 `hs256`、`kty=oct` 混入与 PEM/JWK 误传 HMAC 均被阻断：

```python
def run_alg_confusion_checks() -> None:
    def b64u(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

    verifier = StrictAsymmetricVerifier(
        expected_alg="RS256",
        jwk_keyset={"rsa-1": {"kty": "RSA", "use": "sig", "alg": "RS256", "n": "abc", "e": "AQAB"}},
    )

    for bad_alg in ("HS256", "hs256", "HS384", "HS512", "ES256", "none"):
        tok = f"{b64u({'alg': bad_alg, 'kid': 'rsa-1'})}.{b64u({'sub': 'admin'})}.fakesig"
        try:
            verifier.preflight_verify(tok)
        except AlgorithmConfusionError:
            pass
        else:
            raise AssertionError(f"algorithm confusion not blocked for {bad_alg}")

    for bad_key in (
        b"-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----",
        b'{"kty":"RSA","n":"abc","e":"AQAB"}',
    ):
        try:
            guard_hmac_key_material(bad_key)
        except AlgorithmConfusionError:
            pass
        else:
            raise AssertionError("public key material accepted as HMAC key")

    print("PASS: all algorithm confusion defense checks passed")


if __name__ == "__main__":
    run_alg_confusion_checks()
```

判定标准：
1. **对称/非对称完全隔离**：使用公钥 PEM、DER 或 JWK JSON 按 `HS256`/`HS384`/`HS512` 重签 Token 请求资源接口时全部返回 `401`。
2. **JWK 类型强校验**：JWKS 中出现非预期 `kty` 或 `alg` 时，验签端在加载阶段即拒绝而非降级验证。
3. **密钥用途分离**：JWT 验证公钥的 SHA-256 指纹与站点 TLS 证书公钥指纹互不相同。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `算法混淆`、`RS256`、`JWKS` 检索对应防御条目 |
| 规程读取 | `kb_read_file` | 读取 `02-algorithm-confusion-defense` 与 `05-jku-x5u-abuse-defense` |
| 目录索引核查 | `kb_catalog` | 查看 `02-auth/jwt/` 中签名与密钥管理加固文档 |
