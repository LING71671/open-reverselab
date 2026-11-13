---
id: "general/signature/01-algorithm-defense"
title: "签名算法降级与混淆防御（服务端算法锁定 / 拒绝 alg=none / 密钥类型隔离）"
title_en: "Defense Against Signature Algorithm Downgrade and Confusion"
summary: >
  防御 JWT alg=none、支付回调 sign_type 降级（RSA->MD5）、RS256/HS256 公钥密钥混淆以及多算法回退漏洞：强制服务端算法白名单绑定、密钥对象强制校验用途与类型、禁用不安全算法回退路径。
summary_en: >
  Defense against JWT alg=none, payment callback sign_type downgrade, RS256-to-HS256 key confusion, and multi-algorithm fallback: server-side algorithm pinning, strict key-type binding, and elimination of unsafe fallback paths.
board: "general"
category: "signature"
signals:
  - "algorithm pinning"
  - "reject alg none"
  - "key confusion defense"
  - "sign_type allowlist"
  - "JWT hardening"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "algorithm downgrade defense"
  - "JWT alg none"
  - "RS256 HS256 confusion"
  - "sign_type"
  - "algorithm pinning"
difficulty: "intermediate"
tags:
  - "signature-defense"
  - "JWT"
  - "algorithm-pinning"
  - "crypto-defense"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/signature/01-algorithm"
  - "general/signature/00-overview-defense"
track: "blue"
defends: "general/signature/01-algorithm"
---
# 签名算法降级与混淆防御（服务端算法锁定 / 拒绝 alg=none / 密钥类型隔离）

## 防御目标

消除签名验证中因信任请求体/Header 指定算法（如 `alg`、`sign_type`、`algorithm`）导致的安全隐患，彻底拦截 `alg: none` 空签名、RSA 降级为 MD5/明文对比，以及将非对称公钥错误当作 HMAC 对称密钥的算法混淆攻击。

## 核心防御策略矩阵

| 攻击手法 | 根因模式 | 防御准则 | 实施校验 |
|---|---|---|---|
| `alg: none` / 空算法跳过 | 验签分支允许 `alg.lower() == "none"` 或缺失 `alg` 时直接信任 payload | 显式枚举允许的强算法集合（如 `{"EdDSA", "ES256"}` 或 `{"RS256"}`），绝不允许 `"none"` | Header 缺失 `alg` 或不在白名单内立即拒绝 |
| 回调 `sign_type` 降级 | 多分支 `if sign_type == "MD5": ... elif "RSA": ...` 允许客户端任选 | 商户/接口配置端绑定唯一强制算法，不读取请求参数中的 `sign_type` 决定校验函数 | 请求中 `sign_type != 商户绑定算法` 直接拒收 |
| RS256 → HS256 公钥混淆 | 同一函数 `verify(token, key)` 对不同 `alg` 复用同一个公钥字节串 | 对称密钥与非对称公钥使用强类型隔离封装（`HMACKey` vs `RSAPublicKey`），禁止跨类调用 | `HS*` 算法只接受对称密钥对象；`RS*/ES*` 只接受公钥对象 |
| 隐式多算法回退 | 主算法验证异常后回退到备选旧算法（如 MD5） | 删除历史兼容回退分支；若处于算法平滑升级期，必须按 `kid` 精确映射唯一算法 | 每个 `kid` 只允许绑定 1 个算法 |
| Base64url / Hex 编码绕过 | 忽略大小写、未验证解码长度或忽略多余尾部填充 | 校验签名二进制解码长度（如 SHA256 必须 32 字节）与无填充标准 Base64url | 解码异常或长度不符立即拒绝 |

## 防御实现与校验示例

### 1. 强类型密钥与严格算法锁定验签器（Python）

通过分离密钥类型与服务端预期算法映射，使攻击者无法通过篡改 JWT Header 或 `sign_type` 切换验签分支：

```python
from dataclasses import dataclass
import hmac
import hashlib
import base64
import json

@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    bound_alg: str
    key_type: str  # "symmetric" | "asymmetric_public"
    material: bytes

ALLOWED_SYMMETRIC_ALGS = {"HS256"}
ALLOWED_ASYMMETRIC_ALGS = {"RS256", "ES256", "EdDSA"}

def verify_jwt_header_and_alg(token: str, key_registry: dict[str, KeyRecord], expected_alg: str) -> tuple[bool, str]:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False, "malformed_or_unsigned_jwt"
    try:
        hdr_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(hdr_b64))
    except Exception:
        return False, "invalid_header"

    alg = header.get("alg")
    kid = header.get("kid", "default")
    if not isinstance(alg, str) or alg.lower() == "none" or alg != expected_alg:
        return False, f"disallowed_alg:{alg}"

    rec = key_registry.get(kid)
    if rec is None or rec.bound_alg != expected_alg:
        return False, "key_alg_mismatch"
    if alg in ALLOWED_SYMMETRIC_ALGS and rec.key_type != "symmetric":
        return False, "key_confusion_blocked"
    if alg in ALLOWED_ASYMMETRIC_ALGS and rec.key_type != "asymmetric_public":
        return False, "key_type_mismatch"

    if alg == "HS256":
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        expected_sig = hmac.new(rec.material, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(sig_bytes, expected_sig):
            return False, "bad_hmac_sig"
    return True, "ok"

if __name__ == "__main__":
    reg = {
        "rsa-pub-1": KeyRecord("rsa-pub-1", "RS256", "asymmetric_public", b"PEM_PUBLIC_BYTES"),
        "hmac-1": KeyRecord("hmac-1", "HS256", "symmetric", b"S" * 32),
    }
    fake_none = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=") + ".e30."
    assert verify_jwt_header_and_alg(fake_none, reg, "RS256") == (False, "malformed_or_unsigned_jwt")
    # 尝试使用 rsa-pub-1 公钥伪造 HS256
    fake_hs = base64.urlsafe_b64encode(b'{"alg":"HS256","kid":"rsa-pub-1"}').decode().rstrip("=") + ".e30.AAAA"
    assert verify_jwt_header_and_alg(fake_hs, reg, "HS256") == (False, "key_alg_mismatch")
    print("algorithm_defense_check: PASS")
```

## 防御工作流

```text
1. 禁用不安全算法：从所有生产配置文件与验签路由中彻底移除 MD5、SHA1 裸哈希及 none 算法支持
2. 服务端绑定算法：由服务端接口配置或 kid 密钥元数据决定唯一算法，忽略请求体内的 sign_type/alg 降级声明
3. 强类型密钥隔离：使用独立类或库接口（如 PyJWT algorithms=[expected_alg]）强制校验公钥与对称密钥类型
4. Header 安全收敛：拒绝包含未认证 jku/x5u 外部 URL 或未校验的 kid 路径/注入字符的 JWT Header
5. 回归验证：将 alg=none/None/NoNe、sign_type=MD5 及 RS->HS 混淆矩阵纳入 CI 自动化负向用例
```

## 验证与判定标准

- **None 算法零通过**：`none`、`None`、`NONE`、空字符串及缺失 `alg` 字段均被拒绝（HTTP 401/403）
- **密钥混淆拦截**：使用已知公钥字节串作为 HMAC 密钥签发的令牌，在 `RS256` 绑定端点 100% 返回 `key_alg_mismatch` 或 `invalid_signature`
- **降级分支清零**：支付回调端点携带 `sign_type=MD5` 时，直接触发异常拒绝而非进入降级验签逻辑

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 关联签名防御检索 | `kb_router` | 检索实现缺陷与规范化防御专题 |
| 负向回归测试生成 | `workspace_write_text` | 输出算法白名单与混淆拦截单测文件 |
| 降级试探流量检测 | `make_sigma_stub` | 生成针对 `alg=none` 及 `sign_type=MD5` 探测请求的检测规则 |
