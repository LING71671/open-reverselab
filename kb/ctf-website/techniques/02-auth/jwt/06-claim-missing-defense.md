---
id: "ctf-website/02-auth/jwt/06-claim-missing-defense"
title: "JWT Claim 校验与 Token 类型隔离防御"
title_en: "JWT Claim Enforcement and Token Type Isolation Defense"
summary: >
  针对 JWT 标准 Claim（exp、nbf、iss、aud、sub、jti）校验缺失导致过期 Token 永久有效、跨服务/跨 IdP 越权以及 OIDC ID Token/Refresh Token 当作 Access Token 混用和直接信任 Payload role 声明的问题，提供强制 require 声明列表、RFC 9068 typ=at+jwt 隔离、严格 aud/iss/scope 校验与敏感权限回源核查模板，并附可运行的 Python 验证脚本。
summary_en: >
  Defensive guide against missing JWT claim validation (exp, nbf, iss, aud, jti) and OAuth/OIDC token type confusion (ID/Refresh tokens accepted as Access tokens) as well as blind trust in payload role claims. Provides strict claim requirements, RFC 9068 typ=at+jwt enforcement, server-side authorization lookup, and runnable Python tests.
board: "ctf-website"
category: "02-auth"
signals: ["Claim校验", "exp", "nbf", "iss", "aud", "at+jwt", "Token混用", "权限回源"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["JWT Claim防御", "exp验证", "aud校验", "iss验证", "Token类型隔离", "ID Token混用防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "claims", "authorization"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/06-claim-missing", "ctf-website/02-auth/oauth-sso-defense", "ctf-website/02-auth/jwt/07-theft-replay-defense", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
track: "blue"
defends: "ctf-website/02-auth/jwt/06-claim-missing"
---

# JWT Claim 校验与 Token 类型隔离防御

仅校验签名而忽略 Claim 语义校验，相当于**只检查信封封口有没有拆开，却不看收件人、发件人、有效期和信件用途**。在现代 SSO 与微服务架构中，多个业务共享同一套公钥或同一 IdP 极其常见，缺少 `exp`/`nbf`/`iss`/`aud`/`typ` 强制验证会直接引起过期凭证复用、跨服务重放以及 ID Token 越权调 API。

## Claim 与 Token 类型防御矩阵

| 缺陷类型 | 危害机制 | 强制防御控制 |
|---|---|---|
| `exp` 未校验或允许缺省 | 泄露的旧 Token 永久有效，移除 `exp` 后绕过过期检查 | 强制 `exp` 必须存在且为数字，`now < exp`（时钟容差 `leeway <= 30s`） |
| `nbf` / `iat` 未校验 | 提前签发或极早期签发的 Token 被非法激活 | 强制校验 `now >= nbf`；敏感会话校验 `iat` 不早于用户最近一次改密/全量注销时间戳 |
| `iss` 未绑定 | 接受同一公钥集下其他环境（dev/staging）或其他 IdP 的 Token | 精确匹配单值 `iss == EXPECTED_ISSUER`，禁止任意多域放行 |
| `aud` / `azp` 未校验 | Service A 的 Access Token 或客户端 ID Token 被用于访问 Service B API | 资源服务器强制 `aud` 精确匹配自身服务 URI（拒绝数组含糊放行非预期受众，且不与 `client_id` 混同） |
| ID / Refresh / Access Token 混用 | 资源接口只看 `sub` 导致用 `id_token` 或 `refresh_token` 调业务 API | 依据 RFC 9068 为 Access Token 签发 `Header.typ = "at+jwt"`（Refresh Token 使用不透明随机串或 `rt+jwt`），资源服务器拒绝任何非 `at+jwt` 凭证 |
| 直接信任 Payload `role`/`isAdmin` | 用户账号降权或禁用后，旧 Token 内缓存的 `role=admin` 仍有效 | Token 仅作身份与 `scope` 边界；高危管理接口在验签后必须回源数据库/策略引擎校验当前账号状态与真实权限 |

## 防御工作流

```text
1. 签发侧规范化（Token Separation by Design）
   └─ Access Token 固定 Header.typ="at+jwt"、短 TTL（5-15 分钟）、明确单服务 aud 与最小 scope；Refresh Token 采用高熵不透明串
2. 必选声明集合门禁（Required Claims）
   └─ 解码选项启用 require=["exp", "nbf", "iss", "aud", "sub", "jti"]，缺失任一字段直接拒绝
3. 语义与时间窗校验
   └─ 校验 iss == TRUSTED_ISSUER、EXPECTED_AUD in aud、nbf <= now < exp（leeway <= 30s）
4. 类型与权限边界强制检查
   └─ API 网关/中间件检查 typ == "at+jwt"，拒绝缺少所需 scope 的调用（ID Token 不带业务 scope 且 typ 不同）
5. 实时权限与账号状态核查
   └─ 对管理端/资金/改密接口，根据 sub 回源核对账号未封禁、password_changed_at <= iat 且当前角色仍具授权
```

### Python 严格 Claim 与 Token 类型验证器

```python
import time
from typing import Any


class ClaimValidationError(Exception):
    """拒绝缺失声明、过期、跨受众或类型混用的 Token。"""


def verify_access_token_claims(
    header: dict[str, Any],
    payload: dict[str, Any],
    expected_iss: str,
    expected_aud: str,
    required_scopes: set[str],
    user_state_lookup=None,
    now: int | None = None,
    leeway: int = 30,
) -> dict[str, Any]:
    """在密码学验签通过后，执行 RFC 9068 级别的 Claim 与类型强制校验。"""
    # 1. 严格区分 Token 类型，防止 ID Token / Refresh Token 冒充 Access Token
    if header.get("typ") != "at+jwt":
        raise ClaimValidationError(f"invalid token typ: {header.get('typ')!r}")
    if payload.get("token_use") in ("id", "refresh") or payload.get("typ") in ("id", "id_token", "refresh"):
        raise ClaimValidationError("non-access token rejected on resource API")

    # 2. 必选声明完整性（禁止攻击者删除 exp/aud/iss 绕过校验）
    for req in ("sub", "iss", "aud", "exp", "nbf", "iat", "jti"):
        if req not in payload or payload[req] is None:
            raise ClaimValidationError(f"missing required claim: {req}")

    ts = int(time.time()) if now is None else now
    for t_field in ("exp", "nbf", "iat"):
        if not isinstance(payload[t_field], (int, float)) or isinstance(payload[t_field], bool):
            raise ClaimValidationError(f"invalid timestamp type for {t_field}")

    if ts - leeway >= payload["exp"]:
        raise ClaimValidationError("token expired")
    if ts + leeway < payload["nbf"]:
        raise ClaimValidationError("token not yet active")

    # 3. 精确签发者与受众匹配
    if payload["iss"] != expected_iss:
        raise ClaimValidationError("issuer mismatch")

    aud = payload["aud"]
    if isinstance(aud, str):
        aud_valid = aud == expected_aud
    elif isinstance(aud, list) and all(isinstance(x, str) for x in aud):
        # 拒绝多受众混用或通配符；仅当服务明确在受众列表且无非法宽泛项时允许
        aud_valid = expected_aud in aud and "*" not in aud
    else:
        aud_valid = False
    if not aud_valid:
        raise ClaimValidationError("audience mismatch")

    # 4. Scope 检查（拒绝通配符 * 注入）
    raw_scope = payload.get("scope", "")
    token_scopes = set(raw_scope.split()) if isinstance(raw_scope, str) else set()
    if "*" in token_scopes or not required_scopes.issubset(token_scopes):
        raise ClaimValidationError("insufficient scope")

    # 5. 服务端权威状态与权限核对（不盲信 payload.role / isAdmin）
    if user_state_lookup is not None:
        state = user_state_lookup(str(payload["sub"]))
        if not state or not state.get("active", False):
            raise ClaimValidationError("account disabled")
        if payload["iat"] < state.get("tokens_valid_after", 0):
            raise ClaimValidationError("token invalidated by password change or logout-all")

    return payload
```

## 验证与判定标准

运行下方脚本核对 [06-claim-missing.md](06-claim-missing.md) 中的 `exp` 过期/删除、未来 `nbf`、错 `iss`、错 `aud`、ID Token 混用及 `scope` 不足均被拦截：

```python
def run_claim_defense_checks() -> None:
    now = 1700000000
    good_h = {"alg": "RS256", "typ": "at+jwt"}
    good_p = {
        "sub": "u-42",
        "iss": "https://auth.example.com",
        "aud": "https://api.example.com",
        "iat": now - 60,
        "nbf": now - 60,
        "exp": now + 300,
        "jti": "jti-1",
        "scope": "profile:read orders:read",
    }

    def lookup(sub: str) -> dict[str, Any]:
        return {"active": True, "tokens_valid_after": now - 120, "role": "user"}

    assert verify_access_token_claims(good_h, good_p, "https://auth.example.com", "https://api.example.com", {"orders:read"}, lookup, now)["sub"] == "u-42"

    bad_cases = [
        ({"alg": "RS256", "typ": "JWT"}, good_p),  # ID Token typ 混用
        (good_h, {**good_p, "exp": now - 100}),  # 已过期
        (good_h, {k: v for k, v in good_p.items() if k != "exp"}),  # 删除 exp
        (good_h, {**good_p, "nbf": now + 600}),  # 未来生效
        (good_h, {**good_p, "iss": "https://other-idp.example"}),  # 跨 IdP
        (good_h, {**good_p, "aud": "https://other-api.example"}),  # 跨服务
        (good_h, {**good_p, "scope": "profile:read *"}),  # 通配 scope 注入
        (good_h, {**good_p, "iat": now - 500}),  # 早于改密时间戳
    ]
    for h, p in bad_cases:
        try:
            verify_access_token_claims(h, p, "https://auth.example.com", "https://api.example.com", {"orders:read"}, lookup, now)
        except ClaimValidationError:
            pass
        else:
            raise AssertionError(f"invalid claim case accepted: {(h, p)}")

    print("PASS: all JWT claim & token-type defense checks passed")


if __name__ == "__main__":
    run_claim_defense_checks()
```

判定标准：
1. **声明删除无效**：移除 `exp`、`nbf`、`iss`、`aud` 中任意一个后，即使重签合法签名仍返回 `401`。
2. **跨类型零混用**：用 OIDC `id_token` 或 `refresh_token` 调资源接口时稳定返回 `401`，不执行任何业务查询。
3. **权限不唯 Token 论**：当数据库角色由 `admin` 降级为 `user` 或账号停用后，未过期的旧 Token 立即失去管理接口访问权限。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `Claim`、`aud`、`iss`、`at+jwt`、`Token混用` 检索相关防御文档 |
| 规程读取 | `kb_read_file` | 读取 `06-claim-missing-defense` 与 `oauth-sso-defense` |
| 目录索引核查 | `kb_catalog` | 核对 `02-auth/jwt/` 及 `20-oauth-deep/` 关联文档 |
