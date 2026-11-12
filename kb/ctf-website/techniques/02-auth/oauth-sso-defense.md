---
id: "ctf-website/02-auth/oauth-sso-defense"
title: "OAuth 2.0 / OIDC 单点登录安全防御"
title_en: "OAuth 2.0 and OIDC SSO Defense"
summary: >
  针对 OAuth 2.0 与 OpenID Connect 授权流程中的九大攻击面——redirect_uri 开放重定向与解析绕过、state/nonce 缺失引起的 CSRF、authorization code 复用、按邮箱自动绑定账号劫持、PKCE 缺失、ID Token 与 Access Token 混用、Implicit Flow 泄露、Client Secret 前端暴露及 Device Code / Refresh Token 扩权滥用，提供严格字段绑定策略与可运行的 Python 校验代码。
summary_en: >
  Comprehensive defense guide for OAuth 2.0 and OIDC addressing redirect_uri normalization bypasses, missing state/nonce CSRF, authorization code reuse, email-based account hijacking, missing PKCE, ID/Access token confusion, Implicit Flow exposure, client_secret leakage, and Device Code/Refresh Token scope escalation. Includes runnable Python validation routines.
board: "ctf-website"
category: "02-auth"
signals: ["OAuth", "OIDC", "redirect_uri", "state", "nonce", "PKCE", "S256", "ID Token", "Token Binding"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["OAuth防御", "OIDC加固", "redirect_uri精确匹配", "PKCE强制", "state绑定", "ID Token隔离", "SSO账号绑定"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "oauth", "oidc", "sso"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/oauth-sso", "ctf-website/02-auth/host-header-defense", "ctf-website/02-auth/jwt/06-claim-missing-defense", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
track: "blue"
defends: "ctf-website/02-auth/oauth-sso"
---

# OAuth 2.0 / OIDC 单点登录安全防御

OAuth 2.0 / OIDC 漏洞几乎全部源于**协议字段之间的密码学或会话级绑定缺失**。只要保证 `redirect_uri` 精确匹配、`state`/`nonce`/`PKCE` 与浏览器会话绑定、`code` 单次原子消费、账户仅按 `(iss, sub)` 绑定且禁止客户端硬编码机密，就能同时封堵九类高危利用链。

## 九大攻击面防御矩阵

| 攻击向量 | 漏洞根因 | 强制防御措施 |
|---|---|---|
| `redirect_uri` 绕过 | 前缀/正则/后缀匹配，或允许子域通配、开放重定向跳转、`@`/`#`/`..` 规范化差异 | 按 RFC 6749/OAuth 2.1 执行**字节级精确字符串匹配**，禁止通配符、userinfo、fragment 及相对路径 |
| `state` / `nonce` 缺失 | 回调不校验 `state` 或使用可预测值；OIDC 不验证 `id_token.nonce` | 为每次授权请求生成 >= 128-bit 加密随机 `state` 与 `nonce`，并绑定 HttpOnly 同站会话 Cookie |
| `code` 复用与跨端交换 | 授权码可重复兑换，或未绑定 `client_id` + `redirect_uri` + `code_verifier` | `/token` 端点对 `code` 做原子标记已消费（并发锁/CAS），校验与 `/authorize` 完全一致的绑定元组 |
| 邮箱关联账号劫持 | 仅凭 `email` 自动合并本地账号，未检查 `iss`、`sub` 与 `email_verified` | 主键绑定固定为 `(iss, sub)`；跨 IdP 同邮箱绑定必须要求用户先在本地认证后再显式关联 |
| PKCE 缺失或可降级 | 允许公共客户端不带 `code_challenge`，或接受 `plain` 方法 | 全客户端强制 PKCE，仅允许 `code_challenge_method=S256`（拒绝 `plain` 与空参数） |
| ID Token 当 Access Token | 资源服务器不校验 `typ`、`aud` 与 `scope`，只验签名和 `sub` | 签发端为 Access Token 设置 `typ=at+jwt` 与目标资源 `aud`；资源 API 拒绝 `typ!=at+jwt` 或缺乏所需 `scope` 的凭证 |
| Implicit Flow 泄露 | 允许 `response_type=token` 在 URL fragment 回传访问令牌 | 下线 `response_type=token` 与 `id_token token`，仅启用 Authorization Code + PKCE |
| Client Secret 泄露 | 机密客户端密钥写入前端 JS、`.map`、APK 或公共 `/config` | SPA/移动端统一作为公开客户端使用 PKCE，不得持有 `client_secret`；服务端密钥放入运行时密钥库 |
| Device Code / Refresh 扩权 | 未限制轮询频率；`refresh_token` 允许请求超出初始授权范围的 `scope` 或跨 `client_id` 使用 | Device Code 强制 `interval` 退避限流与短 TTL；Refresh 校验 `client_id` 归属、`scope` 必须为原授权子集并启用轮换吊销 |

## 防御工作流

```text
1. 授权端点校验 (/authorize)
   └─ 拒绝 response_type=token -> 字节级精确匹配 redirect_uri -> 强制校验 S256 PKCE 与高熵 state/nonce
2. 回调与会话绑定 (/callback)
   └─ 常量时间比对 state 与会话 Cookie -> 验证 code 来源无误 -> 校验 id_token 内 iss/aud/nonce
3. 令牌端点原子兑换 (/token)
   └─ 分布式锁原子消费 code（用后即毁）-> 校验 client_id + redirect_uri + SHA256(code_verifier) == code_challenge
4. 身份联合与权限映射
   └─ 以 (iss, sub) 为唯一外部身份键；禁止仅靠未验证 email 自动接管存量账号
5. 资源访问与刷新隔离
   └─ 资源服务器校验 typ=at+jwt、aud、scope；refresh 请求严禁超出原始 grant scope，且旧 refresh 令牌立即失效
```

### Python 核心防御校验器（Redirect URI / PKCE / Code 消费 / 身份绑定）

```python
import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit


def validate_exact_redirect_uri(provided_uri: str, registered_uris: set[str]) -> str:
    """严格拒绝 fragment、userinfo、路径穿越及非精确匹配的 redirect_uri。"""
    parsed = urlsplit(provided_uri)
    if parsed.scheme not in ("https",) and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
        raise ValueError("insecure redirect_uri scheme")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("userinfo or fragment not allowed in redirect_uri")
    if ".." in parsed.path or "\\" in provided_uri or "%" in parsed.netloc:
        raise ValueError("ambiguous encoding or traversal in redirect_uri")
    if not any(hmac.compare_digest(provided_uri, allowed) for allowed in registered_uris):
        raise ValueError("redirect_uri not in exact allowlist")
    return provided_uri


def verify_pkce_s256(code_verifier: str, expected_challenge: str, method: str) -> bool:
    """强制 S256 PKCE 校验，拒绝 plain 或空 verifier。"""
    if method != "S256" or not code_verifier or len(code_verifier) < 43 or len(code_verifier) > 128:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, expected_challenge)


def resolve_federated_identity(claims: dict, trusted_issuers: set[str], link_table: dict[tuple[str, str], str]) -> str:
    """按 (iss, sub) 联合身份，拒绝仅靠 email 自动合并账号。"""
    iss = claims.get("iss", "")
    sub = claims.get("sub", "")
    if iss not in trusted_issuers or not sub:
        raise ValueError("untrusted issuer or missing subject")
    if (iss, sub) in link_table:
        return link_table[(iss, sub)]
    raise PermissionError("explicit local authentication required before linking new IdP identity")


def validate_refresh_scope(requested_scope: str, granted_scope: str) -> list[str]:
    """阻止 refresh_token 刷新阶段权限扩张。"""
    granted = set(granted_scope.split())
    requested = set(requested_scope.split()) if requested_scope else set(granted)
    if not requested.issubset(granted):
        raise PermissionError("scope escalation rejected")
    return sorted(requested)


def generate_state_nonce() -> tuple[str, str]:
    """生成不可预测的高熵 state 与 nonce。"""
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)
```

## 验证与判定标准

运行下方测试集确认 [oauth-sso.md](oauth-sso.md) 中的 URL 规范化绕过、PKCE 错配、邮箱劫持及 Scope 扩权均被拦截：

```python
def run_oauth_hardening_checks() -> None:
    registered = {"https://app.example.com/oauth/callback"}
    bad_uris = [
        "https://evil.com/callback",
        "https://app.example.com.evil.com/oauth/callback",
        "//evil.com/callback",
        "https://app.example.com@evil.com/oauth/callback",
        "https://app.example.com/oauth/callback#@evil.com",
        "https://app.example.com/oauth/callback/../evil",
        "http://app.example.com/oauth/callback",
    ]
    for uri in bad_uris:
        try:
            validate_exact_redirect_uri(uri, registered)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad redirect_uri accepted: {uri}")

    assert validate_exact_redirect_uri("https://app.example.com/oauth/callback", registered)

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert verify_pkce_s256(verifier, challenge, "S256") is True
    assert verify_pkce_s256(verifier, verifier, "plain") is False
    assert verify_pkce_s256("wrong-verifier-" + "x" * 35, challenge, "S256") is False

    try:
        resolve_federated_identity(
            {"iss": "https://github.com", "sub": "999", "email": "victim@company.com", "email_verified": False},
            {"https://github.com"},
            {("https://accounts.google.com", "111"): "user-victim"},
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("cross-IdP email hijacking was not blocked")

    try:
        validate_refresh_scope("openid profile admin", "openid profile")
    except PermissionError:
        pass
    else:
        raise AssertionError("refresh scope escalation was not blocked")

    print("PASS: all OAuth/OIDC hardening checks passed")


if __name__ == "__main__":
    run_oauth_hardening_checks()
```

判定标准：
1. **回调严格一致**：任一子域混淆、userinfo `@`、fragment `#`、编码路径穿越或 `response_type=token` 请求均在 `/authorize` 直接返回 `400`。
2. **Code 与 PKCE 单次强绑定**：同一 `code` 并发请求两次 `/token` 仅第一次成功；错误 `code_verifier` 或更换 `client_id` 一律返回 `invalid_grant`。
3. **令牌用途隔离**：携带 `id_token` 访问资源 API 时，因 `typ` 与 `aud` 不匹配稳定返回 `401/403`。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `OAuth`、`PKCE`、`redirect_uri`、`Token` 检索相关防御规程 |
| 规程读取 | `kb_read_file` | 读取 `oauth-sso-defense` 与 `06-claim-missing-defense` |
| 知识目录核查 | `kb_catalog` | 核查 `02-auth` 与 `20-oauth-deep` 下的加固文档 |
