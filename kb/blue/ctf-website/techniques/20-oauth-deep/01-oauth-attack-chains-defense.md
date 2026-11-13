---
id: "ctf-website/20-oauth-deep/01-oauth-attack-chains-defense"
title: "OAuth 2.0 攻击全链防御 — 强制 PKCE S256、精确 redirect_uri 匹配、State 绑定与授权码单次核销"
title_en: "OAuth 2.0 Attack Chains Defense — Mandatory PKCE S256, Exact redirect_uri Matching, State Binding & Single-Use Codes"
summary: >
  对照 RFC 9700（OAuth 2.0 Security BCP），针对 PKCE 验证缺失与 plain 降级、State 缺失/可预测导致的账号绑定 CSRF、
  redirect_uri 前缀/路径遍历/参数污染/开放重定向链、response_type 切换与 Implicit Flow 令牌泄露、Scope 越权提升、
  Authorization Code 重放及 SPA 硬编码 client_secret 等漏洞，提供完整服务端与客户端防御实现及可运行回归测试。
summary_en: >
  RFC 9700-aligned defense against OAuth 2.0 attack chains: missing PKCE verification and plain downgrade, missing or
  predictable state CSRF, redirect_uri traversal and open-redirect chaining, response_type switching and Implicit Flow
  leakage, scope escalation, authorization code reuse, and public client secrets. Includes runnable Python checks.
board: "ctf-website"
category: "20-oauth-deep"
signals: ["PKCE S256", "exact redirect_uri", "OAuth state CSRF", "RFC 9700", "authorization code reuse", "scope allowlist", "disable implicit flow"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["OAuth防御", "PKCE强制S256", "redirect_uri精确匹配", "OAuth CSRF防御", "授权码防重放", "Scope白名单", "禁用Implicit Flow", "RFC 9700"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "oauth", "pkce", "csrf", "sso"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/20-oauth-deep/01-oauth-attack-chains", "ctf-website/20-oauth-deep/02-session-fixation-attacks-defense"]
track: "blue"
defends: "ctf-website/20-oauth-deep/01-oauth-attack-chains"
---

# OAuth 2.0 攻击全链防御 — 强制 PKCE S256、精确 redirect_uri 匹配、State 绑定与授权码单次核销

## 威胁模型与防御目标

OAuth 2.0 的安全边界由多个独立参与方（授权端点、令牌端点、客户端回调、浏览器跳转）协同维持，任意一环的宽松校验都会串联成完整账号接管链。对照 [01-oauth-attack-chains.md](../../../../red/ctf-website/techniques/20-oauth-deep/01-oauth-attack-chains.md)，依据 **RFC 9700（OAuth 2.0 Security Best Current Practice）** 建立逐环阻断防线：

| 攻击向量 | 漏洞根因 | 蓝队加固控制 |
|---|---|---|
| PKCE 验证缺失或 `S256 -> plain` 降级 | 未强制要求 `code_challenge`，接受 `plain` 方法或允许 HTTP 参数污染覆盖 | 所有客户端强制 PKCE，**仅允许 `code_challenge_method=S256`**；拒绝重复参数（HPP）；服务端用 `hmac.compare_digest` 校验 `SHA256(code_verifier)` |
| `state` 缺失、固定或可预测（OAuth CSRF） | 回调未比对一次性随机 `state`，或账号绑定流程无二次确认 | 客户端生成 >=256-bit CSPRNG `state` 绑定到 `HttpOnly; SameSite=Lax; Secure` 会话并单次核销；绑定新第三方身份前强制要求当前登录态二次确认 |
| `redirect_uri` 绕过与 Open Redirect 链 | 采用正则/前缀匹配、`urlparse` 忽略 `@`/`\`/`..` 或白名单中含开放重定向端点 | **完全逐字节精确字符串匹配（Exact Match）**；拒绝任何路径穿越、用户info `@`、反斜杠、空字节与未注册查询参数；令牌端点再校验 `redirect_uri` 一致性 |
| `response_type` 切换与 Implicit Flow 泄露 | 授权端点对授权码客户端仍开放 `token`/`id_token`/`code token` | 彻底禁用 Implicit 与 Hybrid 响应类型，仅允许按客户端登记的 `response_type=code`；回调页设置 `Referrer-Policy: no-referrer` |
| Scope 权限提升与 `offline_access` 滥用 | 直接信任请求中的 `scope` 字符串且未核验大小写与客户端上限 | 在授权端点按客户端注册表严格求交集并规范化校验；对高权限与 `offline_access` 强制独立授权确认与 Refresh Token 轮换 |
| 授权码重放与移动端 URI Scheme 拦截 | `code` 可在过期前重复换取 Token，或移动 App 使用不唯一的自定义 Scheme | `code` 有效期 `<= 60s` 且严格**单次消费**；检测到同一 `code` 二次提交时立即吊销其已签发的所有 Access/Refresh Token；移动端改用 HTTPS App Links / Universal Links 且不在 SPA/App 中嵌入 `client_secret` |

## 架构加固配置

### 1. OAuth 2.0 授权服务器核心安全状态机（Python）

以下参考实现覆盖授权端点参数校验（HPP 防护、精确 `redirect_uri`、强制 `S256` PKCE、`response_type=code` 白名单、Scope 裁剪）与令牌端点单次核销及重放连带吊销机制：

```python
import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class RegisteredClient:
    client_id: str
    exact_redirect_uris: frozenset[str]
    allowed_scopes: frozenset[str]
    is_confidential: bool = False


@dataclass
class AuthCodeRecord:
    client_id: str
    user_id: str
    redirect_uri: str
    code_challenge: str
    scopes: tuple[str, ...]
    expires_at: float
    consumed: bool = False


class HardenedOAuthServer:
    """遵循 RFC 9700 的硬化 OAuth 2.0 授权/令牌状态机。"""

    def __init__(self, clients: dict[str, RegisteredClient]) -> None:
        self.clients = clients
        self._codes: dict[str, AuthCodeRecord] = {}
        # 记录由特定授权码签发的 token_id 集合，便于检测到 code 重放时联动吊销
        self._issued_by_code: dict[str, set[str]] = {}
        self._active_tokens: dict[str, dict] = {}

    @staticmethod
    def _single_param(query_map: dict[str, list[str]], key: str) -> str:
        values = query_map.get(key, [])
        if len(values) > 1:
            # 阻止 HTTP Parameter Pollution（如同时传 S256 与 plain）
            raise ValueError(f"duplicate parameter not allowed: {key}")
        return values[0] if values else ""

    @staticmethod
    def _validate_exact_redirect_uri(raw_uri: str, registered: frozenset[str]) -> str:
        if any(bad in raw_uri for bad in ("\\", "\x00", "\r", "\n", "@", "..", "#")):
            raise ValueError("malformed redirect_uri rejected")
        parsed = urlparse(raw_uri)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("redirect_uri must use https")
        # 严格逐字节精确匹配，不使用前缀/通配符/正则
        if raw_uri not in registered:
            raise ValueError("redirect_uri does not exactly match registered URI")
        return raw_uri

    def authorize(self, raw_query: str, user_id: str, now: float | None = None) -> dict:
        ts = now if now is not None else time.monotonic()
        qmap = parse_qs(raw_query, keep_blank_values=True)

        client_id = self._single_param(qmap, "client_id")
        client = self.clients.get(client_id)
        if not client:
            raise ValueError("invalid_client")

        # 1. 精确 redirect_uri 校验优先（校验失败绝不重定向回去）
        redirect_uri = self._validate_exact_redirect_uri(
            self._single_param(qmap, "redirect_uri"),
            client.exact_redirect_uris,
        )

        # 2. 禁用 Implicit / Hybrid，只允许 authorization code
        response_type = self._single_param(qmap, "response_type")
        if response_type != "code":
            raise ValueError("unsupported_response_type: implicit/hybrid disabled")

        # 3. 强制存在高熵 state（服务端亦校验最低长度，防止空或短固定值）
        state = self._single_param(qmap, "state")
        if len(state) < 16:
            raise ValueError("invalid_request: missing or weak state")

        # 4. 强制 PKCE 且仅允许 S256
        method = self._single_param(qmap, "code_challenge_method")
        challenge = self._single_param(qmap, "code_challenge")
        if method != "S256" or len(challenge) < 43:
            raise ValueError("invalid_request: PKCE S256 required")

        # 5. Scope 白名单严格校验（大小写敏感且禁止未授权 scope）
        req_scopes = [s for s in self._single_param(qmap, "scope").split() if s]
        if not req_scopes or any(s not in client.allowed_scopes for s in req_scopes):
            raise ValueError("invalid_scope")

        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthCodeRecord(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            code_challenge=challenge,
            scopes=tuple(req_scopes),
            expires_at=ts + 60.0,
        )
        return {"code": code, "state": state, "redirect_uri": redirect_uri}

    def exchange_token(
        self,
        grant_type: str,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        now: float | None = None,
    ) -> dict:
        ts = now if now is not None else time.monotonic()
        if grant_type != "authorization_code":
            # 统一返回标准 OAuth 错误码，绝不暴露堆栈或内部细节
            raise PermissionError("unsupported_grant_type")

        rec = self._codes.get(code)
        if not rec:
            raise PermissionError("invalid_grant")

        # 若检测到同一授权码被二次提交，按 RFC 6749 §4.1.2 立即吊销已签发 Token
        if rec.consumed:
            for tid in self._issued_by_code.get(code, set()):
                self._active_tokens.pop(tid, None)
            raise PermissionError("invalid_grant: code replay detected; tokens revoked")

        if ts > rec.expires_at or rec.client_id != client_id or rec.redirect_uri != redirect_uri:
            rec.consumed = True
            raise PermissionError("invalid_grant")

        # 校验 PKCE S256：BASE64URL-NO-PAD(SHA256(code_verifier)) == code_challenge
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(computed, rec.code_challenge):
            rec.consumed = True
            raise PermissionError("invalid_grant: PKCE verification failed")

        rec.consumed = True
        access_token = secrets.token_urlsafe(32)
        self._active_tokens[access_token] = {
            "user_id": rec.user_id,
            "client_id": client_id,
            "scopes": rec.scopes,
        }
        self._issued_by_code.setdefault(code, set()).add(access_token)
        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 900, "scope": " ".join(rec.scopes)}
```

### 2. 客户端回调防 OAuth CSRF 校验器（Python）

```python
class OAuthClientCallbackGuard:
    """客户端侧一次性高熵 State 生成与单次绑定校验。"""

    def __init__(self) -> None:
        self._session_states: dict[str, tuple[str, str, float]] = {}

    def begin_login(self, session_id: str) -> tuple[str, str]:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        self._session_states[session_id] = (state, verifier, time.monotonic() + 300.0)
        return state, challenge

    def verify_callback(self, session_id: str, returned_state: str) -> str:
        rec = self._session_states.pop(session_id, None)  # 一次性消费
        if not rec:
            raise PermissionError("missing oauth state in session")
        expected_state, verifier, exp = rec
        if time.monotonic() > exp or not hmac.compare_digest(expected_state, returned_state):
            raise PermissionError("oauth state mismatch (possible CSRF)")
        return verifier
```

### 3. 回调响应头与浏览器隔离配置

在客户端 `/oauth/callback` 响应上强制附加以下 HTTP 头，防止历史记录或第三方外链经 `Referer` 泄露任何回调参数：

```http
Referrer-Policy: no-referrer
Cache-Control: no-store
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

## 防御工作流

1. **客户端注册表清点**：将所有 OAuth 客户端的 `redirect_uri` 白名单收紧为完整的精确 HTTPS URI，消除泛域名、通配路径及含开放重定向功能的跳转端点。
2. **强制 PKCE S256 与参数污染防护**：在授权端点拒绝缺少 `code_challenge`、使用 `plain` 或重复传递参数的请求；在令牌端点验证 `code_verifier` 并对齐 `redirect_uri`。
3. **关闭隐式与混合流**：在 IdP/OAuth 服务端全面关闭 `response_type=token` 与 `id_token`（Implicit Flow），并对 SPA/移动端使用公共客户端配置（不配发 `client_secret`）。
4. **State 与账号绑定隔离**：确保每次授权生成绑定于 `HttpOnly; SameSite=Lax; Secure` 会话的一次性 `state`；在将 OAuth 账号关联到既有本地账号前，增加站内二次确认步骤阻断强制绑定 CSRF。
5. **授权码防重放与 Scope 收敛**：将 `code` 有效期压至 60 秒内且单次消费，重放即吊销关联令牌；对请求 `scope` 做精确白名单交集校验并对 Token 端点错误响应做统一化掩盖。

## 验证与判定标准

运行下方回归脚本，验证针对 PKCE 降级、HPP、`redirect_uri` 绕过、Scope 提升、Implicit 切换、State CSRF 与授权码重放的全链防御逻辑：

```python
import base64
import hashlib
import secrets
from urllib.parse import urlencode


def run_self_checks() -> None:
    client = RegisteredClient(
        client_id="spa-web",
        exact_redirect_uris=frozenset({"https://app.example.com/oauth/callback"}),
        allowed_scopes=frozenset({"openid", "profile", "email"}),
        is_confidential=False,
    )
    server = HardenedOAuthServer({"spa-web": client})
    cb_guard = OAuthClientCallbackGuard()

    # 正常流程准备
    state, challenge = cb_guard.begin_login("sess-user-1")

    # 1. 阻断 PKCE plain 降级与 HPP 双参数注入
    for bad_qs in (
        urlencode({"client_id": "spa-web", "redirect_uri": "https://app.example.com/oauth/callback", "response_type": "code", "state": state, "code_challenge": challenge, "code_challenge_method": "plain", "scope": "openid"}),
        "client_id=spa-web&redirect_uri=https://app.example.com/oauth/callback&response_type=code&state=" + state + "&code_challenge=" + challenge + "&code_challenge_method=S256&code_challenge_method=plain&scope=openid",
    ):
        try:
            server.authorize(bad_qs, user_id="u1", now=100.0)
            raise AssertionError("Expected PKCE downgrade/HPP to fail")
        except ValueError:
            pass

    # 2. 阻断 redirect_uri 路径遍历、@ 混淆、参数污染与 http 降级
    for bad_redir in (
        "https://app.example.com/oauth/callback/../evil",
        "https://app.example.com/oauth/callback?next=https://evil.example",
        "https://app.example.com/oauth/callback@evil.example",
        "http://app.example.com/oauth/callback",
    ):
        try:
            server.authorize(urlencode({"client_id": "spa-web", "redirect_uri": bad_redir, "response_type": "code", "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "scope": "openid"}), user_id="u1", now=100.0)
            raise AssertionError(f"Expected redirect_uri bypass rejected: {bad_redir}")
        except ValueError:
            pass

    # 3. 阻断 response_type=token（Implicit Flow）与 scope 提权（admin / aDmin）
    for extra_params in (
        {"response_type": "token", "scope": "openid"},
        {"response_type": "code", "scope": "openid admin"},
        {"response_type": "code", "scope": "openid Profile"},
    ):
        p = {"client_id": "spa-web", "redirect_uri": "https://app.example.com/oauth/callback", "state": state, "code_challenge": challenge, "code_challenge_method": "S256", **extra_params}
        try:
            server.authorize(urlencode(p), user_id="u1", now=100.0)
            raise AssertionError(f"Expected rejection for {extra_params}")
        except ValueError:
            pass

    # 4. 正常授权 + State 校验 + 正确 code_verifier 换取 Token
    auth_res = server.authorize(
        urlencode({"client_id": "spa-web", "redirect_uri": "https://app.example.com/oauth/callback", "response_type": "code", "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "scope": "openid profile"}),
        user_id="u1",
        now=100.0,
    )
    # 攻击者尝试把 code 喂给未发起过该 state 的受害者会话 -> OAuth CSRF 被拒绝
    try:
        cb_guard.verify_callback("sess-victim-2", auth_res["state"])
        raise AssertionError("Expected OAuth CSRF state mismatch")
    except PermissionError:
        pass

    verifier = cb_guard.verify_callback("sess-user-1", auth_res["state"])
    tok_res = server.exchange_token("authorization_code", auth_res["code"], "spa-web", "https://app.example.com/oauth/callback", verifier, now=110.0)
    issued_token = tok_res["access_token"]
    assert issued_token in server._active_tokens

    # 5. 授权码重放必须失败，且连带吊销之前已签发的 access_token
    try:
        server.exchange_token("authorization_code", auth_res["code"], "spa-web", "https://app.example.com/oauth/callback", verifier, now=115.0)
        raise AssertionError("Expected code replay detection")
    except PermissionError:
        pass
    assert issued_token not in server._active_tokens

    print("[PASS] All OAuth 2.0 attack-chain defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- `plain` PKCE、重复 `code_challenge_method`、错误的 `code_verifier` 均在授权或换码阶段被拒绝；
- 非精确匹配的 `redirect_uri`（含路径遍历、查询附加、`@`、HTTP 降级）全部返回错误且不执行 `302` 重定向；
- `response_type=token`/`id_token` 与未登记或大小写变体的 `scope` 被拦截；
- `code` 仅可成功交换一次，二次提交立即失败并同步吊销该 `code` 此前签发的所有令牌。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| OAuth 端点配置探测 | `http_probe` | 验证授权与令牌端点对 `response_type=token`、非精确 `redirect_uri` 与缺失 PKCE 是否已拒绝 |
| 关联防御知识检索 | `kb_router` | 按 `OAuth defense`、`PKCE`、`redirect_uri`、`CSRF` 检索指引 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [01-oauth-attack-chains.md](../../../../red/ctf-website/techniques/20-oauth-deep/01-oauth-attack-chains.md) 逐项核实协议参数防线 |
| 知识目录定位 | `kb_catalog` | 浏览 `20-oauth-deep` 板块全部身份与会话防御文档 |
