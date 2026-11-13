---
id: "ctf-website/20-oauth-deep/02-session-fixation-attacks-defense"
title: "Session 固定与 SSO 劫持防御 — 认证会话轮换、Cookie 主机锁定、JWT 吊销与命名空间隔离"
title_en: "Session Fixation & SSO Hijacking Defense — Session Rotation, Host-Locked Cookies, JWT Revocation & Store Isolation"
summary: >
  针对登录前后 Session ID 固定、URL 参数传递 Session、SSO 注销不同步、可预测 Remember-Me Token、
  JWT 无状态注销失效与 alg:none / RS256-HS256 算法混淆、Session Puzzling 跨应用提权、Redis 未授权及反序列化 RCE、
  以及 SameSite=Lax + GET CSRF 等威胁，给出全面加固架构与可运行验证代码。
summary_en: >
  Defense against session fixation, URL session passing, incomplete SSO logout, predictable remember-me tokens,
  JWT revocation bypass and algorithm confusion, cross-app session puzzling, exposed Redis/pickle deserialization RCE,
  and SameSite=Lax GET CSRF. Provides hardened session/JWT managers and runnable Python verification tests.
board: "ctf-website"
category: "20-oauth-deep"
signals: ["session regeneration", "__Host- cookie", "JWT revocation", "algorithm pinning", "session isolation", "Redis ACL", "anti-CSRF"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Session固定防御", "会话ID轮换", "SSO全局注销", "JWT吊销", "算法固定", "Session隔离", "Redis会话加固", "SameSite防御"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "hardening", "session", "sso", "jwt", "cookie"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/20-oauth-deep/02-session-fixation-attacks", "ctf-website/20-oauth-deep/01-oauth-attack-chains-defense"]
track: "blue"
defends: "ctf-website/20-oauth-deep/02-session-fixation-attacks"
---

# Session 固定与 SSO 劫持防御 — 认证会话轮换、Cookie 主机锁定、JWT 吊销与命名空间隔离

## 威胁模型与防御目标

会话管理的脆弱点往往出现在**状态跃迁**（匿名转已认证、普通用户转管理员、登录转注销）以及**存储/令牌边界**（共享域 Cookie、跨应用 Redis 前缀混用、无状态 JWT 与序列化格式）。对照 [02-session-fixation-attacks.md](../../../../red/ctf-website/techniques/20-oauth-deep/02-session-fixation-attacks.md)，蓝队防线必须全面覆盖以下八类攻击面：

| 攻击向量 | 漏洞根因 | 蓝队加固控制 |
|---|---|---|
| 登录前 Session 固定与 URL 会话传递 | 登录后沿用旧 Session ID；接受 `?PHPSESSID=`/`?sid=` 参数；子域共享 `.target.com` Cookie | 认证/提权/MFA 完成后**销毁旧 Session 并签发新 CSPRNG Session ID**；禁用 URL 会话传输；Cookie 启用 `__Host-` 前缀且不设 `Domain=` |
| SSO 注销不完整与跨应用传播 | 子应用注销仅清本地 Cookie，未通知 IdP 或其他 Relying Party | 实现 OIDC Back-Channel / Front-Channel Logout；应用使用各自独立的 `aud` 与会话键，不共用通配符会话 Cookie |
| Remember-Me Token 可预测与密码修改后仍有效 | 基于用户名/递增 ID/时间戳/UUIDv1 生成且无一次性轮换 | 使用 256-bit CSPRNG 令牌并仅存其 SHA-256；采用 `(series, token_hash)` 单次自动轮换与盗用全吊销机制；改密/注销清空全部持久化令牌 |
| JWT 注销无效、超长 `exp` 与算法混淆（`alg:none` / `RS256 -> HS256`） | 无黑名单机制、接收未经固定的 Header `alg`、混用公钥作 HMAC 密钥 | 访问令牌短 TTL（5-15 分钟）+ Redis `jti` 黑名单/`valid_after` 时间戳；**强制固定校验算法白名单**（绝不读入令牌内 `alg` 决定验签算法） |
| Session Puzzling（跨应用属性覆盖） | 多个应用共享同一 Redis 命名空间，或未区分预认证与已认证状态字段 | 按应用拆分独立存储前缀（`app_a:sess:<id>`）与 Cookie 名；预认证态与已认证态数据分离存储，严禁用户输入直写特权键 |
| Redis/Memcached 未授权与反序列化 RCE | 会话缓存无密码暴露公网，且使用 `pickle` / Java 原生反序列化 | 绑定内网 + TLS + Redis ACL 强认证；禁用高危管理命令；**会话载荷严格使用 JSON**，禁止任何二进制对象反序列化 |
| `SameSite=Lax` + GET CSRF 与开放重定向 | 状态变更接口暴露在 `GET` 方法上，或存在 302 开放重定向 | 所有写操作/状态变更强制 `POST`/`PUT`/`DELETE` + Synchronizer CSRF Token；`SameSite=Strict`（或 `Lax` + `Sec-Fetch-Site`）；根除开放重定向 |

## 架构加固配置

### 1. Cookie、PHP/框架与 Redis 会话存储基线

```ini
; php.ini / Web 运行时会话核心配置基线
session.use_strict_mode = 1
session.use_cookies = 1
session.use_only_cookies = 1
session.use_trans_sid = 0
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Strict"
```

```conf
# redis.conf — 会话存储隔离与加固
bind 127.0.0.1 10.20.1.10
protected-mode yes
tls-port 6379
port 0
# 使用 Redis 6+ ACL 为不同应用分配隔离的 key 前缀权限（防止 Session Puzzling）
user app_a_svc on >StrongRandomCredential_AppA ~app_a:sess:* +@read +@write +@keyspace -KEYS -FLUSHALL -CONFIG
user app_b_svc on >StrongRandomCredential_AppB ~app_b:sess:* +@read +@write +@keyspace -KEYS -FLUSHALL -CONFIG
```

### 2. 硬化的会话管理器、Remember-Me 轮换与防混淆 JWT 校验器（Python）

以下实现提供可直接复用的核心原语：
1. **强制轮换 + 命名空间隔离 + 纯 JSON 会话存储**：拒绝从 URL Query 注入的 Session ID；登录时烧毁旧 Session 并生成全新 256-bit ID；每个应用强制前缀隔离，且序列化仅允许 `json`（彻底杜绝 `pickle` RCE）。
2. **Remember-Me `(series, token_hash)` 轮换与盗用检测**：每次使用后轮换 token；若 `series` 存在但 `token_hash` 不匹配（代表旧令牌已被重放盗用），立即清除该用户的全部自动登录凭据。
3. **固定算法 + `jti` 吊销 + SSO 全局注销时钟 JWT 校验器**：硬编码期望验签算法（如 `HS256` 对称密钥或 `RS256` 公钥，绝不读取 Header `alg` 来决定验签分支），明确拒绝 `alg=none`，并结合 `jti` 吊销表与用户 `tokens_valid_after` 时间戳实现即时注销生效。

```python
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field


class IsolatedSessionManager:
    """支持命名空间隔离、登录轮换与纯 JSON 序列化的会话管理器。"""

    def __init__(self, app_namespace: str) -> None:
        if not app_namespace or ":" in app_namespace:
            raise ValueError("invalid app namespace")
        self.ns = app_namespace
        self._store: dict[str, bytes] = {}  # 模拟 Redis KV（仅存 UTF-8 JSON bytes）

    def _k(self, sid: str) -> str:
        return f"{self.ns}:sess:{sid}"

    def accept_session_cookie_only(self, cookie_sid: str | None, query_params: dict[str, str]) -> str | None:
        """绝不接受 URL 查询参数传递的 session ID；缺失或非高熵格式则返回 None。"""
        if any(k.lower() in {"phpsessid", "session", "jsessionid", "sid", "session_id"} for k in query_params):
            raise PermissionError("url-based session id rejected")
        if not cookie_sid or len(cookie_sid) < 32:
            return None
        return cookie_sid if self._k(cookie_sid) in self._store else None

    def create_pre_auth_session(self) -> tuple[str, str]:
        sid = secrets.token_urlsafe(32)
        payload = {"auth_state": "anonymous", "user_id": None, "created_at": int(time.time())}
        self._store[self._k(sid)] = json.dumps(payload).encode("utf-8")
        cookie_hdr = f"__Host-{self.ns}_sid={sid}; Path=/; Secure; HttpOnly; SameSite=Strict"
        return sid, cookie_hdr

    def rotate_on_login(self, old_sid: str | None, user_id: str, role: str) -> tuple[str, str]:
        """认证成功后立即销毁旧会话并重新生成全新 Session ID，阻断 Session Fixation。"""
        if old_sid:
            self._store.pop(self._k(old_sid), None)
        new_sid = secrets.token_urlsafe(32)
        # 严格重建已认证载荷，绝不继承匿名/跨应用旧键（防止 Session Puzzling）
        payload = {"auth_state": "authenticated", "user_id": user_id, "role": role, "login_at": int(time.time())}
        self._store[self._k(new_sid)] = json.dumps(payload).encode("utf-8")
        cookie_hdr = f"__Host-{self.ns}_sid={new_sid}; Path=/; Secure; HttpOnly; SameSite=Strict"
        return new_sid, cookie_hdr

    def read_session(self, sid: str) -> dict | None:
        raw = self._store.get(self._k(sid))
        if raw is None:
            return None
        # 仅使用 JSON 反序列化，杜绝 pickle/yaml 不安全反序列化 RCE
        return json.loads(raw.decode("utf-8"))


@dataclass
class RememberMeManager:
    """不可预测的 Remember-Me 单次轮换管理器，含重放盗用全清机制。"""

    _records: dict[str, tuple[str, str, float]] = field(default_factory=dict)  # series -> (user_id, sha256_hex, exp)

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, user_id: str, ttl_seconds: float = 86400 * 14, now: float | None = None) -> tuple[str, str]:
        ts = now if now is not None else time.monotonic()
        series = secrets.token_urlsafe(18)
        token = secrets.token_urlsafe(32)
        self._records[series] = (user_id, self._hash(token), ts + ttl_seconds)
        return series, token

    def consume_and_rotate(self, series: str, presented_token: str, now: float | None = None) -> tuple[str, str, str]:
        ts = now if now is not None else time.monotonic()
        rec = self._records.get(series)
        if not rec:
            raise PermissionError("invalid remember-me series")
        user_id, expected_hash, exp = rec
        if ts > exp:
            self._records.pop(series, None)
            raise PermissionError("remember-me expired")

        if not hmac.compare_digest(expected_hash, self._hash(presented_token)):
            # 检测到同 series 旧令牌重放盗用 -> 撤销该用户全部 remember-me 会话
            for s in [k for k, v in self._records.items() if v[0] == user_id]:
                self._records.pop(s, None)
            raise PermissionError("remember-me token theft detected; all series revoked")

        new_token = secrets.token_urlsafe(32)
        self._records[series] = (user_id, self._hash(new_token), exp)
        return user_id, series, new_token

    def revoke_all_for_user(self, user_id: str) -> None:
        for s in [k for k, v in self._records.items() if v[0] == user_id]:
            self._records.pop(s, None)


class HardenedJWTSessionVerifier:
    """强制固定算法、短有效期、jti 单令牌吊销与全局 SSO 注销时钟的 JWT 验证器。"""

    def __init__(self, expected_alg: str, hmac_secret: bytes, issuer: str, audience: str) -> None:
        self.expected_alg = expected_alg
        self.hmac_secret = hmac_secret
        self.issuer = issuer
        self.audience = audience
        self.revoked_jtis: set[str] = set()
        self.user_valid_after: dict[str, int] = {}

    @staticmethod
    def _b64u_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64u_decode(data: str) -> bytes:
        pad = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)

    def sign(self, sub: str, now: int, ttl: int = 600) -> str:
        header = {"alg": self.expected_alg, "typ": "JWT"}
        payload = {
            "sub": sub,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_urlsafe(16),
        }
        signing_input = f"{self._b64u_encode(json.dumps(header).encode())}.{self._b64u_encode(json.dumps(payload).encode())}"
        sig = hmac.new(self.hmac_secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{self._b64u_encode(sig)}"

    def verify(self, token: str, now: int) -> dict:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise PermissionError("malformed or unsigned JWT")
        hdr_b64, pay_b64, sig_b64 = parts
        header = json.loads(self._b64u_decode(hdr_b64))
        # 绝不信任 token 自带的 alg=none 或异构算法切换
        if header.get("alg") != self.expected_alg:
            raise PermissionError("unexpected JWT algorithm")

        expected_sig = hmac.new(self.hmac_secret, f"{hdr_b64}.{pay_b64}".encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_sig, self._b64u_decode(sig_b64)):
            raise PermissionError("invalid JWT signature")

        claims = json.loads(self._b64u_decode(pay_b64))
        if claims.get("iss") != self.issuer or claims.get("aud") != self.audience:
            raise PermissionError("invalid issuer or audience")
        if int(claims.get("exp", 0)) <= now:
            raise PermissionError("JWT expired")
        if claims.get("jti") in self.revoked_jtis:
            raise PermissionError("JWT revoked via jti denylist")
        cutoff = self.user_valid_after.get(claims.get("sub", ""), 0)
        if int(claims.get("iat", 0)) < cutoff:
            raise PermissionError("JWT invalidated by global SSO logout")
        return claims

    def revoke_token(self, claims: dict) -> None:
        if "jti" in claims:
            self.revoked_jtis.add(claims["jti"])

    def global_sso_logout(self, sub: str, now: int) -> None:
        self.user_valid_after[sub] = now + 1
```

### 3. 状态变更方法与 CSRF 强制约束

- 所有账户敏感变更（改密、改邮箱、销户、注销、SSO 绑定）均只绑定 `POST`/`DELETE`，若收到 `GET` 直接返回 `405 Method Not Allowed`，并强制校验 `Sec-Fetch-Site` 与反 CSRF Token。

## 防御工作流

1. **会话生成与轮换核查**：确认登录、MFA 完成与权限变更后调用 `rotate_on_login` 销毁旧 ID，启用 `__Host-` 与 `SameSite=Strict`（或 `Lax` 配合强 CSRF 防护），并在服务端关闭 URL 会话参数解析。
2. **SSO 全局注销闭环**：对接 OIDC Back-Channel Logout 或维护 Redis `user_valid_after` 注销时间戳，确保在 IdP 或任一应用注销后，所有子应用已有会话与访问令牌即时失效。
3. **Remember-Me 与 JWT 策略收口**：升级 Remember-Me 为 CSPRNG + SHA-256 哈希存储 + 单次轮换；缩短 JWT 有效期至 15 分钟内，固定唯一允许的验签算法，并接入 `jti` 黑名单。
4. **会存储隔离与纯 JSON 化**：为每个应用分配独立 Redis ACL 前缀，禁止跨应用共用 session 键空间；将存量 `pickle`/Java 序列化会话迁移为纯 JSON。
5. **消除 GET 状态变更与开放重定向**：核查路由表确保零 GET 写操作并下线任意重定向接口。

## 验证与判定标准

运行下方回归脚本，验证登录轮换、URL 会话拒收、跨应用 Session Puzzling 隔离、Remember-Me 盗用全清及 JWT 吊销/防算法混淆均按预期生效：

```python
import base64
import json


def run_self_checks() -> None:
    # 1. 登录前后必须更换 Session ID，旧 ID 立即失效，且拒绝 URL 参数注入
    app_a = IsolatedSessionManager("app_a")
    app_b = IsolatedSessionManager("app_b")
    pre_sid, pre_cookie = app_a.create_pre_auth_session()
    assert pre_cookie.startswith("__Host-app_a_sid=") and "SameSite=Strict" in pre_cookie

    try:
        app_a.accept_session_cookie_only(pre_sid, {"PHPSESSID": "ATTACKER_FIXED"})
        raise AssertionError("Expected URL session parameter to be rejected")
    except PermissionError:
        pass

    post_sid, _ = app_a.rotate_on_login(pre_sid, user_id="u42", role="user")
    assert post_sid != pre_sid
    assert app_a.read_session(pre_sid) is None      # 旧预登录 ID 已被销毁
    assert app_a.read_session(post_sid)["user_id"] == "u42"
    # 命名空间隔离：app_a 的 session ID 不能在 app_b 中被读取（防 Session Puzzling）
    assert app_b.read_session(post_sid) is None

    # 2. Remember-Me 单次轮换与重放盗用全局吊销
    rm = RememberMeManager()
    series, tok1 = rm.issue("u42", now=100.0)
    uid, _, tok2 = rm.consume_and_rotate(series, tok1, now=110.0)
    assert uid == "u42" and tok2 != tok1
    # 旧令牌 tok1 被攻击者重放 -> 触发盗用检测并吊销整条 series
    try:
        rm.consume_and_rotate(series, tok1, now=120.0)
        raise AssertionError("Expected theft detection on replayed remember-me token")
    except PermissionError:
        pass
    assert series not in rm._records

    # 3. JWT 固定算法（阻断 alg=none / 异构切换）、jti 吊销与 SSO 全局注销生效
    verifier = HardenedJWTSessionVerifier("HS256", b"super-strong-signing-key-32bytes!", "https://sso.example", "app_a")
    jwt_tok = verifier.sign("u42", now=1000, ttl=600)
    claims = verifier.verify(jwt_tok, now=1050)
    assert claims["sub"] == "u42"

    # 构造 alg=none 伪造包
    none_hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    pay_part = jwt_tok.split(".")[1]
    forged_none = f"{none_hdr}.{pay_part}."
    try:
        verifier.verify(forged_none, now=1050)
        raise AssertionError("Expected alg:none to be rejected")
    except PermissionError:
        pass

    # 单令牌吊销与全局 SSO 注销均阻断同一有效期内 JWT
    verifier.revoke_token(claims)
    try:
        verifier.verify(jwt_tok, now=1060)
        raise AssertionError("Expected jti revocation to block token")
    except PermissionError:
        pass

    jwt_tok2 = verifier.sign("u42", now=1100, ttl=600)
    verifier.global_sso_logout("u42", now=1150)
    try:
        verifier.verify(jwt_tok2, now=1160)
        raise AssertionError("Expected global SSO logout to invalidate token")
    except PermissionError:
        pass

    print("[PASS] All session fixation & SSO hijacking defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 登录前后 Session ID 必定变化且旧 ID 从服务端立即清除；URL 参数传入的 Session ID 被拦截；
- 不同应用的会话存储使用互不重叠的命名空间前缀与独立 `__Host-` Cookie，且只允许纯 JSON 序列化；
- Remember-Me 每次使用后轮换令牌，旧令牌重放会触发整账户持久化令牌撤销；
- JWT 验签仅允许预设算法并拒绝 `alg:none`，注销或 SSO 全局登出后已有未过期 JWT 立即失效。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 会话 Cookie 与端点行为探测 | `http_probe` | 验证登录前后 `Set-Cookie` 属性（`__Host-`、`HttpOnly`、`Secure`、`SameSite`）及轮换状态 |
| 关联防御知识检索 | `kb_router` | 按 `session fixation defense`、`JWT revocation`、`SSO logout` 检索指引 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [02-session-fixation-attacks.md](../../../../red/ctf-website/techniques/20-oauth-deep/02-session-fixation-attacks.md) 核验会话全链路防线 |
| 知识目录定位 | `kb_catalog` | 浏览 `20-oauth-deep` 板块下的 OAuth 与 Session 防御文档 |
