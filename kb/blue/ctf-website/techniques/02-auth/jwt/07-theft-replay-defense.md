---
id: "ctf-website/02-auth/jwt/07-theft-replay-defense"
title: "JWT 凭证窃取、重放与持久化防御"
title_en: "JWT Theft, Replay, and Persistence Defense"
summary: >
  针对 JWT 作为 Bearer Token 在前端 localStorage/sessionStorage、URL query/fragment、Referer 与访问日志中的泄露风险，以及登出后仍有效、跨上下文重放和 Refresh Token 并发复用持久化问题，提供 HttpOnly+Secure+SameSite Cookie 落盘方案、Referrer-Policy/CSP/日志掩码化策略、jti 吊销黑名单、Refresh Token 轮换与复用检测（Reuse Detection）家族吊销机制，并附可运行的 Python 验证脚本。
summary_en: >
  Defensive guide against JWT bearer theft, replay, and refresh persistence. Covers HttpOnly/Secure/SameSite cookie storage, URL/Referer/log leakage elimination, CSP/XSS containment, jti revocation on logout, refresh token rotation with reuse detection (family revocation), and runnable Python tests.
board: "ctf-website"
category: "02-auth"
signals: ["Bearer Token", "HttpOnly", "SameSite", "Referrer-Policy", "jti吊销", "Refresh轮换", "Reuse Detection", "重放防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["JWT窃取防御", "Token重放防御", "Refresh Token轮换", "jti黑名单", "HttpOnly Cookie", "Reuse Detection"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "replay", "session-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/07-theft-replay", "ctf-website/02-auth/jwt/06-claim-missing-defense", "ctf-website/07-client/admin-bot-xss", "ctf-website/07-client/cors-csrf"]
track: "blue"
defends: "ctf-website/02-auth/jwt/07-theft-replay"
---

# JWT 凭证窃取、重放与持久化防御

Bearer Token 的天然弱点是“持有即等价于合法用户”。若把长效 JWT 存入 `localStorage`、放入 URL 查询参数、缺少登出撤销机制或允许旧 Refresh Token 并发重复使用，即使签名算法无懈可击，一次 XSS、一条日志泄露或一帧跨站外链 Referer 就足以导致长期会话接管。

## 风险落点与防御控制矩阵

| 风险落点 / 机制 | 攻击影响 | 强制防御控制 |
|---|---|---|
| `localStorage` / `sessionStorage` 存储 | 任意同源 XSS 直接读取完整 JWT 并外传 | 将认证凭证移入 `HttpOnly; Secure; SameSite=Lax/Strict` Cookie，搭配严格 CSP（禁用 `unsafe-inline`） |
| URL query / fragment 传 Token | 经浏览器历史、第三方资源 `Referer` 与代理访问日志明文泄露 | 禁止通过 URL 传递 `access_token`/`id_token`；全站配置 `Referrer-Policy: strict-origin-when-cross-origin` 或 `no-referrer` |
| 日志 / HAR / 错误监控采集 | 网关/APM/Sentry 记录 `Authorization` 头或响应体中的 Token | 网关与日志管线对 `Authorization` 头与 `access_token`/`refresh_token` 字段执行结构化掩码化（仅留末 4 位或哈希指纹） |
| 登出后 Access Token 仍可用 | 无状态服务不维护撤销态，攻击者登出后仍可继续重放 | 缩短 Access Token TTL（<= 10 分钟），并在 Redis 维护 `jti` 吊销集合（TTL=剩余有效期）与用户级 `revoked_before` 时间戳 |
| Refresh Token 复用 / 并发竞争 | 同一 Refresh Token 被多次或并发换取多个新 Access Token | 实施**单次消费轮换（Refresh Token Rotation）+ 家族吊销（Reuse Detection）**：使用分布式原子锁，一旦检测到已消费的旧 Refresh Token 再次提交，立即作废整个令牌家族 |
| 跨设备 / 跨上下文无约束重放 | Token 脱离原始设备或高风险上下文仍全权有效 | 高敏操作绑定设备指纹/确认会话，或采用 DPoP / mTLS 发送方约束令牌（Sender-Constrained Token） |

## 防御工作流

```text
1. 凭证传输与存储加固
   └─ Set-Cookie 强制 HttpOnly + Secure + SameSite=Lax/Strict；全站开启 HSTS 与 strict Referrer-Policy
2. 零 URL 暴露与日志掩码化
   └─ OAuth 仅用 Authorization Code（不走 URL fragment）；Nginx/应用日志过滤器自动遮罩 Bearer 与 token JSON 键
3. 短效 Access + 有状态吊销
   └─ Access TTL <= 10 分钟；用户登出或改密时将当前 jti 写入 Redis 吊销列表并推进用户全局失效水位线
4. Refresh Token 原子轮换与复用检测
   └─ 每次刷新原子标旧 Refresh Token 为已消费并颁发新代次；若旧令牌再现，判定发生窃取并吊销该会话家族全部令牌
5. 同源与跨站辅助边界
   └─ 使用 Cookie 承载 JWT 时，为状态变更接口补充 Origin/CSRF Token 校验与严格 CORS 白名单
```

### Python Refresh Token 轮换、复用检测与 `jti` 吊销核心实现

```python
import secrets
import threading
import time
from dataclasses import dataclass, field


@dataclass
class RefreshRecord:
    family_id: str
    user_id: str
    scope: str
    used: bool = False
    expires_at: int = 0


@dataclass
class TokenStateStore:
    """线程安全的 jti 吊销表与 Refresh 家族轮换状态机（生产环境对应 Redis Lua 原子脚本）。"""
    revoked_jtis: dict[str, int] = field(default_factory=dict)
    user_revoked_before: dict[str, int] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshRecord] = field(default_factory=dict)
    revoked_families: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def revoke_access_jti(self, jti: str, exp: int) -> None:
        with self._lock:
            self.revoked_jtis[jti] = exp

    def revoke_all_user_sessions(self, user_id: str, now: int) -> None:
        with self._lock:
            self.user_revoked_before[user_id] = now

    def is_access_active(self, jti: str, user_id: str, iat: int, now: int) -> bool:
        with self._lock:
            if jti in self.revoked_jtis and self.revoked_jtis[jti] >= now:
                return False
            if iat < self.user_revoked_before.get(user_id, 0):
                return False
            return True

    def issue_refresh_family(self, user_id: str, scope: str, ttl: int, now: int) -> tuple[str, str]:
        family_id = f"fam_{secrets.token_hex(8)}"
        token = secrets.token_urlsafe(32)
        with self._lock:
            self.refresh_tokens[token] = RefreshRecord(
                family_id=family_id, user_id=user_id, scope=scope, used=False, expires_at=now + ttl
            )
        return token, family_id

    def rotate_refresh(self, refresh_token: str, ttl: int, now: int) -> str:
        """单次原子轮换：并发或重放旧 Refresh Token 立即吊销整条家族链。"""
        with self._lock:
            rec = self.refresh_tokens.get(refresh_token)
            if rec is None or now >= rec.expires_at:
                raise PermissionError("invalid or expired refresh token")
            if rec.family_id in self.revoked_families:
                raise PermissionError("refresh token family revoked")
            if rec.used:
                # 关键防御：检测到旧 Refresh Token 被二次使用，立即冻结整条会话家族
                self.revoked_families.add(rec.family_id)
                raise PermissionError("refresh token reuse detected; family revoked")
            rec.used = True
            new_token = secrets.token_urlsafe(32)
            self.refresh_tokens[new_token] = RefreshRecord(
                family_id=rec.family_id,
                user_id=rec.user_id,
                scope=rec.scope,
                used=False,
                expires_at=now + ttl,
            )
            return new_token
```

### Nginx 响应头与日志掩码配置片段

```nginx
# 强制传输加密与防 Referer 泄露
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'" always;
```

## 验证与判定标准

运行下方脚本验证 [07-theft-replay.md](../../../../../red/ctf-website/techniques/02-auth/jwt/07-theft-replay.md) 中的登出后 Access 重放、Refresh 重复消费以及并发重放均触发精准阻断与家族吊销：

```python
import concurrent.futures


def run_theft_replay_defense_checks() -> None:
    store = TokenStateStore()
    now = 1700000000

    # 1. 登出后 jti 立即失效
    assert store.is_access_active("jti-1", "u-1", now - 10, now) is True
    store.revoke_access_jti("jti-1", now + 600)
    assert store.is_access_active("jti-1", "u-1", now - 10, now + 5) is False

    # 2. Refresh 复用检测触发家族吊销
    rt1, _ = store.issue_refresh_family("u-1", "profile", 3600, now)
    rt2 = store.rotate_refresh(rt1, 3600, now + 1)
    try:
        store.rotate_refresh(rt1, 3600, now + 2)
    except PermissionError:
        pass
    else:
        raise AssertionError("reused refresh token was not blocked")

    # 家族冻结后连合法的 rt2 也必须同步失效
    try:
        store.rotate_refresh(rt2, 3600, now + 3)
    except PermissionError:
        pass
    else:
        raise AssertionError("compromised family new token remained active")

    # 3. 并发刷新仅允许唯一胜出者
    rt_conc, _ = store.issue_refresh_family("u-2", "profile", 3600, now)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(lambda _: _try_rotate(store, rt_conc, now + 1), range(5)))
    assert results.count("OK") == 1 and results.count("ERR") == 4, f"unexpected concurrent result: {results}"
    print("PASS: all theft/replay/rotation defense checks passed")


def _try_rotate(store: TokenStateStore, tok: str, now: int) -> str:
    try:
        store.rotate_refresh(tok, 3600, now)
        return "OK"
    except PermissionError:
        return "ERR"


if __name__ == "__main__":
    run_theft_replay_defense_checks()
```

判定标准：
1. **浏览器不可脚本读取**：检查登录态下 `document.cookie`、`localStorage` 与 `sessionStorage`，均不含可用 Access/Refresh JWT。
2. **登出即失效**：执行 `/logout` 后重放原 Access Token 或 Refresh Token 立即返回 `401`。
3. **并发单胜与复用冻结**：5 线程并发提交同一 `refresh_token` 至多 1 次成功；一旦旧 `refresh_token` 再次出现，新旧全部令牌立即作废。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `token窃取`、`重放`、`Refresh`、`HttpOnly` 检索防御方案 |
| 规程读取 | `kb_read_file` | 读取 `07-theft-replay-defense` 与 `07-client/cors-csrf` |
| 目录索引核查 | `kb_catalog` | 核对 `02-auth/jwt/` 及 `07-client/` 下客户端防护文档 |
