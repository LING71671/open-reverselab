---
id: "ctf-website/07-client/cors-csrf-defense"
title: "CORS 跨域策略与 CSRF 请求伪造防御"
title_en: "CORS and CSRF Defense"
summary: >
  针对 CORS 配置缺陷（Origin 反射、子域/前缀正则绕过、null origin、ACAC 滥用）与 CSRF 攻击（SameSite 缺失、token 可删/可置空/跨用户复用、GET 变更与 text/plain Simple Request 绕过 preflight）的纵深防御指南。包含精确 Origin 匹配、HMAC 绑定 Token 中间件、Sec-Fetch-Site 校验及可运行 Python 防御实现。
summary_en: >
  Defense-in-depth guide against CORS misconfigurations (origin reflection, suffix/prefix bypasses, null origin, ACAC abuse) and CSRF attacks (missing SameSite, removable/empty/reusable tokens, GET state changes, text/plain simple requests bypassing preflight). Includes exact origin allowlisting, HMAC-bound token verification, Sec-Fetch-Site checks, and runnable Python middleware.
board: "ctf-website"
category: "07-client"
signals: ["CORS防御", "CSRF防御", "Origin精确白名单", "SameSite加固", "Sec-Fetch-Site", "preflight校验", "CSRF Token绑定"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["CORS防御", "CSRF防御", "Origin白名单", "Vary Origin", "SameSite Cookie", "CSRF Token验证", "Sec-Fetch-Site", "Simple Request防护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cors", "csrf", "authentication", "client-side"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/07-client/cors-csrf", "ctf-website/07-client/admin-bot-xss-defense", "ctf-website/07-client/postmessage-defense", "ctf-website/20-oauth-deep/02-session-fixation-attacks"]
track: "blue"
defends: "ctf-website/07-client/cors-csrf"
---

# CORS 跨域策略与 CSRF 请求伪造防御

CORS 控制跨域脚本“能否读取响应”，CSRF 控制跨站页面“能否借助浏览器 Cookie 触发状态变更”。即使浏览器控制台拦截了 CORS 响应读取，只要服务端未拦截 Simple Request（如 `GET` 导航或 `enctype="text/plain"` 表单 POST），业务副作用依然已经发生。两者必须联动加固：**精确静态 Origin 白名单 + 严格 Content-Type + 会话绑定的 CSRF 校验 + Cookie SameSite/Fetch Metadata**。

## 防御工作流

```text
建立静态精确 CORS Origin 白名单（禁用反射、子串匹配与 null origin）
  → 设置 Vary: Origin 并严禁敏感接口同时配置通配符与 Credentials
  → 所有状态变更禁用 GET 与 _method 覆盖，强校验 Content-Type: application/json
  → 会话 Cookie 启用 SameSite=Lax/Strict + Secure + HttpOnly
  → 状态接口同时校验 Sec-Fetch-Site 与 HMAC 绑定会话/动作的 CSRF Token
```

## 1. CORS 精确匹配与缓存隔离

1. **禁止反射任意 `Origin` 与脆弱正则**：严禁直接把请求头 `Origin` 原样回写 `Access-Control-Allow-Origin`（ACAO），也禁止使用 `origin.endswith("target.com")`、`origin.includes("target.com")` 或无锚点正则（会被 `target.com.attacker.example`、`eviltarget.com`、`http://` 协议降级绕过）。必须采用完整 `scheme + host + port` 的精确集合比对。
2. **禁止允许 `Origin: null`**：带 `Access-Control-Allow-Credentials: true` 时绝不放行 `null` origin，防止 `sandbox` iframe、`data:` 或 `file:` 页面读取认证接口。
3. **强制响应 `Vary: Origin`**：只要接口根据请求 `Origin` 动态切换白名单 ACAO 头，就必须在响应头返回 `Vary: Origin`，阻止 CDN/反向代理缓存投毒向其他来源下发错误 CORS 头。
4. **Preflight（OPTIONS）最小化授权**：`Access-Control-Allow-Methods` 与 `Access-Control-Allow-Headers` 仅列出该路由真实所需的最小集合，不返回反射式允许列表。

## 2. 阻断 CSRF 变体与 Simple Request 旁路

| 攻击手法 | 漏洞根因 | 强制防御措施 |
|---|---|---|
| Token 删除/置空/固定值绕过 | `if token:` 仅在存在时检查（Fail-Open） | **Fail-Closed**：缺省字段、`null`、`""` 一律 `403` 拒绝 |
| 跨用户/跨动作复用 Token | Token 只是一次随机全局串未绑定身份 | Token 通过 HMAC 绑定 `session_id + action_scope + exp`，并与当前会话/路由强制比对 |
| `SameSite=Lax` 下的 GET 状态动作 | 使用 `GET` 触发删除/转账/绑定操作 | 严格遵守 HTTP 幂等语义，所有状态写操作仅限 `POST`/`PUT`/`DELETE`，禁用 `_method` 参数覆盖 |
| `text/plain` / `form` 逃避 Preflight | 后端未校验 `Content-Type`，把表单或纯文本按 JSON 解析 | JSON API 强校验 `Content-Type` 精确为 `application/json`（触发浏览器强制 Preflight），拒绝 `text/plain` 与 `application/x-www-form-urlencoded` |
| 缺少 Cookie 与浏览器上下文防线 | 未设置 `SameSite` 与未利用 Fetch Metadata | 会话 Cookie 设 `SameSite=Lax; Secure; HttpOnly`（管理后台 `SameSite=Strict`）；服务端优先拦截 `Sec-Fetch-Site: cross-site` |

## 3. 可运行 CORS / CSRF / Fetch Metadata 防护实现

以下 Python 模块提供可用于 Web 中间件的三重联防：精确 Origin 集合核查、基于 `HMAC-SHA256` 的会话+动作绑定 CSRF Token 签发与恒定时间验证，以及 `Sec-Fetch-Site` 与严格 `Content-Type` 检查：

```python
#!/usr/bin/env python3
"""CORS 精确白名单、HMAC 会话绑定 CSRF Token 与 Simple Request 防护校验器。"""
import hmac
import hashlib
import os
import secrets
import time

ALLOWED_ORIGINS = frozenset({
    "https://app.example.com",
    "https://admin.example.com",
})
CSRF_KEY = os.urandom(32)


def cors_headers_for_request(origin: str | None) -> dict[str, str]:
    """严格精确匹配 Origin；不匹配时不输出 ACAO/ACAC，并始终附加 Vary: Origin。"""
    headers = {"Vary": "Origin"}
    if origin and origin in ALLOWED_ORIGINS:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token"
    return headers


def issue_csrf_token(session_id: str, action: str, ttl_seconds: int = 1800) -> str:
    """签发绑定 session_id + action + 过期时间的不可预测 CSRF Token。"""
    nonce = secrets.token_urlsafe(16)
    exp = str(int(time.time()) + ttl_seconds)
    msg = f"{session_id}|{action}|{nonce}|{exp}".encode("utf-8")
    sig = hmac.new(CSRF_KEY, msg, hashlib.sha256).hexdigest()
    return f"{nonce}.{exp}.{sig}"


def verify_state_change_request(
    *,
    method: str,
    content_type: str,
    sec_fetch_site: str | None,
    session_id: str,
    expected_action: str,
    provided_token: str | None,
) -> tuple[bool, str]:
    """状态变更请求 Fail-Closed 校验：Method + Content-Type + Fetch Metadata + CSRF Token。"""
    if method.upper() not in {"POST", "PUT", "DELETE", "PATCH"}:
        return False, "reject: state change via non-mutating HTTP method"

    mime = content_type.split(";", 1)[0].strip().lower()
    if mime != "application/json":
        return False, "reject: simple-request Content-Type bypass blocked"

    if sec_fetch_site and sec_fetch_site.lower() == "cross-site":
        return False, "reject: cross-site request blocked by Fetch Metadata"

    if not provided_token or not isinstance(provided_token, str):
        return False, "reject: missing or empty CSRF token"

    parts = provided_token.split(".")
    if len(parts) != 3:
        return False, "reject: malformed CSRF token"
    nonce, exp_str, sig = parts
    try:
        if int(exp_str) < int(time.time()):
            return False, "reject: expired CSRF token"
    except ValueError:
        return False, "reject: invalid CSRF expiration"

    msg = f"{session_id}|{expected_action}|{nonce}|{exp_str}".encode("utf-8")
    expected_sig = hmac.new(CSRF_KEY, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "reject: CSRF token session/action binding mismatch"

    return True, "allow"


if __name__ == "__main__":
    # 1. CORS Origin 绕过变体测试
    for bad_origin in (
        "null",
        "https://evil.app.example.com",
        "https://app.example.com.attacker.example",
        "http://app.example.com",
        "https://attacker.example",
    ):
        hdrs = cors_headers_for_request(bad_origin)
        assert "Access-Control-Allow-Origin" not in hdrs, f"leaked ACAO for {bad_origin}"
    good_hdrs = cors_headers_for_request("https://app.example.com")
    assert good_hdrs["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert good_hdrs["Vary"] == "Origin"
    print("[PASS CORS] all bypass origins rejected; Vary: Origin set")

    # 2. CSRF 变体测试（删除、空值、跨用户、跨动作、text/plain、GET 切换、cross-site）
    tok_alice = issue_csrf_token("sess_alice", "transfer")
    assert verify_state_change_request(
        method="POST", content_type="application/json", sec_fetch_site="same-origin",
        session_id="sess_alice", expected_action="transfer", provided_token=tok_alice,
    )[0] is True

    bad_cases = [
        ("missing", dict(method="POST", content_type="application/json", sec_fetch_site="same-origin", session_id="sess_alice", expected_action="transfer", provided_token=None)),
        ("empty", dict(method="POST", content_type="application/json", sec_fetch_site="same-origin", session_id="sess_alice", expected_action="transfer", provided_token="")),
        ("cross_user", dict(method="POST", content_type="application/json", sec_fetch_site="same-origin", session_id="sess_bob", expected_action="transfer", provided_token=tok_alice)),
        ("cross_action", dict(method="POST", content_type="application/json", sec_fetch_site="same-origin", session_id="sess_alice", expected_action="delete_account", provided_token=tok_alice)),
        ("text_plain_simple", dict(method="POST", content_type="text/plain", sec_fetch_site="same-site", session_id="sess_alice", expected_action="transfer", provided_token=tok_alice)),
        ("get_flip", dict(method="GET", content_type="application/json", sec_fetch_site="same-origin", session_id="sess_alice", expected_action="transfer", provided_token=tok_alice)),
        ("cross_site_fetch", dict(method="POST", content_type="application/json", sec_fetch_site="cross-site", session_id="sess_alice", expected_action="transfer", provided_token=tok_alice)),
    ]
    for name, kw in bad_cases:
        ok, reason = verify_state_change_request(**kw)
        assert not ok, f"expected failure for {name}"
        print(f"[PASS CSRF:{name}] -> {reason}")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| CORS Origin 匹配 | `null`、子域、前缀/后缀伪造与 `http://` 降级均无 ACAO/ACAC 响应头，且包含 `Vary: Origin` | 响应反射非白名单 Origin 并带有 `ACAC: true` |
| CSRF Token 校验 | 缺失、置空、`null`、跨用户 Token、跨动作 Token 均稳定返回 `403` | 去掉 Token 或互换用户 Token 后业务状态仍变更 |
| Simple Request / Method | 状态接口拒绝 `GET`、`_method` 覆盖及 `text/plain`/`application/x-www-form-urlencoded` | `<form enctype="text/plain">` 或 `<a href>` 导航触发转账/修改 |
| Cookie 与 Fetch Metadata | 会话 Cookie 携带 `SameSite=Lax/Strict; Secure; HttpOnly`；`cross-site` 写请求被拒 | 跨站页面自动携 Cookie 完成写操作 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `cors`、`csrf`、`samesite`、`preflight` 搜索配对攻防策略 |
| 读取攻击细节 | `kb_read_file` | 对照 `ctf-website/07-client/cors-csrf` 验证全部 Origin 与 Token 变体 |
| 浏览目录索引 | `kb_catalog` | 确认 `07-client` 与 `20-oauth-deep` 联动防御条目 |
| 响应头与预检核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后测试 `OPTIONS` 与多 Origin 变体响应头 |
