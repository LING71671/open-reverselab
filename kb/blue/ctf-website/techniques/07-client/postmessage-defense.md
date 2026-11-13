---
id: "ctf-website/07-client/postmessage-defense"
title: "PostMessage 跨域消息通信纵深防御"
title_en: "PostMessage Cross-Origin Communication Defense"
summary: >
  针对 window.postMessage 跨域通信的全面防御指南，涵盖接收端严格 Origin 精确匹配与防 null origin 绕过、event.source 与实时 Origin 联合校验防导航竞态、发送端禁止通配符 "*" 泄露 OAuth Token、消息 Schema 强白名单防 Prototype Pollution 与 XSS Sink，以及可运行 Python 策略校验器。
summary_en: >
  Comprehensive defense guide for window.postMessage cross-origin communication covering exact origin allowlisting against null/substring bypasses, simultaneous event.source and origin verification against navigation races, prohibiting wildcard "*" targetOrigin to stop OAuth token leaks, strict message schema validation against prototype pollution/XSS sinks, and runnable validation checks.
board: "ctf-website"
category: "07-client"
signals: ["postMessage防御", "origin精确校验", "targetOrigin指定", "event.source竞态防护", "消息schema白名单", "OAuth回包防护"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["postMessage防御", "跨域通信安全", "targetOrigin通配符禁用", "null origin防护", "event.source验证", "OAuth弹窗安全", "DOM XSS防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "client-side", "postmessage", "oauth", "xss"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/07-client/postmessage", "ctf-website/03-injection/prototype-pollution-defense", "ctf-website/07-client/admin-bot-xss-defense", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
track: "blue"
defends: "ctf-website/07-client/postmessage"
---

# PostMessage 跨域消息通信纵深防御

`window.postMessage` 的风险分为**接收端失守**与**发送端泄密**两面：接收端使用 `includes`/`endsWith`、信任 `"null"` origin、仅校验一次性 `event.source` 或把未校验 `event.data` 送入 `merge`/`innerHTML`/`location`；发送端使用 `postMessage(secret, "*")` 导致任意嵌入页面或被重定向的 `opener` 截获 OAuth Token。防御必须在发包与收包两端同时执行精确契约。

## 防御工作流

```text
接收端第一行执行严格 Origin 集合等值校验（拒绝 "null" 与子串匹配）
  → 若校验 event.source，必须每次同步重新核对当前 event.origin
  → 解析 event.data 为纯平面 JSON 字段并过滤原型污染键
  → 按 action/type 显式枚举路由，严禁直接进入 innerHTML/eval/不安全跳转
  → 发送端永远指定精确 targetOrigin 禁用 "*"，OAuth 凭据改走后端 PKCE
```

## 1. 接收端 Origin 与 Source 竞态防护

| 错误做法 | 绕过方式 | 正确加固代码 |
|---|---|---|
| `e.origin.includes("target.com")` 或 `endsWith` | `https://target.com.attacker.test` | `if (!ALLOWED_ORIGINS.has(e.origin)) return;` |
| 忽略 `"null"` 字符串比较 | `sandbox` iframe / `data:` URL | `"null"` 不得加入 `ALLOWED_ORIGINS` |
| 初始化时保存 `trustedSource = iframe.contentWindow`，后续仅判断 `e.source === trustedSource` | iframe 或弹窗被导航至恶意域后 `source` 引用仍相同 | 每次处理消息都必须同时满足 `ALLOWED_ORIGINS.has(e.origin)` 与预期窗口引用校验 |
| `e.origin.startsWith("https://target.com")` | `https://target.com.evil.test` | 使用 `Set.has(e.origin)` 严格等值匹配（包含 `scheme + host + port`） |

## 2. 发送端禁用通配符 `"*"` 与 OAuth 隔离

1. **严格指定 `targetOrigin`**：向父窗口、子 `iframe` 或 `window.opener` 发送任何带用户状态、业务结果或导航指令的消息时，严禁使用 `"*"`，必须写明精确目标源（如 `opener.postMessage(payload, "https://app.example.com")`）。
2. **OAuth / Token 传递改造**：避免 OAuth Callback 页面通过 `opener.postMessage(access_token, "*")` 或隐式流把凭据交到前端通道；生产环境采用 **Authorization Code + PKCE** 在服务端交换 Token 并写入 `HttpOnly; SameSite=Lax` 会话 Cookie，前端仅通知 `{ type: "auth_complete" }` 非敏感状态信号。
3. **关闭不必要嵌套与 Opener 引用**：无需被第三方嵌入的敏感页面设置 `X-Frame-Options: DENY` 与 CSP `frame-ancestors 'self'`；外部跳转链接设置 `rel="noopener noreferrer"` 切断 `window.opener`。

## 3. 消息 Schema、Prototype Pollution 与 Sink 加固

```javascript
const ALLOWED_ORIGINS = new Set(["https://app.example.com", "https://auth.example.com"]);
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

window.addEventListener("message", (event) => {
  // 1. 严格 Origin 白名单（绝对拒绝 "null" 与子串匹配）
  if (!ALLOWED_ORIGINS.has(event.origin)) {
    return;
  }

  // 2. 基础结构与防原型链污染检查
  const raw = event.data;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return;
  }
  for (const k of Object.keys(raw)) {
    if (FORBIDDEN_KEYS.has(k)) {
      return;
    }
  }

  // 3. 显式 Action 枚举与字段白名单提取（不透传整包，不接受 RegExp 等带状态结构化克隆对象）
  if (raw.type === "render_notice" && typeof raw.text === "string") {
    // 使用 textContent 而非 innerHTML，阻断 DOM XSS
    document.getElementById("notice-box").textContent = raw.text.slice(0, 200);
  } else if (raw.type === "navigate" && typeof raw.path === "string") {
    // 仅允许同源相对路径，阻断 javascript: 或开放重定向
    const target = new URL(raw.path, window.location.origin);
    if (target.origin === window.location.origin) {
      window.location.assign(target.pathname + target.search);
    }
  }
});
```

## 4. 可运行前端契约静态检查与规则校验器

以下 Python 脚本用于对前端 JS 代码与消息载荷策略进行自动化核查：检测不安全 `postMessage(..., "*")`、脆弱 `origin` 比较模式（`includes`/`endsWith`/`indexOf`）及接收器中原型键/危险动作枚举校验：

```python
#!/usr/bin/env python3
"""PostMessage 源码反模式核查与运行期消息契约校验器。"""
import re
from typing import Any

ALLOWED_ORIGINS = frozenset({"https://app.example.com", "https://auth.example.com"})
ALLOWED_ACTIONS = frozenset({"ping", "render_notice", "auth_complete"})
FORBIDDEN_KEYS = frozenset({"__proto__", "constructor", "prototype"})

JS_ANTI_PATTERNS = [
    ("wildcard_target_origin", re.compile(r"\.postMessage\s*\([^,]+,\s*['\"]\*['\"]\s*\)")),
    ("weak_origin_includes", re.compile(r"\.origin\.(?:includes|endsWith|startsWith|indexOf)\s*\(")),
    ("missing_origin_check", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]\s*,(?![\s\S]{0,200}\.origin)")),
]


def scan_js_handler(js_code: str) -> list[str]:
    return [name for name, rx in JS_ANTI_PATTERNS if rx.search(js_code)]


def validate_incoming_message(origin: str, data: Any) -> tuple[bool, str]:
    """模拟浏览器 message 事件处理器前的严格策略校验。"""
    if origin == "null" or origin not in ALLOWED_ORIGINS:
        return False, f"reject: untrusted origin {origin!r}"
    if not isinstance(data, dict):
        return False, "reject: message data must be plain object"
    for k in data.keys():
        if k in FORBIDDEN_KEYS:
            return False, f"reject: forbidden prototype key {k!r}"
    action = data.get("type")
    if action not in ALLOWED_ACTIONS:
        return False, f"reject: unknown or privileged action {action!r}"
    if "html" in data:
        return False, "reject: raw HTML field is forbidden"
    return True, "allow"


if __name__ == "__main__":
    unsafe_js = """
    window.addEventListener("message", (e) => {
      if (e.origin.includes("example.com")) {
        document.body.innerHTML = e.data.html;
        e.source.postMessage({token: localStorage.getItem("jwt")}, "*");
      }
    });
    """
    hits = scan_js_handler(unsafe_js)
    assert "wildcard_target_origin" in hits and "weak_origin_includes" in hits
    print(f"[PASS JS scan] detected anti-patterns: {hits}")

    bad_msgs = [
        ("null", {"type": "ping"}),
        ("https://app.example.com.attacker.test", {"type": "ping"}),
        ("https://app.example.com", {"type": "getFlag"}),
        ("https://app.example.com", {"type": "ping", "__proto__": {"isAdmin": True}}),
        ("https://app.example.com", {"type": "render_notice", "html": "<img src=x onerror=alert(1)>"}),
    ]
    for orig, msg in bad_msgs:
        ok, reason = validate_incoming_message(orig, msg)
        assert not ok, f"expected block for {orig} {msg}"
        print(f"[PASS msg] {reason}")

    assert validate_incoming_message("https://app.example.com", {"type": "auth_complete"})[0] is True
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| Origin 与 Source 检查 | `null`、子域、包含匹配及 `iframe`/`opener` 导航替换后均不触发任何业务分支 | `sandbox` iframe 或兄弟/恶意子域消息触发回包或状态修改 |
| 发送端 targetOrigin | 代码库零 `postMessage(..., "*")` 传敏调用；OAuth 回调无前端明文 Token 回传 | 恶意 `opener` 捕获包含 `access_token`/`code`/`flag` 的消息 |
| 消息 Schema 与 PP/XSS | 非白名单 `type`/`action`、`__proto__`、`html` 字段均被忽略或拒绝 | 全局对象被污染或 `innerHTML` 执行脚本 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `postmessage`、`origin`、`oauth`、`prototype pollution` 搜索相关条目 |
| 读取攻击矩阵 | `kb_read_file` | 对照 `ctf-website/07-client/postmessage` 核查 Origin/Source/Schema 全向量 |
| 浏览目录索引 | `kb_catalog` | 列出 `07-client` 与 `20-oauth-deep` 关联防御条目 |
| 前端资源核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后确认 `X-Frame-Options` 与 `frame-ancestors` 策略已下发 |
