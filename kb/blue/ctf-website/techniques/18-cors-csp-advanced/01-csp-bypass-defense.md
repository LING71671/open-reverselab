---
id: "ctf-website/18-cors-csp-advanced/01-csp-bypass-defense"
title: "CSP 绕过防御 — Strict-Dynamic、单次 Nonce、Trusted Types 与无脚本外带阻断"
title_en: "CSP Bypass Defense — Strict-Dynamic, Per-Response Nonces, Trusted Types & Scriptless Exfiltration Blocking"
summary: >
  针对 JSONP 端点滥用、CDN 白名单脚本 Gadget（Angular/Vue/Prototype）、框架 DOM Sink、DOM Clobbering、
  Base 标签劫持、CSS 选择器与悬空标记外带、strict-dynamic 动态导入污染及 Nonce 复用等 CSP 绕过手段，
  提供现代严苛 CSP 策略模板、JSON 数据桥接与 Trusted Types 防护架构，并附可运行策略校验脚本。
summary_en: >
  Defense against JSONP abuse, CDN allowlist script gadgets, framework DOM sinks, DOM Clobbering, base tag hijacking,
  CSS selector and dangling markup exfiltration, strict-dynamic injection, and nonce reuse. Covers strict CSP Level 3
  templates, safe JSON data bridges, Trusted Types, and a runnable Python CSP policy verifier.
board: "ctf-website"
category: "18-cors-csp-advanced"
signals: ["strict-dynamic", "CSP nonce", "Trusted Types", "base-uri none", "DOM Clobbering defense", "CSS exfiltration", "JSONP hardening"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["CSP防御", "strict-dynamic加固", "Nonce单次生成", "DOM Clobbering防御", "Trusted Types", "Base标签防御", "CSS外带阻断", "JSONP加固"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "csp", "xss", "trusted-types", "dom-clobbering"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/18-cors-csp-advanced/01-csp-bypass", "ctf-website/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels-defense"]
track: "blue"
defends: "ctf-website/18-cors-csp-advanced/01-csp-bypass"
---

# CSP 绕过防御 — Strict-Dynamic、单次 Nonce、Trusted Types 与无脚本外带阻断

## 威胁模型与防御目标

传统基于域名白名单的 Content-Security-Policy（CSP）极易因 CDN 上的历史框架 Gadget 或 JSONP 端点而失效；即便引入 `'strict-dynamic'` 与 `style-src`，仍可能遭遇 Nonce 缓存复用、模板插值污染、DOM Clobbering、`base-uri` 缺失或 CSS 选择器/悬空标记外带。对照 [01-csp-bypass.md](../../../../red/ctf-website/techniques/18-cors-csp-advanced/01-csp-bypass.md)，蓝队防线必须覆盖以下全部绕过路径：

| 绕过技术 | 触发条件 | 蓝队根治措施 |
|---|---|---|
| JSONP 端点与 CDN Gadget（Angular/Vue/Prototype） | `script-src` 存在域名白名单或宽泛 CDN 托管域 | 废弃域名白名单，改用 `'strict-dynamic' 'nonce-<rand>'`；自托管依赖 + SRI；下线 JSONP 或严格校验回调标识符 |
| Nonce 复用与可预测 | 静态 Nonce、跨请求共享或含 Nonce 页面被 CDN 缓存 | 每次响应使用 CSPRNG 生成 >=128-bit Nonce，并对带 Nonce 的 HTML 强制 `Cache-Control: no-store` |
| `strict-dynamic` 下 `import()` / `Worker` 滥用 | 受信任脚本或内联脚本中存在变量插值 | 禁止向带 Nonce `<script>` 内插动态值（改用 `<script type="application/json">` 安全转义）；限定 `worker-src 'self'` 与 `connect-src 'self'` |
| 框架绕过（React/Vue/Angular）与 DOM Clobbering | `dangerouslySetInnerHTML`/`v-html`/SSR Hydration 错位或依赖未核验的 `window.config` | 启用 Trusted Types (`require-trusted-types-for 'script'`)；DOMPurify 开启 `SANITIZE_NAMED_PROPS`；使用 `Object.freeze` 与类型断言防止元素覆盖 |
| Base 标签与悬空标记（Dangling Markup） | 缺失 `base-uri` 与 `form-action` 指令 | 显式声明 `base-uri 'none'`（或 `'self'`）、`form-action 'self'`、`object-src 'none'` |
| 无脚本 CSS 注入外带（属性选择器 / `:target` / `</style>`） | `style-src 'unsafe-inline'` 或外链 `img-src`/`font-src` 开放 | 移除 `style-src 'unsafe-inline'` 改用 Nonce；限制 `img-src`/`font-src`/`connect-src` 为 `'self'`；敏感 token 不写入可被 CSS 匹配的 DOM `value` 属性 |

## 架构加固配置

### 1. 生产级 Strict CSP Level 3 响应头基线

与 `Cache-Control: no-store` 配合下发，既阻断内联与 CDN Gadget，又封堵 Base 劫持、插件执行与 CSS 外带信道：

```http
Cache-Control: no-store, max-age=0
X-Content-Type-Options: nosniff
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-<128bit_random_per_response>' 'strict-dynamic';
  style-src 'self' 'nonce-<128bit_random_per_response>';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  worker-src 'self';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  upgrade-insecure-requests;
  report-to csp-endpoint
```

### 2. 防 DOM Clobbering 与安全 JSON 数据桥接

- **禁止在带 Nonce 的 `<script>` 内直接拼接服务端数据**（如 `var avatar = "{{url}}";`），否则任何引号逃逸都会直接获得 `'strict-dynamic'` 信任链执行 `import()` 或 `new Worker()`。
- **改用非执行型 JSON 数据块**并对 `<`、`>`、`&` 进行 Unicode 转义（`\u003c`），同时前端校验配置对象原型与属性类型，免疫 `<form id="config"><input name="cdn">` 导致的 DOM Clobbering：

```javascript
// 前端安全读取配置（免疫 DOM Clobbering 与原型污染）
function readSafeAppConfig() {
  const node = document.getElementById("app-config");
  if (!(node instanceof HTMLScriptElement) || node.type !== "application/json") {
    return Object.freeze({});
  }
  const parsed = JSON.parse(node.textContent || "{}");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return Object.freeze({});
  }
  // 显式校验预期字段类型为字符串且为同源路径，防止任意 CDN 注入
  const cdnBase = typeof parsed.cdnBase === "string" && parsed.cdnBase.startsWith("/") ? parsed.cdnBase : "/static";
  return Object.freeze({ cdnBase });
}
```

### 3. CSP 策略硬化验证器与安全渲染辅助（Python）

以下 Python 代码提供：
1. 每响应单次 CSPRNG Nonce 生成与安全的 JSON HTML 内嵌序列化器；
2. JSONP 遗留接口回调名严格校验器（拒绝箭头函数、`with`、分号、括号等一切非标识符表达式）；
3. 严苛 CSP 响应头策略检测器，自动捕获所有可被绕过的危险组合。

```python
import base64
import json
import re
import secrets


SAFE_JSONP_CALLBACK_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,63}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,63}){0,3}$")
RISKY_CDN_HOSTS = ("cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com", "code.jquery.com")


def generate_csp_nonce(nbytes: int = 16) -> str:
    """生成至少 128-bit 熵的单次响应 CSP Nonce。"""
    return base64.b64encode(secrets.token_bytes(nbytes)).decode("ascii")


def build_strict_csp(nonce: str) -> str:
    """构造同时阻断 CDN Gadget、Base 劫持、CSS 外带与无脚本表单劫持的 CSP。"""
    return "; ".join([
        "default-src 'none'",
        f"script-src 'nonce-{nonce}' 'strict-dynamic'",
        f"style-src 'self' 'nonce-{nonce}'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "worker-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
    ])


def render_safe_json_script_tag(element_id: str, payload: dict) -> str:
    """把服务端数据安全序列化到非执行 JSON 块，消除 strict-dynamic 脚本插值风险。"""
    raw = json.dumps(payload, ensure_ascii=True)
    # 防止 </script> 闭合或 HTML 注入
    safe_json = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f'<script id="{element_id}" type="application/json">{safe_json}</script>'


def validate_jsonp_callback(callback: str) -> bool:
    """仅允许受限点分标识符，阻断 alert(1)、箭头函数与注释注入。"""
    return bool(SAFE_JSONP_CALLBACK_RE.fullmatch(callback))


def evaluate_csp_hardening(csp_header: str, cache_control: str = "") -> list[str]:
    """核查 CSP 策略中仍可被绕过的薄弱指令并返回阻断项列表。"""
    issues: list[str] = []
    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    script_src = directives.get("script-src") or directives.get("default-src", [])
    style_src = directives.get("style-src") or directives.get("default-src", [])

    if not script_src:
        issues.append("missing script-src and default-src")
    if "'unsafe-inline'" in script_src:
        issues.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in script_src:
        issues.append("script-src allows 'unsafe-eval'")
    if "'unsafe-inline'" in style_src:
        issues.append("style-src allows 'unsafe-inline' (CSS exfiltration risk)")

    # 检查是否依赖风险 CDN 白名单而非 strict-dynamic
    if "'strict-dynamic'" not in script_src:
        for src in script_src:
            if any(cdn in src for cdn in RISKY_CDN_HOSTS):
                issues.append(f"script-src trusts risky CDN allowlist without strict-dynamic: {src}")

    # 校验 Nonce 长度与响应缓存控制
    nonces = [t[7:-1] for t in script_src if t.startswith("'nonce-") and t.endswith("'")]
    for n in nonces:
        if len(n) < 22:  # 128-bit base64 至少 22-24 字符
            issues.append("nonce entropy too short (<128 bits)")
    if nonces and "no-store" not in cache_control.lower():
        issues.append("nonced HTML missing Cache-Control: no-store (nonce reuse risk)")

    if "base-uri" not in directives or not any(x in directives["base-uri"] for x in ("'none'", "'self'")):
        issues.append("missing strict base-uri ('none' or 'self')")
    if "object-src" not in directives or "'none'" not in directives["object-src"]:
        issues.append("object-src must be 'none'")
    if "form-action" not in directives or "*" in directives["form-action"]:
        issues.append("missing strict form-action (dangling markup risk)")

    return issues
```

## 防御工作流

1. **梳理外链脚本与淘汰 JSONP**：将所有第三方 JS 依赖自托管或绑定 SRI，下线不再需要的 JSONP 接口；对必须保留的跨域数据接口改用 CORS + `Content-Type: application/json` + `X-Content-Type-Options: nosniff`。
2. **迁移至 Nonce + Strict-Dynamic**：生成基于 CSPRNG 的单次响应 Nonce，为动态 HTML 响应设置 `Cache-Control: no-store`，并逐步替换所有 `'unsafe-inline'`、`'unsafe-eval'` 与宽泛 CDN 域白名单。
3. **补齐结构性收口指令**：补充 `base-uri 'none'`、`object-src 'none'`、`form-action 'self'`、`worker-src 'self'` 与 `frame-ancestors 'none'`，并移除 `style-src 'unsafe-inline'` 阻断 CSS 选择器外带。
4. **DOM Sink 与数据传递改造**：全部服务端变量通过 `<script type="application/json">` 传递并做 `<`/`>` 转义；前端启用 Trusted Types 策略与 DOMPurify 命名属性清洗，杜绝 DOM Clobbering。
5. **先 Report-Only 观测再强制拦截**：先通过 `Content-Security-Policy-Report-Only` 收集业务兼容性告警，确认零误杀后切换为强阻断头并纳入 CI 自动化回归门禁。

## 验证与判定标准

运行下方回归脚本，确认生成的策略通过全部高危绕过项检测、旧弱策略被准确识别，且 JSONP 与 JSON 桥接具备免疫能力：

```python
def run_self_checks() -> None:
    # 1. 新生成的 Strict CSP + no-store 应零问题通过校验
    n1 = generate_csp_nonce()
    n2 = generate_csp_nonce()
    assert n1 != n2 and len(n1) >= 22
    strict_hdr = build_strict_csp(n1)
    assert evaluate_csp_hardening(strict_hdr, "no-store, max-age=0") == []

    # 2. 弱策略应精确检出 unsafe-inline、CDN 白名单、缺 base-uri/object-src/form-action 与可缓存 Nonce
    weak_hdr = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com 'nonce-short'; style-src 'unsafe-inline'"
    weak_issues = evaluate_csp_hardening(weak_hdr, "public, max-age=3600")
    assert any("unsafe-inline" in i for i in weak_issues)
    assert any("cdnjs.cloudflare.com" in i for i in weak_issues)
    assert any("base-uri" in i for i in weak_issues)
    assert any("object-src" in i for i in weak_issues)
    assert any("form-action" in i for i in weak_issues)
    assert any("no-store" in i for i in weak_issues)

    # 3. JSONP 回调过滤阻断载荷注入
    assert validate_jsonp_callback("app.callbacks.handleSearch") is True
    for bad_cb in ("alert(1)", "x=>{alert(1)}//", ";alert(1)//", "cb)({"):
        assert validate_jsonp_callback(bad_cb) is False

    # 4. JSON 数据桥接转义 </script> 逃逸
    tag = render_safe_json_script_tag("app-config", {"avatar": "</script><script>alert(1)</script>"})
    assert "</script><script>" not in tag
    assert "\\u003c/script\\u003e" in tag

    print("[PASS] All CSP bypass defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- `evaluate_csp_hardening` 对生产响应头返回空告警列表（`[]`），且每次响应 Nonce 均唯一且带有 `Cache-Control: no-store`；
- 响应头显式包含 `base-uri 'none'`、`object-src 'none'`、`form-action 'self'` 与 `require-trusted-types-for 'script'`；
- JSONP 仅允许纯标识符或下线，HTML 内嵌 JSON 块不存在未转义 `<`/`>` 闭合标签风险；
- 前端全局配置读取校验对象原型与实例类型，不被同 ID/Name 表单元素劫持。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 响应头与缓存基线验证 | `http_probe` | 获取目标页面 `Content-Security-Policy`、`Cache-Control` 与 `X-Content-Type-Options` 验证策略生效 |
| 关联防御知识检索 | `kb_router` | 按 `CSP defense`、`Trusted Types`、`DOM Clobbering` 检索关联条目 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [01-csp-bypass.md](../../../../red/ctf-website/techniques/18-cors-csp-advanced/01-csp-bypass.md) 验证每个指令绕过链是否均已封堵 |
| 知识目录定位 | `kb_catalog` | 浏览 `18-cors-csp-advanced` 板块的全部红蓝对抗文档 |
