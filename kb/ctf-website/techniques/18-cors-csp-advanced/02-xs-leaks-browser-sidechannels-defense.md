---
id: "ctf-website/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels-defense"
title: "XS-Leaks 浏览器侧信道防御 — Fetch Metadata、CORP/COOP 跨源隔离与恒定响应防线"
title_en: "XS-Leaks Browser Side-Channel Defense — Fetch Metadata, CORP/COOP Isolation & Constant-Shape Responses"
summary: >
  针对 Frame Counting、Cache Probing 定时探测、CORP/CORB MIME 混淆、Performance/Navigation Timing 泄露、
  Scroll-to-Text-Fragment、XS-Search 压缩与耗时侧信道、连接池竞争及 Web Locks API 状态推断等 XS-Leaks 攻击，
  构建基于 Sec-Fetch-Site 拒绝跨站读取、CORP/COOP/COEP 跨源隔离、SameSite Cookie 与恒定形态响应的系统防线，并附可运行自检代码。
summary_en: >
  Comprehensive defense against XS-Leaks including Frame Counting, Cache Probing, CORP/CORB bypass, Performance API
  leaks, Scroll-to-Text-Fragment, XS-Search timing and compression side-channels, connection pool contention, and Web Locks
  API leaks. Covers Fetch Metadata enforcement, CORP/COOP/XFO isolation, Document-Policy, and runnable verification tests.
board: "ctf-website"
category: "18-cors-csp-advanced"
signals: ["Sec-Fetch-Site", "CORP same-origin", "COOP same-origin", "frame-ancestors", "Document-Policy", "SameSite Strict", "BREACH defense"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["XS-Leaks防御", "Fetch Metadata", "跨源隔离", "CORP", "COOP", "侧信道防御", "XS-Search防御", "Document-Policy"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "xs-leaks", "side-channel", "browser-isolation", "corp"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels", "ctf-website/18-cors-csp-advanced/01-csp-bypass-defense"]
track: "blue"
defends: "ctf-website/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels"
---

# XS-Leaks 浏览器侧信道防御 — Fetch Metadata、CORP/COOP 跨源隔离与恒定响应防线

## 威胁模型与防御目标

XS-Leaks 不破坏同源策略（SOP）的直接读取限制，而是利用跨站请求附带的凭据（Cookie）以及浏览器暴露的副作用（Frame 数量、缓存耗时、错误事件、重定向、压缩长度、连接池排队或锁占用）构造成立的二元 Oracle。对照 [02-xs-leaks-browser-sidechannels.md](02-xs-leaks-browser-sidechannels.md)，蓝队的核心策略是**切断跨站携带凭据请求的触发入口 + 强化浏览器进程与窗口隔离 + 消除依赖秘密状态的响应差异**：

| XS-Leak 向量 | 侧信道载体 | 防御控制 |
|---|---|---|
| Frame Counting（`window.length`）与 Lazy-Load iframe | 跨域嵌入页面后观察子 Frame 数或加载触发 | 设置 `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`，彻底禁止第三方嵌入 |
| Opener / `window.name` / Web Locks 状态推断 | `window.open` 共享浏览上下文组或共享跨源特征 | 设置 `Cross-Origin-Opener-Policy: same-origin`（`COOP`）隔离浏览上下文组；禁止以状态命名锁或嵌入页持锁 |
| CORP/CORB 绕过（`no-cors` / `script` / `object` / MIME 混淆） | `<img/script/object>` 跨源加载后观察 `onload`/`onerror` 差异 | 所有私有/API 响应设置 `Cross-Origin-Resource-Policy: same-origin`、`X-Content-Type-Options: nosniff` 与准确 `Content-Type` |
| Cache Probing 定时攻击 | 跨源探测静态或私有资源是否命中本地共享缓存 | 敏感/态依赖资源强制 `Cache-Control: no-store, private`，严禁使用 `public` 缓存 |
| XS-Search（计时/压缩长度/连接池竞争） | 第三方通过 `fetch(..., {mode:'no-cors', credentials:'include'})` 反复采样 | **Fetch Metadata（`Sec-Fetch-Site`）中间件拒绝跨站异步/子资源请求**；搜索响应填充等长或关闭压缩；隔离长连接域名 |
| Performance / Redirect Timing 泄露 | 未设防的重定向链长度与 `Timing-Allow-Origin` | 禁止根据查询命中与否做差异化 `302` 重定向；不设置 `Timing-Allow-Origin: *` |
| Scroll-to-Text-Fragment（`#:~:text=`）与 Cookie Jar | 跨站导航携带 `#:~:text=` 触发滚动或通过子域/跨站跳转探测 Cookie | 下发 `Document-Policy: force-load-at-top` 禁用文本片段滚动；全站认证 Cookie 使用 `__Host-` 前缀 + `SameSite=Strict`（或导航保护配合 `Lax`） |

## 架构加固配置

### 1. 全局浏览器隔离响应头基线（Nginx / 网关层）

在认证应用与 API 响应头统一附加跨源隔离与抗侧信道策略：

```nginx
# /etc/nginx/conf.d/xs_leaks_hardening.conf
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'; object-src 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Document-Policy "force-load-at-top" always;
add_header Cache-Control "no-store, private" always;
# 注意：绝不对含用户私有状态的端点下发 Timing-Allow-Origin: *
```

同时，会话 Cookie 必须满足主机锁定与跨站隔离要求：

```http
Set-Cookie: __Host-session=<opaque_token>; Path=/; Secure; HttpOnly; SameSite=Strict
```

> 若业务确需从外部邮件/门户直接跳入页面并保持登录态（需使用 `SameSite=Lax`），则所有搜索、导出、状态查询 API 仍必须通过下方的 **Fetch Metadata** 校验阻断跨站 `no-cors` / `iframe` / `img` / `navigate` 侧信道探测。

### 2. Fetch Metadata 服务端防御中间件 + 恒定形态搜索响应（Python）

现代浏览器（Chrome/Firefox/Safari/Edge）会自动为请求附加不可由前端 JS 伪造的 `Sec-Fetch-Site`、`Sec-Fetch-Mode`、`Sec-Fetch-Dest` 头。通过服务端资源隔离策略（Resource Isolation Policy），可从根源阻断跨站 `fetch(mode='no-cors')`、跨站 `<script>`/`<img>`/`<iframe>` 以及跨站搜索计时攻击：

```python
from dataclasses import dataclass


ALLOWED_SAFE_NAV_DESTS = {"document", "nested-document"}


@dataclass(frozen=True)
class IsolationDecision:
    allowed: bool
    status_code: int
    reason: str


def enforce_fetch_metadata(
    method: str,
    path: str,
    headers: dict[str, str],
    allow_top_level_navigation_paths: set[str] | None = None,
) -> IsolationDecision:
    """
    基于 Fetch Metadata (Sec-Fetch-*) 阻断跨站 XS-Leaks 子资源与异步采样请求。
    参考：web.dev Resource Isolation Policy。
    """
    norm = {k.lower(): v.strip().lower() for k, v in headers.items()}
    sec_site = norm.get("sec-fetch-site")
    sec_mode = norm.get("sec-fetch-mode", "")
    sec_dest = norm.get("sec-fetch-dest", "")

    # 1. 无 Sec-Fetch-Site（如非浏览器脚本直连）交由常规认证/CORS 控制；浏览器同源或用户直接地址栏访问放行
    if sec_site in (None, "same-origin", "none"):
        return IsolationDecision(True, 200, "same-origin-or-direct")

    # 2. 对跨站（cross-site）或同站异源（same-site）默认拒绝 API 与私有资源加载
    public_nav_paths = allow_top_level_navigation_paths or {"/", "/login", "/public/docs"}
    if (
        sec_site == "cross-site"
        and sec_mode == "navigate"
        and method.upper() == "GET"
        and sec_dest in ALLOWED_SAFE_NAV_DESTS
        and path in public_nav_paths
    ):
        # 仅对明确公开的落地页允许跨站顶层 GET 导航（且不可携带 search 查询秘密参数）
        return IsolationDecision(True, 200, "allowed-public-top-navigation")

    return IsolationDecision(
        False,
        403,
        f"blocked-cross-origin-sidechannel:{sec_site}:{sec_mode}:{sec_dest}",
    )


def build_xs_leak_defense_headers(is_sensitive_response: bool = True) -> dict[str, str]:
    """生成完整的抗 XS-Leaks 浏览器隔离响应头。"""
    headers = {
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Document-Policy": "force-load-at-top",
    }
    if is_sensitive_response:
        headers["Cache-Control"] = "no-store, private"
        # 避免压缩长度差异（BREACH / 压缩侧信道）
        headers["Content-Encoding"] = "identity"
    return headers


def pad_constant_search_payload(raw_json_bytes: bytes, block_size: int = 4096) -> bytes:
    """将搜索结果填充至固定块大小并固定状态码，消除结果命中与否带来的长度和编码差异。"""
    if len(raw_json_bytes) >= block_size:
        # 向上对齐到 block_size 整数倍
        target_len = ((len(raw_json_bytes) + block_size - 1) // block_size) * block_size
    else:
        target_len = block_size
    pad_len = target_len - len(raw_json_bytes)
    # 假设末尾为 '}'，在 JSON 外或空白填充（JSON 解析器忽略尾部空白）
    return raw_json_bytes + (b" " * pad_len)
```

### 3. 消除结构性状态差异（防状态 Oracle）

- **统一 HTTP 状态码与分支耗时**：搜索接口在“命中 0 条”与“命中 N 条”时一律返回 `200 OK`、固定分片大小（如 4KB 对齐）以及恒定执行槽位；禁止在未命中时返回 `404` 或 `302` 重定向。
- **连接池隔离**：SSE / WebSocket 等长连接服务部署在独立子域（如 `stream.example.com`），避免恶意页面通过占满主域连接池观察长连接活跃状态。

## 防御工作流

1. **清点跨站可嵌入与可读端点**：排查所有返回敏感或登录态依赖结果的页面、搜索 API、图片/静态资产与重定向路由，标记未受保护的跨域暴露点。
2. **下发浏览器隔离响应头矩阵**：全量部署 `CORP: same-origin`、`COOP: same-origin`、`XFO: DENY`、`frame-ancestors 'none'`、`nosniff`、`Document-Policy: force-load-at-top` 与 `Cache-Control: no-store, private`。
3. **上线 Fetch Metadata 拦截中间件**：在所有搜索接口、用户状态接口与敏感资源端点启用 `Sec-Fetch-Site` 校验，阻断跨站 `no-cors` fetch、`iframe`、`img` 与非白名单顶层导航探测。
4. **Cookie 与长连接隔离**：Cookie 升级为 `__Host-` 前缀 + `SameSite=Strict`（或 `Lax` 配合 Fetch Metadata），将长连接通道迁至独立域，并消除依赖命中结果的重定向链与压缩差异。
5. **回归验证与校准**：运行下方的策略检测脚本并利用 `http_probe` 核查关键端点的响应头完整性与跨站拒绝行为。

## 验证与判定标准

执行下方回归自检脚本，验证 Fetch Metadata 阻断跨站探测、隔离头完整性与搜索载荷定长填充：

```python
import json


def run_self_checks() -> None:
    # 1. Fetch Metadata 阻断跨站 no-cors fetch（XS-Search 计时探测）与跨站 iframe（Frame Counting）
    dec_nocors = enforce_fetch_metadata(
        "GET",
        "/api/search",
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "empty"},
    )
    assert dec_nocors.allowed is False and dec_nocors.status_code == 403

    dec_iframe = enforce_fetch_metadata(
        "GET",
        "/search",
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"},
    )
    assert dec_iframe.allowed is False and dec_iframe.status_code == 403

    # 跨站顶层导航到 /search（含潜在 #:~:text= 或搜索参数）同样被拦截，仅放行公开白名单落地页
    dec_search_nav = enforce_fetch_metadata(
        "GET",
        "/search",
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
    )
    assert dec_search_nav.allowed is False

    dec_public_nav = enforce_fetch_metadata(
        "GET",
        "/login",
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
    )
    assert dec_public_nav.allowed is True

    # 同源前端请求正常放行
    dec_same = enforce_fetch_metadata(
        "GET",
        "/api/search",
        {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
    )
    assert dec_same.allowed is True

    # 2. 隔离响应头校验：涵盖 CORP / COOP / XFO / CSP / nosniff / Document-Policy / Cache-Control
    hdrs = build_xs_leak_defense_headers(is_sensitive_response=True)
    assert hdrs["Cross-Origin-Resource-Policy"] == "same-origin"
    assert hdrs["Cross-Origin-Opener-Policy"] == "same-origin"
    assert hdrs["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in hdrs["Content-Security-Policy"]
    assert hdrs["Document-Policy"] == "force-load-at-top"
    assert "no-store" in hdrs["Cache-Control"]
    assert "Timing-Allow-Origin" not in hdrs

    # 3. 定长填充确保命中与未命中响应字节长度完全一致且仍为合法 JSON
    hit_bytes = pad_constant_search_payload(json.dumps({"hits": ["flag_item_1", "flag_item_2"]}).encode("utf-8"))
    miss_bytes = pad_constant_search_payload(json.dumps({"hits": []}).encode("utf-8"))
    assert len(hit_bytes) == len(miss_bytes) == 4096
    assert json.loads(hit_bytes.decode("utf-8"))["hits"][0] == "flag_item_1"
    assert json.loads(miss_bytes.decode("utf-8"))["hits"] == []

    print("[PASS] All XS-Leaks defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 跨站 `no-cors`、跨站 `iframe` 与跨站对敏感查询路径的顶层导航均被 `Sec-Fetch-Site` 策略返回 `403` 拒绝；
- 响应头同时包含 `CORP: same-origin`、`COOP: same-origin`、`X-Frame-Options: DENY`、`frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Document-Policy: force-load-at-top` 与 `Cache-Control: no-store, private`，且无 `Timing-Allow-Origin`；
- 敏感查询端点无论命中与否返回相同 HTTP 状态码与块对齐载荷长度，且关闭压缩差异泄漏。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 隔离响应头基线验证 | `http_probe` | 检查目标页面与搜索 API 是否完整下发 `CORP`、`COOP`、`XFO`、`Document-Policy` 与 `Cache-Control` |
| 关联防御知识检索 | `kb_router` | 按 `XS-Leaks defense`、`CORP`、`Fetch Metadata` 检索相关文档 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [02-xs-leaks-browser-sidechannels.md](02-xs-leaks-browser-sidechannels.md) 核验全部侧信道关闭情况 |
| 知识目录定位 | `kb_catalog` | 查看 `18-cors-csp-advanced` 全部防御规范 |
