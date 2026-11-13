---
id: "ctf-website/08-infra/web-cache-deception-defense"
title: "Web Cache Deception 防御与 CDN/源站路径一致性加固"
title_en: "Web Cache Deception Defense & CDN/Origin Path Consistency"
summary: >
  防御攻击者利用 CDN 与源站对静态扩展名和路径分隔符（;.css、%3b、%00、..;/）的解析差异诱导缓存认证后动态页面（/account、/orders、/wallet）并泄露 PII/Token/XSS 的 Web Cache Deception 攻击。
summary_en: >
  Defense against Web Cache Deception attacks where attackers exploit path-delimiter and static-extension mismatches between CDNs and origin frameworks (e.g. ;.css, %3b, %00, ..;/) to cache authenticated dynamic responses (/account, /orders, /wallet) and leak sensitive user data or stored XSS.
board: "ctf-website"
category: "08-infra"
signals: ["web cache deception", "缓存欺骗", "Cache-Control", "Vary", "path delimiter", "CDN加固"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Web Cache Deception防御", "缓存欺骗防御", "Cache-Control private", "CDN路径一致性", "分号矩阵参数拦截", "Content-Type校验", "blue-team"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "cache-deception", "cdn", "caching", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/08-infra/web-cache-deception", "ctf-website/08-infra/race-cache-smuggling-defense", "ctf-website/01-recon/recon-routing-defense"]
track: "blue"
defends: "ctf-website/08-infra/web-cache-deception"
---
# Web Cache Deception 防御与 CDN/源站路径一致性加固

## 防御目标与威胁面

Web Cache Deception（WCD）利用了“**CDN 按 URL 后缀（`.css`/`.js`/`.json`）决定缓存，而后端框架忽略后缀或分隔符继续按动态路由渲染当前用户数据**”的双层失配：

1. **尾部静态后缀欺骗**：访问 `/account/settings.css` 时，后端框架（Rails/Play/宽容路由）仍匹配 `/account/settings` 并输出用户 PII，而 CDN 误判为 CSS 静态文件写入公共缓存，随后匿名用户直接读取。
2. **分隔符解析差异（Delimiter Differential）**：Spring/Tomcat 将 `/account;.css` 或 `/account..;/x.css` 中的 `;` 视作 Matrix Variable 分隔符回退到 `/account`；Nginx/OpenLiteSpeed 历史上受 `%00` 或编码斜杠 `%2f..%2f` 截断影响，而 CDN 仅看最终 `.css` 后缀。
3. **缺少严格的响应头缓存控制**：认证后接口、订单发票、导出数据未强制输出 `Cache-Control: private, no-store` 且 CDN 忽略源站 `Content-Type` 与状态码缓存规则。

## 核心防御架构

| 防护层 | 根治控制措施 | 实施要点 |
|---|---|---|
| 源站响应头层 | 所有带用户态/认证态/动态业务路由强制输出强禁缓存头 | `Cache-Control: private, no-store, max-age=0`，必要时叠加 `CDN-Cache-Control: no-store` |
| 源站路由严格匹配 | 禁用隐式后缀兜底与未知扩展名路由回落 | 若静态文件不存在或路由末尾含非预期 `.css`/`.js`/`;`/`%00`，直接返回 `404`，绝不渲染动态页面 |
| CDN 缓存策略层 | 仅对明确静态前缀（如 `/static/*`、`/assets/*`）启用缓存，并校验 `Content-Type` 匹配 | 禁止全站按扩展名无差别缓存；若响应 `Content-Type` 为 `text/html` 或 `application/json`，即使 URL 以 `.css` 结尾也绝不缓存 |
| 边缘分隔符清洗 | 边缘网关先统一路径规范化，拒绝含 `;`、`%3b`、`%00`、`..;` 的动态探测路径 | 确保 CDN 缓存键评估路径与上游接收路径完全一致 |

## 加固配置与离线核查示例

Cloudflare / Nginx 边缘与源站双重防线配置示例：

```nginx
# 1. 动态接口统一禁止任何代理与共享缓存
location ~ ^/(api|account|orders|wallet|payments|admin|export)/ {
    if ($request_uri ~* "(;|%3b|%00|\.\.;)") {
        return 404;
    }
    add_header Cache-Control "private, no-store, no-cache, must-revalidate" always;
    add_header Pragma "no-cache" always;
    proxy_pass http://app_backend;
}

# 2. 仅允许 /static/ 目录下真实静态资源进入共享缓存，且回源前严格校验路径
location ^~ /static/ {
    proxy_cache static_cache;
    proxy_cache_valid 200 1h;
    # 若后端返回 text/html 或带 Set-Cookie，一律跳过缓存
    proxy_no_cache $http_set_cookie $upstream_http_set_cookie;
}
```

以下 Python 响应与路由安全校验器用于自动核查缓存策略是否满足防 WCD 基线（认证响应禁缓存、`Content-Type` 与 URL 扩展名一致性及分隔符拦截）：

```python
import posixpath
from typing import Dict, List


def check_cache_deception_posture(
    request_path: str,
    authenticated: bool,
    status_code: int,
    headers: Dict[str, str],
) -> List[str]:
    findings: List[str] = []
    h = {k.lower(): v for k, v in headers.items()}

    # 1. 分隔符混淆路径必须由源站直接 404/400 拒绝，不应返回 200
    if any(tok in request_path.lower() for tok in (";", "%3b", "%00", "..;")):
        if status_code == 200:
            findings.append("delimiter_variant_returned_200")

    # 2. 认证后动态响应必须显式禁止共享缓存
    cc = h.get("cache-control", "").lower()
    if authenticated and status_code == 200:
        if "no-store" not in cc and "private" not in cc:
            findings.append("auth_response_missing_private_or_no_store")
        x_cache = (h.get("x-cache", "") + " " + h.get("cf-cache-status", "")).lower()
        if "hit" in x_cache:
            findings.append("auth_response_served_from_shared_cache")

    # 3. 扩展名与实际 Content-Type 错配检查（如 .css 实际返回 text/html）
    clean_path = posixpath.normpath(request_path.split("?", 1)[0]).lower()
    ctype = h.get("content-type", "").lower()
    if clean_path.endswith(".css") and "text/html" in ctype:
        findings.append("css_extension_returned_html")
    if clean_path.endswith(".js") and "text/html" in ctype:
        findings.append("js_extension_returned_html")

    return findings


if __name__ == "__main__":
    bad = check_cache_deception_posture(
        "/account/settings;.css",
        authenticated=True,
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=3600", "X-Cache": "HIT"},
    )
    assert set(bad) == {
        "delimiter_variant_returned_200",
        "auth_response_missing_private_or_no_store",
        "auth_response_served_from_shared_cache",
        "css_extension_returned_html",
    }

    good = check_cache_deception_posture(
        "/account/settings",
        authenticated=True,
        status_code=200,
        headers={"Content-Type": "application/json", "Cache-Control": "private, no-store"},
    )
    assert good == []
    print("Web Cache Deception defense self-check passed.")
```

## 防御工作流

```text
1. 全局禁缓头：为所有登录态、个人中心、订单、导出与 API 响应统一注入 Cache-Control: private, no-store
2. 收敛缓存规则：CDN 改为按静态资源专属路径前缀（/assets/、/static/）缓存，关闭全站按扩展名盲目缓存
3. 源站严格路由：后端框架禁用后缀通配符回落（如 Spring 关闭 Matrix Variables/后缀匹配），对 /account.css 返回 404
4. 边缘阻断分隔符：WAF/反代拦截路径中的 ;、%3b、%00、..;，保证缓存键与源站路由严格同步
5. MIME 对齐校验：CDN 仅当响应 Content-Type 与静态扩展名匹配且无 Set-Cookie 时才允许落盘缓存
```

## 验证与判定标准

- **双身份复取隔离**：账号 A 携带 Cookie 访问 `/account/settings.css`、`/account;.css`、`/orders/1001.json` 后，均返回 `404` 或携带 `Cache-Control: private, no-store`；账号 B 或匿名请求在同一 URL 上绝不会读取到账号 A 的任何数据且 `X-Cache` / `CF-Cache-Status` 不为 `HIT`。
- **分隔符零穿透**：Spring/Tomcat/Nginx 后端收到 `;`、`%3b`、`%00`、`..;/` 变体时均统一返回 `400` 或 `404`，不再回落匹配原动态路由。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索缓存欺骗防御方案 | `kb_router` | 搜索 `Web Cache Deception防御`、`缓存欺骗`、`Cache-Control` |
| 对照扩展名与分隔符矩阵 | `kb_read_file` | 读取 [web-cache-deception.md](../../../../red/ctf-website/techniques/08-infra/web-cache-deception.md) 校验各类绕过路径 |
| 联动缓存投毒与路由一致性 | `kb_catalog` | 协同查阅 `race-cache-smuggling-defense` 与 `recon-routing-defense` |
