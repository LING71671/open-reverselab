---
id: "ctf-website/02-auth/jwt/07-theft-replay"
title: "JWT 窃取、重放与持久化"
title_en: "JWT Theft, Replay, and Persistence"
summary: >
  JWT 是 Bearer Token，拿到即可作为身份材料进入业务接口。本篇围绕 token 落点枚举、URL/Referer/日志泄露、XSS 与前端状态捕获、登出后重放、跨设备/跨 IP/跨会话重放、刷新链持久化，给出可运行的提取、分类和 oracle 脚本。
summary_en: >
  JWT is a bearer credential. This playbook covers token location discovery, URL/Referer/log leakage, XSS and frontend-state capture, replay after logout, cross-device/IP/session replay, refresh-chain persistence, and runnable extraction/classification/oracle scripts.
board: "ctf-website"
category: "02-auth"
signals: ["token窃取", "XSS", "重放", "Bearer Token", "HttpOnly", "Referer泄露", "HSTS", "Cookie属性", "refresh token"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["JWT窃取", "token重放", "XSS", "HttpOnly", "Referer", "HSTS", "Cookie属性", "token泄露", "refresh持久化"]
difficulty: "advanced"
tags: ["authentication", "jwt", "token-theft", "xss", "replay", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/02-auth/jwt/06-claim-missing", "ctf-website/07-client/admin-bot-xss"]
---

# JWT 窃取、重放与持久化

JWT 的关键性质是 Bearer：服务端把 token 当作身份材料，默认不证明“谁正在持有”。CTF 里不要只问 token 从哪里来，要同时问三个问题：

1. **落点**：token 存在哪里，谁能读到。
2. **绑定**：token 绑定了哪些上下文，哪些没有绑定。
3. **持久化**：access 过期、logout、换 IP、换 UA、刷新链轮换后还能不能继续走。

## 工作流

```text
抽 token 落点
  → 解码 header/claim 并聚类来源
  → 用同一业务 oracle 建 baseline
  → 新 session / logout 后 / UA-IP-Origin 变化重放
  → refresh 复用与并发测试
  → 按成功样本跳到 claim、弱密钥、CVE 或客户端链
```

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| `Authorization: Bearer` 出现在 XHR/fetch | hook 请求头和响应体 | token 可复制到新 session 访问同一 API | token 绑定 cookie/device，单独 bearer 被拒 |
| `access_token/id_token/token` 出现在 URL | 抽 URL、Referer、history、日志 | 第三方资源 Referer 带完整 token | `Referrer-Policy` 只泄露 origin 或 URL 已 replace |
| localStorage/sessionStorage 有 JWT | 前端状态快照 + XSS/DOM sink 路由 | 读取 token 后可重放业务接口 | token 只用于前端展示，API 另走 cookie |
| Cookie 中有 JWT | 检查属性和同站触发 | 非 HttpOnly 可读，或 SameSite 缺失可借浏览器附带 | HttpOnly 但接口仍校验 CSRF/Origin |
| 登出后 access 仍可用 | logout 前后同一 oracle 重放 | logout 后仍返回用户数据/订单/flag | 立即 `401/invalid jti` |
| refresh token 存在 | 记录轮换、复用、跨设备 | 旧 refresh 可重复换新 access | refresh 一次后旧值失效 |

## 0. 路由矩阵

| token 来源 | 优先 oracle | 下一跳 |
|---|---|---|
| URL query/fragment | Referer、浏览器 history、日志抽取 | 若是 reset/verify token，转业务状态机 |
| localStorage/sessionStorage | XSS、postMessage、前端 bundle 状态 | 转 `07-client/admin-bot-xss` |
| Cookie | SameSite/Origin/CSRF 差分 | 转 `07-client/cors-csrf` |
| API 响应体 | 登录/刷新/SSO callback 抓包 | 转 `20-oauth-deep` 或 claim 混用 |
| access log/HAR/Sentry | 正则抽 JWT，按 alg/kid/aud 聚类 | 转 `08-cve-library` 或 `03-weak-key-bruteforce` |

## 1. 落点枚举

先把 token 从 HAR、日志、HTML、JS 状态和 URL 里抽出来，按 `alg/kid/aud/iss/exp` 聚类。不要只保存 token 字符串，必须保留来源字段，否则后面无法判断泄露路径。

```python
#!/usr/bin/env python3
import argparse
import base64
import json
import re
from pathlib import Path

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

def b64json(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part.encode()))

def classify(token):
    h, p, _ = token.split(".", 2)
    header, payload = b64json(h), b64json(p)
    return {
        "alg": header.get("alg", ""),
        "kid": header.get("kid", ""),
        "typ": header.get("typ", ""),
        "iss": payload.get("iss", ""),
        "aud": payload.get("aud", ""),
        "sub": payload.get("sub", ""),
        "exp": payload.get("exp", ""),
        "scope": payload.get("scope", payload.get("scp", "")),
    }

def iter_text(path):
    raw = Path(path).read_text(encoding="utf-8", errors="ignore")
    try:
        obj = json.loads(raw)
        yield from walk_json(obj)
    except Exception:
        for idx, line in enumerate(raw.splitlines(), 1):
            yield f"line:{idx}", line

def walk_json(obj, prefix="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_json(v, f"{prefix}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_json(v, f"{prefix}[{i}]")
    else:
        yield prefix, "" if obj is None else str(obj)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    seen = set()
    for path in args.files:
        for source, text in iter_text(path):
            for m in JWT_RE.finditer(text):
                token = m.group(0)
                if token in seen:
                    continue
                seen.add(token)
                try:
                    meta = classify(token)
                except Exception as exc:
                    meta = {"parse_error": str(exc)}
                print(json.dumps({"file": path, "source": source, "token": token[:32] + "...", **meta}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：不同来源抽出的 token 具有同一 `iss/aud/kid`，且能映射到具体登录、callback、日志或 XSS 路径。失败样本：字符串看似 JWT 但 header/payload 解析失败，或只是静态测试 fixture。

## 2. 浏览器运行时捕获

在题目允许控制浏览器时，优先 hook 请求头、响应体和前端存储。目标不是“偷一次 token”，而是确认 token 何时产生、哪里落盘、刷新时如何变化。

```javascript
(() => {
  const dump = label => {
    console.log("[jwt-store]", label, {
      local: {...localStorage},
      session: {...sessionStorage},
      cookie: document.cookie
    });
  };
  dump("initial");
  const oldFetch = window.fetch;
  window.fetch = async function(input, init = {}) {
    const url = String(input && input.url || input);
    const headers = init.headers || {};
    console.log("[jwt-fetch:req]", url, headers, init.body || "");
    const resp = await oldFetch.apply(this, arguments);
    const clone = resp.clone();
    clone.text().then(t => {
      if (/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/.test(t)) {
        console.log("[jwt-fetch:resp]", url, t.slice(0, 1000));
      }
    }).catch(() => {});
    return resp;
  };
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this.__jwt_url = url;
    this.__jwt_method = method;
    return open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    console.log("[jwt-xhr:req]", this.__jwt_method, this.__jwt_url, body || "");
    return send.apply(this, arguments);
  };
})();
```

## 3. 重放 oracle

同一个 token 至少测四组：原 session、新 session、logout 后、改 UA/IP/Origin 后。响应只看 `200/401` 太粗，应该同时记录 body hash、身份字段、权限字段、业务副作用。

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import requests

def digest(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def hit(url, token, cookie="", ua="ReplayOracle/1.0", origin=""):
    headers = {"Authorization": f"Bearer {token}", "User-Agent": ua}
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
    r = requests.get(url, headers=headers, timeout=10)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text[:300]}
    return {
        "status": r.status_code,
        "hash": digest(r.text),
        "location": r.headers.get("Location", ""),
        "user": body.get("user", body.get("sub", "")) if isinstance(body, dict) else "",
        "role": body.get("role", body.get("scope", "")) if isinstance(body, dict) else "",
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--logout-url", default="")
    args = ap.parse_args()
    out = {"baseline": hit(args.url, args.token, args.cookie)}
    if args.logout_url:
        requests.post(args.logout_url, headers={"Authorization": f"Bearer {args.token}", "Cookie": args.cookie}, timeout=10)
        out["after_logout"] = hit(args.url, args.token, args.cookie)
    out["fresh_session"] = hit(args.url, args.token)
    out["ua_flip"] = hit(args.url, args.token, args.cookie, ua="Mozilla/5.0 ReplayFlip")
    out["origin_flip"] = hit(args.url, args.token, args.cookie, origin="https://attacker.example")
    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
```

判定：

| 结果 | 解释 | 下一步 |
|---|---|---|
| fresh session 仍成功 | bearer 未绑定 cookie/device | 测跨账号、跨 IP、长时间窗口 |
| logout 后仍成功 | jti/撤销链缺失 | 测 refresh 轮换与 access 延寿 |
| UA/IP 改动后失败 | 存在上下文绑定 | 找绑定字段、设备 ID、指纹 cookie |
| only cookie 成功 | bearer 不是唯一凭据 | 转 CSRF/CORS/Origin 差分 |

## 4. refresh 持久化

| 变体 | 操作 | 命中样本 | 失败样本 |
|---|---|---|---|
| reuse | 同一 refresh 连续换 access | 每次返回新 access | 第二次 `invalid refresh` |
| parallel | 并发使用同一 refresh | 多个 access 同时有效 | 只有一个成功，其余失效 |
| logout reuse | logout 后继续 refresh | 仍返回 access | refresh 被吊销 |
| cross device | 设备 A refresh 给设备 B | B 可换 access | 绑定 device/session |
| scope lift | refresh 换出的 access scope 更大 | `scope/role/aud` 扩张 | 与原 access 一致 |

```python
#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import requests

def refresh(url, token):
    r = requests.post(url, json={"refresh_token": token}, timeout=10)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text[:200]}
    return {"status": r.status_code, "body": body}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--refresh", required=True)
    ap.add_argument("--workers", type=int, default=5)
    args = ap.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda _: refresh(args.url, args.refresh), range(args.workers)))
    print(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
```

## 5. Evidence

| 项 | 记录内容 |
|---|---|
| token 来源 | HAR/log/URL/storage/cookie 字段路径、原始行号、时间点 |
| 解码信息 | header、claim、`alg/kid/iss/aud/sub/exp/jti/scope` |
| 重放矩阵 | baseline、fresh session、logout 后、UA/IP/Origin 变化的响应 |
| 持久化结果 | refresh 复用、并发、logout 后、跨设备的 access 产出 |
| 成功样本 | 新 session/登出后/跨上下文仍能访问用户数据、订单、后台、flag |
| 失败样本 | `invalid jti`、`session mismatch`、`device mismatch`、`refresh reused`、同一 body hash 的拒绝 |
| 下一跳 | 弱密钥转 `03-weak-key-bruteforce`；claim 缺失转 `06-claim-missing`；库指纹转 `08-cve-library` |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| token 路由 | `kb_router` | 按 token leak、JWT replay、refresh reuse 搜索 |
| HTTP oracle | `http_probe` | 固定请求头/响应 hash，比较重放结果 |
| 浏览器 hook | `jshook` | 捕获 localStorage、fetch/XHR、URL callback |
