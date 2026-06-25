# Network 规则拦截 — 阻止 Paywall 脚本加载

## 场景

Paywall 服务 (Piano, Poool, Sophi, Zephr, Axate) 通过第三方 JS SDK 检测文章访问次数并注入 overlay。如果**阻止这些 SDK 从网络层加载**，paywall 逻辑就永远不会执行——而文章正文已在服务端渲染的 HTML 中，只是被 JS 动态截断和隐藏。

```
正常流程:
  页面加载 HTML (含正文)
  → 浏览器加载 piano.js
  → piano.js 检查 localStorage 阅读计数
  → piano.js 截断正文 + 注入 overlay
  → 用户看到 paywall

阻断流程:
  页面加载 HTML (含正文)
  → 浏览器尝试加载 piano.js
  → declarativeNetRequest 拦截 (block 规则)
  → piano.js 未加载
  → 正文完整可见，无 overlay
```

Manifest V3 通过 `declarativeNetRequest` 的 session rules 实现，无需 content script。

## 输入信号

- `<script src="https://cdn.tinypass.com/...">` 或 `*.piano.io/*` 出现在页面 `<head>` 中
- `script[src*="/poool.js"]` 或 `script[src*=".poool.fr/"]` 加载 Poool SDK
- `script[src*=".sophi.io/"]` 加载 Sophi paywall
- `script[src*="/agate.js"]` 或 `script[src*=".axate.io/"]` 加载 Axate
- `div[id^="piano_"]` / `div[class*="tp-container"]` — Piano/Tinypass DOM 标记
- 网络面板中 `jwt` / `entitlements` / `access` / `meter` 等 API 请求
- 响应头 `x-paywall-*` / `x-piano-*` / `x-metered-remaining` 等标记
- `window.tp.push()` / `window.PianoID` / `window._poool` 等 JS 全局对象
- `<script>` 标签中包含 `var _sf_async_config` (Sophi) 或 `tp.push` (Piano)

---

## 方法 1: declarativeNetRequest block 规则

### 原理

对于 Manifest V3 扩展，使用 `declarativeNetRequest` 的 `block` action 阻止匹配特定 URL 模式的脚本和 XHR 请求。规则支持正则表达式匹配 (`regexFilter`)，精确到具体域名+路径。

### 代码: 脚本阻止规则构建

```javascript
// background.js — add_session_rule() 中的 block 规则部分
function add_session_rule(domain, rule) {

  // 模式 A: block_regex — 阻止特定 paywall 脚本 URL
  if (blockedRegexes_rule) {
    rule_id++;
    let regex = blockedRegexes_rule;
    if (regex instanceof RegExp)
      regex = regex.source;

    let block_rule = {
      id: rule_id,
      priority: 1,
      action: { type: "block" },
      condition: {
        initiatorDomains: [domain],
        regexFilter: regex,
        resourceTypes: ["script", "xmlhttprequest"]
      }
    };
    push_session_rule(block_rule, rule_id);
  }

  // 模式 B: block_regex_general — 全局 paywall SDK 阻止
  if (blockedRegexesGeneral_rule) {
    rule_id++;
    let regex = blockedRegexesGeneral_rule.block_regex;
    if (regex instanceof RegExp)
      regex = regex.source;

    let block_rule = {
      id: rule_id,
      priority: 1,
      action: { type: "block" },
      condition: {
        // excludedInitiatorDomains: 已排除的站点不受影响
        excludedInitiatorDomains: excludedSites.concat(
          rule_excluded_base_domains,
          blockedRegexesGeneral_rule.excluded_domains
        ),
        regexFilter: regex,
        resourceTypes: ["script", "xmlhttprequest"]
      }
    };
    push_session_rule(block_rule, rule_id);
  }

  // 模式 C: block_js / block_js_ext — 阻止全部或外部 JS
  if (block_js_custom.includes(domain) || block_js_custom_ext.includes(domain)) {
    rule_id++;
    let url_filter = block_js_custom.includes(domain) ? '||' + domain : '*';

    let block_rule = {
      id: rule_id,
      priority: 1,
      action: { type: "block" },
      condition: {
        initiatorDomains: [domain],
        urlFilter: url_filter,
        resourceTypes: ["script"]
      }
    };
    push_session_rule(block_rule, rule_id);

    // 如果仅阻止外部 JS → 需要 allow 同源
    if (block_js_custom_ext.includes(domain)) {
      rule_id++;
      let allow_rule = {
        id: rule_id,
        priority: 2,  // 优先级高于 block
        action: { type: "allow" },
        condition: {
          initiatorDomains: [domain],
          urlFilter: '||' + domain,
          resourceTypes: ["script"]
        }
      };
      push_session_rule(allow_rule, rule_id);
    }
  }
}
```

### 代码: 常用 Paywall SDK 阻止正则

```javascript
// background.js — 规则初始化时注入的通用 Paywall SDK 正则
var blockedRegexesGeneral = {};

// Piano / Tinypass
blockedRegexesGeneral['piano.io'] = {
  block_regex: /\.(piano\.io|tinypass\.com)\//,
  excluded_domains: []
};

// Poool (法国媒体常用)
blockedRegexesGeneral['poool.fr'] = {
  block_regex: /\.poool\.fr\//,
  excluded_domains: []
};

// Sophi (加拿大/美国媒体)
blockedRegexesGeneral['sophi.io'] = {
  block_regex: /\.sophi\.io\//,
  excluded_domains: []
};

// 从 sites.js 中提取的站点级正则示例:
// block_regex: /\.adweek\.com\/wp-content\/plugins\/adw-zephr\//
// block_regex: /\.haaretz\.co(\.il|m)\/htz\/js\/paywall\.js/
// block_regex: /\.ampproject\.org\/v0\/amp-(access|subscriptions)-.+\.js/
// block_regex: /\.(axate|agate)\.io\//
// block_regex: /\.wallkit\.net\//
// block_regex: "temptation\\.{domain}\\/"  (DPG Media 荷兰)
```

### 正则到 URL Filter 的优化转换

```javascript
// declarativeNetRequest 的 regexFilter 性能较低
// 对于简单模式可转换为更高效的 urlFilter
function regexToUrlFilter(rule, regex, domain) {
  let urlFilter;

  // 检查正则是否可以安全转换为 glob 模式
  if (!(regex.match(/([([|*{$\^]|\\[a-z\?])/) || regex.match(/([^\.]|\\\.)\+/))) {
    let match_domain = gpw_domains.concat(['tinypass.com', 'wallkit.net', domain])
      .find(x => regex.replace(/\\/g, '').match(new RegExp(x.replace(/\./, '\\.'))));

    urlFilter = regex.replace(/\\/g, '').replace(/\.\+/g, '*');

    if (match_domain)
      urlFilter = '||' + urlFilter.replace(/^[\.\/]/g, '');

    delete rule.condition.regexFilter;
    rule.condition.urlFilter = urlFilter;
  }
  // 如果无法转换 → 保留 regexFilter (性能较差但正确)
}
```

---

## 方法 2: CSP Injection — 解除内联脚本阻止

### 原理

某些 paywall 在**内联脚本**（非外部文件）中实现。Manifest V2 时代可以通过 `onHeadersReceived` 直接修改 CSP 头。Manifest V3 中通过 `declarativeNetRequest` 的 `modifyHeaders` 修改**响应头**中的 `Content-Security-Policy`，将其改为 `script-src *;`，允许所有内联脚本执行。

### 代码: CSP 修改规则

```javascript
// background.js — CSP 注入 (block_js_inline)
if (blockedJsInline_rule) {
  rule_id++;
  let regex = blockedJsInline_rule.source;
  let block_inline_rule = {
    id: rule_id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [{
        header: "Content-Security-Policy",
        operation: "set",
        value: "script-src *;"  // 覆盖原有 CSP，允许所有脚本
      }]
    },
    condition: {
      requestDomains: [domain],
      regexFilter: regex,
      resourceTypes: ["main_frame", "sub_frame"]
    }
  };
  push_session_rule(block_inline_rule, rule_id);
}
```

### 对应的 Manifest V2 实现 (对比)

```javascript
// Manifest V2 — 通过 webRequest API 修改 CSP 响应头
function blockJsInlineListener(details) {
  let domain = matchUrlDomain(blockedJsInlineDomains, details.url);
  let matched = domain && details.url.match(blockedJsInline[domain]);
  if (!isSiteEnabled(details) || !matched)
    return;

  var headers = details.responseHeaders;
  headers.push({
    'name': 'Content-Security-Policy',
    'value': "script-src *;"  // 覆盖 CSP
  });
  return { responseHeaders: headers };
}

ext_api.webRequest.onHeadersReceived.addListener(
  blockJsInlineListener,
  { types: ['main_frame', 'sub_frame'],
    urls: blocked_js_inline_urls },
  ['blocking', 'responseHeaders']
);
```

---

## 方法 3: AMP 页面内容解除隐藏

### 原理

Google AMP 页面使用 `<amp-access>` 组件实现 paywall。该组件通过 `amp-access-hide` 类隐藏付费内容。移除该类 + 删除 `amp-access` 脚本即可恢复完整内容。

### 代码: contentScript.js — AMP unhide

```javascript
// contentScript.js — amp_unhide 处理
if (bg2csData.amp_unhide) {
  window.setTimeout(function () {
    let amp_page_hide = document.querySelector(
      'script[src*="/amp-access-"], script[src*="/amp-subscriptions-"]'
    );
    if (amp_page_hide) {
      // 1. 显示被隐藏的内容区段
      function amp_unhide_subscr_section() {
        document.querySelectorAll('[subscriptions-section="content-not-granted"]')
          .forEach(el => el.removeAttribute('subscriptions-section'));
      }

      // 2. 移除 amp-access-hide 类
      function amp_unhide_access_hide() {
        document.querySelectorAll('[amp-access-hide]')
          .forEach(el => el.removeAttribute('amp-access-hide'));
      }

      // 3. 加载 data-src 中的真实图片 (AMP 懒加载)
      function amp_images_replace() {
        document.querySelectorAll('amp-img img[src], amp-img img[data-src]')
          .forEach(img => {
            if (img.getAttribute('data-src'))
              img.src = img.getAttribute('data-src');
          });
      }

      // 4. 加载 iframe
      function amp_iframes_replace() {
        document.querySelectorAll('amp-iframe iframe')
          .forEach(iframe => {
            if (iframe.getAttribute('data-src'))
              iframe.src = iframe.getAttribute('data-src');
          });
      }

      amp_unhide_subscr_section();
      amp_unhide_access_hide();
      amp_images_replace();
      amp_iframes_replace();
    }
  }, 100);
}
```

---

## 方法 4: URL 重定向规则

### 原理

某些网站有特定的 paywall URL 模式（如订阅页、登录页）。通过 `declarativeNetRequest` 的 `redirect` action 将用户从 paywall URL 重定向到实际内容 URL。

### 代码: 典型重定向规则

```javascript
// background.js — Australia News Corp 订阅页重定向
if (grouped_sites['###_au_news_corp'].includes(domain)) {
  rule_id++;
  let redirect_rule = {
    id: rule_id,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        // 从 /subscribe/ 重定向到 /<article-slug>
        regexSubstitution: "https://www." + domain + "/\\1" +
          (au_news_corp_amp ? '?amp' : '')
      }
    },
    condition: {
      regexFilter: ".+\\." + domain + "\\/subscribe\\/.+&dest=.+\\.com\\.au%2F([\\w-%]+)&.+",
      resourceTypes: ["main_frame"]
    }
  };
  push_session_rule(redirect_rule, rule_id);
}

// inkl.com — 绕过 etok 参数 + signin 重定向
// 移除 etok token 或从 signin redirect_to 提取真实 URL
var updatedUrl = details.url.replace(/etok=[\w]*&/, '');
if (details.url.includes('/signin?') && details.url.includes('redirect_to='))
  updatedUrl = 'https://www.inkl.com' +
    decodeURIComponent(updatedUrl.split('redirect_to=')[1]);
```

---

## 方法 5: 通用 Paywall 脚本阻止 (跨站点)

### 原理

Manifest V2 的 `webRequest.onBeforeRequest` 可以动态决定是否阻止。Manifest V3 中对应的是**全局 block_regex_general 规则**——对除 excluded 站点外的所有站点生效。

### 代码: Manifest V2 webRequest 对比

```javascript
// Manifest V2 — 动态阻止 paywall 脚本
ext_api.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (!isSiteEnabled(details))
      return;

    let domain = matchUrlDomain(Object.keys(blockedRegexes), details.url);
    let matched_general = matchUrlDomain(Object.keys(blockedRegexesGeneral), details.url);

    if (domain && details.url.match(blockedRegexes[domain]))
      return { cancel: true };

    if (matched_general && details.url.match(
      blockedRegexesGeneral[matched_general].block_regex))
      return { cancel: true };
  },
  { urls: ["*://*/*"], types: ["script", "xmlhttprequest"] },
  ["blocking"]
);
```

---

## 攻击链

```
1. 确认 paywall SDK
   Network 面板 → 找到 piano.js / poool.js / sophi.js
   → 记录 URL 模式

2. 添加 block_regex
   sites.js → block_regex: /\.piano\.io\//
   → 扩展自动生成 declarativeNetRequest block 规则

3. 如果内联脚本
   sites.js → block_js_inline: /domain\.com\/article\/.+/
   → 扩展注入 CSP: script-src *; 覆盖原有限制

4. 如果全站 JS 需阻止
   sites.js → block_js: 1 或 block_js_ext: 1
   → 阻止同源 JS 或仅外部 JS

5. AMP 备选
   sites.js → amp_redirect: "pattern"
   → 重定向到 AMP 版本 (对 UA 敏感度低)

6. URL 绕过
   sites.js → redirect rule
   → 从 paywall URL 直接跳转到内容 URL
```

### 关联技术

- [01-paywall-detection-bypass](01-paywall-detection-bypass.md) — Paywall 平台识别
- [02-http-header-manipulation](02-http-header-manipulation.md) — HTTP 头伪装
- [04-content-extraction](04-content-extraction.md) — 内容提取
- [05-dom-css-manipulation](05-dom-css-manipulation.md) — DOM 操作
- [race-cache-smuggling](../08-infra/race-cache-smuggling.md) — Web Cache Poisoning

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“页面可见变化”与服务端内容授权分开记录；只有正文差分、状态变化或 Flag 可重复出现才算确认。
- 从全新浏览器 profile/session 最小化重放，记录 UA、Cookie、Storage、脚本拦截规则和执行时序。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据使用 `REDACTED` 占位并自动检索常见 Flag 格式。

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 真实浏览器运行时分析 | `jshook` | 观察 DOM、脚本、Storage、请求与 paywall 状态 |
| HTTP 差分 | `http_probe` | 比较匿名、登录、UA/Referer/Cookie 变体 |
| 知识路由 | `kb_router` | 按 paywall 平台与提取信号选择技术文件 |
