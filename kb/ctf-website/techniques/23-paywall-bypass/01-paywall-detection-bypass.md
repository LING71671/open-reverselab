# Paywall 检测与绕过总览

## 场景

现代新闻/内容网站的 Paywall 是客户端+服务端混合的访问控制系统。绕过 paywall 本质上是利用网站为搜索引擎爬虫保留的 SEO 后门——Googlebot 需要索引全文内容，因此 paywall 必须对特定 User-Agent/Referer 放行。攻击面横跨 HTTP 头、DOM、Cookie、脚本加载和第三方服务。

```
攻击目标:
  - Metered paywall: N 篇免费后封锁 (计数器通常在 Cookie/LocalStorage)
  - Hard paywall: 立即要求订阅 (需 UA 伪装或内容提取)
  - Freemium: 部分 Premium 内容隐藏 (CSS + Script + JSON-LD)
  - Dynamic paywall: ML 驱动的动态拦截策略 (阈值模型可被时序操控)
  - AMP paywall: Google AMP 页面部分隐藏内容 (amp-access 标签)
  - Registration wall: 需注册但内容免费 (CSRF + 自动注册)
  - Cookie wall: GDPR 弹窗 + 阅读计数 (清除 Cookie 重置)
```

截至 2026-06，已确认支持绕过 400+ 网站，涵盖全球主要新闻出版集团。

## 输入信号

- DOM 中出现 paywall overlay 模态框 (`div.paywall`, `#gateway-content`, `.meter`, `#piano_*`)
- `<script>` 加载 pianola.io / tinypass.com / poool.fr / sophi.io / wallkit.net / axate.io 等 paywall SDK
- Googlebot UA 请求同一 URL 返回更长的响应体 (检查 UA 差异化)
- `document.cookie` 中存在 `pw_*` / `pay_*` / `meter_*` / `article_limit` / `blaize_*` / `TDNotesRead` 等标记
- `<script type="application/ld+json">` 或 `<script id="__NEXT_DATA__">` 中包含完整正文但 DOM 中被截断
- HTTP 响应头 `x-paywall-*` / `x-metered-*` / `x-article-access` / `x-cache-status` 等标记
- `<link rel="amphtml">` 存在，AMP 版本包含完整内容但 canonical 页面隐藏
- Google webcache / archive.is / textise dot iitty 中存有完整内容
- `localStorage` 中 `articleViews` / `meterReads` / `pw_*` / `piano_*` 等计数键
- `<meta generator="Ghost">`, `<link href="https://substackcdn.com">` 等 CMS 指纹
- `<div id="issuem-leaky-paywall-*">`, `span#hmn-logo` 等出版集团后端标记
- `window.Fusion.globalContent.content_restrictions` / `isPremium` 等 JS 运行时变量

---

## 方法 1: Paywall 平台指纹识别

### 原理

不同 CMS 和 paywall 服务在 DOM 中留下独特的"指纹"，通过检测这些标记可以自动匹配合适的绕过策略。

### Paywall 平台指纹表

```
第三方服务:
  Piano/Tinypass    → script[src*="tinypass.com"], script[src*="piano.io"], div#piano_*
  Poool             → script[src*=".poool.fr/"], script[src*="poool.js"]
  Sophi             → script[src*=".sophi.io/"], div[class*="sophi"]
  Axate/Agate       → script[src*=".axate.io/"], script[src*=".agate.io/"]
  Wallkit           → script[src*=".wallkit.net"], link[href$=".wallkit.net"]
  Leaky Paywall(WP) → script[src*="/leaky-paywall"], div[id^="issuem-leaky-paywall-"]
  Zephr/Blaize      → script[src*="zephr"], script[src*="blaize"]
  Memberstack       → script[data-memberstack-app]

CMS 平台:
  Substack    → link[href^="https://substackcdn.com/"]
  Ghost       → meta[name="generator"][content^="Ghost"] (不含 SteadyHQ)
  Medium      → link[href*=".medium.com/"]
  beehiiv     → meta[property="og:image"][content*="beehiiv"]
  WordPress   → /wp-content/ + Leaky Paywall / Zephr 插件标记

出版集团后端 (按国家/地区):
  Gannett(USA)         → link[href*="/gannett_net.js"], footer a[href^="https://www.gannett.com"]
  Hearst(USA)          → script[src*="/treg.hearstnp.com/"]
  Lee Enterprises(USA) → script[src*=".townnews.com/leetemplates.com/"]
  McClatchy(USA)       → link[href^="https://mcclatchy-d.openx.net"]
  MNG(USA)             → link[id^="dfm-accuweather-"], footer a[href^="https://www.medianewsgroup.com"]
  Postmedia(CA)        → script[src*=".postmedia.digital/"]
  TownNews(USA)        → meta[name="tncms-access-version"]
  CNHI(USA)            → script[src*="-cnhi-pw.newsmemory.com"]
  BridgeTower(USA)     → script[src="https://cdn.blueconic.net/bridgetowermedia.js"]
  News Corp(AU)        → 付费墙 URL: */subscribe/*?dest=*
  DPG Media(NL)        → block_regex: "temptation\\.{domain}\\/"
  Mediahuis(NL/BE)     → script 中 /pmgnews/ 路径
  Reach PLC(UK)        → footer a[href="https://jobs.reachplc.com/jobs"]
  Newsquest(UK)        → footer a[href^="https://www.newsquest.co.uk/"]
  Haymarket(UK)        → footer a[href^="http://www.haymarket.com"]
  Delinian(UK)         → footer a[href^="https://www.delinian.com/privacy-policy"]
  Madsack(DE)          → link[href*=".rndtech.de/"]
  Ippen Media(DE)      → header a[href^="https://www.ippen.media"]
  CH Media(CH)         → script[src^="https://static.data.chmedia.ch/"]
  Tamedia(CH)          → div#__next li > a[href^="https://jobs.tamedia.ch/"]
  Kaleva Media(FI)     → head[prefix*=".kalevamedia.fi/"]
  Groupe Ebra(FR)      → 特定 domain 模式
  Groupe Infopro(FR)   → 含 group 成员 domain
  Vocento(ES)          → 含 group 成员 domain
  Prensa Ibérica(ES)   → link[href*="/estaticos-cdn."]
  Bonnier News(SE)     → footer a[href*=".bonniernews.se/cookiepolicy"]
```

### 代码: 页面指纹采集 (contentScript_once.js)

```javascript
// 发送给 background 进行规则匹配
window.setTimeout(function () {
  let hostname = window.location.hostname.replace(/^www\./, '');
  let group, nofix;

  if (document.querySelector('head > link[href*=".medium.com/"]'))
    group = '###_medium';
  else if (document.querySelector('head > meta[property="og:image"][content*="beehiiv"]')) {
    group = '###_beehiiv';
    nofix = 1;
  } else if (document.querySelector('head > meta[name="generator"][content^="Ghost"]')
             && !document.querySelector('script[src^="https://steadyhq.com/"]')) {
    group = '###_ghost';
    nofix = 1;
  } else if (document.querySelector('div[id^="issuem-leaky-paywall-"]'))
    group = '###_wp_leaky_paywall';
  else if (document.querySelector('head > link[href^="https://substackcdn.com/"]')) {
    group = '###_substack_custom';
    nofix = 1;
  } else if (hostname.match(/^thelocal\.(at|ch|com|de|dk|es|fr|it|no|se)$/))
    group = '###_eu_thelocal';
  // ... 更多国家/地区的 DOM 签名检测
  else if (hostname.endsWith('.com')) {
    if (document.querySelector('footer a[href^="https://www.valnetinc.com"]'))
      group = '###_ca_valnet';
    else if (document.querySelector('head > meta[property][content^="https://cdn.forumcomm.com/"]'))
      group = '###_usa_forum_comm';
    else if (document.querySelector('footer a[href^="https://www.delinian.com/privacy-policy"]'))
      group = '###_uk_delinian';
  }

  if (group) {
    console.log(group);
    ext_api.runtime.sendMessage({
      request: 'custom_domain',
      data: { domain: getCookieDomain(hostname), group: group, nofix: nofix }
    });
  }
}, 1000);
```

---

## 方法 2: Cookie 域探测

### 原理

浏览器 Cookie 可在不同域级别设置。Paywall 系统常在父域写 Cookie 跨子域生效。需要从子域向父域逐级遍历探测准确的有效域。

### 代码: Cookie 域遍历探测

```python
# Python 版本 — 用于爬虫
def cookie_domain_sweep(hostname: str, session) -> str:
    """从子域向父域遍历，找到 cookie 有效域"""
    parts = hostname.split('.')
    test_key = f'_gd{hash(hostname)}'

    for n in range(len(parts) - 1):
        domain = '.'.join(parts[-(1+n):])
        session.cookies.set(test_key, '1', domain=domain)
        # 验证 cookie 是否成功被域接受
        if session.cookies.get(test_key, domain=domain) == '1':
            # 清理探测 cookie
            session.cookies.clear(domain=domain, name=test_key)
            return domain
    return hostname
```

```javascript
// JS 版本 — 用于浏览器扩展
function getCookieDomain(hostname) {
  let parts = hostname.split('.');
  let str = '_gd' + Date.now();
  let domain = hostname;
  let n = 0;
  while (n < parts.length - 1 && document.cookie.indexOf(str + '=' + str) === -1) {
    domain = parts.slice(-1 - (++n)).join('.');
    document.cookie = str + "=" + str + ";domain=" + domain + ";";
  }
  document.cookie = str + "=;expires=Thu, 01 Jan 1970 00:00:01 GMT;domain=" + domain + ";";
  return domain;
}
```

---

## 攻击链

```
1. 指纹 → 平台识别
   DOM 选择器 + <meta>/<link>/<script> 标签 → 确定 CMS + Paywall 服务

2. 分层绕过 (按优先级)
   UA 伪装 + Cookie 清除 → 服务器直接返回全文 (最强方式)
   ↓ 不适用
   脚本拦截 → 阻止 paywall SDK 加载，正文自然可见
   ↓ 不适用
   JSON-LD 提取 → 从 <script> JSON 中恢复完整正文
   ↓ 不适用
   archive.is 代理 → 从外部缓存获取完整内容
   ↓ 不适用
   DOM/CSS 操作 → 移除 overlay，恢复正文可见

3. 持久化
   localStorage.clear() + sessionStorage.clear() → 重置阅读计数器
   定时清除 Cookie → 防止计数器累积
```

### 关联技术

- [02-http-header-manipulation](02-http-header-manipulation.md) — UA/Referer/Cookie 伪装
- [03-network-rule-blocking](03-network-rule-blocking.md) — declarativeNetRequest 脚本拦截
- [04-content-extraction](04-content-extraction.md) — JSON-LD/Next.js/archive.is 提取
- [05-dom-css-manipulation](05-dom-css-manipulation.md) — DOM/CSS 操作与 storage
- [js-runtime](../07-client/js-runtime.md) — JS Hook 与运行时修改
- [version-fingerprinting](../01-recon/version-fingerprinting.md) — CMS 平台指纹
- [cloudflare-bypass](../01-recon/cloudflare-bypass.md) — CDN 源站绕过

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
