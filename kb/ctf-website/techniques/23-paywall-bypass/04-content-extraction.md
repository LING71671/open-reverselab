# 内容提取 — JSON-LD / Next.js / archive.is

## 场景

SEO 最佳实践要求网站在 `<script type="application/ld+json">` 中提供完整文章内容供搜索引擎索引。Next.js 等 SSR 框架在 `<script id="__NEXT_DATA__">` 中嵌入完整数据。即使 DOM 中正文被截断，这些 JSON blob 中仍包含原始全文。外部存档服务 (archive.is, Google Cache) 在爬取时使用 Googlebot UA，缓存了完整的无 paywall 内容。

```
DOM 渲染 (用户看到):
  "Lorem ipsum dolor sit amet... [Subscribe to continue reading]"
  └─ 正文 200 字后截断

JSON-LD (搜索引擎看到):
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do
   eiusmod tempor incididunt ut labore et dolore magna aliqua..."
  └─ 完整正文 2000+ 字

archive.is (外部存档看到的):
  使用 Googlebot UA 爬取 → 存储完整无 paywall HTML
```

## 输入信号

- DOM 中存在 `<script type="application/ld+json">` 且 JSON 包含 `articleBody` 字段 (比 DOM 中的文本长)
- DOM 中存在 `<script id="__NEXT_DATA__">` (Next.js 应用)
- 页面源码 view-source: 中存在 JSON 对象含完整正文 (`view-source:URL`)
- `<link rel="alternate" type="application/json" href="...">` 指向完整内容的 JSON API
- archive.is / textise dot iitty 已存档该 URL (Google Dork: `site:archive.is URL`)
- Google 搜索结果的 "Cached" 链接或 `webcache.googleusercontent.com` 可访问
- JSON-LD 中 `@type: NewsArticle` 或 `@type: Article` 结构化数据
- script 标签内联 JavaScript 中含 `window.__INITIAL_STATE__` 或 `window.__PRELOADED_STATE__`
- 页面内 `<style amp-custom>` 或无 JS 时显示完整内容 (noscript 标签)
- 同一 URL 的 print 版本 (`?print=1` / `/print/`) 或 text 版本返回完整内容

---

## 方法 1: JSON-LD 提取 (`<script type="application/ld+json">`)

### 原理

Google 结构化数据指南要求新闻文章在 JSON-LD 中包含 `articleBody` 字段。这个字段通常包含**原始的完整正文**（HTML 格式），即使 DOM 中前端已经截断。定位 paywall overlay 的选择器 → 删除 DOM 节点 → 从 JSON-LD 中恢复正文。

### 代码: contentScript.js — JSON-LD 提取核心

```javascript
// contentScript.js — ld_json 处理
if (bg2csData.ld_json && dompurify_loaded) {
  let data = bg2csData.ld_json;
  // data 格式: "paywall_sel|article_sel|article_append|article_hold"
  if (data.includes('|')) {
    window.setTimeout(function () {
      let [paywall_sel, article_sel, article_append, article_hold] = data.split('|');
      let paywall = document.querySelectorAll(paywall_sel);
      let article = document.querySelector(article_sel);

      if (paywall.length && article) {
        removeDOMElement(...paywall);  // 移除 paywall overlay

        // 获取页面中的 JSON-LD
        let json_script = getArticleJsonScript();
        if (json_script) {
          try {
            let json = JSON.parse(json_script.text.replace(/[\r\n\t]/g, ''));

            // 递归搜索 articleBody 或 text 字段
            let json_key = findKeyJson(json, /^articlebody$/i)
                        || findKeyJson(json, /^text$/i);

            if (json_key) {
              // 清理 JSON 中的转义换行符
              let json_text = parseHtmlEntities(
                json_key.replace(/(\\r)?\\n/g, '<br>')
                         .replace(/\[[^\[]+]/g, '')
              );

              // 如果不是 HTML (无 src/href 属性) → 添加段落格式
              if (!json_text.match(/\s(src|href)=/))
                json_text = breakText(json_text).replace(/\n\n/g, '<br><br>');

              // 安全处理: DOMPurify 防止 XSS
              let parser = new DOMParser();
              let doc = parser.parseFromString(
                '<div style="margin: 25px 0px">' +
                DOMPurify.sanitize(json_text, dompurify_options) +
                '</div>',
                'text/html'
              );
              let article_new = doc.querySelector('div');

              // 替换或追加到原有 article 容器
              if (article_append || !article.parentNode) {
                if (!article_hold)
                  article.innerHTML = '';
                article.appendChild(article_new);
              } else if (article.parentNode) {
                article.parentNode.replaceChild(article_new, article);
              }
            }
          } catch (err) {
            console.log(err);
          }
        }
      }
    }, 1000);
  }
}
```

### 辅助函数: JSON-LD 定位与字段搜索

```javascript
// 定位 JSON-LD script 标签
function getArticleJsonScript() {
  // 优先级 1: @type: Article / NewsArticle / BlogPosting
  let scripts = document.querySelectorAll('script[type="application/ld+json"]');
  for (let script of scripts) {
    try {
      let json = JSON.parse(script.text);
      if (json['@type'] && /article|newsarticle|blogposting/i.test(json['@type']))
        return script;
    } catch (e) {}
  }
  // 优先级 2: 包含 articleBody 的 JSON
  for (let script of scripts) {
    try {
      let json = JSON.parse(script.text);
      if (findKeyJson(json, /^articlebody$/i))
        return script;
    } catch (e) {}
  }
  // 优先级 3: 返回第一个 JSON-LD
  return scripts[0];
}

// 递归搜索 JSON 中的键 (大小写不敏感)
function findKeyJson(json, search, min_length = 0) {
  if (typeof search === 'string')
    search = [search];

  let stack = [json, 'root'](json, 'root'.md);
  while (stack.length) {
    let [obj, path] = stack.shift();
    for (let key in obj) {
      if (typeof obj[key] === 'string') {
        for (let s of search) {
          let match = (s instanceof RegExp) ? s.test(key) : (key === s);
          if (match && obj[key].length > min_length)
            return obj[key];
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        stack.push([obj[key], path + '.' + key]);
      }
    }
  }
  return null;
}
```

---

## 方法 2: Next.js `__NEXT_DATA__` 提取

### 原理

Next.js SSR 页面在 `<script id="__NEXT_DATA__">` 中嵌入序列化的 page props——包括 `article.body`、`blocks`、`content`、`html` 等完整内容。格式为 JSON，可直接解析。

### 代码: contentScript.js — Next.js 提取

```javascript
// contentScript.js — ld_json_next 处理
if (bg2csData.ld_json_next && dompurify_loaded) {
  let data = bg2csData.ld_json_next;
  if (data.includes('|')) {
    window.setTimeout(function () {
      let [paywall_sel, article_sel, article_append, article_hold] = data.split('|');
      let paywall = document.querySelectorAll(paywall_sel);
      let article = document.querySelector(article_sel);

      if (paywall.length && article) {
        removeDOMElement(...paywall);

        let json_script = document.querySelector('script#__NEXT_DATA__');
        if (json_script) {
          try {
            let json = JSON.parse(json_script.text);

            // 验证 URL slug 匹配 → 确保提取的是当前文章数据
            let query_slug = json.query && json.query.slug;
            if (query_slug && Array.isArray(query_slug))
              query_slug = query_slug.pop();
            let url_next = query_slug || findKeyJson(json, ['slug']);
            if (url_next && typeof url_next === 'string' &&
                !decodeURIComponent(window.location.pathname)
                  .endsWith(decodeURIComponent(url_next)))
              refreshCurrentTab();  // slug 不匹配 → 刷新页面等待正确数据

            // 搜索文章正文: 按优先级尝试多个键名
            let json_text = findKeyJson(json, [
              'blocks', 'body', 'BodyPlainText',
              'content', 'contentHtml',
              'description', 'html'
            ], 500);  // 最少 500 字符

            if (typeof json_text === 'string')
              json_text = parseHtmlEntities(json_text);
            else if (Array.isArray(json_text))
              // 数组格式: 拼接段落
              json_text = '<p style="margin: 10px;">' +
                json_text.map(x =>
                  (typeof x === 'string') ? x :
                  (x.children ? x.children.map(y => y.text).join('') :
                   x.text || x.innerHTML)
                ).join('<br><br>') + '</p>';

            if (json_text) {
              let parser = new DOMParser();
              let doc = parser.parseFromString(
                '<div>' + DOMPurify.sanitize(json_text, dompurify_options) + '</div>',
                'text/html'
              );
              let article_new = doc.querySelector('div');

              if (article_append || !article.parentNode) {
                if (!article_hold)
                  article.innerHTML = '';
                article.appendChild(article_new);
              } else if (article.parentNode) {
                article.parentNode.replaceChild(article_new, article);
              }
            }
          } catch (err) {
            console.log(err);
          }
        }
      }
    }, 1000);
  }
}
```

---

## 方法 3: 页面源码 JSON 提取 (内联 Script)

### 原理

有些网站不遵循标准 JSON-LD，而是将文章数据嵌入在内联 `<script>` 变量中（如 `var articleData = {...}`）。通过正则定位包含特定 key 的 `<script>` 标签文本，提取 JSON 片段。

### 代码: contentScript.js — ld_json_source 处理

```javascript
// contentScript.js — ld_json_source 处理 (内联 script 变量提取)
if (bg2csData.ld_json_source && dompurify_loaded) {
  let data = bg2csData.ld_json_source;
  if (data.includes('|')) {
    window.setTimeout(function () {
      let [paywall_sel, article_sel, filter_re, json_key,
           article_append, article_hold] = data.split('|');
      let filter = new RegExp(
        filter_re.replace(/\./g, '\\.').replace('=', '\\s?=\\s?')
      );
      let paywall = document.querySelectorAll(paywall_sel);
      let article = document.querySelector(article_sel);

      if (paywall.length && article) {
        removeDOMElement(...paywall);

        // 在所有不含 src 属性 (内联) 的 <script> 中搜索
        let json_script = getSourceJsonScript(filter, ':not([src])');
        if (json_script) {
          let script_text = json_script.text.split(filter)[1];
          // 截断到 }; (对象结束)
          if (script_text.includes('};'))
            script_text = script_text.split('};')[0] + '}';

          try {
            let json = JSON.parse(script_text);
            if (json) {
              let json_text = parseHtmlEntities(getNestedKeys(json, json_key));
              let parser = new DOMParser();
              let doc = parser.parseFromString(
                '<div>' + DOMPurify.sanitize(json_text, dompurify_options) + '</div>',
                'text/html'
              );
              let article_new = doc.querySelector('div');

              if (article_append || !article.parentNode) {
                if (!article_hold) article.innerHTML = '';
                article.appendChild(article_new);
              } else if (article.parentNode) {
                article.parentNode.replaceChild(article_new, article);
              }
            }
          } catch (err) {
            console.log(err);
          }
        }
      }
    }, 1000);
  }
}

// 辅助: 在所有不含 src 的 <script> 中匹配 regex filter
function getSourceJsonScript(filter, not_selector = ':not([src])') {
  let scripts = document.querySelectorAll('script' + not_selector);
  for (let script of scripts) {
    if (filter.test(script.text))
      return script;
  }
  return null;
}

// 辅助: 通过点号路径获取嵌套 JSON 值
function getNestedKeys(json, key_path) {
  let keys = key_path.split('.');
  let value = json;
  for (let key of keys) {
    if (value && typeof value === 'object')
      value = value[key];
    else
      return null;
  }
  return value;
}
```

---

## 方法 4: JSON URL 链接提取

### 原理

某些网站通过 `<link rel="alternate" type="application/json" href="...">` 提供纯数据 API。直接 fetch 该 URL 获取完整结构化数据。

### 代码: contentScript.js — ld_json_url 处理

```javascript
if (bg2csData.ld_json_url && dompurify_loaded) {
  let data = bg2csData.ld_json_url;
  if (data.includes('|')) {
    window.setTimeout(function () {
      let [paywall_sel, article_sel, article_append, article_hold,
           article_id_sel, key, url_rest] = data.split('|');

      // 从 DOM 中提取文章 ID
      let article_id;
      if (article_id_sel) {
        let el = document.querySelector(article_id_sel + '[content]');
        if (el) article_id = el.content;
        else return;
      }

      function setMediaSrc(elem) {
        if (elem.getAttribute('data-src'))
          elem.src = elem.getAttribute('data-src');
        else {
          let data_src = [...elem.attributes]
            .find(x => x.name.endsWith('-src'));
          if (data_src) elem.src = elem.getAttribute(data_src.name);
        }
      }

      // 后续图片/iframe 媒体加载
      func_post = function () {
        document.querySelectorAll('figure img[src^="data:image/"], picture img[src^="data:image/"]')
          .forEach(setMediaSrc);
        document.querySelectorAll('iframe[src="about:blank"]')
          .forEach(setMediaSrc);
      }

      getJsonUrl(paywall_sel, '', article_sel,
        { art_append: article_append, art_hold: article_hold,
          art_style: 'margin: 25px 0px;' },
        article_id, key, url_rest);
    }, 1000);
  }
}
```

---

## 方法 5: archive.is 内容代理

### 原理

archive.is 使用 headless browser 爬取页面，结果中保存了完整的渲染后 DOM。通过 fetch archive.is 的存档页面，从中提取 `.TEXT-BLOCK` 等正文选择器内容，注入当前页面。

### 代码: contentScript.js — archive.is fetch 代理

```javascript
// contentScript.js — ld_archive_is 处理
if (bg2csData.ld_archive_is && dompurify_loaded) {
  let data = bg2csData.ld_archive_is;
  if (data.includes('|')) {
    window.setTimeout(function () {
      let url = window.location.href;
      let [paywall_sel, article_sel, article_src_sel, article_link_sel] = data.split('|');

      // 移动端图片样式修正
      func_post = func_post || function () {
        if (mobile) {
          document.querySelectorAll(
            'figure img[loading="lazy"][style], picture img[loading="lazy"][style]'
          ).forEach(e => e.style = 'width: 95%;');
        }
      }

      // fetch archive.is → 提取正文 → 注入
      getArchive(url, paywall_sel, '', article_sel,
                 '', article_src_sel || article_sel,
                 article_link_sel || article_sel);
    }, 1000);
  }
}

// archive.is 内容获取核心
function getArchive(url, paywall_sel, ...args) {
  let archive_url = 'https://archive.is/' + url;

  // 通过 background.js 的 offscreen document 绕过 CORS
  ext_api.runtime.sendMessage({
    request: 'fetchArchive',
    data: { url: archive_url, paywall_sel: paywall_sel, args: args }
  }, function (response) {
    if (response && response.html) {
      replaceDomElementExtSrc(
        url, archive_url, response.html, true, false, ...args
      );
    }
  });
}

// archive.is DOM 解析与注入
function replaceDomElementExtSrc(url, url_src, html, ...) {
  let paywall = document.querySelectorAll(paywall_sel);
  let article_src = document.querySelector(article_src_sel);

  if (paywall.length && article_src && html) {
    removeDOMElement(...paywall);

    let parser = new DOMParser();
    let doc = parser.parseFromString(html, 'text/html');

    // archive.is 的文章正文在 .TEXT-BLOCK 中
    let article_new = doc.querySelector('.TEXT-BLOCK') ||
                      doc.querySelector('article') ||
                      doc.querySelector('[itemprop="articleBody"]');

    if (article_new) {
      // DOMPurify 安全处理
      let clean = DOMPurify.sanitize(article_new.innerHTML, dompurify_options);
      if (article_hold)
        article_src.insertAdjacentHTML('beforebegin', clean);
      else
        article_src.innerHTML = clean;
    }
  }
}
```

---

## 方法 6: Python 外部提取 — JSON-LD + archive.is

### 适用于爬虫/自动化场景

```python
"""content_extraction.py — 从 JSON-LD / Next.js / archive.is 提取完整内容"""
import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote


def extract_json_ld(html: str) -> str | None:
    """从 JSON-LD 提取 articleBody"""
    soup = BeautifulSoup(html, 'lxml')
    for script in soup.find_all('script', type='application/ld+json'):
        try:
            data = json.loads(script.string)
            # 处理 @graph 格式
            items = data.get('@graph', [data])
            if not isinstance(items, list):
                items = [items]

            for item in items:
                if item.get('@type', '').lower() in (
                    'article', 'newsarticle', 'blogposting'
                ):
                    body = item.get('articleBody', '')
                    if len(body) > 500:
                        return body
        except (json.JSONDecodeError, AttributeError):
            continue
    return None


def extract_next_data(html: str) -> str | None:
    """从 __NEXT_DATA__ 提取文章正文"""
    match = re.search(
        r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        html, re.DOTALL
    )
    if not match:
        return None

    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None

    props = data.get('props', {}).get('pageProps', {})
    article = props.get('article', {}) or props.get('post', {})

    # 按优先级尝试提取
    for key in ('body', 'content', 'contentHtml', 'text', 'description'):
        value = article.get(key, '')
        if isinstance(value, str) and len(value) > 200:
            return value
        if isinstance(value, list):
            # 块级结构 → 拼接
            text = ' '.join(
                b.get('text', '') or b.get('children', [{}])[0].get('text', '')
                for b in value if isinstance(b, dict)
            )
            if len(text) > 200:
                return text
    return None


def fetch_archive_is(url: str) -> str | None:
    """从 archive.is 获取存档内容"""
    archive_url = f'https://archive.is/{quote(url, safe="")}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)'
    }
    resp = requests.get(archive_url, headers=headers, timeout=30)
    if resp.status_code != 200:
        return None

    soup = BeautifulSoup(resp.text, 'lxml')
    # archive.is 使用 .TEXT-BLOCK 类标记正文
    text_block = soup.select_one('.TEXT-BLOCK')
    if text_block:
        return text_block.get_text('\n', strip=True)

    article = soup.find('article')
    if article:
        return article.get_text('\n', strip=True)

    return soup.get_text('\n', strip=True)


def extract_full_content(url: str) -> dict:
    """多层提取策略: JSON-LD → Next.js → archive.is"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)'
    }
    resp = requests.get(url, headers=headers, timeout=30)
    html = resp.text

    result = {
        'url': url,
        'source': None,
        'content': None,
        'content_length': 0,
    }

    # 策略 1: JSON-LD
    body = extract_json_ld(html)
    if body:
        result['source'] = 'json-ld'
        result['content'] = body
        result['content_length'] = len(body)
        return result

    # 策略 2: Next.js __NEXT_DATA__
    body = extract_next_data(html)
    if body:
        result['source'] = '__NEXT_DATA__'
        result['content'] = body
        result['content_length'] = len(body)
        return result

    # 策略 3: archive.is 代理
    body = fetch_archive_is(url)
    if body:
        result['source'] = 'archive.is'
        result['content'] = body
        result['content_length'] = len(body)
        return result

    # 策略 4: 原始 HTML (含 paywall overlay)
    result['source'] = 'raw_html'
    result['content'] = html
    result['content_length'] = len(html)
    return result


if __name__ == '__main__':
    url = 'https://www.nytimes.com/2025/01/01/technology/example.html'
    result = extract_full_content(url)
    print(f"Source: {result['source']}")
    print(f"Content length: {result['content_length']} chars")
    print(f"Preview: {result['content'][:200]}...")
```

---

## 攻击链

```
1. 检查内容来源
   view-source:URL → 搜索 "articleBody" / "__NEXT_DATA__"
   → 确认 JSON 中有完整内容

2. 优先级提取
   JSON-LD > __NEXT_DATA__ > 内联 Script > JSON URL > archive.is

3. JSON-LD (最可靠)
   script[type="application/ld+json"]
   → @type: Article/NewsArticle → articleBody 字段
   → DOMPurify 清理 HTML → 注入 DOM

4. Next.js (特定框架)
   script#__NEXT_DATA__
   → props.pageProps.article.body / blocks / content
   → DOMPurify 清理 → 注入

5. 内联 Script (特定网站)
   正则匹配 script 文本中的 JSON-like 变量
   → 按 filter regex 定位 → 解析 JSON 片段

6. archive.is (最后手段)
   fetch https://archive.is/<url>
   → 解析 .TEXT-BLOCK 或 article 标签
   → 注入当前页面
```

### 关联技术

- [01-paywall-detection-bypass](01-paywall-detection-bypass.md) — Paywall 类型识别
- [02-http-header-manipulation](02-http-header-manipulation.md) — UA 伪装 (增强 JSON 中的内容完整性)
- [03-network-rule-blocking](03-network-rule-blocking.md) — 脚本拦截
- [05-dom-css-manipulation](05-dom-css-manipulation.md) — DOM 操作
- [web-cache-deception](../08-infra/web-cache-deception.md) — 缓存内容欺骗

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
