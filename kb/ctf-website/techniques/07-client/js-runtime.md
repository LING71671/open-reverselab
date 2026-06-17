# JS Runtime / Browser Reversing

在 Web CTF 以及前端对抗中，混淆的 JS 捆绑包（如 Webpack, Rollup 产物）和动态防分析手段是最常见的门槛。本指南聚焦于**如何通过动态运行时 Hook 捕获密钥**以及**利用 AST 技术静态净化混淆代码**。

---

## 1. 运行时 Hook 与凭证抓取

动态 Hook 是绕过繁琐代码分析、直接提取明文参数或加密密钥的首选。

### A. 全局网络请求拦截 (fetch/XHR)
用于捕获加密请求的数据，并分析签名（如 `sign` 或 `token`）生成的上下文。

```javascript
// Hook fetch
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const url = args[0];
    const options = args[1] || {};
    console.log(`[Fetch Request] URL: ${url}`, options);
    
    const response = await originalFetch(...args);
    const clone = response.clone();
    clone.text().then(body => {
        console.log(`[Fetch Response] URL: ${url}\nBody: ${body}`);
    });
    return response;
};

// Hook XMLHttpRequest (XHR)
const originalSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(body) {
    console.log("[XHR Send] Body:", body);
    this.addEventListener("readystatechange", function() {
        if (this.readyState === 4) {
            console.log("[XHR Response] URL:", this.responseURL, "\nResponse:", this.responseText);
        }
    });
    return originalSend.apply(this, arguments);
};
```

### B. 密码学与签名函数 Hook
Web 挑战常使用 `CryptoJS` 或原生 `WebCrypto API` 生成防篡改 Token。

```javascript
// Hook 原生 WebCrypto API
const originalImportKey = window.crypto.subtle.importKey;
window.crypto.subtle.importKey = function(format, keyData, algorithm, extractable, keyUsages) {
    if (format === "raw") {
        const keyHex = Array.from(new Uint8Array(keyData))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        console.log("[WebCrypto] Key Imported (Hex):", keyHex, "Algorithm:", algorithm);
    }
    return originalImportKey.apply(this, arguments);
};

// Hook CryptoJS AES 算法 (如果混淆代码直接打包了 CryptoJS)
if (window.CryptoJS) {
    const originalEncrypt = CryptoJS.AES.encrypt;
    CryptoJS.AES.encrypt = function(message, key, cfg) {
        console.log("[CryptoJS AES Encrypt] Plaintext:", message.toString());
        console.log("[CryptoJS AES Encrypt] Key:", key.toString(CryptoJS.enc.Utf8) || key.toString());
        if (cfg && cfg.iv) {
            console.log("[CryptoJS AES Encrypt] IV:", cfg.iv.toString());
        }
        return originalEncrypt.apply(this, arguments);
    };
}
```

---

## 2. 反调试绕过 (Anti-debug Bypass)

混淆器（如 JSObfuscator）常内置定时 `debugger` 或利用检测控制台开启的手段来阻碍调试。

### A. 定时器 `debugger` 过滤
过滤掉含有 `debugger` 的 `setInterval` / `setTimeout` 调用。

```javascript
const originalSetInterval = window.setInterval;
window.setInterval = function(func, delay, ...args) {
    const funcStr = func.toString();
    if (funcStr.includes("debugger") || funcStr.includes("action") && funcStr.includes("run")) {
        console.log("[Anti-Debug] Blocked setInterval debugger trigger");
        return 0; // 返回无效定时器ID以丢弃
    }
    return originalSetInterval.call(this, func, delay, ...args);
};
```

### B. 防止函数特征校验 (`toString` Hook)
防调试代码常对 `Function.prototype.toString` 进行 Hook 以判断某个原生 API 是否被逆向者篡改。

```javascript
const originalToString = Function.prototype.toString;
Function.prototype.toString = function() {
    // 遇到检测时，伪造并返回原生代码标志
    if (this.name === "setInterval" || this.name === "fetch") {
        return `function ${this.name}() { [native code] }`;
    }
    return originalToString.call(this);
};
```

---

## 3. 基于 Babel 的 AST 静态去混淆

对于需要彻底理解逻辑的自定义加密，需要使用基于 Babel 的脚本进行 AST（抽象语法树）分析。以下提供核心逻辑模板，放置于 `tools/ctf-website/scripts/` 下执行。

### A. Babel 分析基本结构
```javascript
const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generator = require('@babel/generator').default;
const t = require('@babel/types');

const code = fs.readFileSync('obfuscated.js', 'utf-8');
const ast = parser.parse(code);
```

### B. 字面量折叠与字符串拼接还原
将 `'a' + 'b'` 折叠为 `'ab'`，`0x123 ^ 0x321` 折叠为计算后的十进制字面量。

```javascript
const constantFoldingVisitor = {
    BinaryExpression(path) {
        const { left, right, operator } = path.node;
        // 确认左右节点均为字面量类型
        if (t.isLiteral(left) && t.isLiteral(right)) {
            const evaluated = path.evaluate();
            if (evaluated.confident) {
                path.replaceWith(t.valueToNode(evaluated.value));
            }
        }
    }
};
traverse(ast, constantFoldingVisitor);
```

### C. 还原大数组混淆与解密函数调用
混淆代码最常见的特征是：`var _0xabc = ['href', 'cookie', 'length'];`，后文调用 `_0xabc[0]`。
我们可以编写脚本在静态期预加载该数组，并把所有的数组检索替换回真实字符串：

```javascript
const arrayDecryptVisitor = {
    // 匹配 _0xabc[0] 这种 MemberExpression 形式
    MemberExpression(path) {
        const { object, property, computed } = path.node;
        // 假定 _0xabc 已经被定义并存放在一个局部 Map 中
        const arrName = "_0xabc";
        const decryptArray = ['href', 'cookie', 'length']; // 真实数组内容
        
        if (t.isIdentifier(object, { name: arrName }) && computed && t.isNumericLiteral(property)) {
            const index = property.value;
            const realVal = decryptArray[index];
            if (realVal !== undefined) {
                path.replaceWith(t.stringLiteral(realVal));
                console.log(`[AST] Replaced ${arrName}[${index}] -> "${realVal}"`);
            }
        }
    }
};
traverse(ast, arrayDecryptVisitor);
```

### D. 写入输出
```javascript
const output = generator(ast, {}, code);
fs.writeFileSync('deobfuscated.js', output.code);
```

---

## 4. Proxy 全对象 Hook

```javascript
// 全局 Proxy — 劫持任意对象的属性读写
const handler = {
    get(target, prop, receiver) {
        if (typeof target[prop] === 'function') {
            return new Proxy(target[prop], {
                apply(fn, thisArg, args) {
                    console.log(`[Proxy] ${fn.name || prop} called with:`, args);
                    const result = Reflect.apply(fn, thisArg, args);
                    console.log(`[Proxy] ${fn.name || prop} returned:`, result);
                    return result;
                }
            });
        }
        console.log(`[Proxy] get ${String(prop)} → ${target[prop]}`);
        return Reflect.get(target, prop, receiver);
    },
    set(target, prop, value) {
        console.log(`[Proxy] set ${String(prop)} = ${value}`);
        return Reflect.set(target, prop, value);
    }
};

// 劫持全局对象
window = new Proxy(window, handler);
navigator = new Proxy(navigator, handler);
document = new Proxy(document, handler);
```

## 5. WebAssembly 逆向

```javascript
// Hook WebAssembly 实例化
const origInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function(...args) {
    console.log('[WASM] instantiate called');
    if (args[0] instanceof ArrayBuffer) {
        const bytes = new Uint8Array(args[0]);
        console.log('[WASM] Module size:', bytes.length, 'bytes');
        // 导出 wasm bytes 供外部分析 (wasm2wat, ghidra)
        window.__wasm_dump = bytes;
    }
    const result = await origInstantiate.apply(this, args);
    if (result.instance) {
        console.log('[WASM] Exports:', Object.keys(result.instance.exports));
        // Hook 每个导出函数
        for (const [name, fn] of Object.entries(result.instance.exports)) {
            if (typeof fn === 'function') {
                result.instance.exports[name] = new Proxy(fn, {
                    apply(target, thisArg, args) {
                        console.log(`[WASM] ${name}(${args.map(String).join(', ')})`);
                        const ret = Reflect.apply(target, thisArg, args);
                        console.log(`[WASM] ${name} → ${ret}`);
                        return ret;
                    }
                });
            }
        }
    }
    return result;
};
```

## 6. 更多 AST 去混淆模式

```javascript
// 模式 A: 控制流平坦化恢复
const controlFlowVisitor = {
    WhileStatement(path) {
        // 匹配: while(true) { switch(_0x) { case 0: ... break; case 1: ... } }
        const body = path.node.body;
        if (t.isSwitchStatement(body) || path.get('body.body.0').isSwitchStatement()) {
            // 提取 case 块，按正确顺序拼接
            console.log('[AST] Found flattened control flow');
        }
    }
};

// 模式 B: 死代码消除
const deadCodeVisitor = {
    IfStatement(path) {
        const test = path.node.test;
        if (t.isBooleanLiteral(test)) {
            if (test.value) {
                path.replaceWith(path.node.consequent);
            } else {
                path.replaceWith(path.node.alternate || t.emptyStatement());
            }
        }
    }
};

// 模式 C: 变量重命名 — 恢复有意义的名称
const renameVisitor = {
    VariableDeclarator(path) {
        const name = path.node.id.name;
        // 匹配 _0x[a-f0-9]{4,} 模式
        if (/^_0x[a-f0-9]{4,}$/.test(name) && t.isStringLiteral(path.node.init)) {
            const value = path.node.init.value;
            // 如果是 URL path → 重命名
            if (value.startsWith('/') || value.includes('api')) {
                path.node.id.name = `API_PATH_${value.replace(/[^a-zA-Z0-9]/g, '_')}`;
            }
        }
    }
};
```

## 7. 动态调试整合

```bash
# 1. 开题
powershell scripts/ctf-website/ctf_new_challenge.ps1

# 2. 注入 hooks 到 Chrome (JSHook MCP)
# 3. 在 Debugger 中设事件断点 (事件→脚本→脚本加载)
# 4. 首次加载的脚本逐份保存到 exports/<case>/js/

# 5. 分析完 JS 后，用 Python 复现前端签名逻辑
```

```python
# replay_sign.py — 复现前端签名逻辑
import hashlib, hmac, requests, time

def sign_request(params: dict, secret: str) -> dict:
    """从 JS hook 捕获的 sign 逻辑写成 Python"""
    timestamp = str(int(time.time()))
    raw = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    raw += f"&timestamp={timestamp}"
    sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return {**params, "timestamp": timestamp, "sign": sig}

# 直接用 Python 调 API — 绕过前端所有限制
resp = requests.post("https://target.com/api/sensitive",
    json=sign_request({"userId": 1}, "captured_secret_from_hook"))
```

