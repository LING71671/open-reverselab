---
id: "ctf-website/03-injection/ssti-defense"
title: "SSTI (服务器端模板注入) 与多引擎沙盒加固"
title_en: "Server-Side Template Injection (SSTI) Defense"
summary: >
  针对 Jinja2、Thymeleaf、FreeMarker、Velocity、Smarty、Tornado、ERB、Razor、Pebble 及客户端模板（Vue/Angular）的 SSTI 纵深防御指南。涵盖静态模板参数绑定原则、各引擎安全模式与反射链阻断配置、HTTP Header/邮件/错误页隐式渲染收敛、CSTI 运行时构建隔离及可运行 Python 沙盒与代码静态检测校验器。
summary_en: >
  Defense-in-depth guide against Server-Side and Client-Side Template Injection across Jinja2, Thymeleaf, FreeMarker, Velocity, Smarty, Tornado, ERB, Razor, Pebble, and Vue/Angular. Covers static template parameter binding, engine-specific sandbox and reflection blocking, implicit header/mail/error-page rendering hardening, CSTI runtime compilation removal, and runnable Python sandbox/policy checks.
board: "ctf-website"
category: "03-injection"
signals: ["SSTI防御", "模板注入防御", "SandboxedEnvironment", "ALLOWS_NOTHING_RESOLVER", "CSTI防护", "静态模板绑定", "反射链阻断"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["SSTI防御", "Jinja2沙盒", "Thymeleaf安全", "FreeMarker加固", "Smarty安全", "CSTI防御", "模板引擎加固", "表达式注入防护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "injection", "ssti", "template-engine", "sandbox"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/03-injection/ssti", "ctf-website/03-injection/prototype-pollution-defense", "ctf-website/07-client/admin-bot-xss-defense"]
track: "blue"
defends: "ctf-website/03-injection/ssti"
---

# SSTI (服务器端模板注入) 与多引擎沙盒加固

SSTI 的本质是**把不可信输入当作“模板源码”编译执行，而非作为“数据变量”填入静态模板**。诸如过滤 `.`、`__`、单双引号或黑名单关键词（`__class__`、`config`）的防护很容易被 `|attr()`、`\x5f` 十六进制编码、`request.args` 外部传参或 `dict()|join` 字符串拼接绕过。根治方案是彻底分离模板代码与用户输入，并在必须支持用户自定义模板的场景下启用最小能力沙盒与无特权运行时。

## 防御工作流

```text
排查所有渲染入口（页面、错误页、HTTP Header、邮件、PDF、Markdown 后处理）
  → 将动态字符串拼接模板全部改造为静态模板文件 + 上下文数据绑定
  → 针对不同后端引擎配置无反射沙盒与禁用危险内建函数/全局变量
  → 前端移除运行时模板编译器（CSTI）并编码 {{ }} 边界
  → 使用自动化校验阻断 __class__ / __globals__ / Runtime 等逃逸链
```

## 1. 根本原则：静态模板 + 数据变量绑定

任何业务需求（问候语、发票预览、动态通知、错误回显）都不应通过拼接字符串构造模板源码：

| 危险用法 | 安全替代写法 |
|---|---|
| Flask/Jinja2: `render_template_string("Hello " + name)` | `render_template("hello.html", name=name)` |
| Smarty: `$smarty->display("string:" . $real_ip)` | `$smarty->assign("ip", $real_ip); $smarty->display("ip.tpl");` |
| Thymeleaf: `return "user/" + viewName;`（URL 参数入视图名） | 返回固定视图名或枚举映射表；对片段参数禁用 `__${...}__` 预处理并设为只读数据模型 |
| Tornado: `tornado.template.Template(user_tpl).generate()` | 使用 `self.render("page.html", content=user_text)` 并开启 `autoescape="xhtml_escape"` |
| ERB / Razor / Pebble | 禁止 `ERB.new(input).result`、`RazorEngine` 编译用户输入、动态 `PebbleEngine.getLiteralTemplate(input)` |

> [!WARNING]
> **隐式渲染路径高发盲区**：`X-Forwarded-For`、自定义 404/500 错误页、邮件主题/正文模板、PDF 导出 HTML 预览以及 Markdown 渲染后二次塞入前端模板容器，均是攻击者绕过常规参数检查触发 SSTI/CSTI 的常见入口。

## 2. 多模板引擎安全加固矩阵

若业务确需向受限用户开放模板预览功能（如邮件编辑、静态站自定义页），必须按引擎特性收敛对象图与类解析能力，仅靠单层 WAF 或黑名单无法阻断：

| 模板引擎 | 危险利用面 | 强制加固配置 |
|---|---|---|
| **Jinja2 (Python)** | `__class__`、`__mro__`、`__subclasses__`、`lipsum`/`cycler`/`namespace`/`url_for`/`config` 全局对象 | 使用 `SandboxedEnvironment`，清空或拒绝注入 `request`/`config`/`lipsum` 等带 `__globals__` 的函数对象；覆写 `is_safe_attribute` 拦截全部双下划线属性与内部方法 |
| **FreeMarker (Java)** | `?new()` 实例化 `Execute` 或利用 Model Bean `.getClass().getProtectionDomain()` | 设置 `cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)`；使用受限 `MemberAccessPolicy` / `SimpleObjectWrapper` 包装 Model Bean，禁止通过 getter 触达 `getClass()` / `Class.forName` |
| **Thymeleaf / SpEL** | URL 片段预处理 `__${T(java.lang.Runtime)...}__::.x` | 控制器路径不直接映射用户输入作为视图名；任何动态 SpEL 必须使用 `SimpleEvaluationContext` 替代 `StandardEvaluationContext`，禁用 `T(...)` 类型引用与方法调用 |
| **Velocity (Java)** | `$class.inspect("java.lang.Runtime")` | 配置 `SecureUberspector` 并禁止向上下文放入 `ClassTool`、任意反射工具类 |
| **Smarty (PHP)** | `{php}...{/php}` 与 `{if system('id')}{/if}` 原生 PHP 表达式 | 禁用 `SmartyBC` 与 `string:` 资源；启用 `Smarty_Security` 策略类并把 `php_functions`、`php_modifiers`、`streams` 设为空白名单或极窄只读函数集合 |
| **Twig (PHP)** | `filter('system')`、`map` 等高阶回调函数执行 | 升级至修复版 Twig 并启用 `SandboxExtension` 白名单限制标签、过滤器与对象方法 |
| **Vue / Angular (CSTI)** | 服务端 HTML 转义未覆盖 `{{ }}`，全局构建 `vue.global.js` 暴露 `_Vue.constructor` | 生产环境改用预编译 SFC 与纯运行时包（`vue.runtime.esm-bundler.js`，无客户端模板编译器），开启 CSP 禁止 `'unsafe-eval'`，并在服务端渲染插入文本时对 `{` / `}` 及 `v-` 属性做实体编码或绑定到 `v-pre` / 纯 `textContent` |

## 3. Jinja2 严格沙盒与危险调用核查脚本

以下可运行 Python 脚本演示两部分防御工程实践：（1）配置拒绝所有双下划线与敏感全局对象的最小权限沙盒模板渲染器；（2）扫描应用源码中常见高危模板动态拼接模式（如 `render_template_string` 拼接与 `display('string:'...)`）：

```python
#!/usr/bin/env python3
"""Jinja2 安全绑定策略校验与常见 SSTI 代码模式静态核查器。"""
import re
from string import Template

# 1. 若无复杂逻辑需求，优先使用无反射能力的极简占位替换（如 string.Template）
def safe_placeholder_render(user_name: str, role: str) -> str:
    tpl = Template("Welcome, $name (role=$role)")
    # 即使输入包含 {{7*7}}、${7*7}、<%=7*7%> 也不会被二次求值
    return tpl.safe_substitute(name=user_name, role=role)


# 2. 如果构建自定义沙盒策略，必须阻断一切属性反射路径与隐式全局对象
BLOCKED_ATTR_PREFIXES = ("_", "gi_", "cr_", "ag_", "f_")
BLOCKED_NAMES = {
    "__class__", "__mro__", "__base__", "__bases__", "__subclasses__",
    "__init__", "__globals__", "__builtins__", "__import__", "lipsum",
    "cycler", "namespace", "url_for", "get_flashed_messages", "config", "request",
}


def validate_template_ast_tokens(template_src: str) -> tuple[bool, str]:
    """在沙盒渲染前对模板表达式做属性访问与编码混淆预检（配合原生 SandboxedEnvironment 使用）。"""
    # 拒绝十六进制/八进制/Unicode 字符逃逸拼接（如 \x5f\x5fclass\x5f\x5f）
    if re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}", template_src):
        return False, "reject: escaped string literals are forbidden in user templates"

    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", template_src)
    for tok in tokens:
        if tok in BLOCKED_NAMES or tok.startswith(BLOCKED_ATTR_PREFIXES):
            return False, f"reject: forbidden reflection/global identifier {tok!r}"

    # 阻止 |attr(...) 动态属性查找绕过点号
    if re.search(r"\|\s*attr\b", template_src):
        return False, "reject: dynamic attr filter is disabled in sandbox"
    return True, "allow"


# 3. 代码库静态模式检查（识别把变量拼进模板字符串的高危用法）
SINK_RULES = [
    ("flask_render_template_string", re.compile(r"render_template_string\s*\([^)]*[+f%]")),
    ("jinja2_raw_template", re.compile(r"jinja2\.Template\s*\([^)]*[+f%]")),
    ("smarty_string_resource", re.compile(r"->display\s*\(\s*['\"]string:['\"]\s*\.")),
    ("freemarker_raw_string", re.compile(r"new\s+Template\s*\([^,]+,\s*new\s+StringReader\s*\(")),
]


def scan_source_snippet(code: str) -> list[str]:
    return [name for name, rx in SINK_RULES if rx.search(code)]


if __name__ == "__main__":
    # 验证纯占位替换不求值常见 SSTI 载荷
    for payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{T(java.lang.Runtime)}"):
        rendered = safe_placeholder_render(payload, "guest")
        assert "49" not in rendered and payload in rendered
        print(f"[PASS bind] literal preserved: {rendered}")

    # 验证沙盒预检阻断绕过链
    evil_templates = [
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ ''|attr('__class__') }}",
        "{{ ''['\\x5f\\x5fclass\\x5f\\x5f'] }}",
        "{{ lipsum.__globals__['os'].popen('id').read() }}",
    ]
    for tpl in evil_templates:
        ok, msg = validate_template_ast_tokens(tpl)
        assert not ok, f"expected block for {tpl}"
        print(f"[PASS sandbox] {msg}")

    # 验证静态模式规则捕获危险拼接
    bad_code = 'return render_template_string("<h1>Hello " + username + "</h1>")'
    hits = scan_source_snippet(bad_code)
    assert "flask_render_template_string" in hits
    print(f"[PASS scan] detected unsafe template sink: {hits}")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| 多引擎算术指纹 | `{{7*7}}`、`${7*7}`、`<%=7*7%>`、`#{7*7}`、`*{7*7}` 均按纯文本字面量原样或 HTML 转义后输出 | 响应任意位置（含错误页、邮件、Header 回显）出现计算结果 `49` |
| Jinja2/FreeMarker 逃逸链 | 反射属性、`|attr()`、`\x5f`、`?new()` 及 `Bean.getClass()` 访问均被沙盒拒绝 | 返回对象类名列表、`config` 键、文件内容或产生异常栈泄露 |
| Smarty/Thymeleaf 隐式入口 | `X-Forwarded-For`、URL 片段路径与错误信息不进入模板编译流 | 头部注入 `{if system(id)}{/if}` 或路径 `__${...}__` 产生执行副作用 |
| Vue/Angular CSTI | 运行时禁用动态编译且服务端编码 `{{`/`}}`，浏览无 `pageerror` 或表达式求值 | 页面内 `{{7*7}}` 被前端框架渲染成 `49` 或 `_Vue.constructor` 可执行 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `ssti`、`jinja2`、`freemarker`、`csti`、`sandbox` 检索配对文档 |
| 读取攻击链条 | `kb_read_file` | 对照 `ctf-website/03-injection/ssti` 核查多引擎绕过与隐式渲染入口 |
| 浏览目录索引 | `kb_catalog` | 确认 `03-injection` 与 `07-client` 模板相关防御覆盖度 |
| 渲染回显核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后验证数学探针是否原样文本返回而非 `49` |
