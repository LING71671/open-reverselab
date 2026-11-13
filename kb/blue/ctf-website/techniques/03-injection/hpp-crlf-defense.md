---
id: "ctf-website/03-injection/hpp-crlf-defense"
title: "HPP 与 CRLF 响应头注入防御"
title_en: "HPP and CRLF Header Injection Defense"
summary: >
  针对 HTTP 参数污染（HPP）与 CRLF/Header 注入的纵深防御指南，聚焦消除网关、WAF 与后端框架之间的解析器差异。涵盖重复参数与 JSON 重复键严格拒绝策略、URL 解码边界归一化、Location/Set-Cookie/Cache/SSRF/Email 五类 CRLF Sink 阻断方案及可运行 Python 校验器。
summary_en: >
  Defense-in-depth guide against HTTP Parameter Pollution (HPP) and CRLF/Header injection, focusing on eliminating parser differentials across gateways, WAFs, and application frameworks. Covers strict rejection of duplicate parameters and duplicate JSON keys, single-pass URL normalization, CRLF blocking across Location/Set-Cookie/Cache/SSRF/Email sinks, and runnable Python validators.
board: "ctf-website"
category: "03-injection"
signals: ["HPP防御", "CRLF防御", "重复参数拦截", "JSON重复键", "响应头注入防护", "parser differential防御", "Header归一化"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["HPP防御", "CRLF防御", "参数污染防护", "Header注入防护", "JSON重复键检测", "解析器一致性", "HTTP响应拆分防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "injection", "hpp", "crlf", "parser-differential"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/03-injection/hpp-crlf", "ctf-website/04-ssrf/ssrf", "ctf-website/08-infra/race-cache-smuggling", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
track: "blue"
defends: "ctf-website/03-injection/hpp-crlf"
---

# HPP 与 CRLF 响应头注入防御

HPP 与 CRLF 注入的根本成因是“解析不一致”与“控制字符边界失控”：前置代理/WAF 与后端服务对重复参数（取首值、末值、拼接或数组）、编码层级以及换行符的处理存在分叉。有效的防御策略是让边界层与业务层严格使用同一份规范化结果，并对任何多义结构采取 Fail-Closed 拒绝策略。

## 防御工作流

```text
入口边界强制单次解码与严格参数基数校验
  → 拒绝同名重复 Query/Form 键、分号分隔与非预期数组后缀
  → 使用 strict JSON 解析器阻断重复键覆盖
  → 对所有 Header/Redirect/SSRF URL/Email 写入点强力剥离或拒绝 CR/LF/NUL 控制字符
  → 验证上游网关与下游框架解析行为完全一致
```

## 1. 消除 HPP 多层解析差异

不同技术栈对重复参数的行为差异极大（PHP 取最后一个、Java Servlet `getParameter` 取首个而 `getParameterValues` 取全部、ASP.NET 逗号拼接、Express `qs` 构造数组、Flask 取首个而 `getlist` 取全部、Go `net/http` 保留切片）。防御不能依赖“哪一端取第几个”，而应从协议边界消除歧义：

| 风险构造 | 攻击利用手法 | 加固策略 |
|---|---|---|
| 同名重复参数 | `?role=user&role=admin` 利用校验与取值顺序错位 | 网关与业务层同时校验每个单值参数出现次数 `count == 1`，出现 `>= 2` 直接返回 `400` |
| 分号/数组后缀变形 | `?role=user;role=admin` 或 `?role=user&role[]=admin` | 禁用 `;` 作为 Query 分隔符（Python `parse_qs` 默认注意分隔行为），禁止非列表字段带 `[]` 或嵌套键语法 |
| 编码层数不一致 | `%26role%3Dadmin` 在中间件被二次解码拆分 | 仅允许在最外层 HTTP 解析时执行**一次** URL 解码，禁止业务或重定向逻辑再次 `unquote` |
| Express `qs` 隐式嵌套 | 扩展 Query 解析器将键转化为数组或对象 | 显式设置 `app.set('query parser', 'simple')` 或使用 `qs.parse(raw, { allowDots: false, depth: 0, parameterLimit: 100 })` 并配合参数基数中间件 |

## 2. 阻断 JSON 重复键歧义

RFC 8259 允许语法上存在重复键且许多标准库（如 Python `json.loads`、JavaScript `JSON.parse`）默认采用 Last-Win 覆盖语义，而部分网关校验器或 Go/C++ 解析器可能采用 First-Win 导致 `{"role":"user","role":"admin"}` 绕过拦截：

- **解析钩子强制拒绝重复键**：在所有 JSON 反序列化入口注册键冲突检查（如 Python 使用 `object_pairs_hook`、Java Jackson 启用 `DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY`、Go 严格逐 Token 校验键集合）。
- **网关与业务同构校验**：禁止在网关通过正则抽取 JSON 字段校验，应由解析后的结构化对象统一签发或传递给下游。

## 3. 全链路阻断 CRLF 与 Header 注入

CRLF 注入发生于用户输入被拼入 HTTP 响应头、下游请求头或邮件头部。所有现代标准库虽有一定防护，但自研代理、旧版驱动、模板拼装响应及自定义邮件库仍存在盲区：

1. **输入层全局拒绝控制字符**：对进入 URL 路径、Query 参数、Header 构造器的字符串，在单次 URL 解码后检查是否包含 `\r` (`0x0d`)、`\n` (`0x0a`)、`\x00` 及 Unicode 行分隔符（`\u0085`, `\u2028`, `\u2029`），命中立即返回 `400`（不采用静默删除后继续放行，以防跨层构造新序列）。
2. **`Location` 重定向 Sink 加固**：严禁将原始用户输入直接写入 `Location` 头；采用路由映射 ID（白名单字典）或严格校验解析后的 `scheme`（仅 `https`/`http`）与 `netloc`（精确匹配许可域名集），并对目标 URL 重新编码拼装。
3. **`Set-Cookie` 与缓存头加固**：Cookie 值仅允许安全字符集（如 Base64URL/Hex），显式固定 `Path`、`HttpOnly`、`Secure`、`SameSite`；禁止业务参数控制 `Cache-Control`、`Vary` 或代理路由头。
4. **SSRF 内部请求与邮件头加固**：发起下游 HTTP 请求前使用解析器校验 Host/Port/Path 无控制字符与空白符；邮件 `Subject`、`To`、`From` 使用标准库 MIME/RFC 2047 编码器生成，禁止手工拼接 `\r\n` 头行。

## 4. 可运行严格参数与 Header 校验器

以下 Python 代码实现用于微服务或 API 网关前置层的 HPP 严格解析器、JSON 重复键拒绝解析器以及 CRLF 响应头写入防护，并附带自测断言：

```python
#!/usr/bin/env python3
"""HPP 重复参数、JSON 重复键与 CRLF Header 注入严格校验器。"""
import json
from urllib.parse import unquote_to_bytes

FORBIDDEN_HEADER_CHARS = {"\r", "\n", "\x00", "\u0085", "\u2028", "\u2029"}


class InputValidationError(ValueError):
    pass


def parse_query_strict(raw_query: str, array_allowlist: set[str] | None = None) -> dict[str, str | list[str]]:
    """单次严格解析 Query String：拒绝分号分隔、重复单值参数与编码后换行符。"""
    array_allowlist = array_allowlist or set()
    if not raw_query:
        return {}
    if ";" in raw_query:
        raise InputValidationError("semicolon delimiter is forbidden in query string")

    parsed: dict[str, list[str]] = {}
    for pair in raw_query.split("&"):
        if not pair:
            continue
        k_raw, _, v_raw = pair.partition("=")
        k = unquote_to_bytes(k_raw.replace("+", " ")).decode("utf-8", errors="strict")
        v = unquote_to_bytes(v_raw.replace("+", " ")).decode("utf-8", errors="strict")

        if any(c in k or c in v for c in FORBIDDEN_HEADER_CHARS):
            raise InputValidationError("control/newline characters forbidden in parameter")

        clean_k = k[:-2] if k.endswith("[]") else k
        if k.endswith("[]") and clean_k not in array_allowlist:
            raise InputValidationError(f"unexpected array parameter: {k}")

        parsed.setdefault(clean_k, []).append(v)

    result: dict[str, str | list[str]] = {}
    for k, vals in parsed.items():
        if k in array_allowlist:
            result[k] = vals
        elif len(vals) > 1:
            raise InputValidationError(f"duplicate parameter detected (HPP blocked): {k}")
        else:
            result[k] = vals[0]
    return result


def loads_json_no_duplicates(raw_body: str):
    """拒绝 JSON 中任何层级的重复键。"""
    def _no_dup_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        obj: dict[str, object] = {}
        for k, v in pairs:
            if k in obj:
                raise InputValidationError(f"duplicate JSON key detected: {k}")
            obj[k] = v
        return obj

    return json.loads(raw_body, object_pairs_hook=_no_dup_pairs)


def sanitize_header_value(name: str, value: str) -> str:
    """响应头写入前强制校验，阻断 CRLF 与 HTTP 响应拆分。"""
    if any(c in name or c in value for c in FORBIDDEN_HEADER_CHARS):
        raise InputValidationError(f"CRLF/NUL detected in header {name}")
    # 二次编码检查：阻止未解码的 %0d/%0a 进入不支持自动编码的底层栈
    low = value.lower()
    if "%0d" in low or "%0a" in low or "%00" in low:
        raise InputValidationError(f"encoded CRLF detected in header {name}")
    return value


if __name__ == "__main__":
    # 1. HPP 拦截测试
    for bad_q in ("role=user&role=admin", "role=user;role=admin", "role[]=admin", "next=/%0d%0aSet-Cookie:a=1"):
        try:
            parse_query_strict(bad_q)
            raise AssertionError(f"expected failure for {bad_q}")
        except InputValidationError as exc:
            print(f"[PASS HPP/CRLF] {bad_q} -> {exc}")

    assert parse_query_strict("role=user&tag[]=a&tag[]=b", array_allowlist={"tag"}) == {
        "role": "user",
        "tag": ["a", "b"],
    }

    # 2. JSON 重复键拦截测试
    for bad_j in ('{"role":"user","role":"admin"}', '{"meta":{"price":100,"price":1}}'):
        try:
            loads_json_no_duplicates(bad_j)
            raise AssertionError(f"expected failure for {bad_j}")
        except InputValidationError as exc:
            print(f"[PASS JSON] {bad_j} -> {exc}")

    # 3. Header 写入检查
    try:
        sanitize_header_value("Location", "https://app.example/cb\r\nSet-Cookie: sid=evil")
        raise AssertionError("expected CRLF failure")
    except InputValidationError as exc:
        print(f"[PASS Header] -> {exc}")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| 重复参数与数组变体 | `role=user&role=admin`、`role=user;role=admin`、`role[]=admin` 统一返回 `400` | 网关与业务分别取首/末值或拼接后放行 |
| JSON 重复键 | `{"role":"user","role":"admin"}` 与嵌套重复键被反序列化层拒绝 | 请求进入业务逻辑且状态按首个或末个键生效 |
| 编码边界归一化 | `%26` 与双重编码 `%250d%250a` 不触发二次拆分或跨层误判 | 先验证后二次 URL 解码导致新增参数或换行生效 |
| Header / Redirect / Email Sink | 含 `\r`/`\n`/`%0d`/`%0a` 的输入在构造响应头或邮件头时抛出异常并阻断 | 响应头出现新增 `Set-Cookie`/`X-Injected` 或邮件结构改变 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `hpp`、`crlf`、`parser differential`、`header injection` 检索策略 |
| 读取攻击矩阵 | `kb_read_file` | 对照 `ctf-website/03-injection/hpp-crlf` 验证已覆盖全部参数/Sink 变体 |
| 浏览目录索引 | `kb_catalog` | 确认 `03-injection` 与 `08-infra`、`04-ssrf` 联动防护条目 |
| 边界一致性校验 | `http_probe` | 切换到 `red` 或 `both` 轨道后核验网关与后端对重复键和 CRLF 的返回状态码 |
