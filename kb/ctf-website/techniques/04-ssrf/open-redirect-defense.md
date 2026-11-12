---
id: "ctf-website/04-ssrf/open-redirect-defense"
title: "开放重定向与 URL 解析差分防御"
title_en: "Open Redirect & URL Parser Differential Defense"
summary: >
  防御因 URL 解析器差分（UserInfo @、反斜杠归一化、scheme-relative //、双重编码、Fragment 截断与同形字）引发的开放重定向及其串联的 OAuth code 劫持、SSRF 302 跟随与 CRLF 头注入攻击，实施基于严格规范化、精确源白名单与无状态令牌化跳转的综合防护。
summary_en: >
  Defense against open redirects and URL parser differentials (userinfo @, backslash normalization, scheme-relative //, double decoding, fragment truncation, IDNA homoglyphs) that enable OAuth code theft, SSRF redirect pivoting, and CRLF header injection. Enforces strict canonical parsing, exact origin allowlisting, and opaque redirect tokens.
board: "ctf-website"
category: "04-ssrf"
signals: ["open redirect", "URL parser differential", "redirect_uri", "OAuth redirect", "302", "开放重定向防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["开放重定向防御", "URL解析器一致性", "白名单校验", "OAuth redirect_uri加固", "反斜杠拦截", "相对路径跳转", "CRLF防御", "blue-team"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "open-redirect", "oauth", "url-parsing", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/04-ssrf/open-redirect", "ctf-website/04-ssrf/ssrf-defense", "ctf-website/02-auth/oauth-sso-defense"]
track: "blue"
defends: "ctf-website/04-ssrf/open-redirect"
---
# 开放重定向与 URL 解析差分防御

## 防御目标与威胁面

开放重定向常被低估为单纯钓鱼跳板，但在现代认证与服务端架构中它是高危组合链的枢纽：

1. **URL 解析器差分绕过白名单**：`https://target.com@evil.com`、`https://target.com\@evil.com`、`//evil.com`、`/\evil.com`、`https://evil.com%23.target.com` 或双重解码 `%2f%2fevil.com` 会导致校验层提取出合法域名而浏览器/HTTP 客户端跳转到恶意域。
2. **OAuth 2.0 / OIDC 凭据回收**：若站点内部存在任意开放跳转且 OAuth `redirect_uri` 允许子路径前缀匹配，攻击者即可通过站内跳转将 `code` 或 `token` 外带。
3. **SSRF 跳转跟随链**：外网域名通过 SSRF 首跳检查后返回 `302 Location: http://169.254.169.254/...`，诱使后端 HTTP 客户端进入内网。
4. **非 HTTP Scheme 与 CRLF 注入**：将 `javascript:`、`data:` 写入 `<meta refresh>` 或 JS `location`，或在 `Location` 头中注入 `%0d%0aSet-Cookie:`。

## 核心防御架构

| 风险维度 | 根治控制措施 | 实施要点 |
|---|---|---|
| 站内业务回跳 | 优先采用无参数枚举 ID / 相对路径强制校验 | 仅接受以单 `/` 开头且第二字符非 `/`、`\` 的站内相对路径 |
| 跨域白名单跳转 | 拒绝原始字符串包含控制符、反斜杠、`@` 及多轮编码后差异 | 统一按 WHATWG/RFC 3986 单次解析，严格比对 `(scheme, netloc/hostname, port)` 精确三元组 |
| OAuth `redirect_uri` | 全字符串精确相等匹配，禁用通配符与子路径前缀 | 强制开启 PKCE 与不可预测一次性 `state` |
| DOM / Meta 跳转 | 禁用 `javascript:`/`data:`/`vbscript:`，只允许 `https://` 或同源相对路径 | 响应写入 `Location` 前阻断任何 `\r`/`\n`/`\0` 字符 |

## 加固代码与离线核查示例

以下 Python 严格跳转目标校验器同时覆盖相对路径校验、Parser 差分防线、CRLF 阻断与精确 Origin 白名单比对：

```python
import re
from urllib.parse import urlparse, unquote
from typing import Iterable, Tuple

ALLOWED_ORIGINS = {
    ("https", "app.example.com", 443),
    ("https", "portal.example.com", 443),
}
CONTROL_OR_SLASH_RE = re.compile(r"[\x00-\x1f\x7f\\]")


def validate_redirect_target(
    raw_target: str,
    allowed_origins: Iterable[Tuple[str, str, int]] = ALLOWED_ORIGINS,
    allow_relative: bool = True,
) -> Tuple[bool, str]:
    if not isinstance(raw_target, str) or not raw_target.strip():
        return False, "empty_target"

    # 1. 拒绝控制字符(含 CR/LF/NUL)与反斜杠
    if CONTROL_OR_SLASH_RE.search(raw_target):
        return False, "forbidden_control_or_backslash"

    # 2. 拒绝双重/多重编码引发的前后解析分歧
    once_decoded = unquote(raw_target)
    if CONTROL_OR_SLASH_RE.search(once_decoded) or "%" in once_decoded and unquote(once_decoded) != once_decoded:
        return False, "ambiguous_encoding"

    # 3. 仅允许单斜杠开头的纯站内相对路径
    if raw_target.startswith("/"):
        if allow_relative and not raw_target.startswith("//") and not once_decoded.startswith("//"):
            parsed_rel = urlparse(raw_target)
            if not parsed_rel.scheme and not parsed_rel.netloc:
                return True, raw_target
        return False, "invalid_relative_path"

    # 4. 绝对 URL 严格解析：禁止 userinfo、fragment 混淆与非 HTTPS
    parsed = urlparse(raw_target)
    if parsed.scheme.lower() != "https":
        return False, "scheme_not_https"
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return False, "userinfo_forbidden"
    if not parsed.hostname:
        return False, "missing_host"

    try:
        ascii_host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False, "invalid_idna_host"

    port = parsed.port or 443
    origin = ("https", ascii_host, port)
    if origin not in set(allowed_origins):
        return False, f"origin_not_allowed:{origin}"

    return True, raw_target


if __name__ == "__main__":
    cases = [
        ("/dashboard?tab=1", True),
        ("//evil.example/cb", False),
        ("/\\evil.example/cb", False),
        ("https://app.example.com@evil.example/cb", False),
        ("https://app.example.com.evil.example/cb", False),
        ("https://evil.example%23.app.example.com/cb", False),
        ("https:%5c%5cevil.example", False),
        ("javascript:alert(1)", False),
        ("https://app.example.com/welcome\r\nSet-Cookie: a=1", False),
        ("https://app.example.com/oauth/done", True),
    ]
    for url, expected in cases:
        ok, _ = validate_redirect_target(url)
        assert ok is expected, f"Failed on {url}: got {ok}, expected {expected}"
    print("Open redirect defense self-check passed.")
```

## 防御工作流

```text
1. 参数梳理：清点所有接收 next/redirect/returnUrl/callback/dest 的接口及模板渲染点
2. 语义收敛：站内跳转一律收敛为固定枚举索引或仅支持单斜杠相对路径
3. 解析器统一：白名单校验与实际发出跳转使用完全相同的 URL 解析库与精确 (scheme, host, port) 匹配
4. 边界阻断：在校验最前端拒绝反斜杠、@ userinfo、CR/LF 控制符及跨层多重 URL 编码
5. 下游联动：OAuth 客户端配置精确 redirect_uri；出站 HTTP 客户端默认禁用自动跟随 3xx 重定向
```

## 验证与判定标准

- **解析差分全阻断**：发送 `//attacker.example`、`/\attacker.example`、`https://target@attacker.example`、`https://attacker.example%23.target`、`%2f%2fattacker.example` 及 `javascript:`，服务端均返回 `400` 或回落到默认安全首页，不产生外域 `Location`。
- **CRLF 零注入**：携带 `%0d%0aSet-Cookie:` 的请求被直接拒绝，响应头不出现伪造头字段。
- **OAuth 回调零中转**：使用站内任意路径或参数编码偏移请求 `/authorize` 时被精确比对拦截。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索重定向与 URL 差分防御 | `kb_router` | 搜索 `open redirect`、`URL解析器一致性`、`OAuth redirect` |
| 对照 URL 绕过变体表 | `kb_read_file` | 读取 [open-redirect.md](open-redirect.md) 校验全部绕过向量 |
| 联动 SSRF 与 OAuth 加固 | `kb_catalog` | 协同查阅 `ssrf-defense` 与 `oauth-sso-defense` |
