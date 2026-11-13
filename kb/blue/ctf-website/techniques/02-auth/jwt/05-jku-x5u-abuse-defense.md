---
id: "ctf-website/02-auth/jwt/05-jku-x5u-abuse-defense"
title: "JWT jku / x5u / x5c 密钥源劫持防御"
title_en: "JWT jku, x5u, and x5c Key Source Hijacking Defense"
summary: >
  针对 JWT Header 中 jku、x5u、jwk、x5c 字段引起的公钥源劫持、URL 白名单解析绕过（后缀伪造、userinfo @、fragment #、开放重定向、scheme 降级）、DNS Rebinding 及 SSRF 链，提供完全屏蔽 Header 动态 URL 拉取、固定服务端 jwks_uri、HTTPS 与出站 IP 防护（禁止内网 CIDR 与 3xx 重定向跟随）及内联 JWK/证书链禁令方案，并附可运行的 Python 验证代码。
summary_en: >
  Defensive guide against JWT jku/x5u/jwk/x5c key source hijacking and URL parser bypasses (suffix spoofing, userinfo, fragment, open redirect, scheme downgrade, DNS rebinding, and SSRF). Enforces ignoring header key URLs in favor of static server-configured jwks_uri, strict SSRF/redirect blocking, and runnable Python checks.
board: "ctf-website"
category: "02-auth"
signals: ["jku", "x5u", "x5c", "jwk", "JWKS", "SSRF防御", "DNS Rebinding", "密钥源劫持防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["jku防御", "x5u防御", "JWKS白名单", "JWT密钥源防护", "DNS重绑定防御", "禁跟随重定向"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "ssrf", "jwks"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/05-jku-x5u-abuse", "ctf-website/02-auth/jwt/02-algorithm-confusion-defense", "ctf-website/04-ssrf/ssrf"]
track: "blue"
defends: "ctf-website/02-auth/jwt/05-jku-x5u-abuse"
---

# JWT `jku` / `x5u` / `x5c` 密钥源劫持防御

`jku`、`x5u`、`jwk` 与 `x5c` 在设计上允许 Token 自身携带“去哪里或用什么公钥验证我”，这违背了**信任根必须独立于待验证输入**的基本安全原则。在几乎所有生产业务中，验证方已经知道可信 IdP 是谁——完全不需要、也不应该由客户端 Token 指定公钥下载 URL 或内联公钥材料。

## 绕过手法与防御控制映射

| 攻击向量 | 漏洞根因 | 强制防御控制 |
|---|---|---|
| 任意 `jku` / `x5u` URL 拉取 | 服务端无条件 `requests.get(header["jku"])` | **默认彻底禁用 `jku`/`x5u`/`jwk`/`x5c`**：验证方只从本地静态配置的 `TRUSTED_JWKS_URL` 拉取并缓存公钥 |
| 后缀 / 子串白名单绕过 (`trusted.com.evil.com`) | 使用 `in` 或 `endswith` 校验 URL 字符串 | 必须解析 URL 后核对完整精确 `hostname`（且只允许预配置的完整 origin + path，而非仅匹配域名） |
| UserInfo (`@`) / Fragment (`#`) 解析差异 | 正则与 HTTP 客户端对 `https://trusted.com@evil.com` 或 `#@evil.com` 解释不一致 | 显式拒绝含 `username`、`password`、`fragment`、非标准端口、非 `https` 协议及非 `file://` 等非法 scheme 的 URL |
| 开放重定向 (`trusted.com/redirect?u=...`) | HTTP 客户端默认 `allow_redirects=True`，借可信域 302 跳到攻击者 JWKS | 拉取 JWKS 时强制 `allow_redirects=False`（拒收任何 3xx 跳转） |
| DNS Rebinding & SSRF (`127.0.0.1` / metadata) | 校验域名后未校验解析出的真实 IP，或再次解析时切到内网地址 | DNS 一次解析后校验 IP 不属于私网/回环/链路本地/保留段，并直接连接该已校验 IP 配合 SNI/Host 校验 |
| `x5u` / `x5c` 任意自签名证书 | 只从证书提取公钥而不校验证书链是否由受信任根 CA 签发 | 禁用 `x5u`/`x5c`；若联邦场景必须支持，需完成完整 X.509 证书链、有效期及固定 Root CA 指纹钉扎验证 |

## 防御工作流

```text
1. Header 密钥源头字段拦截
   └─ 解析 Header 后若出现 jwk / x5c / jku / x5u（在非静态白名单场景），直接拒绝 Token
2. 服务端静态 JWKS 绑定（首选架构）
   └─ 仅通过环境变量或 OIDC Discovery 离线锁定 TRUSTED_JWKS_URI，验证只按白名单 kid 从本地缓存取键
3. 多联邦域名场景严格 URL + IP 防护（次选架构）
   └─ 仅允许精确 (scheme="https", hostname, port=443, path) 四元组 -> 禁止 userinfo/fragment -> 禁止 3xx 跳转 -> 阻断私网/回环 IP
4. 缓存隔离与签名算法锁定
   └─ JWKS 按 kid 缓存在服务端并设置合理刷新间隔，禁止用拉取结果覆盖服务端预期 alg
5. 出站网络策略兜底
   └─ 应用容器 egress 防火墙限制仅允许访问已登记 IdP 域名/IP，阻断对内网与云元数据地址（169.254.169.254）的出站访问
```

### Python 严格 JWKS URL 防劫持校验器

```python
import ipaddress
import socket
from urllib.parse import urlsplit

# 显式登记可信 JWKS 精确端点（不仅限域名，而是精确 origin + path）
ALLOWED_JWKS_ENDPOINTS = {
    ("auth.example.com", "/.well-known/jwks.json"),
    ("idp.partner.example", "/oauth2/v3/certs"),
}


class UntrustedKeySourceError(Exception):
    """拒绝不可信密钥源 URL、内联密钥或 SSRF 风险地址。"""


def reject_inline_or_untrusted_key_headers(header: dict) -> None:
    """默认安全基线：拒绝一切在 Token Header 中携带公钥或远程密钥源的尝试。"""
    for field in ("jwk", "x5c", "jku", "x5u"):
        if field in header:
            raise UntrustedKeySourceError(f"forbidden header key source: {field}")


def validate_jwks_url_strict(raw_url: str, resolve_dns: bool = False) -> str:
    """若业务必须校验多联邦 jku，强制精确端点白名单与反 SSRF/反解析混淆。"""
    if not isinstance(raw_url, str) or not raw_url:
        raise UntrustedKeySourceError("empty key url")
    if any(ch in raw_url for ch in ("\\", "\r", "\n", " ")):
        raise UntrustedKeySourceError("illegal whitespace or backslash")

    parts = urlsplit(raw_url)
    if parts.scheme != "https":
        raise UntrustedKeySourceError("only https scheme allowed")
    if parts.username is not None or parts.password is not None:
        raise UntrustedKeySourceError("userinfo (@) disallowed in key url")
    if parts.fragment:
        raise UntrustedKeySourceError("fragment (#) disallowed in key url")
    if parts.port not in (None, 443):
        raise UntrustedKeySourceError("non-standard port disallowed")

    host = (parts.hostname or "").lower()
    if (host, parts.path) not in ALLOWED_JWKS_ENDPOINTS:
        raise UntrustedKeySourceError(f"endpoint not in exact allowlist: {(host, parts.path)}")
    if parts.query:
        raise UntrustedKeySourceError("query string disallowed on JWKS endpoint")

    if resolve_dns:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise UntrustedKeySourceError(f"resolved to non-public IP: {ip}")
    return raw_url
```

## 验证与判定标准

运行下方脚本验证 [05-jku-x5u-abuse.md](../../../../../red/ctf-website/techniques/02-auth/jwt/05-jku-x5u-abuse.md) 中的全部 URL 解析混淆、协议降级、`file://` 本地读取及内联 `jwk`/`x5c` 均被阻断：

```python
def run_jku_x5u_defense_checks() -> None:
    for field in ("jku", "x5u", "jwk", "x5c"):
        try:
            reject_inline_or_untrusted_key_headers({"alg": "RS256", field: "https://evil.example/k"})
        except UntrustedKeySourceError:
            pass
        else:
            raise AssertionError(f"header field {field} was not blocked")

    bypass_urls = [
        "https://auth.example.com.attacker.com/.well-known/jwks.json",
        "https://auth.example.com@attacker.com/.well-known/jwks.json",
        "https://auth.example.com%40attacker.com/.well-known/jwks.json",
        "https://attacker.com/#auth.example.com/.well-known/jwks.json",
        "https://auth.example.com/.well-known/jwks.json#@attacker.com",
        "https://auth.example.com/redirect?url=https://attacker.com/jwks.json",
        "http://auth.example.com/.well-known/jwks.json",
        "http://127.0.0.1:8080/.well-known/jwks.json",
        "file:///etc/ssl/certs/jwt-public.pem",
        "https://auth.example.com:8443/.well-known/jwks.json",
    ]
    for bad in bypass_urls:
        try:
            validate_jwks_url_strict(bad, resolve_dns=False)
        except UntrustedKeySourceError:
            pass
        else:
            raise AssertionError(f"URL bypass accepted: {bad}")

    assert validate_jwks_url_strict("https://auth.example.com/.well-known/jwks.json") == "https://auth.example.com/.well-known/jwks.json"
    print("PASS: all jku/x5u key source defense checks passed")


if __name__ == "__main__":
    run_jku_x5u_defense_checks()
```

判定标准：
1. **零外部回连**：将 Token Header 中 `jku`/`x5u` 改为受控监听地址后，目标服务端零 DNS 查询与零 HTTP 出站请求。
2. **解析混淆全拦截**：含 `@`、`#`、开放重定向路径、`http://`、`file://` 及非标准端口 URL 在静态校验阶段全部拒绝。
3. **无内联公钥信任**：携带 `jwk` 或自签 `x5c` 的 Token 一律返回 `401`。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `jku`、`x5u`、`JWKS`、`SSRF` 搜索相关防御条目 |
| 规程读取 | `kb_read_file` | 读取 `05-jku-x5u-abuse-defense` 与 `04-ssrf/ssrf` |
| 目录索引核查 | `kb_catalog` | 核对 `02-auth/jwt/` 及 `04-ssrf/` 关联防御文档 |
