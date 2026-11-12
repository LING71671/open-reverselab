---
id: "ctf-website/02-auth/host-header-defense"
title: "Host Header 注入与路由越权防御"
title_en: "Host Header Injection and Virtual Host Bypass Defense"
summary: >
  针对 Host 头注入引起的密码重置链接劫持、X-Forwarded-Host 等覆写头优先级混淆、Host-to-SSRF 内网服务探测、基于 Host 的管理后台鉴权绕过以及 Cache Poisoning 缓存投毒链，提供 Nginx/反向代理层严格 server_name 白名单、Trusted Proxy 剥离策略、应用层静态 canonical origin 配置与缓存键隔离方案，并附可运行的 Python 加固自检脚本。
summary_en: >
  Defensive guide against Host header injection covering password reset link hijacking, override header precedence abuse (X-Forwarded-Host, X-Original-Host, Forwarded), Host-to-SSRF chaining, virtual-host authentication bypass, and cache poisoning. Provides reverse-proxy strict allowlisting, trusted-proxy header stripping, static canonical origin configuration, and runnable Python verification checks.
board: "ctf-website"
category: "02-auth"
signals: ["Host header", "X-Forwarded-Host", "X-Original-Host", "Forwarded", "密码重置劫持", "vhost绕过", "Cache Poisoning", "Canonical Origin"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Host头防御", "Host header defense", "X-Forwarded-Host加固", "密码重置链接固定域名", "vhost隔离", "缓存投毒防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "host-header", "reverse-proxy", "cache-poisoning"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/host-header", "ctf-website/02-auth/oauth-sso-defense", "ctf-website/04-ssrf/ssrf", "ctf-website/08-infra/web-cache-deception"]
track: "blue"
defends: "ctf-website/02-auth/host-header"
---

# Host Header 注入与路由越权防御

Host 头注入的本质是**边缘代理、CDN 与应用框架对请求主机名的信任边界不一致**，以及业务代码将不可信请求头直接拼入绝对 URL、服务间调用地址或缓存键。完整防线必须同时覆盖网关层白名单、覆写头剥离、应用静态基准域名与缓存键隔离。

## 威胁面与防御映射

| 攻击向量 | 根因机制 | 防御控制点 |
|---|---|---|
| 密码重置 / 邮箱验证链接劫持 | 后端用 `Host` 或 `X-Forwarded-Host` 拼接 reset/verify URL | 强制从服务端配置读取 `CANONICAL_ORIGIN`，禁止动态取请求头 |
| Override Header 优先级绕过 | `X-Forwarded-Host`、`X-Host`、`X-Original-Host`、`X-Forwarded-Server`、`X-HTTP-Host-Override`、`Forwarded` 被框架优先采信 | 边缘网关无条件清除客户端传入的覆写头；仅对可信代理 CIDR 显式开启 |
| `Host` 语法混淆（端口/`@`/`#`/双编码） | URL 解析器与字符串白名单对 `target.com@evil.com`、`target.com:1337`、`127.0.0.1` 解析不一致 | 使用严格 `^[a-z0-9.-]+$` + 精确集合匹配，并在首跳 Nginx default_server 直接 `444/400` 拒绝 |
| Host → SSRF 内网探测 | 服务间调用使用 `http://{Host}/internal/health` | 内部调用地址必须走服务注册表或静态环境变量，严禁引入请求 `Host` |
| Host 鉴权绕过 / Debug 触发 | 以 `Host == admin.internal` 或 `localhost` 跳过认证或开启调试模式 | 鉴权与调试开关绑定内部网络隔离与独立凭据，不得依赖 HTTP `Host` |
| Host → Cache Poisoning | CDN/Varnish 缓存未将 `Host` 或覆写头纳入 Cache Key，却在 `Location`、`<link rel="canonical">`、OpenGraph 中回显 | 剥离未授权覆写头；规范化并固定跳转与页面内的绝对域名 |

## 防御工作流

```text
1. 边界入口拦截（Nginx/Envoy/ALB）
   └─ 配置 catch-all default_server 返回 400/444，只放行精确 server_name
2. 覆写头清洗（Trusted Proxy Policy）
   └─ 在边界删除客户端自带的 X-Forwarded-Host / X-Host / X-Original-Host / Forwarded
3. 应用框架加固（Django/Express/Spring/Flask）
   └─ 启用 ALLOWED_HOSTS / trust proxy 白名单，禁用绝对 URL 动态推导
4. 业务 URL 生成隔离
   └─ 密码重置、OAuth redirect_uri、支付 notify_url、Sitemap 统一使用静态 CANONICAL_ORIGIN
5. 缓存与内网调用隔离
   └─ 响应中不反射未校验 Host；内部微服务调用使用固定 Service Discovery 端点
```

### 1. Nginx 边界拦截与覆写头清洗

```nginx
# 默认兜底虚拟主机：拦截所有未知 Host（含 IP 直连、@/# 混淆、内网主机名）
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_certificate     /etc/nginx/ssl/fallback.crt;
    ssl_certificate_key /etc/nginx/ssl/fallback.key;
    return 444;
}

# 生产业务虚拟主机
server {
    listen 443 ssl;
    server_name app.example.com;

    location / {
        # 强制使用静态配置的主机名，防止后端框架读取伪造覆写头
        proxy_set_header Host app.example.com;
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Host "";
        proxy_set_header X-Original-Host "";
        proxy_set_header X-Forwarded-Server "";
        proxy_set_header X-HTTP-Host-Override "";
        proxy_set_header Forwarded "";
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### 2. Python 应用层 Host 校验与静态绝对 URL 生成

```python
import re
from urllib.parse import urlsplit

ALLOWED_HOSTS = frozenset({"app.example.com", "api.example.com"})
CANONICAL_ORIGIN = "https://app.example.com"
HOST_TOKEN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def validate_host_header(raw_host: str, allowed_ports: frozenset[str] = frozenset({"443"})) -> str:
    """严格校验 Host 头，拒绝非授权端口、userinfo(@)、fragment(#) 与未知域名。"""
    if not raw_host:
        raise ValueError("missing host header")
    candidate = raw_host.strip().lower()
    if any(ch in candidate for ch in ("@", "#", "/", "\\", "%", " ")):
        raise ValueError("illegal character in host header")
    if ":" in candidate:
        hostname, port = candidate.split(":", 1)
        if port not in allowed_ports:
            raise ValueError(f"disallowed port in host header: {port}")
    else:
        hostname = candidate
    if not HOST_TOKEN_RE.fullmatch(hostname):
        raise ValueError("malformed hostname")
    if hostname not in ALLOWED_HOSTS:
        raise ValueError(f"untrusted host: {hostname}")
    return hostname


def build_password_reset_url(token: str) -> str:
    """密码重置/邮箱验证链接严禁使用请求 Host，必须绑定静态 CANONICAL_ORIGIN。"""
    origin = urlsplit(CANONICAL_ORIGIN)
    if origin.scheme != "https" or origin.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("invalid canonical origin configuration")
    return f"{CANONICAL_ORIGIN}/reset?token={token}"
```

## 验证与判定标准

运行下方自检脚本验证 Host 校验器对 [host-header.md](host-header.md) 中列举的全部绕过变体均返回拒绝，且密码重置链接始终指向固定可信域：

```python
def run_host_hardening_checks() -> None:
    malicious_hosts = [
        "attacker.com",
        "app.example.com:1337",
        "app.example.com@attacker.com",
        "attacker.com#app.example.com",
        "attacker.com%23app.example.com",
        "attacker.com%2fapp.example.com",
        "app.example.com.evil.com",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "169.254.169.254",
    ]
    for bad in malicious_hosts:
        try:
            # 含端口或非法域名均应被严格拦截
            host_only = validate_host_header(bad)
            if ":" in bad:
                raise AssertionError(f"port variant bypassed check: {bad}")
            if host_only not in ALLOWED_HOSTS:
                raise AssertionError(f"untrusted host accepted: {bad}")
        except ValueError:
            pass
        else:
            raise AssertionError(f"malicious host not rejected: {bad}")

    assert validate_host_header("app.example.com") == "app.example.com"
    reset_url = build_password_reset_url("tok-123")
    assert reset_url == "https://app.example.com/reset?token=tok-123"
    print("PASS: all host-header hardening checks passed")


if __name__ == "__main__":
    run_host_hardening_checks()
```

判定标准：
1. **边缘拒止率 100%**：向业务端口发送任意未知 `Host` 或携带 `X-Forwarded-Host`/`X-Original-Host`/`Forwarded` 时，响应 `Location`、正文 URL 与邮件模板均不包含外部主机名。
2. **端口与解析器一致性**：带 `@`、`#`、`%2f`、`[::1]` 与非授权端口的 `Host` 头全部返回 `400`/`444`。
3. **无内部端点映射**：修改 `Host` 为 `127.0.0.1` 或 `169.254.169.254` 不触发差异状态码、耗时变化或调试栈回显。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `Host header`、`X-Forwarded-Host`、`Cache Poisoning` 检索对应防御条目 |
| 规程读取 | `kb_read_file` | 读取 `host-header-defense` 与关联 SSRF/缓存文档 |
| 知识目录核对 | `kb_catalog` | 列出 `02-auth` 与 `08-infra` 下的配对防御文档 |
