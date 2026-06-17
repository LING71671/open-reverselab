# JWT 攻击全景

JWT 攻击**不是破解加密算法**，而是利用签名验证、密钥管理、权限判断、Token 存储等环节的设计与实现缺陷。

---

## 结构速览

```
base64url(Header).base64url(Payload).base64url(Signature)
```

```
┌─────────────────────────────────────────────────────────────┐
│ Header                                                      │
│   alg   → 签名算法 (HS256/RS256/ES256/none)                 │
│   typ   → "JWT"                                              │
│   kid   → 密钥标识符，服务端用来找密钥                          │
│   jku   → JWK Set URL，告诉服务端去哪取公钥                    │
│   x5u   → X.509 证书 URL                                     │
├─────────────────────────────────────────────────────────────┤
│ Payload                                                     │
│   sub   → 用户 ID                                            │
│   role / isAdmin / permissions → 自定义权限                   │
│   exp   → 过期时间 (Unix timestamp)                          │
│   nbf   → 生效时间                                           │
│   iss   → 签发者                                              │
│   aud   → 接收者                                              │
│   iat   → 签发时间                                           │
├─────────────────────────────────────────────────────────────┤
│ Signature = HMAC-SHA256(Header.Payload, secret)             │
│   或      = RSA-SHA256(Header.Payload, privateKey)          │
│   JWT 防篡改依赖签名，不提供加密/保密                          │
└─────────────────────────────────────────────────────────────┘
```

## 攻击面地图

```
                          JWT 攻击面
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   [签名绕过]             [密钥攻击]            [逻辑缺陷]
        │                     │                     │
   alg:none              弱密钥爆破            Claim 缺失
   算法混淆               kid 注入              Token 混用
   签名未验证             jku/x5u 滥用         超长有效期
                         CVE/库漏洞           无撤销机制
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                      [Token 窃取]
                         XSS / 日志
                         Referer 泄露
                         明文传输
                         insecure 存储
```

## 攻击手法索引

| 编号 | 文件 | 攻击类型 | 核心原理 |
|------|------|----------|----------|
| 01 | `jwt-alg-none.md` | 无签名绕过 | 修改 `alg` 为 `none`，诱导跳过验证 |
| 02 | `jwt-algorithm-confusion.md` | 算法混淆 | 公钥当 HMAC 密钥用 |
| 03 | `jwt-weak-key-bruteforce.md` | 弱密钥爆破 | 离线字典攻击 HMAC 密钥 |
| 04 | `jwt-kid-injection.md` | kid 注入 | kid→路径穿越/SQLi/命令注入→控制密钥 |
| 05 | `jwt-jku-x5u-abuse.md` | 密钥源劫持 | jku/x5u 指向攻击者控制的 JWKS |
| 06 | `jwt-claim-missing.md` | Claim 缺失 + 混用 | exp/aud/iss 未验证，ID Token 当 Access Token |
| 07 | `jwt-theft-replay.md` | 窃取与重放 | XSS/日志/Referer 泄露 + 无状态无法撤销 |
| 08 | `jwt-cve-library.md` | CVE与依赖库 | 库实现缺陷导致验签绕过 |
| 09 | `jwt-toolchain-defense.md` | 工具链+防御 | 攻击套件、标准流程、防御矩阵 |

## 快速决策树

```
拿到 JWT Token
  │
  ├─ 1. 解码 Header，看 alg 值
  │     ├─ RS256/ES256 → 去找公钥 (/.well-known/jwks.json)
  │     │                   → 尝试 算法混淆 (02)
  │     │                   → 尝试 jku/x5u (05)
  │     ├─ HS256/HS384/HS512 → 尝试 弱密钥爆破 (03)
  │     └─ 直接尝试 alg:none (01)
  │
  ├─ 2. 看 kid/jku/x5u 字段是否存在
  │     ├─ kid → 尝试注入 (04)
  │     └─ jku/x5u → 尝试 hijack (05)
  │
  ├─ 3. 修改 Payload (role/sub/exp)，观察是否仍然接受
  │     ├─ 修改后 200 → 签名未验证，直接伪造
  │     ├─ 过期 Token 仍能用 → Claim 缺失 (06)
  │     └─ ID Token 能调 API → Token 混用 (06)
  │
  ├─ 4. 检查 Token 传输和存储
  │     └─ URL/Cookie/JS 变量/日志 → (07)
  │
  └─ 5. 指纹库版本 → (08)
```

## 前置知识

- JWT 是**签名**（防篡改），不是**加密**（防偷看）
- Header + Payload 是 Base64URL **编码**，不是加密，任何人可解码
- Bearer Token：谁持有谁能用，不验证持有者身份
- 无状态设计：服务端不存 Token 状态，无法主动撤销
