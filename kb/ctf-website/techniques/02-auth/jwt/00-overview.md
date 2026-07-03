---
id: "ctf-website/02-auth/jwt/00-overview"
title: "JWT 攻击全景"
title_en: "JWT Attack Overview"
summary: >
  JWT 攻击全景导航，涵盖签名绕过、密钥攻击、逻辑缺陷和 Token 窃取四大攻击面的结构速览、攻击面地图、手法索引表和快速决策树。帮助渗透测试者快速定位 JWT 实现中的薄弱环节并选择对应攻击手法。
summary_en: >
  A comprehensive JWT attack navigation covering four attack surfaces: signature bypass, key attacks, logic flaws, and token theft. Includes structure overview, attack surface map, technique index, and a quick decision tree for rapidly identifying JWT implementation weaknesses.
board: "ctf-website"
category: "02-auth"
signals: ["JWT", "签名绕过", "算法混淆", "kid注入", "jku", "x5u", "弱密钥", "token窃取"]
mcp_tools: ["run_ctf_tool", "http_probe", "kb_router"]
keywords: ["JWT攻击", "JSON Web Token", "JWT安全", "签名绕过", "算法混淆", "jwt_tool", "jwt攻击面", "Bearer Token"]
difficulty: "intermediate"
tags: ["authentication", "jwt", "token", "web-security", "signature-bypass", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

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

## Token Oracle 与变体矩阵

JWT 分析必须有稳定 oracle：同一个 token 访问同一组端点，观察身份、权限、状态码、响应字段，而不是只看“能不能 200”。

| 变体 | 修改点 | 目标判断 | 命中信号 |
|---|---|---|---|
| Payload 权限 | `role/isAdmin/permissions` | 是否验签 | 修改后仍 200 |
| Subject | `sub/user_id` | 权限是否只信 claim | 登录成其他用户 |
| 过期时间 | `exp` 设过去/未来 | 是否校验 exp | 过期仍可用 |
| Audience | `aud` 改 API/client | 是否校验接收方 | 跨 API 可用 |
| Issuer | `iss` 改 IdP | 是否校验签发方 | 跨环境可用 |
| Algorithm | `alg` 改 none/HS256 | 签名绕过/混淆 | 伪造 token 接受 |
| Key id | `kid` 改路径/SQL/URL | 密钥查找注入 | 错误/外连/签名可控 |
| JWK source | `jku/x5u` 改 URL | 远程 key 信任 | 服务端拉取攻击者 JWKS |

```python
import base64
import json
import requests

def b64url_decode(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

def jwt_parts(token):
    h, p, s = token.split(".")
    return b64url_decode(h), b64url_decode(p), s

def token_oracle(token, endpoints):
    for name, url in endpoints.items():
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=8)
        print(name, r.status_code, r.text[:180])

header, payload, _ = jwt_parts("HEADER.PAYLOAD.SIGNATURE")
print(header)
print(payload)
```

失败样本同样要记录：`invalid signature` 证明验签存在；`jwt audience invalid` 指向 `aud` 校验；`kid not found` 说明服务端使用 `kid` 查 key，可转 `04-kid-injection`。

## 前置知识

- JWT 是**签名**（防篡改），不是**加密**（防偷看）
- Header + Payload 是 Base64URL **编码**，不是加密，任何人可解码
- Bearer Token：谁持有谁能用，不验证持有者身份
- 无状态设计：服务端不存 Token 状态，无法主动撤销

## Claim 语义速查

| Claim | 实战问题 | 常见错法 |
|---|---|---|
| `sub` | 身份主体 | 可预测 ID，被直接当用户主键 |
| `aud` | token 给谁用 | Resource server 不校验 |
| `iss` | 谁签发 | 多 IdP/多环境混用 |
| `exp` | 过期时间 | 不校验或容忍过大 |
| `nbf` | 生效时间 | 未来 token 提前生效 |
| `iat` | 签发时间 | 接受极旧 token |
| `jti` | token 唯一 ID | 不做撤销/重放控制 |
| `azp` | authorized party | OAuth client 混用 |
| `scope` | 权限范围 | API 只看 role 不看 scope |

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| JWT 分析/攻击 | `run_ctf_tool jwt_tool` | 运行 jwt_tool 进行 JWT 签名/载荷分析 |
| Token 验证 | `http_probe` | HTTP GET 探测验证 JWT token 效果 |
| 知识检索 | `kb_router` | 按 JWT 攻击信号搜索知识库 |

## 工作流

捕获原始 Token → 解码 header/claims → 一次验证一个签名或校验假设 → 构造最小变体 → 访问同一权限 oracle → 对比身份/权限/Flag。


## Evidence

- 保存原始 token、header/payload 解码结果、签名算法、`kid/jku/x5u`、关键 claims。
- 对每个变体记录：修改字段、是否重新签名、访问端点、状态码、身份/权限响应、失败错误。
- 保存 JWKS、`.well-known/openid-configuration`、库错误指纹和 token oracle 输出。
- 输出统一放入 `exports/ctf-website/<case>/`，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
