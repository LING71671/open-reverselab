---
id: "ctf-website/02-auth/jwt/03-weak-key-bruteforce-defense"
title: "JWT HMAC 弱密钥与泄露防御"
title_en: "JWT Weak HMAC Secret and Exposure Defense"
summary: >
  针对 HS256/HS384/HS512 对称 JWT 密钥因长度不足、可预测语境词（域名/项目名/默认口令）或 .env/Git 历史泄露而遭离线 hashcat/john 爆破并无限伪造的问题，提供密钥熵基线（>= 256-bit CSPRNG）、启动期弱密钥拒绝门禁、跨用途密钥隔离（与 APP_KEY/PAY_KEY 分离）、安全轮换方案及可运行的 Python 强度检查脚本。
summary_en: >
  Defensive guide against offline HS256/HS384/HS512 brute-forcing via hashcat/john or credential leaks. Covers >= 256-bit CSPRNG entropy mandates, startup weak-secret rejection gates, domain/app-key separation, zero-downtime key rotation via kid, and runnable Python entropy checks.
board: "ctf-website"
category: "02-auth"
signals: ["HMAC", "HS256", "弱密钥防御", "密钥熵", "密钥轮换", "SECRET_KEY", "hashcat防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["JWT强密钥", "HMAC密钥规范", "JWT密钥轮换", "防爆破", "CSPRNG", "密钥隔离"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "hmac", "key-management"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/03-weak-key-bruteforce", "ctf-website/02-auth/jwt/00-overview-defense", "ctf-website/24-database/04-config-exposure"]
track: "blue"
defends: "ctf-website/02-auth/jwt/03-weak-key-bruteforce"
---

# JWT HMAC 弱密钥与泄露防御

只要 HS256/HS384/HS512 的签名密钥是**短字符串、常见词、项目/域名派生词或源码默认值**，攻击者仅凭单个已截获 Token 即可完全离线用 GPU（`hashcat -m 16500`）高速破解，期间不产生任何服务端告警。防线的根本在于**高熵随机生成、启动期强校验拒止、密钥用途分离与可灰度轮换**，对外暴露验证能力时优先迁移至非对称算法（RS256/ES256/EdDSA）。

## 风险成因与防御控制

| 风险场景 | 危害机制 | 强制防御控制 |
|---|---|---|
| 短密钥 / 字典词 (`secret`, `changeme`, `jwt_secret`) | 离线每秒数亿次尝试，秒级还原密钥 | 密钥必须由 CSPRNG 生成 >= 32 字节（HS256）、48 字节（HS384）、64 字节（HS512） |
| 语境派生密钥 (`target2026`, `app_secret`) | 定制语境字典可直接命中 | 启动门禁校验香农熵与禁词表，拒绝含项目名/域名/年份/常见口令的字符串 |
| 配置文件与 Git 历史泄露 | `.env`、Compose、镜像层或历史 commit 保留硬编码密钥 | 全密钥走 KMS/Secrets Manager 运行时注入；禁止写入仓库，引入 pre-commit 密钥扫描 |
| 密钥跨模块复用 (`APP_KEY == JWT_SECRET == PAY_KEY`) | 单处泄露或爆破连带攻破 Session 与支付签名 | 强制 HKDF 按用途派生独立子密钥或分别生成独立密钥材料 |
| 多微服务共享对称密钥 | 每个消费服务都持有签名能力，任意节点失陷即可伪造全站 Token | 对外/跨服务认证迁移至 **RS256 / ES256 / EdDSA**：仅认证中心持有私钥，业务服务仅持公钥 |

## 防御工作流

```text
1. 密钥生成与存储升级
   └─ 使用 secrets.token_bytes(32+) 或 KMS 生成随机密钥，注入运行时环境变量，严禁默认 fallback 值
2. 启动期密钥强度门禁（Fail-Closed Startup Gate）
   └─ 应用启动时检查 JWT_SECRET 字节长度、最小信息熵与弱口令黑名单，不达标立即中止启动
3. 用途隔离与对称→非对称迁移
   └─ 将 JWT 密钥与数据库密码、Session Secret、支付签名密钥彻底拆分；微服务架构优先改用 ES256/RS256
4. 基于 kid 的双键平滑轮换
   └─ KeyStore 同时保留 [current_kid, previous_kid]，签发切到新 kid 后等待最大 TTL 过期再下线旧密钥
5. 仓库与制品泄露清理
   └─ 清理 .env/.git 历史残留并立即强制轮换所有历史暴露密钥
```

### Python 启动期 HMAC 密钥门禁与 HKDF 用途隔离

```python
import hashlib
import hmac
import math
import secrets
from collections import Counter

COMMON_WEAK_SECRETS = frozenset({
    "secret", "password", "admin", "key", "private", "changeme",
    "test", "dev", "debug", "jwt_secret", "jwt_key", "jwt-secret",
    "secret_key", "secretkey", "mysecret", "your-256-bit-secret",
    "123456", "qwerty", "letmein", "abcdef",
})


def shannon_entropy_bits(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) * total


def validate_hmac_secret(secret: bytes, min_bytes: int = 32, context_seeds: tuple[str, ...] = ()) -> None:
    """启动门禁：拒绝短密钥、低熵密钥、常见默认词及项目语境派生词。"""
    if len(secret) < min_bytes:
        raise ValueError(f"HMAC secret too short: {len(secret)} < {min_bytes} bytes")
    low = secret.decode("utf-8", errors="ignore").strip().lower()
    if low in COMMON_WEAK_SECRETS:
        raise ValueError("HMAC secret matches known weak default")
    for seed in context_seeds:
        if seed and seed.lower() in low:
            raise ValueError(f"HMAC secret contains predictable context seed: {seed}")
    # 256-bit 随机密钥总熵通常远高于 128 bits
    if shannon_entropy_bits(secret) < 120.0:
        raise ValueError("HMAC secret entropy too low")


def generate_strong_hmac_secret(num_bytes: int = 32) -> bytes:
    """使用操作系统 CSPRNG 生成 >= 256-bit 签名密钥。"""
    if num_bytes < 32:
        raise ValueError("num_bytes must be >= 32")
    return secrets.token_bytes(num_bytes)


def derive_purpose_subkey(master_secret: bytes, purpose: str) -> bytes:
    """使用 RFC 5869 HKDF-SHA256 思想派生用途隔离密钥，防止 JWT 与支付/Session 密钥混用。"""
    prk = hmac.new(b"reverselab-jwt-kdf-salt-v1", master_secret, hashlib.sha256).digest()
    return hmac.new(prk, purpose.encode("utf-8") + b"\x01", hashlib.sha256).digest()
```

## 验证与判定标准

运行以下自检验证 [03-weak-key-bruteforce.md](03-weak-key-bruteforce.md) 中列出的默认弱密钥、语境词变体均被门禁阻断，且随机 256-bit 密钥及子密钥派生符合要求：

```python
def run_weak_key_defense_checks() -> None:
    weak_samples = [
        b"secret",
        b"your-256-bit-secret",
        b"target2026_secret_jwt_padding_len32",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"12345678901234567890123456789012",
    ]
    for sample in weak_samples:
        try:
            validate_hmac_secret(sample, min_bytes=32, context_seeds=("target", "2026"))
        except ValueError:
            pass
        else:
            raise AssertionError(f"weak HMAC secret accepted: {sample!r}")

    strong = generate_strong_hmac_secret(32)
    validate_hmac_secret(strong, min_bytes=32, context_seeds=("target", "2026"))

    jwt_key = derive_purpose_subkey(strong, "jwt-access-v1")
    pay_key = derive_purpose_subkey(strong, "payment-webhook-v1")
    assert len(jwt_key) == 32 and jwt_key != pay_key
    print("PASS: all HMAC weak-key defense checks passed")


if __name__ == "__main__":
    run_weak_key_defense_checks()
```

判定标准：
1. **启动期零弱密钥**：配置空密钥、示例字符串、`length < 32` 或含项目名/年份的密钥时进程拒绝启动。
2. **代码库无硬编码 fallback**：所有 `JWT_SECRET` 读取逻辑缺失环境变量时直接抛出异常，不存在 `os.getenv("JWT_SECRET", "dev-secret")` 兜底。
3. **跨用途密钥独立**：用于 JWT 的密钥哈希与 `APP_KEY`、数据库口令及支付签名密钥完全不同。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `HMAC`、`弱密钥`、`密钥轮换` 检索对应防御条目 |
| 规程读取 | `kb_read_file` | 读取 `03-weak-key-bruteforce-defense` 与配置暴露防御文档 |
| 目录索引核查 | `kb_catalog` | 查看 `02-auth/jwt/` 及 `24-database/` 下的密钥安全文档 |
