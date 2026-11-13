---
id: "general/signature/03-key-attacks-defense"
title: "签名密钥生命周期防御（CSPRNG 强熵 / KMS 托管 / 客户端隔离与轮换）"
title_en: "Defense Against Signature Key Attacks"
summary: >
  防御弱密钥字典、框架默认密钥、前端 JS/Sourcemap/配置泄露、伪随机可预测密钥以及跨环境密钥复用：强制 256-bit CSPRNG 密钥生成、KMS/HSM 密钥托管与零硬编码、环境与用途密钥域隔离以及自动化轮换机制。
summary_en: >
  Defense against weak key dictionaries, framework defaults, frontend/sourcemap/config leaks, predictable PRNG keys, and cross-environment key reuse: 256-bit CSPRNG generation, KMS/HSM secret custody, domain-separated keys, and automated rotation.
board: "general"
category: "signature"
signals:
  - "256-bit CSPRNG key"
  - "KMS custody"
  - "key rotation"
  - "domain separation"
  - "zero hardcoded secrets"
  - "sourcemap removal"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "extract_iocs_from_summary"
keywords:
  - "key management"
  - "CSPRNG"
  - "KMS"
  - "key rotation"
  - "secret scanning"
  - "domain separation"
difficulty: "intermediate"
tags:
  - "signature-defense"
  - "key-management"
  - "KMS"
  - "secret-hygiene"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/signature/03-key-attacks"
  - "general/signature/00-overview-defense"
track: "blue"
defends: "general/signature/03-key-attacks"
---
# 签名密钥生命周期防御（CSPRNG 强熵 / KMS 托管 / 客户端隔离与轮换）

## 防御目标

彻底消除 HMAC/JWT/API 签名密钥因弱字典、框架默认值（`secret`、`changeme`、`your-256-bit-secret`）、可预测伪随机数（`time()` 种子）、前端打包产物或配置文件泄露以及多环境复用而被破解或提取的风险。

## 密钥全生命周期防御矩阵

| 威胁类型 | 常见失陷原因 | 防御控制标准 | 验证指标 |
|---|---|---|---|
| 弱密钥 / 框架默认密钥 | 未覆盖模板默认 `SECRET_KEY` / `APP_KEY` 或使用短口令 | 强制 >= 32 字节（256 bit）密码学安全随机密钥（`secrets.token_bytes(32)`） | 启动自检拒绝长度 < 32 字节或熵值过低的密钥 |
| 可预测密钥生成 | 使用 `random.seed(timestamp)`、PID 或顺序 UUID 生成密钥 | 仅允许 OS CSPRNG（`/dev/urandom`、`secrets`、`crypto.randomBytes`）或 KMS 产生主密钥 | 连续生成样本通过熵与不可预测性检查 |
| 源码与前端泄露 | 密钥硬编码在代码、`.env` 被公网访问、JS sourcemap 暴露 | 密钥由运行时环境变量/KMS 注入；客户端严禁持有服务端验签/签发对称密钥 | 构建产物与静态目录无密钥或 `.map` / `.env` 暴露 |
| 跨环境 / 跨服务复用 | 测试环境与生产环境共用密钥，或 JWT 与 Webhook 共用密钥 | 按环境（dev/prod）与用途（HKDF 域分离 `info="jwt-v1"` vs `"webhook-v1"`）派生独立子密钥 | 任一服务密钥轮换不影响其他业务域 |
| 长期未轮换 | 单一密钥多年不变 | 支持多 `kid` 平滑轮换与 TTL 过期机制（如 90 天自动切换主签发 `kid`） | 新 `kid` 签发即时生效，旧 `kid` 按窗口平滑下线 |

## 防御实现与校验示例

### 1. 强熵密钥校验与 HKDF 域分离派生（Python）

应用启动时自检密钥长度与熵质量，防止空值、默认值或低熵密钥上线，并使用域分离派生子密钥：

```python
import hmac
import hashlib
import secrets
from collections import Counter
import math

WEAK_PLACEHOLDERS = {
    b"secret", b"changeme", b"your-256-bit-secret", b"default", b"123456", b"test"
}

def shannon_entropy(data: bytes) -> float:
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) if total else 0.0

def validate_master_key(key: bytes) -> tuple[bool, str]:
    if len(key) < 32:
        return False, "key_too_short(<32B)"
    if key.lower() in WEAK_PLACEHOLDERS or len(set(key)) < 12:
        return False, "weak_or_repetitive_key"
    if shannon_entropy(key) < 3.5:
        return False, "low_entropy_key"
    return True, "ok"

def derive_scoped_key(master_key: bytes, env: str, purpose: str, key_id: str) -> bytes:
    info = f"reverselab|{env}|{purpose}|{key_id}".encode("utf-8")
    return hmac.new(master_key, info, hashlib.sha256).digest()

if __name__ == "__main__":
    assert validate_master_key(b"your-256-bit-secret")[0] is False
    assert validate_master_key(b"A" * 32)[0] is False
    master = secrets.token_bytes(32)
    assert validate_master_key(master)[0] is True
    k_jwt = derive_scoped_key(master, "prod", "jwt", "k2026-11")
    k_pay = derive_scoped_key(master, "prod", "payment-webhook", "k2026-11")
    assert k_jwt != k_pay and len(k_jwt) == 32
    print("key_defense_check: PASS")
```

## 防御工作流

```text
1. 密钥强检门禁：在应用启动钩子中调用 validate_master_key()，密钥不足 32 字节或低熵则拒绝启动
2. 托管与注入：通过 KMS / Vault / Secrets Manager 在运行时注入密钥，禁止写入 git 仓库与镜像层
3. 域分离派生：使用 HKDF/HMAC 按环境与用途派生子密钥，杜绝跨功能共用密钥
4. 构建与公网收敛：生产环境关闭 debug 错误回显，Nginx/CDN 拦截 .env/.git/*.map 等敏感路径
5. 轮换演练：维护双活 kid 列表，定期生成新版本密钥并回收过期 kid
```

## 验证与判定标准

- **弱密钥拒绝启动**：注入低于 32 字节或重复字符密钥时，服务启动自检返回非零状态阻止带病上线
- **域隔离有效**：相同主密钥下 `jwt` 与 `payment-webhook` 派生密钥互不相等，跨接口提交签名 100% 失败
- **静态产线清洁**：仓库提交前扫描及生产 Web 根目录检查均无明文私钥、`.env` 或 `.js.map` 暴露

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 密钥防御知识关联 | `kb_router` | 检索算法锁定与重放防御方案 |
| 密钥强检脚本落盘 | `workspace_write_text` | 将启动密钥自检与轮换脚本保存到项目工具链 |
| 静态反编译密钥残留核查 | `extract_iocs_from_summary` | 检查客户端编译产物中是否意外残留硬编码密钥串 |
