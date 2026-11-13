---
id: "general/signature/05-length-extension-defense"
title: "哈希长度扩展（HLE）防御（HMAC / KMAC / 非对称签名迁移）"
title_en: "Defense Against Hash Length Extension Attacks"
summary: >
  彻底消除 Merkle-Damgard 哈希构造（MD5/SHA-1/SHA-256/SHA-512）用于 H(secret || message) 裸拼接引发的长度扩展攻击：迁移至双层嵌套构造的 HMAC-SHA256、抗扩展的 SHA-3/KMAC 或非对称 Ed25519，并配套输入规范校验与平滑迁移方案。
summary_en: >
  Eliminate Hash Length Extension attacks caused by raw H(secret || message) on Merkle-Damgard hashes: migrate to HMAC-SHA256, sponge-based SHA-3/KMAC, or Ed25519 signatures, with strict input schema enforcement and dual-header transition guidance.
board: "general"
category: "signature"
signals:
  - "HMAC-SHA256"
  - "KMAC"
  - "SHA-3"
  - "Ed25519"
  - "length extension defense"
  - "Merkle-Damgard"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "length extension defense"
  - "HMAC"
  - "SHA3"
  - "KMAC"
  - "Merkle-Damgard"
difficulty: "intermediate"
tags:
  - "signature-defense"
  - "crypto-defense"
  - "HMAC"
  - "hash-hardening"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/signature/05-length-extension"
  - "general/signature/01-algorithm-defense"
track: "blue"
defends: "general/signature/05-length-extension"
---
# 哈希长度扩展（HLE）防御（HMAC / KMAC / 非对称签名迁移）

## 防御目标

根治因错误使用 `MD5(secret || data)`、`SHA1(secret || data)` 或 `SHA256(secret || data)` 作为消息认证码（MAC）而导致的哈希长度扩展攻击，防止攻击者在不知道 `secret` 的前提下向原始消息末尾追加 `&status=paid`、`&admin=1` 等恶意字段并生成有效签名。

## 算法构造与抗扩展能力对照

| 签名构造 | 底层结构 | 是否受 HLE 影响 | 防御处置建议 |
|---|---|---|---|
| `H(secret \|\| msg)`（`H` 为 MD5/SHA1/SHA256/SHA512） | Merkle-Damgard 迭代压缩，输出即内部状态 | **高危（易受 HLE 攻击）** | 立即废弃并迁移至 `HMAC-SHA256` |
| `H(msg \|\| secret)` | 同上，secret 放末尾 | 免疫长度扩展，但受**碰撞攻击**影响（尤其 MD5/SHA1） | 不推荐自造构造，统一迁至标准 HMAC |
| `HMAC-SHA256(secret, msg)` | 外层+内层双哈希 `H((K^opad) \|\| H((K^ipad) \|\| msg))` | **完全免疫 HLE** | 推荐默认标准方案 |
| `KMAC256` / `SHA3-256` | Keccak 海绵（Sponge）结构，输出截断容量位 | **完全免疫 HLE** | 适用于新协议或高性能硬件环境 |
| `Ed25519` / `ECDSA P-256` | 非对称数字签名 | **完全免疫 HLE** | 适用于跨信任域回调、第三方验签 |

## 防御实现与校验示例

### 1. 用 HMAC-SHA256 替换裸前缀拼接并校验非规范字节（Python）

不仅用标准 `HMAC-SHA256` 从密码学结构上免疫 HLE，还禁止业务载荷中出现长度扩展填充常用的 `\x80` / `\x00` 非法控制字符：

```python
import hashlib
import hmac

def legacy_vulnerable_mac(secret: bytes, msg: bytes) -> str:
    # 反例：H(secret || msg) 暴露内部压缩状态
    return hashlib.sha256(secret + msg).hexdigest()

def hardened_hmac_sign(secret: bytes, msg: bytes) -> str:
    if len(secret) < 32:
        raise ValueError("secret_must_be_at_least_32_bytes")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def hardened_hmac_verify(secret: bytes, msg: bytes, sig_hex: str) -> bool:
    # 拒绝包含空字节等异常填充残留的控制载荷
    if b"\x00" in msg:
        return False
    expected = hardened_hmac_sign(secret, msg)
    return hmac.compare_digest(sig_hex.lower(), expected)

if __name__ == "__main__":
    sec = b"S" * 32
    orig = b"order=123&amount=100"
    sig = hardened_hmac_sign(sec, orig)
    assert hardened_hmac_verify(sec, orig, sig) is True
    # 即使在原消息尾部附加标准 MD padding + "&admin=1"，HMAC 也绝不接受
    forged_msg = orig + b"\x80\x00\x00\x00&admin=1"
    assert hardened_hmac_verify(sec, forged_msg, sig) is False
    print("hle_defense_check: PASS")
```

### 2. 存量系统无感迁移方案

若线上仍有历史客户端调用旧签名接口，可采用双版本版本号路由平滑过渡（禁止隐式回退）：
- 在请求头或版本字段显式区分 `v2`（强制 `HMAC-SHA256`），对 `v1` 设定明确下线截止时间；
- 过渡期内为 `v1` 增加严格载荷白名单与禁止控制字节（`\x00`、非打印字符）策略作为临时缓解，同时尽快完成迁移。

## 防御工作流

```text
1. 代码基线排查：检索项目中所有 sha256(/md5(/sha1( 传入 secret + data 或 f"{secret}{body}" 的拼接调用
2. 原语替换：全部替换为标准库 hmac.new(key, msg, hashlib.sha256) 或非对称签名 Ed25519
3. 密钥长度校准：确认 HMAC 密钥长度 >= 32 字节（避免与旧短口令混用）
4. 输入边界拦截：网关层拒绝包含 \x00 等非法二进制填充字节的文本/表单请求
5. 兼容性收尾：下线旧版本裸哈希验签路由，防止攻击者降级回旧端点触发 HLE
```

## 验证与判定标准

- **HLE 向量 100% 拦截**：使用 `hashpumpy` / `hlextend` 对合法样本计算任意长度猜测下的扩展签名与填充消息，服务端均返回 `False`
- **空字节/填充拦截**：携带 `\x80...\x00` Merkle-Damgard 填充字节的表单或 URL 请求直接被网关或验签函数拒收
- **旧逻辑清零**：代码库中不再存在以 `H(secret + msg)` 作为认证签名的调用点

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 算法锁定关联文档 | `kb_router` | 检索算法降级拦截方案确保旧裸哈希端点不可回退 |
| HMAC 迁移测试脚本 | `workspace_write_text` | 编写 `HMAC-SHA256` 迁移验证测试样例 |
| 填充特征检测规则 | `make_sigma_stub` | 生成检测请求中包含 `\x80` + 大量 `\x00` 填充字节的告警规则 |
