---
id: "pe-reverse/10-license-keygen/03-key-algorithm-recovery-defense"
title: "注册码算法加固与防 Keygen 密码学设计"
title_en: "License Key Algorithm Hardening and Anti-Keygen Cryptography"
summary: >
  针对攻击者从反编译代码还原位域布局、截断 CRC、XOR+移位混淆、自定义哈希链与 5-bit 字符集编码
  从而编写 Python 注册机（keygen）的威胁，提供基于 Ed25519 全载荷签名、域分离规范化编码及
  禁止客户端持有秘密常量的防 Keygen 密码学工程标准。
summary_en: >
  Defense against license key algorithm recovery and keygen replication targeting bit-field layouts,
  truncated CRCs, XOR+shift obfuscation, custom hash chains, and partial-slice checks. Enforces
  Ed25519 full-payload asymmetric signatures, canonical domain separation, and elimination of
  client-side signing secrets.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "anti-keygen"
  - "Ed25519"
  - "CRC 截断脆弱性"
  - "全载荷覆盖"
  - "域分离"
  - "规范化编码"
  - "防注册机"
mcp_tools:
  - ghidra_summary_function_detail
  - rizin_strings
  - rizin_xrefs
  - triage_pe
  - kb_router
keywords:
  - "anti-keygen"
  - "Ed25519 license"
  - "full payload coverage"
  - "canonical encoding"
  - "CRC vulnerability"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "anti-keygen"
  - "Ed25519"
  - "cryptography"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
---
# 注册码算法加固与防 Keygen 密码学设计

## 防御目标与威胁面

在 [03-key-algorithm-recovery.md](03-key-algorithm-recovery.md) 中，攻击者只需从反编译代码中识别以下五类弱构件，就能在数小时内写出完整的 Python 注册机（keygen）：

1. **线性位域与 XOR/移位混淆**：`((A << 7) ^ A)` 与 `val ^ magic` 属于可逆算术变换，没有任何保密性。
2. **截断 CRC / 自定义哈希链**：25~31 bit CRC 校验或客户端自带的 `h1|h2|h3` 伪签名算法完全暴露在二进制中，攻击者直接照抄公式即可为任意用户名/邮箱生成匹配校验串。
3. **局部切片验证**：仅对 192 字符中的某 19 字符做检查，其余字符成为自由熵，极大降低构造门槛。
4. **共享对称秘密**：校验函数与生成函数对称，一旦客户端可执行验证逻辑，便等价于泄露了生成逻辑。

**核心防御原则**：校验端与签发端必须在密码学上**非对称**——客户端只包含验签公钥与规范化解析器，绝对不能包含可推导合法注册码的算法或私钥。

## 核心防御架构

| 弱算法构件 | 根治替代方案 | 关键实现约束 |
|---|---|---|
| `CRC-32 & 0x1FFFFFF` / 自定义哈希链 | 使用 **Ed25519**（64B 签名，Base32/Base64 编码后约 103 字符）或 **ECDSA P-256** | 私钥严格保存在服务端 HSM/KMS；客户端仅做非对称公钥验签 |
| 局部字符切片验证 | **100% 全字节载荷覆盖**，签名必须覆盖 `(version || product_id || customer || edition || exp || nonce)` 全部字段 | 拒绝任何未参与签名计算的“填充字符”或“自由熵切片” |
| 宽松 `normalize()` 容忍任意置换与分隔符 | 严格规范化解析与**域分离前缀**（如 `b"APP-LIC-V2:" + canonical_payload`） | 解析器严格检查长度、字符集（如 Crockford Base32 无歧义字符）、版本与结构，防止延展性或切片绕过 |
| 位域硬编码常量依赖系统本地时间 | 到期时间与策略写入签名载荷内部，在线模式协同服务端时间校准 | 防止本地时间回拨或直接篡改无签名的期限字段 |

## 加固实现与验证代码

以下 Python 参考实现演示标准的防 Keygen 授权码体系（**结构化载荷 + 域分离 + 100% Ed25519 覆盖验签**），并内置篡改载荷、局部修改自由位、域前缀伪造等自检断言（可直接使用标准 `cryptography` 库运行，若无第三方库时亦清晰展示规范化签名结构；此处提供基于标准库 `hashlib`/`hmac` 的结构化验证骨架与 `cryptography` Ed25519 完整生产验签双支持）：

```python
"""anti_keygen_license.py: 抗 Keygen 的全载荷非对称签名授权生成与严格验签"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # 无第三方 cryptography 库时的离线自检兼容桩（生产环境必须使用真实 Ed25519）
    class InvalidSignature(Exception):
        pass

    class Ed25519PublicKey:
        def __init__(self, key_bytes: bytes):
            self._k = key_bytes

        def verify(self, sig: bytes, data: bytes) -> None:
            if not hmac.compare_digest(sig, hmac.new(self._k, data, hashlib.sha256).digest() * 2):
                raise InvalidSignature()

    class Ed25519PrivateKey:
        def __init__(self, key_bytes: bytes):
            self._k = key_bytes

        @classmethod
        def generate(cls) -> "Ed25519PrivateKey":
            return cls(os.urandom(32))

        def public_key(self) -> Ed25519PublicKey:
            return Ed25519PublicKey(self._k)

        def sign(self, data: bytes) -> bytes:
            return hmac.new(self._k, data, hashlib.sha256).digest() * 2

DOMAIN_SEP = b"RELAB-LICENSE-V2\x00"


def encode_canonical_payload(user: str, edition: str, expires_at: int, key_id: int) -> bytes:
    """规范化序列化所有业务字段，确保零未覆盖自由位。"""
    obj = {
        "v": 2,
        "kid": key_id,
        "user": user.strip(),
        "edition": edition,
        "exp": int(expires_at),
    }
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")


def issue_license(priv: Ed25519PrivateKey, user: str, edition: str, expires_at: int, key_id: int = 1) -> str:
    payload = encode_canonical_payload(user, edition, expires_at, key_id)
    sig = priv.sign(DOMAIN_SEP + payload)
    blob = struct.pack(">H", len(payload)) + payload + sig
    return base64.b32encode(blob).decode("ascii").rstrip("=")


def verify_license(pub: Ed25519PublicKey, token: str, now_ts: int | None = None) -> Tuple[bool, dict | str]:
    if not isinstance(token, str) or not token.isascii():
        return False, "invalid_format"
    # 严格规范化 Base32 字符检查，拒绝任意分隔符或非标准替换
    padded = token + "=" * ((8 - len(token) % 8) % 8)
    try:
        blob = base64.b32decode(padded, casefold=False)
    except Exception:
        return False, "invalid_base32"

    if len(blob) < 2 + 64:
        return False, "truncated_token"
    payload_len = struct.unpack_from(">H", blob, 0)[0]
    if len(blob) != 2 + payload_len + 64:
        return False, "trailing_or_malformed_bytes"

    payload = blob[2:2 + payload_len]
    sig = blob[2 + payload_len:]
    try:
        pub.verify(sig, DOMAIN_SEP + payload)
    except InvalidSignature:
        return False, "bad_signature"

    claims = json.loads(payload.decode("utf-8"))
    ts = int(time.time()) if now_ts is None else now_ts
    if claims.get("v") != 2 or claims.get("exp", 0) < ts:
        return False, "expired_or_bad_version"
    return True, claims


if __name__ == "__main__":
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    lic = issue_license(sk, "alice@example.com", "pro", expires_at=2000000000)
    ok, info = verify_license(pk, lic, now_ts=1700000000)
    assert ok and info["edition"] == "pro"

    # 1. 篡改任意字符（无自由熵位可利用）
    tampered = ("A" if lic[0] != "A" else "B") + lic[1:]
    assert verify_license(pk, tampered, now_ts=1700000000)[0] is False

    # 2. 追加冗余后缀字节（防御尾部未校验空间）
    assert verify_license(pk, lic + "AA", now_ts=1700000000)[0] is False

    # 3. 攻击者使用自建密钥对签发（公钥未替换时必失败）
    attacker_sk = Ed25519PrivateKey.generate()
    forged = issue_license(attacker_sk, "alice@example.com", "pro", expires_at=2000000000)
    assert verify_license(pk, forged, now_ts=1700000000)[0] is False
    print("Anti-keygen Ed25519 license self-check passed.")
```

## 防御工作流

```text
1. 移除弱校验构件：全面清退客户端中的 CRC 截断、XOR/移位混淆校验、自定义哈希拼接与局部切片逻辑
2. 引入标准非对称算法：采用 Ed25519（或 ECDSA-P256）作为唯一离线授权验签算法，私钥仅留存服务端签名机
3. 强制全载荷规范化：通过长度前缀 + 规范 JSON/Protobuf + 域分离前缀签名，消除任意可被利用的自由比特位
4. 严格边界解析：拒绝尾随冗余字符、大小写混用或非白名单格式变形
5. 结合信任锚保护：将客户端公钥嵌入与 Authenticode/节区完整性防护绑定（防公钥替换接管）
```

## 验证与判定标准

- **无对称逆向路径**：反编译客户端二进制仅能看到公钥字节与标准 `Ed25519 Verify`（如 `BCryptVerifySignature` / `libsodium` / `openssl`）调用，不存在任何可用于推算合法注册码的秘密常量或哈希公式。
- **全比特雪崩测试**：对合法注册码任意位置修改 1 个字符或追加 1 字节填充，`verify_license` 必须 100% 返回 `False`。
- **离线自签拒绝**：未对二进制公钥区进行非法修改前，外部私钥生成的同格式授权码必须被验签拒绝。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查校验函数是否仍含自定义位运算/CRC 常量 | `ghidra_summary_function_detail` | 验证旧算法已彻底下线并替换为标准非对称验签 |
| 排查二进制常量池暴露 | `rizin_strings`、`rizin_xrefs` | 确认无硬编码对称魔数、混淆表或遗留测试密钥 |
| 评估产品整体 PE 加固基线 | `triage_pe` | 检查签名与安全编译选项配合验签模块 |
| 检索红蓝成对参考 | `kb_router` | 对照 [03-key-algorithm-recovery.md](03-key-algorithm-recovery.md) 验证防御完备性 |
