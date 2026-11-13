---
id: "pe-reverse/10-license-keygen/07-self-referencing-signature-convergence-defense"
title: "自引用切片漏洞根治与抗迭代收敛签名架构"
title_en: "Eliminating Self-Referencing Slice Vulnerabilities and Convergence Attacks"
summary: >
  针对冷启动自引用校验机制因局部不变性（X[pos:pos+4] 不随 code[pos:pos+4] 改变）与客户端自行计算期望串 X
  而导致攻击者通过“写入占位 key → 冷启动抓取切片 → 回填”单步迭代收敛的致命缺陷，提供全载荷雪崩非对称验签、
  禁止客户端生成期望串与双机制统一加固方案。
summary_en: >
  Defense against self-referencing signature embedding and one-shot iterative convergence attacks,
  where local invariance of X[pos:pos+4] and client-side expected-value generation allow attackers
  to capture and backfill valid slices without reversing the algorithm. Enforces full-payload
  asymmetric verification, removal of client-side signature generation, and unified validation.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "self-referencing signature"
  - "局部不变性"
  - "迭代收敛防御"
  - "全载荷雪崩"
  - "Ed25519 verify"
  - "双机制统一"
mcp_tools:
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - rizin_strings
  - triage_pe
  - kb_router
keywords:
  - "self-referencing signature defense"
  - "iterative convergence defense"
  - "avalanche property"
  - "asymmetric verification"
  - "unified validation"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "anti-convergence"
  - "cryptography"
  - "Ed25519"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/07-self-referencing-signature-convergence"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery-defense"
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/07-self-referencing-signature-convergence"
---
# 自引用切片漏洞根治与抗迭代收敛签名架构

## 防御目标与威胁面

在 [07-self-referencing-signature-convergence.md](../../../../red/pe-reverse/techniques/10-license-keygen/07-self-referencing-signature-convergence.md) 中，存在一种极其隐蔽的设计缺陷：软件拥有两套独立的校验逻辑（UI 输入校验 + 冷启动校验），且冷启动逻辑通过客户端内部的生成函数 `X = GEN(name, code, ...)` 算出期望串 `X` 后，**仅截取某局部切片** `X[pos:pos+4]` 与 `code[pos:pos+4]` 对比。

该设计之所以会被攻击者“零算法理解、单步直接收敛”攻破，根源在于同时犯了三个错误：

1. **客户端持有了签名生成函数 `GEN`**，并在内存中直接暴露了预期结果 `X`，使 Frida/调试器可以直接抓取出正确答案。
2. **校验输入存在局部不变性**：`GEN` 忽略了 `code[pos:pos+4]` 自身（或未把完整内容纳入强密码学摘要），导致回填切片后 `X` 的其他部分纹丝不动，不等式瞬间收敛为恒等式。
3. **仅比对局部切片且双机制割裂**：UI 输入只检查格式就弹窗通过，把真实校验推迟到冷启动后门比对 4 字符切片。

## 核心防御架构

| 漏洞根因 | 根治防御措施 | 关键实现约束 |
|---|---|---|
| 客户端调用 `X = GEN(...)` 计算预期串再 `memcmp` | **严禁客户端存在 `GEN` 函数**：客户端仅执行非对称验签 `Ed25519.Verify(pub, payload, sig)` | 客户端内存中永远不会产生可被抓取的“正确签名值 `X`” |
| 仅比较 4 字符局部切片 `code[pos:pos+4] == X[pos:pos+4]` | 校验整个 **512-bit Ed25519 签名**（或 256-bit HMAC/ECDSA），彻底消除局部切片与日期派生位置 `pos` | 256/512 位强密码学空间不存在部分命中或抓取回填可能 |
| `GEN` 对切片位置满足局部不变性 | 签名覆盖**除独立签名字段外的 100% 规范化载荷**；任何 1 bit 输入改动触发密码学雪崩效应 | 即使假设存在自引用或状态重算，1 bit 变更也会完全破坏原签名 |
| 输入窗口校验与冷启动校验为两套割裂机制 | **统一唯一强校验入口**（输入即执行完整非对称验签，冷启动复核同一信任链与完整性耦合密钥） | 占位 key 在输入窗口阶段即直接失败拒绝写入 |

## 加固实现与对比验证代码

以下 Python 脚本清晰对比了脆弱的“局部不变性切片校验（可被单步抓取回填收敛）”与加固后的“全载荷 Ed25519 非对称验签（内存中不产生期望值 `X`，回填收敛失败率 100%）”：

```python
"""anti_convergence_verifier.py: 对比局部不变切片漏洞与抗迭代收敛的全载荷非对称验签"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
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


# --- 反面模式: 脆弱的局部不变自引用生成校验（可被单步收敛攻破） ---
def vulnerable_gen(name: str, code: str) -> str:
    # 缺陷1: 忽略了 code[8:12] 切片本身（满足局部不变性）
    # 缺陷2: 客户端自行计算出了完整期望串 X
    invariant_input = f"{name}:{code[:8]}:{code[12:]}"
    return hashlib.sha256(invariant_input.encode()).hexdigest()[:16]


def attempt_backfill_attack_on_vulnerable(name: str, placeholder: str) -> bool:
    x = vulnerable_gen(name, placeholder)
    backfilled = placeholder[:8] + x[8:12] + placeholder[12:]
    return vulnerable_gen(name, backfilled)[8:12] == backfilled[8:12]


# --- 蓝队加固模式: 统一输入与冷启动的全载荷 Ed25519 非对称验签 ---
def issue_hardened_key(priv: Ed25519PrivateKey, name: str, edition: str, nonce: str) -> str:
    payload = json.dumps(
        {"name": name, "edition": edition, "nonce": nonce},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig = priv.sign(b"UNIFIED-LIC-V1\x00" + payload)
    return base64.urlsafe_b64encode(payload).decode() + "." + base64.urlsafe_b64encode(sig).decode()


def unified_verify(pub: Ed25519PublicKey, key_str: str, expected_name: str) -> Tuple[bool, str]:
    """输入窗口与冷启动共用同一无期望值泄露的严格验签函数。"""
    try:
        p_b64, s_b64 = key_str.split(".", 1)
        payload = base64.urlsafe_b64decode(p_b64)
        sig = base64.urlsafe_b64decode(s_b64)
        pub.verify(sig, b"UNIFIED-LIC-V1\x00" + payload)
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, InvalidSignature, Exception):
        return False, "rejected"

    if obj.get("name") != expected_name:
        return False, "holder_mismatch"
    return True, obj.get("edition", "")


if __name__ == "__main__":
    # 1. 验证旧模式确实会被占位回填一次攻破
    assert attempt_backfill_attack_on_vulnerable("alice", "ABCD1234XXXX9999") is True

    # 2. 验证加固后的非对称模式完全免疫占位注入与任意片段回填
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    valid_key = issue_hardened_key(sk, "alice", "enterprise", "n-2026")
    assert unified_verify(pk, valid_key, "alice") == (True, "enterprise")

    # 占位注入立即在输入阶段被拒，且客户端内存无期望签名 X 可抓
    placeholder_key = base64.urlsafe_b64encode(b'{"name":"alice","edition":"enterprise","nonce":"0"}').decode() + "." + base64.urlsafe_b64encode(b"\x00" * 64).decode()
    assert unified_verify(pk, placeholder_key, "alice") == (False, "rejected")
    print("Anti-convergence signature verification self-check passed.")
```

## 防御工作流

```text
1. 全面废除客户端 GEN：梳理二进制内所有类似 X = GEN(...) 的预期签名生成函数并彻底移除，私钥签名仅留存服务端
2. 消除局部切片比对：废除按 pos/date 截取 4 字符比对的逻辑，升级为全载荷覆盖的 Ed25519/ECDSA 整块签名验证
3. 统一双路径校验器：输入保存阶段与冷启动阶段调用同一套强非对称验签与信任锚完整性检查，杜绝占位 key 写入磁盘
4. 保护公钥信任锚：按 04-signature-chain-pubkey-swap-defense 对客户端内嵌公钥实施指纹钉扎与 Authenticode 自检
```

## 验证与判定标准

- **无期望签名生成函数**：使用 `ghidra_headless_analyze` 核查客户端二进制，确认内部不存在能产出预期签名串 `X` 的算法函数，仅存在非对称 `verify` 调用。
- **占位注入零容忍**：向激活入口与配置文件写入任意合法格式的占位 key 后，输入阶段与冷启动阶段均必须 100% 拒绝且不写入已激活状态。
- **全载荷雪崩验证**：修改签名授权载荷中任一字段的 1 个字符，`unified_verify` 必须稳定返回 `(False, "rejected")`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 排查是否存在双套校验与客户端签名生成逻辑 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` | 定位冷启动校验与输入校验函数，确认无 `GEN` 预期值生成逻辑 |
| 搜索日期派生位置或切片比对特征 | `rizin_strings` | 核查是否残留切片长度/格式掩码模板 |
| 检查整体二进制签名与防护基线 | `triage_pe` | 验证 Authenticode 与进程缓解策略配合 |
| 检索红蓝成对参考 | `kb_router` | 对照 [07-self-referencing-signature-convergence.md](../../../../red/pe-reverse/techniques/10-license-keygen/07-self-referencing-signature-convergence.md) 验证根治效果 |
