---
id: "pe-reverse/10-license-keygen/01-license-mechanism-classification-defense"
title: "商业软件授权架构纵深防御选型"
title_en: "Commercial Software Licensing Defense-in-Depth Architecture"
summary: >
  针对攻击者对本地算法（A 类）、签名链（B 类）、自引用切片（C 类）与云端校验（D 类）四类授权机制的
  路径选择策略，提供蓝队架构演进路线与风险量化评估器，指导消除纯本地可推导算法与自引用脆弱模式，
  落地非对称签名 + 信任锚保护 + 服务端能力裁决的防御体系。
summary_en: >
  Defensive architecture guide countering attacker license classification across Type-A (local
  algorithm), Type-B (signature chain), Type-C (self-referencing slice), and Type-D (cloud
  validation). Includes an architecture risk scorer and migration roadmap to asymmetric signatures,
  trust-anchor hardening, and server-side capability enforcement.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "授权架构"
  - "license defense"
  - "Ed25519"
  - "服务端能力裁决"
  - "反注册机"
  - "信任锚加固"
  - "防破解设计"
mcp_tools:
  - triage_pe
  - ghidra_headless_analyze
  - ghidra_summary_imports
  - hash_file
  - kb_router
keywords:
  - "license architecture defense"
  - "anti-keygen"
  - "Ed25519 licensing"
  - "cloud capability enforcement"
  - "trust anchor protection"
  - "blue-team"
difficulty: "beginner"
tags:
  - "defense"
  - "blue-team"
  - "license-protection"
  - "architecture"
  - "anti-keygen"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/01-license-mechanism-classification"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery-defense"
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap-defense"
  - "pe-reverse/10-license-keygen/06-cloud-license-frida-hook-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/01-license-mechanism-classification"
---
# 商业软件授权架构纵深防御选型

## 防御目标与威胁面

在 [01-license-mechanism-classification.md](../../../../red/pe-reverse/techniques/10-license-keygen/01-license-mechanism-classification.md) 中，攻击者首先把软件授权机制分为 A（纯本地算法）、B（签名链）、C（自引用签名切片）、D（云端校验）四类，再选择成本最低的武器（keygen、公钥替换、迭代收敛、Frida Hook/状态伪造）。

从产品安全与防盗版工程视角来看，**防御的第一原则是架构选型**：只要在客户端残留可推导的局部算法或未受保护的单点布尔判定，攻击者便可用极低成本批量签发或绕过。蓝队应当明确淘汰 A 类与 C 类机制，并将 B/D 类机制加固至不可单点绕过。

## 四类机制防御矩阵与演进路线

| 原机制类型 | 攻击面本质 | 蓝队架构改造要求 | 残留风险缓解手段 |
|---|---|---|---|
| **A 类：纯本地算法** | 对称/可逆逻辑暴露在客户端，缺乏密码学非对称性 | **强制淘汰**：迁移为 B 类非对称签名或 D 类在线签发，严禁 CRC/XOR/自定义哈希 | 若因兼容遗留需过渡，必须全字段覆盖 HMAC-SHA256 并配合服务端激活绑定 |
| **B 类：本地签名链** | 私钥不落地，但内嵌公钥与验签结果易被二进制补丁替换 | **信任锚与代码完整性绑定**：Authenticode 验签 + 宿主/依赖联合 SHA-256 校验 + 非布尔能力解耦 | 校验公钥指纹钉扎，防止同尺寸替换公钥数组或将验签函数改为恒真 |
| **C 类：自引用切片** | 仅校验局部切片且客户端自行算出期望值，满足局部不变性 | **彻底废弃**：改用全载荷覆盖的 Ed25519/ECDSA 验签，客户端禁止计算期望签名串 | 合并输入校验与冷启动校验，拒绝任意部分切片比对逻辑 |
| **D 类：云端校验** | 在线验签无法 keygen，但本地状态缓存、试用标记与查询面易被 Hook | **服务端能力下发 + 短时签名租约**：核心功能/数据加密密钥由服务端按授权实时下发；本地租约绑定设备指纹与单调计数 | 启用 CIG/Anti-Frida 防护查询面，本地缺失状态默认未授权（禁止自动重置试用） |

## 架构风险评估与核查代码

以下 Python 工具对软件授权设计方案的配置元数据（算法类型、校验覆盖率、完整性绑定、功能解耦级别）进行自动化评分与缺口定位：

```python
"""license_architecture_scorer.py: 评估授权方案对 A/B/C/D 四类攻击路径的抵御能力"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List


@dataclass
class LicenseDesignProfile:
    mechanism: str                  # "local_algo" | "signature_chain" | "self_ref_slice" | "cloud_attested"
    asymmetric_crypto: bool         # 是否使用 Ed25519 / ECDSA / RSA-PSS 等非对称签名
    full_payload_coverage: bool     # 签名/校验是否覆盖 100% 载荷字段
    trust_anchor_integrity: bool    # 公钥与验签代码是否受 Authenticode + 分散哈希保护
    server_capability_gate: bool    # 高价值能力或解密密钥是否依赖服务端实时签发
    anti_hook_hardening: bool       # 是否启用 CIG/ACG/Anti-Frida 保护查询面


def evaluate_license_posture(p: LicenseDesignProfile) -> dict:
    blockers: List[str] = []
    score = 100

    if p.mechanism in {"local_algo", "self_ref_slice"} or not p.asymmetric_crypto:
        score -= 50
        blockers.append("CRITICAL: 可推导本地算法或自引用切片极易被 Keygen/收敛攻破，必须升级为非对称签名")
    if not p.full_payload_coverage:
        score -= 20
        blockers.append("HIGH: 存在未校验自由字段或局部切片，必须实行 100% 规范化载荷签名")
    if not p.trust_anchor_integrity:
        score -= 15
        blockers.append("HIGH: 内嵌公钥与验签代码缺少完整自检，面临公钥替换或逻辑 Patch 风险")
    if not p.server_capability_gate:
        score -= 10
        blockers.append("MEDIUM: 客户端本地全量交付功能，建议核心计算/资产由服务端签名能力令牌解锁")
    if not p.anti_hook_hardening:
        score -= 5
        blockers.append("LOW: 查询面未启用 CIG/Anti-Frida 防护，面临运行时返回值劫持风险")

    grade = "STRONG" if score >= 90 and not blockers else ("MODERATE" if score >= 70 else "WEAK")
    return {"score": max(score, 0), "grade": grade, "findings": blockers}


if __name__ == "__main__":
    weak = LicenseDesignProfile("local_algo", False, False, False, False, False)
    assert evaluate_license_posture(weak)["grade"] == "WEAK"

    hardened = LicenseDesignProfile("cloud_attested", True, True, True, True, True)
    res = evaluate_license_posture(hardened)
    assert res["grade"] == "STRONG" and res["score"] == 100
    print("License architecture scoring self-check passed.")
```

## 防御工作流

```text
1. 盘点现有机制：识别产品当前属于 A/B/C/D 哪一类，立即立项淘汰纯本地算法（A）与自引用切片（C）
2. 密码学底座升级：引入 Ed25519 或 ECDSA-P256 对规范化授权载荷进行 100% 字节覆盖签名，服务端独掌私钥
3. 信任锚防篡改：将验签公钥哈希钉扎与 PE Authenticode/节区哈希校验耦合进核心业务解密密钥派生
4. 离线租约与试用收敛：离线缓存改为短 TTL 签名租约 + 设备指纹绑定；试用意向由服务端账号/设备指纹裁决
5. 激活与查询面加固：启用 CIG/ACG 防护进程空间，并将核心高价值业务能力下沉至服务端授权下发
```

## 验证与判定标准

- **无局部/可推导弱点**：运行 `evaluate_license_posture` 评估目标设计文档与实现，得分必须达到 `>= 90` 且无 `CRITICAL` 或 `HIGH` 级别发现项。
- **断网与降级行为验证**：云端授权模式下断开网络且删除本地所有缓存状态后，软件必须保持未授权受限状态，不得自动恢复满额试用或信任伪造状态文件。
- **反公钥替换验证**：使用工具修改二进制内嵌公钥字节后，程序必须因代码/数据完整性耦合失效而拒绝启动或解密失败。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 识别二进制中残留的弱算法与明文公钥 | `triage_pe`、`ghidra_summary_imports` | 检查是否缺失系统/现代密码库调用或仍存在裸本地校验特征 |
| 深入分析授权模块边界 | `ghidra_headless_analyze` | 定位全部授权入口并确认是否存在多套不一致校验路径 |
| 计算并保存发布产物校验基线 | `hash_file` | 生成二进制指纹用于发布与自检验证 |
| 检索红蓝成对参考 | `kb_router` | 对照 [01-license-mechanism-classification.md](../../../../red/pe-reverse/techniques/10-license-keygen/01-license-mechanism-classification.md) 评估攻防对称性 |
