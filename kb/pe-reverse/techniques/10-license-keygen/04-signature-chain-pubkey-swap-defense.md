---
id: "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap-defense"
title: "签名链信任锚保护与抗公钥替换加固"
title_en: "Signature Chain Trust Anchor Protection and Anti-Pubkey-Swap Hardening"
summary: >
  针对攻击者定位并替换客户端内嵌 Ed25519/RSA/PGP 公钥数组（pubkey swap），以及利用库级白名单漏洞
  仅补丁宿主程序绕过完整性校验的威胁，提供信任锚指纹钉扎、宿主与全依赖联合 Authenticode/SHA-256
  校验、密钥拆片动态重组及规范化 PGP/非对称验签加固方案。
summary_en: >
  Defense against public key extraction and replacement patches (Ed25519/RSA/PGP) and host-only
  patching that bypasses library-only SHA-256 whitelists. Covers trust-anchor fingerprint pinning,
  unified Authenticode + section-hash verification across both host and dependencies, split key
  reconstruction, and strict canonical verification.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "pubkey swap"
  - "trust anchor"
  - "Ed25519"
  - "Authenticode"
  - "WinVerifyTrust"
  - "SHA-256 白名单"
  - "公钥保护"
  - "抗补丁"
mcp_tools:
  - triage_pe
  - hash_file
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - rizin_strings
  - kb_router
keywords:
  - "pubkey swap defense"
  - "trust anchor protection"
  - "Authenticode pinning"
  - "host and dependency integrity"
  - "split key reconstruction"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "signature-chain"
  - "trust-anchor"
  - "anti-tamper"
  - "Ed25519"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap"
  - "pe-reverse/08-patch/01-code-patching-defense"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap"
---
# 签名链信任锚保护与抗公钥替换加固

## 防御目标与威胁面

在 [04-signature-chain-pubkey-swap.md](04-signature-chain-pubkey-swap.md) 中，攻击者虽然无法伪造厂商私钥，但可以通过逆向定位客户端中的静态信任锚（32B Ed25519 公钥、256B RSA 模数或 `99 02` 开头的 PGP 公钥环），实施两类替换攻击：

1. **同尺寸公钥替换（Pubkey Swap）**：直接在 `.data`/`.rdata` 或 JAR 字节码 `getPublicKey()` 中覆盖原有公钥为攻击者自建公钥，再用对应私钥签发任意授权。
2. **宿主补丁绕过库级白名单**：当产品仅对第三方密码库（如 `bcpg.jar`/`libcrypto.dll`）做 SHA-256 白名单，而未将宿主主程序自身纳入签名与实时完整性校验时，攻击者直接补丁宿主的公钥数组或将验签接口置空（`mov eax, 1; ret`），从而保持库文件哈希不变并成功绕过检查。

## 核心防御架构

| 攻击环节 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| 在 `.data`/`.rdata` 直接搜索定位裸公钥 blob | **公钥拆片与运行期混淆重组** + 不保留连续明文公钥数组 | 将公钥拆分为多个掩码分片分散在不同 `.text` 函数内，按需在栈上异或重组并校验完即清零 |
| 同尺寸替换内嵌公钥（`swap_pubkey`） | **信任锚 SHA-256 指纹钉扎 + 代码耦合**：将完整公钥指纹混入核心解密密钥与多处常量校验 | 仅替换公钥数组而不破坏其他耦合位在密码学上不可行 |
| 库级白名单忽略宿主自身完整性 | **双向全链路完整性校验**：OS Authenticode（`WinVerifyTrust` 钉扎厂商证书指纹）+ 宿主自身与全依赖 DLL/JAR 哈希核查 | 禁止仅校验第三方库；宿主可执行文件与所有加载模块必须处于同一受签信任链下 |
| 验签函数入口被直接置空（`mov eax, 1; ret`） | **验签结果与能力结构绑定**：验签输出服务端加密载荷解封密钥或签名结构，且多处分散复核公钥指纹 | 消灭单点布尔返回值，配合 ACG 防止运行期代码补丁 |
| PGP 清文签名规范化差异与弱密钥接受 | 强制固定 `key_id`、算法族、主子钥指纹白名单，规范行尾与无尾随空白校验 | 拒绝任何未经指纹钉扎的密钥环，防止跨版本/跨格式歧义 |

## 加固实现与检测代码

以下 Python 脚本模拟蓝队的**拆片信任锚重组 + 指纹钉扎 + 宿主与依赖全链完整性校验**流程，演示为何同尺寸替换公钥或宿主补丁均会即刻失效；下方附带 C++ Authenticode 证书主体指纹钉扎模板：

```python
"""trust_anchor_guard.py: 信任锚拆片保护、公钥指纹钉扎及宿主+依赖全链路完整性检验"""
from __future__ import annotations
import hashlib
import hmac
from typing import Dict, List, Tuple


def split_pubkey_shares(pubkey: bytes, mask_seed: bytes) -> Tuple[bytes, bytes, bytes]:
    """将 32B 公钥拆分为两份异或分片，并生成带域分离的公钥钉扎指纹。"""
    assert len(pubkey) == 32
    s1 = hashlib.sha256(mask_seed + b":share1").digest()
    s2 = bytes(a ^ b for a, b in zip(pubkey, s1))
    pin_digest = hashlib.sha256(b"TRUST-ANCHOR-PIN-V1:" + pubkey).digest()
    return s1, s2, pin_digest


def reconstruct_and_verify_anchor(
    s1: bytes, s2: bytes, expected_pin: bytes
) -> Tuple[bool, bytes]:
    rebuilt = bytes(a ^ b for a, b in zip(s1, s2))
    actual_pin = hashlib.sha256(b"TRUST-ANCHOR-PIN-V1:" + rebuilt).digest()
    if not hmac.compare_digest(actual_pin, expected_pin):
        return False, b""
    return True, rebuilt


def verify_host_and_deps(
    component_blobs: Dict[str, bytes], expected_sha256: Dict[str, str]
) -> List[str]:
    """同时核验宿主 EXE 与全部密码/业务依赖库，消除仅查依赖库的盲区。"""
    violations: List[str] = []
    for name, expected in expected_sha256.items():
        blob = component_blobs.get(name)
        if blob is None:
            violations.append(f"missing:{name}")
            continue
        actual = hashlib.sha256(blob).hexdigest()
        if not hmac.compare_digest(actual, expected):
            violations.append(f"tampered:{name}")
    return violations


if __name__ == "__main__":
    official_pub = hashlib.sha256(b"vendor-ed25519-pub").digest()
    s1, s2, pin = split_pubkey_shares(official_pub, b"build-2026-11")
    ok, rebuilt = reconstruct_and_verify_anchor(s1, s2, pin)
    assert ok and rebuilt == official_pub

    # 模拟攻击者替换其中一个分片/公钥数组
    attacker_pub = hashlib.sha256(b"attacker-ed25519-pub").digest()
    forged_s2 = bytes(a ^ b for a, b in zip(attacker_pub, s1))
    assert reconstruct_and_verify_anchor(s1, forged_s2, pin) == (False, b"")

    # 模拟“库文件未动、仅补丁宿主程序”的场景
    host_orig, dep_orig = b"HOST_BIN_V1", b"BCPG_LIB_V1"
    manifest = {
        "app.exe": hashlib.sha256(host_orig).hexdigest(),
        "crypto_dep.dll": hashlib.sha256(dep_orig).hexdigest(),
    }
    assert verify_host_and_deps({"app.exe": host_orig, "crypto_dep.dll": dep_orig}, manifest) == []
    violations = verify_host_and_deps({"app.exe": b"HOST_PATCHED", "crypto_dep.dll": dep_orig}, manifest)
    assert violations == ["tampered:app.exe"]
    print("Trust anchor & host integrity guard self-check passed.")
```

以下 C++ 片段演示在客户端加载与验签之前，强制校验当前进程主模块（及关键 DLL）的 Authenticode 签名且证书 SHA-256 指纹必须匹配官方发行者（而非任意自签证书）：

```cpp
// authenticode_pinning.cpp: 校验文件签名存在且证书指纹匹配官方发布者
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <cstring>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

bool VerifyPinnedAuthenticode(LPCWSTR filePath, const BYTE expectedCertSha256[32]) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(nullptr, &policy, &wtd);
    bool pinnedMatch = false;

    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
        CRYPT_PROVIDER_SGNR* signer = provData ? WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0) : nullptr;
        CRYPT_PROVIDER_CERT* cert = signer ? WTHelperGetProvCertFromChain(signer, 0) : nullptr;
        if (cert && cert->pCert) {
            BYTE actualHash[32] = {};
            DWORD cbHash = sizeof(actualHash);
            if (CertGetCertificateContextProperty(cert->pCert, CERT_SHA256_HASH_PROP_ID, actualHash, &cbHash) &&
                cbHash == 32) {
                pinnedMatch = (std::memcmp(actualHash, expectedCertSha256, 32) == 0);
            }
        }
    }

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &wtd);
    return (status == ERROR_SUCCESS) && pinnedMatch;
}
```

## 防御工作流

```text
1. 消除裸公钥存储：对内嵌 Ed25519/RSA/PGP 公钥执行分片掩码与指纹钉扎，禁止完整连续公钥字节直接落于 .rdata
2. 宿主与全依赖共检：将主可执行文件自身纳入 SHA-256 与 Authenticode 证书指纹钉扎范围，封堵“库未动、打宿主”绕过
3. 启用 ACG/CFG 保护：阻止运行时通过 VirtualProtect 改写验签逻辑或覆盖内存公钥缓冲区
4. 验签解耦去除布尔口：验签模块在核验签名同时校验信任锚指纹并输出后续解码所需的派生参数
5. 严格规范化输入：对 PGP 清文或结构化授权文件强制执行固定换行、无尾随字符与 key_id 白名单检查
```

## 验证与判定标准

- **同尺寸公钥替换拦截**：使用十六进制工具或补丁脚本将测试样本内公钥分片替换为攻击者生成的新公钥后，`reconstruct_and_verify_anchor` 必须返回 `False`。
- **宿主单独篡改拦截**：保持依赖库字节完全不变、仅改写宿主主程序 1 字节时，`verify_host_and_deps` 与 `VerifyPinnedAuthenticode` 必须均返回篡改失败。
- **自签证书重签拦截**：即使用攻击者自己的代码签名证书对篡改后的 EXE 重新签名，`VerifyPinnedAuthenticode` 必须因证书 SHA-256 指纹不匹配而拒绝放行。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查样本是否仍暴露裸公钥常量 | `rizin_strings`、`triage_pe` | 搜索 `BEGIN PGP PUBLIC KEY` 及大整数常量块 |
| 计算发布产物宿主与依赖哈希矩阵 | `hash_file` | 产出 `app.exe` 与全依赖 DLL 的基线校验清单 |
| 核查验签函数控制流与调用点 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` | 确认不存在孤立可置空的布尔验签入口 |
| 检索红蓝成对参考 | `kb_router` | 对照 [04-signature-chain-pubkey-swap.md](04-signature-chain-pubkey-swap.md) 验证抗替换能力 |
