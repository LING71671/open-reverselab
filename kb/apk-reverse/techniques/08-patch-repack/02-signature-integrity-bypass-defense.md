---
id: "apk-reverse/08-patch-repack/02-signature-integrity-bypass-defense"
title: "APK 签名与包体完整性多层加固"
title_en: "APK Signature and Package Integrity Multi-Layer Hardening"
summary: >
  针对 Hook PackageManager.getPackageInfo/SigningInfo、Hook MessageDigest/SHA256_Update、拦截 open(base.apk) 及 Smali 布尔分支 Patch 等完整性绕过手法，提供直连系统调用解析 APK v2/v3 签名块、无导出静态哈希校验、校验结果参与密钥派生及服务端 Play Integrity 强绑定方案。
summary_en: >
  Multi-layer hardening against signature and integrity bypasses targeting getPackageInfo/SigningInfo, MessageDigest/SHA256_Update, open(base.apk) hooks, and smali boolean patches. Covers direct-syscall APK v2/v3 Signing Block parsing, inlined unexported hashing, key-coupled integrity checks, and backend Play Integrity verdict validation.
board: "apk-reverse"
category: "08-patch-repack"
signals:
  - "APK Signature Scheme v2/v3"
  - "Play Integrity API"
  - "Signing Block 解析"
  - "无导出 SHA-256"
  - "anti-hook 完整性校验"
  - "requestHash 绑定"
mcp_tools:
  - "android_package_info"
  - "android_app_baseline"
  - "android_crypto_unpack_recipe"
  - "ghidra_headless_analyze"
  - "hash_file"
  - "kb_router"
keywords:
  - "签名校验加固"
  - "完整性防绕过"
  - "APK v2/v3"
  - "Play Integrity"
  - "防Smali Patch"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "signature"
  - "integrity"
  - "play-integrity"
  - "anti-repack"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/08-patch-repack/02-signature-integrity-bypass"
  - "apk-reverse/08-patch-repack/01-so-injection-repack-defense"
  - "apk-reverse/01-dex-java/01-smali-injection-defense"
track: "blue"
defends: "apk-reverse/08-patch-repack/02-signature-integrity-bypass"
---
# APK 签名与包体完整性多层加固

## 防御目标与威胁面

常见客户端签名与完整性检查容易被一次性击穿，根因在于：
1. **依赖 Framework Java API**：调用 `PackageManager.getPackageInfo(..., GET_SIGNING_CERTIFICATES)` 或 `getInstallerPackageName`，可被 Frida 轻松伪造返回值。
2. **依赖可挂钩的标准库符号**：直接调用 `java.security.MessageDigest`、libc `open`/`openat` 或 OpenSSL `SHA256_Update` 读取 `base.apk`/`classes.dex`，易被通用文件与摘要 Hook 定位调用栈并替换预期摘要。
3. **孤立布尔判断**：以 `checkSignature()Z` 返回 `true/false`，在 Smali 层改写为 `const/4 v0, 0x1` 即可完全绕过。

根治方案是**Java + Native 直连解析 + 服务端 Play Integrity 三重联动**，且让客户端校验值直接参与后续会话密钥派生。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| Hook `getPackageInfo` / `SigningInfo` | Native 层直接读取 `/proc/self/maps` 中的 `base.apk` 路径并解析 ZIP EOCD 与 APK Signing Block v2/v3 | 提取原始 X.509 签名证书字节计算 SHA-256，不经过 Java `PackageManager` |
| Hook `open`/`openat`/`SHA256_Update` | 文件读取使用内联 `SVC #0` 系统调用，SHA-256 实现静态内联且剥离符号 | 校验逻辑分散至多处业务节点，避免单点 `SHA256_Update` 导出符号暴露 |
| Smali `const/4 v0, 0x1` 单点绕过 | 将真实证书摘要参与本地配置解密密钥或请求 HMAC 因子派生 | 重打包修改证书后即使强行跳过判断分支，解密与签名仍因密钥错误失效 |
| 客户端本地逻辑被全面逆向并重算 | 服务端集成 Google Play Integrity API，按业务请求绑定 `requestHash` | 后端核验 `appRecognitionVerdict == PLAY_RECOGNIZED` 及官方签名摘要 |

## 加固代码与校验示例

### 1. Python 验证 APK Signing Block（v2/v3 Magic）与 Play Integrity 后端裁决逻辑

```python
import hashlib
import struct
from typing import Dict, Tuple

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def find_apk_signing_block_magic(apk_bytes: bytes) -> Tuple[bool, str]:
    """核验 APK 是否包含 v2/v3 Signing Block 结构（不依赖易被 v1 伪造的 META-INF）。"""
    eocd_marker = b"PK\x05\x06"
    eocd_pos = apk_bytes.rfind(eocd_marker)
    if eocd_pos == -1 or len(apk_bytes) - eocd_pos < 22:
        return False, "missing_eocd"

    cd_offset = struct.unpack_from("<I", apk_bytes, eocd_pos + 16)[0]
    if cd_offset < 24 or cd_offset > len(apk_bytes):
        return False, "invalid_cd_offset"

    magic = apk_bytes[cd_offset - 16 : cd_offset]
    if magic != APK_SIG_BLOCK_MAGIC:
        return False, "missing_v2_v3_signing_block"

    block_size_footer = struct.unpack_from("<Q", apk_bytes, cd_offset - 24)[0]
    block_start = cd_offset - 8 - block_size_footer
    if block_start < 0:
        return False, "corrupted_signing_block"
    block_size_header = struct.unpack_from("<Q", apk_bytes, block_start)[0]
    if block_size_header != block_size_footer:
        return False, "size_mismatch"
    return True, "valid_v2_v3_block"


def verify_play_integrity_verdict(
    verdict: Dict[str, dict],
    expected_pkg: str,
    expected_cert_sha256: str,
    expected_request_hash: str,
) -> Tuple[bool, str]:
    """服务端对解密后的 Play Integrity 令牌声明执行 Fail-Closed 核验。"""
    req_details = verdict.get("requestDetails", {})
    if req_details.get("requestPackageName") != expected_pkg:
        return False, "package_mismatch"
    if req_details.get("requestHash") != expected_request_hash:
        return False, "request_hash_mismatch"

    app_integrity = verdict.get("appIntegrity", {})
    if app_integrity.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
        return False, "unrecognized_app_binary"
    certs = app_integrity.get("certificateSha256Digest", [])
    if expected_cert_sha256 not in certs:
        return False, "certificate_mismatch"

    device_verdicts = verdict.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    if "MEETS_DEVICE_INTEGRITY" not in device_verdicts and "MEETS_STRONG_INTEGRITY" not in device_verdicts:
        return False, "device_integrity_failed"
    return True, "ok"


if __name__ == "__main__":
    # 构造最小化合法 APK Signing Block v2/v3 测试结构
    payload = b"\x01" * 16
    block_size = 8 + len(payload) + 16
    signing_block = struct.pack("<Q", block_size) + payload + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    cd = b"PK\x01\x02" + b"\x00" * 16
    cd_offset = len(signing_block)
    eocd = b"PK\x05\x06" + b"\x00" * 12 + struct.pack("<I", cd_offset) + b"\x00\x00"
    sample_apk = signing_block + cd + eocd
    assert find_apk_signing_block_magic(sample_apk) == (True, "valid_v2_v3_block")

    req_hash = hashlib.sha256(b"action=transfer&amount=100&nonce=abc").hexdigest()
    good_verdict = {
        "requestDetails": {"requestPackageName": "com.vendor.app", "requestHash": req_hash},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "certificateSha256Digest": ["deadbeef"]},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
    }
    assert verify_play_integrity_verdict(good_verdict, "com.vendor.app", "deadbeef", req_hash) == (True, "ok")
    assert verify_play_integrity_verdict(good_verdict, "com.vendor.app", "repacked", req_hash) == (False, "certificate_mismatch")
    print("Signature & Play Integrity defense check passed.")
```

## 防御工作流

```text
1. 强制 v2/v3 签名：发布构建禁用纯 v1 签名，确保 APK 携带完整 APK Signing Block
2. Native 直连解析：在 C++ 层通过 SVC #0 直接打开自身 base.apk 并定位 Signing Block 提取签名证书摘要
3. 校验密钥耦合：将证书 SHA-256 与 classes.dex 摘要纳入密钥派生，彻底淘汰孤立 boolean 返回函数
4. 符号与分支硬化：内联哈希实现并移除 SHA256_Update/MD5_Update 等外部符号依赖，多点交叉复核
5. 后端 Play Integrity 裁决：高风险请求携带绑定业务参数的 requestHash 令牌，由服务端验签并判定证书一致性
```

## 验证与判定标准

- **v2/v3 结构强制性**：运行 `find_apk_signing_block_magic` 对发布包校验必须返回 `valid_v2_v3_block`；仅采用 v1 重签名的包必须被客户端拒绝。
- **Java Hook 抗性测试**：仅对 `PackageManager.getPackageInfo`、`MessageDigest.getInstance` 与 `getInstallerPackageName` 挂载 Frida 返回伪造值时，Native 完整性校验与服务端 Play Integrity 核验仍须识别篡改。
- **Smali Patch 抗性**：强行修改 Java 校验方法返回 `true` 后，重打包应用在密钥派生或后端令牌检查环节必须失败。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 读取官方包签名信息 | `android_package_info` | 确认发布包签名方案及证书摘要基准 |
| 检查 Native 哈希符号暴露 | `ghidra_headless_analyze` | 核实未残留明文 `SHA256_Update` 校验调用或孤立判断函数 |
| 核查客户端加密绑定 | `android_crypto_unpack_recipe` | 验证证书摘要是否参与后续密钥/签名运算 |
| 计算 APK 制品摘要 | `hash_file` | 固化官方安装包 SHA-256 用于远端比对 |
| 关联红蓝文档 | `kb_router` | 对照 [02-signature-integrity-bypass.md](02-signature-integrity-bypass.md) 逐项封闭绕过路径 |
