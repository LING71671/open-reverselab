---
id: "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap"
title: "签名链校验与公钥替换攻击"
title_en: "Signature Chain Validation and Public Key Swap"
summary: >
  攻击者视角的签名链攻击手册：识别内嵌公钥（Ed25519/RSA/PGP）、提取公钥、生成自持
  密钥对、公钥替换 patch 的完整流程，以及库级完整性自检（SHA-256 白名单）的
  绕过策略——方法级补丁避开 jar/exe 级白名单。覆盖 B 类机制的完整攻击路径。
summary_en: >
  Attacker-oriented manual for signature chain attacks: identifying embedded public
  keys (Ed25519/RSA/PGP), extracting them, generating a self-held keypair, and
  performing public key swap patches, plus bypass strategies for library-level
  integrity self-checks (SHA-256 whitelist) — method-level patching avoids
  jar/exe-level whitelists. Covers the full attack path for type-B mechanisms.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "Ed25519"
  - "RSA 签名"
  - "PGP 清文签名"
  - "内嵌公钥"
  - "公钥替换"
  - "密钥对"
  - "SHA-256 白名单"
  - "BouncyCastle"
  - "bcpg"
  - "验签绕过"
  - "自签名 license"
mcp_tools:
  - ghidra_summary_function_detail
  - rizin_strings
  - rizin_imports
  - patch_pe_bytes
  - patch_bytes
  - rizin_assemble_patch
  - die_scan
keywords:
  - "signature chain"
  - "Ed25519"
  - "RSA"
  - "PGP clearsign"
  - "public key extraction"
  - "keypair"
  - "pubkey swap"
  - "SHA-256 whitelist"
  - "tamper check"
  - "BouncyCastle"
difficulty: "advanced"
tags:
  - "license-keygen"
  - "signature-chain"
  - "pubkey-swap"
  - "integrity-check"
  - "PGP"
  - "Ed25519"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/01-license-mechanism-classification"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
  - "pe-reverse/08-patch/01-code-patching"
---
# 签名链校验与公钥替换攻击

## 场景

目标为 B 类签名链机制：key/license 文件由厂商私钥签名，客户端内嵌公钥验签。
直接还原"签名算法"不可行（私钥不在客户端），但**攻击面在公钥本身**：
把程序内嵌公钥替换成自己的，再用自持私钥签发合法授权。本文给出完整操作链，
并处理最常见的天花板——库级完整性自检。

## 输入信号

- 二进制内大整数常量 / 32B Ed25519 公钥 / PGP 公钥环
- 密码库导入：`bcrypt.dll`（BCryptVerifySignature）、OpenSSL、Java 侧
  BouncyCastle（`bcpg`/`bcprov` jar）、自实现 `modPow`/`R` 例程
- license 属性文本（`name=...`、`email=...` + 签名块）

## 攻击链：签名链攻击流水线

```text
确认签名现场（验签调用/公钥 blob）
  → 提取内嵌公钥
  → 生成自持密钥对（同族算法/同格式）
  → 公钥替换 patch（同尺寸优先）
  → 自持私钥签发授权
  → 处理库级完整性自检（方法级补丁）
  → 实机验证
```

## 第一步：确认签名现场并定位公钥

静态定位三选一：

1. **按调用链**：`02` 定位到校验函数后走验签分支，看它把哪个缓冲区交给验签 API
   ——该缓冲区通常就是**公钥 blob 起始地址**。
2. **按特征常量**：Ed25519 公钥恰 32B；RSA-2048 公钥 256B（模数）且通常
   `e=0x10001` 附近字节模式 `01 00 01`；PGP 公钥环以 `99 02`（public key packet）
   开头。在 `data` 节搜索：
   ```powershell
   rizin -zz target.exe | findstr /i "BEGIN PGP PUBLIC KEY"
   # 或对二进制直接 hex 搜索 99 02 / 找 256B 大整数连续块
   ```
3. **按反编译常量**：ghidra 中搜索 256 字节数组引用（`DEF` 大数组 + 传给验签函数）。

**提取**：记录公钥偏移与长度，`dd`/python 读 32~1195 字节存为 `pubkey.bin`。

## 第二步：生成自持密钥对

```python
# Ed25519 示例（RSA/PGP 见下方注）
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
# 公钥 32B，直接与提取值比对结构（同族算法替换才可能被接受）
```

- RSA：`RSA.generate(2048)` → 公钥需与目标**同尺寸/同格式**（DER SubjectPublicKeyInfo
  或裸模数）才有直接替换价值；必要时重新编码。
- PGP：用 OpenPGP 库生成主钥+签名子钥，导出**公钥环格式**与目标一致（如
  主钥 RSA-2048 + 子钥 RSA-2048，1195 字节公钥环）。
- Java（BouncyCastle）场景：`PGPKeyRingGenerator` 生成密钥环，导出 `pubring`。

**为什么能替换**：验签端只校验"签名是否由'内嵌公钥'对应私钥产生"，
不校验公钥归属。替换后自签授权即可通过验签。

## 第三步：公钥替换 patch

```python
import shutil

def swap_pubkey(src: bytes, offset: int, old_len: int, new_pub: bytes) -> bytes:
    """同尺寸替换优先（不动节区/偏移）；变长替换需 PE 节扩容或文件级方案。"""
    assert len(new_pub) <= old_len, "same-size swap preferred"
    patched = bytearray(src)
    patched[offset:offset + len(new_pub)] = new_pub
    return bytes(patched)
```

| 场景 | 替换方式 | 注意 |
|---|---|---|
| 原生 PE（.data 内公钥数组） | `patch_pe_bytes` 同偏移写新公钥 | 尺寸一致最稳；变长需 `VirtualAlloc`+改指针 |
| Java jar（`License.class` 内数组） | 方法级字节码补丁 | 只改 `getPublicKey()` 返回数组，**不要改类名/结构** |
| 多版本兼容 | patch 前先备份原始文件 | 回滚=换回备份 |

## 第四步：签发合法授权

```python
# Ed25519: 用自持私钥签名属性文本
signature = priv.sign(props_text.encode())

# PGP 清文签名: 属性文本 → "-----BEGIN PGP SIGNED MESSAGE-----" 块，
# 按目标验签端规范做规范化（行尾、CRC-24、装甲），逐字节对齐验证端实现
```

**规范化是对齐的关键**：清文签名先规范化属性文本（`name=...` 行序、`\r\n`、
无尾随空白），任何字节差异都会导致验签失败。用"提取的公钥 + 官方 license 样本"
先复刻验证端行为，再生成。

## 天花板的处理：库级完整性自检

部分目标对**库文件**做 SHA-256 白名单（如对 `bcpg.jar`、`bcprov.jar`、jna 等
整文件哈希比对）——直接改库文件会触发自检失败。绕过策略：

1. **避开库，打方法**：被白名单覆盖的是"整个库文件"，但**宿主程序自身文件
   往往不在白名单**（自检代码运行后即放弃）→ 只 patch 宿主内的公钥数组/
   验签调用，库保持原样 → 白名单哈希不变。
2. **先改后算**：若宿主也在白名单，先提取白名单计算逻辑（哈希表位置），
   patch 后同步更新表中对应哈希。
3. **验签置空**：把验签函数入口改为恒真（`mov eax,1; ret` 或等价），
   同时保留调用面（不删符号）——被反射调用的场景保持接口兼容。

## 证据与验证

- 提取与替换双向证据：替换前官方 key 验签=TRUE；替换后官方 key= FALSE、
  自签发 key=TRUE（同一程序同一地址验证）
- 实机：补丁后程序接受自签授权、功能解锁、重启保持
- 备份证据：原始文件偏移/字节、新字节、patch 脚本路径

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 定位/提取公钥 | `ghidra_summary_function_detail`、`rizin_strings`、`rizin_imports` |
| 同尺寸字节替换 | `patch_pe_bytes`、`patch_bytes`、`rizin_assemble_patch` |
| 生成补丁报告 | `generate_patch_report` |
| 完整性自检识别 | `die_scan`、`ghidra_summary_functions` |
| 反编译验签函数 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` |

## 下一跳

- 替换完成 → `05-keygen-frida-verification-loop` 实机验证
- 想对比"公钥替换 vs 逻辑 patch"的取舍 → `08-patch/01-code-patching`