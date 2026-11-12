---
id: "pe-reverse/08-patch/01-code-patching-defense"
title: "代码篡改防护与 PE 节区完整性自检"
title_en: "Code Patching Defense and PE Section Integrity Verification"
summary: >
  针对 NOP 填充、强制条件跳转（JE/JNE 改 JMP）、立即数修改、返回值劫持（mov eax, 1; ret）
  与 Xbyak 运行时字节补丁等五类代码篡改手法，提供 Authenticode 磁盘验签、PE .text 节区加密哈希校验、
  ACG/CFG 运行时页保护与密钥耦合防绕过架构。
summary_en: >
  Defense against five code patching patterns (NOP sleds, forced conditional branches, immediate
  value modification, return value hijacking, and Xbyak runtime patches). Covers Authenticode
  verification, PE .text section cryptographic hashing, ACG/CFG memory protection, and
  integrity-coupled execution.
board: "pe-reverse"
category: "08-patch"
signals:
  - "code patch"
  - "Authenticode"
  - "WinVerifyTrust"
  - "section hash"
  - "VirtualProtect"
  - "PAGE_EXECUTE_WRITECOPY"
  - "anti-tamper"
  - "代码完整性"
mcp_tools:
  - triage_pe
  - hash_file
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - make_yara_stub
  - kb_router
keywords:
  - "code patching defense"
  - "anti-tamper"
  - "Authenticode"
  - "PE section hash"
  - "VirtualProtect defense"
  - "ACG"
  - "CFG"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "anti-tamper"
  - "code-integrity"
  - "Authenticode"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/08-patch/01-code-patching"
  - "pe-reverse/04-dynamic-analysis/02-trampoline-detour-defense"
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap-defense"
track: "blue"
defends: "pe-reverse/08-patch/01-code-patching"
---
# 代码篡改防护与 PE 节区完整性自检

## 防御目标与威胁面

在 [01-code-patching.md](01-code-patching.md) 中，攻击者通过磁盘字节补丁或运行期 `VirtualProtect(PAGE_EXECUTE_READWRITE)` 改页保护，实施五类代码篡改：

1. **NOP 填充（`0x90`）**：抹除反调试或校验调用指令。
2. **强制条件分支**：将 `JE`（`0x74`）改写为无条件短跳 `JMP`（`0xEB`）或用 NOP 消除 `JNE`。
3. **立即数与常量池修改**：篡改指令中内嵌立即数或 `.rdata`/`.data` 常量系数。
4. **函数返回值劫持**：向函数首部写入 `mov eax, 1; ret`（`B8 01 00 00 00 C3`）或 x64 版本 `48 C7 C0 01 00 00 00 C3`。
5. **Xbyak 运行时动态生成补丁**：在运行时生成复杂条件覆写逻辑。

如果程序仅在单点通过 `if (CheckIntegrity())` 判定，攻击者只需再补丁该校验分支即可整体绕过。有效防御必须结合**签名校验、分散式密钥耦合校验与操作系统内存页硬隔离**。

## 核心防御架构

| 篡改路径 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| 磁盘 PE 字节补丁（`.text`/`.rdata`） | Authenticode 数字签名 + 运行期 `WinVerifyTrust` 核验自身映像与关键依赖 DLL | 需校验证书主体指纹（Pinning）而非仅检查“签名是否有效”，防止攻击者重签自签名证书 |
| 内存 `VirtualProtect(PAGE_EXECUTE_READWRITE)` | 启动启用 ACG（`ProcessDynamicCodePolicy`）禁止代码页改为可写或动态分配执行页 | 阻断一切运行期 `WriteProtectedBytes` 与 Xbyak 动态代码注入 |
| 局部 `0x74 -> 0xEB` / `0x90` / `mov eax, 1; ret` | 多处分散计算关键代码片段 SHA-256/CRC32，并与后续配置/资源解密密钥做 XOR/HKDF 绑定 | 消除单个 `VerifyIntegrity() -> bool` 布尔瓶颈，使任意字节篡改直接导致核心密钥派生出错 |
| 内存页写时复制（Copy-on-Write）补丁 | 运行时扫描 `.text` 页保护属性，禁止出现 `PAGE_EXECUTE_WRITECOPY` 或 `PAGE_EXECUTE_READWRITE` | 正常映射的共享只读代码页始终为 `PAGE_EXECUTE_READ`（`0x20`） |
| 校验分支与返回值单点劫持 | 将授权与核心能力计算移至服务端，客户端接收签名能力令牌而非单纯布尔标志 | 避免 `CheckLicense() -> 0/1` 这类极易被 `B8 01 00 00 00 C3` 接管的单点接口 |

## 加固实现与检测代码

以下 Python 脚本实现 PE 文件 `.text` 与 `.rdata` 节区的离线基线哈希计算及篡改比对（同时扫描常见函数返回值劫持与大片 NOP 序列），C++ 示例展示运行时 `.text` 页属性巡检与自身 Authenticode 校验：

```python
"""pe_integrity_guard.py: 计算并核验 PE 代码/只读数据节区完整性及常见补丁模式"""
from __future__ import annotations
import hashlib
import re
import struct
from typing import Dict, List

RETURN_HIJACK_PATTERNS = (
    ("x86_mov_eax_1_ret", re.compile(rb"\xB8\x01\x00\x00\x00\xC3")),
    ("x64_mov_rax_1_ret", re.compile(rb"\x48\xC7\xC0\x01\x00\x00\x00\xC3")),
    ("nop_sled_6plus", re.compile(rb"\x90{6,}")),
)


def parse_pe_sections(pe_bytes: bytes) -> Dict[str, dict]:
    if pe_bytes[:2] != b"MZ":
        raise ValueError("Invalid DOS header")
    lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[lfanew:lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")
    num_sections = struct.unpack_from("<H", pe_bytes, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", pe_bytes, lfanew + 20)[0]
    sec_off = lfanew + 24 + opt_size

    sections: Dict[str, dict] = {}
    for idx in range(num_sections):
        entry = pe_bytes[sec_off + idx * 40:sec_off + (idx + 1) * 40]
        name = entry[:8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, rva, raw_size, raw_ptr, _, _, _, _, chars = struct.unpack_from("<IIIIIIHHI", entry, 8)
        raw_data = pe_bytes[raw_ptr:raw_ptr + raw_size]
        sections[name] = {
            "rva": rva,
            "raw_ptr": raw_ptr,
            "raw_size": raw_size,
            "characteristics": chars,
            "sha256": hashlib.sha256(raw_data).hexdigest(),
            "data": raw_data,
        }
    return sections


def detect_section_tampering(baseline_hashes: Dict[str, str], candidate_pe: bytes) -> List[dict]:
    current = parse_pe_sections(candidate_pe)
    findings = []
    for sec_name, expected_hash in baseline_hashes.items():
        sec = current.get(sec_name)
        if not sec:
            findings.append({"section": sec_name, "issue": "missing_section"})
            continue
        if sec["sha256"] != expected_hash:
            patterns = [label for label, rx in RETURN_HIJACK_PATTERNS if rx.search(sec["data"])]
            findings.append({
                "section": sec_name,
                "issue": "hash_mismatch",
                "expected": expected_hash,
                "actual": sec["sha256"],
                "suspicious_patterns": patterns,
            })
    return findings


if __name__ == "__main__":
    # 构造带 .text 节的最小 PE64 测试样本
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x80 + 6, 1)      # NumberOfSections = 1
    struct.pack_into("<H", buf, 0x80 + 20, 0xF0)  # SizeOfOptionalHeader
    sec_hdr = 0x80 + 24 + 0xF0
    buf[sec_hdr:sec_hdr + 5] = b".text"
    struct.pack_into("<IIII", buf, sec_hdr + 8, 0x40, 0x1000, 0x40, 0x200)
    buf[0x200:0x210] = b"\x48\x83\xEC\x28\x33\xC0\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC"

    base_secs = parse_pe_sections(bytes(buf))
    baseline = {".text": base_secs[".text"]["sha256"]}
    assert detect_section_tampering(baseline, bytes(buf)) == []

    patched = bytearray(buf)
    patched[0x200:0x208] = b"\x48\xC7\xC0\x01\x00\x00\x00\xC3"  # 返回值劫持
    alerts = detect_section_tampering(baseline, bytes(patched))
    assert len(alerts) == 1 and "x64_mov_rax_1_ret" in alerts[0]["suspicious_patterns"]
    print("Code patching defense self-check passed.")
```

以下 C++ 片段展示运行期检测 `.text` 代码页是否因内存补丁而丧失纯只读执行属性（`PAGE_EXECUTE_READ`）：

```cpp
// text_page_protection_check.cpp: 检测代码段是否出现 WRITECOPY 或 RWX 篡改痕迹
#include <windows.h>
#include <cstdint>

bool VerifyCodeSectionReadOnly(HMODULE hMod) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        uintptr_t start = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
        uintptr_t end = start + sec[i].Misc.VirtualSize;

        MEMORY_BASIC_INFORMATION mbi = {};
        for (uintptr_t cur = start; cur < end; cur += mbi.RegionSize) {
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi))) return false;
            if (mbi.Protect != PAGE_EXECUTE_READ) {
                // 出现 PAGE_EXECUTE_READWRITE 或 PAGE_EXECUTE_WRITECOPY 说明代码页被修改
                return false;
            }
        }
    }
    return true;
}
```

## 防御工作流

```text
1. 签名与发布基线：对所有 PE 产物签署 Authenticode 证书，并记录 .text / .rdata 节区 SHA-256 哈希清单
2. 消除布尔校验单点：将单纯返回 TRUE/FALSE 的关键检查与核心业务加解密密钥耦合，避免被 mov eax, 1; ret 替换
3. 启动激活内存护盾：启用 ACG 禁止 VirtualProtect 改写代码段保护属性，结合 CFG 与 CET 阻断跳转劫持
4. 周期与交叉完整性核验：在多条独立路径执行磁盘 WinVerifyTrust 证书钉扎检查与内存页 PAGE_EXECUTE_READ 核验
```

## 验证与判定标准

- **字节补丁检出**：对 `.text` 内任意 1 字节实施 NOP（`0x90`）、条件跳转反转（`0x74 -> 0xEB`）或返回值劫持（`48 C7 C0 01 00 00 00 C3`）后，`detect_section_tampering` 必须准确检出哈希失配与补丁模式。
- **内存页属性异常捕捉**：在未启用 ACG 的测试样本上执行 `VirtualProtect(.text, ..., PAGE_EXECUTE_READWRITE)` 写入补丁后，`VerifyCodeSectionReadOnly` 必须返回 `false`。
- **ACG 硬阻断验证**：启用 `ProcessDynamicCodePolicy` 后，`WriteProtectedBytes` 中的 `VirtualProtect(..., PAGE_EXECUTE_READWRITE, ...)` 必须直接失败返回 `FALSE`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 计算发布二进制与各节区哈希基线 | `hash_file`、`triage_pe` | 提取文件哈希、签名信息及节区特征 |
| 识别易被补丁的单点条件分支 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` | 排查孤立的布尔返回函数与直接 `test eax, eax; jz` 分支 |
| 生成异常补丁特征 YARA 规则 | `make_yara_stub` | 监测异常返回值覆写与代码段篡改残留 |
| 检索红蓝成对参考 | `kb_router` | 对照 [01-code-patching.md](01-code-patching.md) 验证全模式覆盖 |
