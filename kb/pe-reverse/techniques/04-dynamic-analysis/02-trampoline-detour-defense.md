---
id: "pe-reverse/04-dynamic-analysis/02-trampoline-detour-defense"
title: "Trampoline Inline Hook 防护与代码段完整性检测"
title_en: "Trampoline Inline Hook Protection and Code Integrity Detection"
summary: >
  针对 Trampoline Hook 在目标函数入口写入 JMP/CALL 跳板、通过 VirtualProtect 修改 .text 页保护
  以及 VirtualAlloc 分配 RWX 跳板内存等攻击手法，提供 ACG 动态代码禁止、CFG/CET 控制流防护
  与运行时 .text 入口字节完整性比对检测机制。
summary_en: >
  Defense against Trampoline inline hooking vectors including prologue JMP/CALL overwrites,
  VirtualProtect RWX transitions on .text, and VirtualAlloc RWX gateway allocations. Covers ACG
  dynamic code blocking, CFG/CET control-flow hardening, and runtime prologue byte integrity checks.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "trampoline"
  - "inline hook"
  - "VirtualProtect"
  - "PAGE_EXECUTE_READWRITE"
  - "ACG"
  - "CFG"
  - "CET"
  - "代码完整性"
mcp_tools:
  - triage_pe
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - search_pattern
  - make_yara_stub
  - kb_router
keywords:
  - "trampoline hook defense"
  - "anti-hook"
  - "ACG"
  - "ProcessDynamicCodePolicy"
  - "CFG"
  - "CET shadow stack"
  - "prologue integrity"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "anti-hook"
  - "ACG"
  - "CFG"
  - "code-integrity"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/02-trampoline-detour"
  - "pe-reverse/08-patch/01-code-patching-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/02-trampoline-detour"
---
# Trampoline Inline Hook 防护与代码段完整性检测

## 防御目标与威胁面

在 [02-trampoline-detour.md](02-trampoline-detour.md) 中，攻击者通过 `VirtualAlloc(..., PAGE_EXECUTE_READWRITE)` 申请跳板内存写入寄存器保存/恢复与回调分发代码，随后调用 `VirtualProtect` 将目标函数入口页改为 `PAGE_EXECUTE_READWRITE`，写入 5 字节相对跳转（`E9 rel32`）或 14 字节绝对跳转（`FF 25 00 00 00 00 + addr`）及 `0x90` NOP 填充实现无感函数劫持。

防御重点在于消除可写可执行内存并建立函数入口字节完整性基线：

1. **禁止动态生成与修改可执行页**：激活 ACG（Arbitrary Code Guard）阻断 `VirtualAlloc(RWX)` 跳板分配及 `VirtualProtect` 将 `.text` 转为可写。
2. **控制流约束**：启用 CFG 与硬件 CET Shadow Stack，使未在编译期登记的跳板间接跳转或异常返回立即触发异常终止。
3. **运行时入口字节核查**：定期或关键路径前比对高敏函数入口字节与磁盘清洁映像（或加密基线哈希），捕获 `E9`、`E8`、`FF 25`、`68 .. C3` 与异常 `90` 填充。

## 核心防御架构

| 攻击步骤 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| `VirtualAlloc(PAGE_EXECUTE_READWRITE)` 创建跳板 | 启用 ACG（`ProcessDynamicCodePolicy.ProhibitDynamicCode = 1`） | 进程内禁止 JIT 或无签名动态代码页；需要 JIT 的组件须拆分为独立受限子进程 |
| `VirtualProtect` 修改 `.text` 页属性为 RWX | ACG 自动拒绝将已映射映像页改写为可执行+可写，并触发拒绝返回 | 配合内核内存保护阻止跨进程 `VirtualProtectEx` 修改代码段 |
| `CALL/JMP` 跳转至外部跳板与回调分发 | 编译启用 `/guard:cf`（CFG）与 `/CETCOMPAT`（Shadow Stack） | 确保所有合法函数指针与回调目标在编译器 CFG 位图登记 |
| 入口覆盖 5~14 字节 `E9`/`FF 25` 或 `NOP` 填充 | 运行时比对关键导出与内部函数入口字节与磁盘原始 `.text` / 基线哈希 | 发现 `MEM_IMAGE` 页被触发写时复制（`PAGE_EXECUTE_WRITECOPY`）或字节偏移即触发熔断 |

## 加固实现与检测代码

以下 C++ 示例展示启动期激活 ACG 与检测函数入口是否被植入常见 x86/x64 Trampoline 跳板或页属性异常：

```cpp
// anti_trampoline_defense.cpp: ACG 启用与函数入口跳板检测
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

bool EnableDynamicCodeGuard() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {};
    policy.ProhibitDynamicCode = 1;
    return SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)) != FALSE;
}

bool HasInlineHookPrologue(const void* funcAddr, const uint8_t* expectedBytes, size_t len) {
    if (!funcAddr || !expectedBytes || len == 0) return true;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(funcAddr, &mbi, sizeof(mbi)) == 0) return true;

    // 1. 正常代码页应为 MEM_IMAGE 且只读可执行，不应出现 RWX 或 Private 页
    if (mbi.Type != MEM_IMAGE) return true;
    if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
        return true;
    }

    const auto* code = reinterpret_cast<const uint8_t*>(funcAddr);
    // 2. 常见跳转 opcode 快速特征匹配
    if (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xE8) return true;
    if (code[0] == 0xFF && code[1] == 0x25) return true; // x64 JMP [RIP+0]
    if (code[0] == 0x48 && code[1] == 0xB8 && len >= 12 &&
        code[10] == 0xFF && code[11] == 0xE0) return true; // MOV RAX, imm64; JMP RAX

    // 3. 与干净字节基线比对
    return std::memcmp(code, expectedBytes, len) != 0;
}
```

以下 Python 脚本可对内存转储或待检二进制区段扫描典型 Trampoline 跳板模式及校验已知基线偏移：

```python
"""detect_trampoline_stubs.py: 离线扫描函数入口是否被写入 JMP/NOP 劫持模式"""
from __future__ import annotations
from typing import List, Tuple

TRAMPOLINE_SIGNATURES = (
    ("rel32_jmp", b"\xE9"),
    ("x64_rip_jmp", b"\xFF\x25\x00\x00\x00\x00"),
    ("nop_sled_5", b"\x90\x90\x90\x90\x90"),
)


def check_prologue_integrity(
    live_bytes: bytes, baseline_bytes: bytes, func_offsets: List[Tuple[str, int, int]]
) -> List[dict]:
    findings = []
    for name, offset, size in func_offsets:
        live = live_bytes[offset:offset + size]
        orig = baseline_bytes[offset:offset + size]
        if live != orig:
            matched_kind = "modified_bytes"
            for label, prefix in TRAMPOLINE_SIGNATURES:
                if live.startswith(prefix):
                    matched_kind = label
                    break
            findings.append({
                "function": name,
                "offset": hex(offset),
                "kind": matched_kind,
                "orig_hex": orig.hex(),
                "live_hex": live.hex(),
            })
    return findings


if __name__ == "__main__":
    clean = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20" + b"\xCC" * 6
    hooked = bytearray(clean)
    hooked[0:5] = b"\xE9\x11\x22\x33\x44"  # 模拟 Trampoline JMP rel32
    alerts = check_prologue_integrity(bytes(hooked), clean, [("CheckLicense", 0, 8)])
    assert len(alerts) == 1 and alerts[0]["kind"] == "rel32_jmp"
    print("Trampoline hook detection self-check passed.")
```

## 防御工作流

```text
1. 编译期启用控制流防护：开启 /guard:cf、/CETCOMPAT 与 /NXCOMPAT，并消除运行期自修改代码需求
2. 进程启动激活 ACG：在初始化阶段调用 SetProcessMitigationPolicy(ProcessDynamicCodePolicy) 阻断 RWX 跳板分配
3. 生成清洁代码段基线：发布阶段提取关键保护函数 RVA 与前 16 字节特征，签名存根或拆片嵌入校验模块
4. 运行时双向验证：核心业务调用前查验 MEMORY_BASIC_INFORMATION.Protect 与字节一致性，异常即安全退出
5. 异常页属性猎捕：周期扫描进程内 MEM_PRIVATE 且具 EXECUTE 属性的页面，结合 YARA 特征定位隐蔽跳板
```

## 验证与判定标准

- **ACG 阻断验证**：在目标进程激活 `ProcessDynamicCodePolicy` 后，尝试执行 `VirtualAlloc(NULL, 4096, ..., PAGE_EXECUTE_READWRITE)` 或 `VirtualProtect(.text, ..., PAGE_EXECUTE_READWRITE)` 均必须失败（返回 `NULL`/`FALSE`，错误码 `ERROR_ACCESS_DENIED`）。
- **跳板写入捕获**：向未启用 ACG 的测试环境函数入口写入 `E9 rel32` 或 `FF 25` 跳转后，`HasInlineHookPrologue` 与 `check_prologue_integrity` 必须准确识别偏移并返回非空告警。
- **CFG / CET 校验**：使用未登记在 CFG 表的动态分配地址执行间接调用时，进程必须触发 `STATUS_STACK_BUFFER_OVERRUN` / fast-fail 终止。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 核查编译期 CFG 与节区属性 | `triage_pe` | 检查 `GUARD_CF`、`NX_COMPAT` 及 `.text` 节区读写执行权限 |
| 提取关键函数基线偏移与字节 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` | 定位高敏保护函数 RVA 与原始 prologue 指令序列 |
| 生成跳板特征扫描规则 | `search_pattern`、`make_yara_stub` | 搜索进程转储或可疑驱动中的 Trampoline 特征码 |
| 检索红蓝成对文档 | `kb_router` | 对照 [02-trampoline-detour.md](02-trampoline-detour.md) 全部技术细节 |
