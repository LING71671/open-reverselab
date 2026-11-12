---
id: "pe-reverse/04-dynamic-analysis/07-direct-syscall-defense"
title: "Direct Syscall 检测与内核态调用链溯源防护"
title_en: "Direct Syscall Detection and Kernel-Side Call Stack Defense"
summary: >
  针对绕过用户态 ntdll.dll Hook 的 Direct Syscall、Hell's Gate/Halo's Gate 动态 SSN 提取及
  运行时 syscall stub 生成技术，提供 ProcessInstrumentationCallback 返回地址校验、内核堆栈回溯
  （ETW-Ti / Call Stack Origin 验证）与 ACG 阻断方案。
summary_en: >
  Detection and defense against Direct Syscalls, Hell's Gate/Halo's Gate dynamic SSN extraction,
  and runtime syscall stub generation designed to bypass ntdll.dll hooks. Covers
  ProcessInstrumentationCallback origin validation, kernel stack-walk telemetry (ETW-Ti), and ACG.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "Direct Syscall"
  - "Hell's Gate"
  - "Halo's Gate"
  - "ProcessInstrumentationCallback"
  - "ETW-Ti"
  - "call stack validation"
  - "系统调用检测"
mcp_tools:
  - triage_pe
  - search_pattern
  - make_yara_stub
  - make_sigma_stub
  - ghidra_headless_analyze
  - kb_router
keywords:
  - "direct syscall detection"
  - "ProcessInstrumentationCallback"
  - "kernel stack walk"
  - "ETW-Ti"
  - "Hell's Gate defense"
  - "syscall origin"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "direct-syscall"
  - "ETW-Ti"
  - "instrumentation-callback"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/07-direct-syscall"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/07-direct-syscall"
---
# Direct Syscall 检测与内核态调用链溯源防护

## 防御目标与威胁面

在 [07-direct-syscall.md](07-direct-syscall.md) 中，攻击者为绕过安全产品或调试器在 `ntdll.dll` 部署的 Inline/IAT Hook，采取三种手段：

1. 从内存或磁盘 `C:\Windows\System32\ntdll.dll` 提取系统调用号（SSN，如 Hell's Gate / Halo's Gate）。
2. 在自身代码段或 MASM stub 中硬编码 `mov r10, rcx; mov eax, ssn; syscall; ret`。
3. 通过 `VirtualAlloc(..., PAGE_EXECUTE_READWRITE)` 在运行时动态拼装 `4C 8B D1 B8 <ssn> 0F 05 C3` stub 执行系统调用。

**核心防御认知**：Direct Syscall 仅绕过了**用户态 `ntdll.dll` 的 Hook 点**，但系统调用最终仍必须进入 Windows 内核（`ntoskrnl.exe`）。因此，**内核回调、ETW-Ti 事件与调用栈源头验证**完全不受用户态绕过影响。

## 核心防御架构

| 攻击手法 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| 运行时 `VirtualAlloc(RWX)` 生成 syscall stub | 启用 ACG（`ProcessDynamicCodePolicy`）禁止动态可执行页 | 阻断 `GenerateSyscallStub` 在堆或私有内存中写入可执行机器码 |
| 不经过 `ntdll.dll` 直接执行 `syscall` | 注册 `ProcessInstrumentationCallback`（`NtSetInformationProcess` info class `40`） | 每次 `syscall` 返回用户态瞬间检查 `RIP`/栈帧是否来自 `ntdll.dll` 或 `win32u.dll` 合法区间 |
| 规避用户态 API 监控执行敏感操作 | 部署 ETW-Ti 与内核回调（`ObRegisterCallbacks`、`PsSetCreateThreadNotifyRoutine`）+ 内核调用栈回溯 | 内核捕获 `NtAllocateVirtualMemory`/`NtWriteVirtualMemory` 时回溯用户态栈帧，发现调用者不在 `ntdll` 即触发高危告警 |
| 二进制内嵌手写 `syscall` stub 与 Hell's Gate 解析 | 静态 YARA 扫描非 `ntdll` 模块中的 `0F 05`（`syscall`）与 `4C 8B D1 B8` 模式 | 正常商业应用几乎不直接包含 `syscall` 指令（除系统运行时与极少数反作弊/DRM） |

## 加固实现与检测代码

以下 C++ 代码展示如何利用 `ProcessInstrumentationCallback`（或离线栈帧校验逻辑）核验系统调用返回地址是否落在 `ntdll.dll` / `win32u.dll` 的合法代码段范围内；同时附带 Python 脚本对 PE 代码段扫描异常嵌入的 Direct Syscall Stub 字节序列：

```cpp
// syscall_origin_verifier.cpp: 核验 syscall 返回地址是否源于合法系统模块
#include <windows.h>
#include <cstdint>

struct ModuleRange {
    uintptr_t start;
    uintptr_t end;
};

static ModuleRange g_ntdllRange = {};
static ModuleRange g_win32uRange = {};

bool InitSystemModuleRanges() {
    auto getRange = [](const wchar_t* name, ModuleRange& out) -> bool {
        HMODULE hMod = GetModuleHandleW(name);
        if (!hMod) return false;
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
        out.start = reinterpret_cast<uintptr_t>(hMod);
        out.end = out.start + nt->OptionalHeader.SizeOfImage;
        return true;
    };
    bool okNt = getRange(L"ntdll.dll", g_ntdllRange);
    getRange(L"win32u.dll", g_win32uRange); // GUI 进程可选
    return okNt;
}

bool IsLegitimateSyscallOrigin(uintptr_t returnRip) {
    if (returnRip >= g_ntdllRange.start && returnRip < g_ntdllRange.end) return true;
    if (g_win32uRange.end > g_win32uRange.start &&
        returnRip >= g_win32uRange.start && returnRip < g_win32uRange.end) return true;
    return false; // RIP 落于非 ntdll/win32u 区域 -> Direct Syscall 特征
}
```

以下 Python 检测脚本用于在静态分析或内存转储中识别非系统模块内嵌的 x64 Direct Syscall Stub（`mov r10, rcx; mov eax, imm32; syscall; ret` 及变体）与异常 `ntdll.dll` 磁盘读取模式：

```python
"""detect_direct_syscalls.py: 静态/内存扫描非系统 PE 中的 Direct Syscall stub 特征"""
from __future__ import annotations
import re
import struct

# 匹配 x64 典型 direct syscall: mov r10, rcx (4C 8B D1) + mov eax, imm32 (B8 ?? ?? 00 00) + syscall (0F 05)
DIRECT_SYSCALL_RE = re.compile(rb"\x4C\x8B\xD1\xB8(.{2})\x00\x00.{0,16}?\x0F\x05", re.S)


def scan_direct_syscall_stubs(module_name: str, code_bytes: bytes) -> list[dict]:
    if module_name.lower() in {"ntdll.dll", "win32u.dll"}:
        return []
    hits = []
    for m in DIRECT_SYSCALL_RE.finditer(code_bytes):
        ssn = struct.unpack_from("<H", m.group(1), 0)[0]
        hits.append({
            "module": module_name,
            "offset": hex(m.start()),
            "ssn_candidate": hex(ssn),
            "pattern": m.group(0).hex(),
        })
    return hits


if __name__ == "__main__":
    # 模拟攻击者生成的 NtAllocateVirtualMemory stub (SSN=0x18)
    fake_text = b"\x90" * 16 + b"\x4C\x8B\xD1\xB8\x18\x00\x00\x00\x0F\x05\xC3"
    alerts = scan_direct_syscall_stubs("sample_loader.exe", fake_text)
    assert len(alerts) == 1 and alerts[0]["ssn_candidate"] == "0x18"
    assert scan_direct_syscall_stubs("ntdll.dll", fake_text) == []
    print("Direct syscall detection self-check passed.")
```

## 防御工作流

```text
1. 静态与入库扫描：对非系统模块执行 Direct Syscall 指令序列（4C 8B D1 B8 ... 0F 05）与磁盘读取 ntdll.dll 路径特征扫描
2. 进程缓解启用：开启 ACG (ProcessDynamicCodePolicy) 阻断运行时动态生成可执行 syscall stub
3. 内核态与 ETW-Ti 采集：通过内核回调及 ETW-Ti 捕获实际系统调用事件，彻底消除对用户态 ntdll Hook 的单点依赖
4. 调用栈源头校验：借助 ProcessInstrumentationCallback 与内核栈回溯验证系统调用发起地址是否位于 ntdll.dll/win32u.dll
```

## 验证与判定标准

- **Stub 扫描精度**：对包含 `4C 8B D1 B8 18 00 00 00 0F 05 C3` 的普通 PE 样本运行 `scan_direct_syscall_stubs` 必须检出异常偏移与候选 SSN `0x18`，而对 `ntdll.dll` 本身不得产生误报。
- **调用源头判定**：当系统调用返回地址位于非 `ntdll`/`win32u` 地址区间时，`IsLegitimateSyscallOrigin` 必须返回 `false`。
- **ACG 阻断验证**：启用 `ProcessDynamicCodePolicy` 后，运行时通过 `VirtualAlloc(..., PAGE_EXECUTE_READWRITE)` 分配并写入 `GenerateSyscallStub` 机器码必须被拒绝。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 扫描样本 `.text` 内嵌 `syscall` 特征 | `search_pattern`、`make_yara_stub` | 搜索 `4C 8B D1 B8 ?? ?? 00 00 0F 05` 并生成检测规则 |
| 定位潜在 Hell's Gate 解析函数 | `ghidra_headless_analyze` | 排查是否读取 `ntdll.dll` 导出表提取 SSN |
| 生成内核/ETW 异常调用栈 Sigma 规则 | `make_sigma_stub` | 基于非 `ntdll` 源头调用栈生成告警规则 |
| 检索红蓝成对文档 | `kb_router` | 对照 [07-direct-syscall.md](07-direct-syscall.md) 验证防御覆盖 |
