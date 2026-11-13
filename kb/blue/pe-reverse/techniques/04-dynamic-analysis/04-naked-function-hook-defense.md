---
id: "pe-reverse/04-dynamic-analysis/04-naked-function-hook-defense"
title: "Naked 汇编跳板 Hook 防护与未映射代码检测"
title_en: "Naked Assembly Gateway Hook Defense and Unbacked Code Detection"
summary: >
  针对 __declspec(naked) 与 MASM 汇编跳板利用 VirtualAlloc 分配 Gateway、pushad/pushfd 保存寄存器、
  Detour32 写入 5 字节跳转以及 GetAsyncKeyState 热键动态开关 Hook 的隐蔽手法，提供 CET 影子栈、
  持续入口完整性哈希、线程起始地址溯源及未映射可执行内存巡检方案。
summary_en: >
  Defense against __declspec(naked) and MASM gateway hooks that allocate RWX gateways, spill
  registers via pushad/pushfd, install Detour32 jumps, and toggle hooks with GetAsyncKeyState.
  Covers CET shadow stacks, continuous prologue hashing, thread start-address checks, and
  unbacked executable page scanning.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "naked function"
  - "gateway"
  - "Detour32"
  - "GetAsyncKeyState"
  - "MEM_PRIVATE"
  - "CET"
  - "Shadow Stack"
  - "汇编跳板检测"
mcp_tools:
  - triage_pe
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - search_pattern
  - make_yara_stub
  - kb_router
keywords:
  - "naked hook defense"
  - "gateway detection"
  - "CET shadow stack"
  - "unbacked executable memory"
  - "hotkey hook detection"
  - "prologue hash"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "anti-hook"
  - "CET"
  - "memory-scanner"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/04-naked-function-hook"
  - "pe-reverse/04-dynamic-analysis/02-trampoline-detour-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/04-naked-function-hook"
---
# Naked 汇编跳板 Hook 防护与未映射代码检测

## 防御目标与威胁面

在 [04-naked-function-hook.md](../../../../red/pe-reverse/techniques/04-dynamic-analysis/04-naked-function-hook.md) 中，攻击者通过 `__declspec(naked)` 或 x64 MASM 汇编构建极简 Gateway（`pushad`/`pushfd` 或手写 volatile 寄存器压栈 + `call` 回调 + 恢复寄存器 + 原指令 + `jmp` 跳回），并借助 `Detour32` 修改目标入口以及 `GetAsyncKeyState(VK_HOME/VK_END)` 实现运行时按需热切换——在非激活窗口期甚至会临时恢复原始字节以逃避单次启动自检。

针对此类极简跳板与动态热切换 Hook，防御设计需覆盖：

1. **硬件与系统级阻断**：激活 ACG 禁止动态生成 Gateway 页，开启 CET Shadow Stack 捕获控制流偏离。
2. **持续周期性入口哈希校验**：不在启动时只查一次，而是在核心业务调用链与随机周期内校验函数入口与已知基线字节，捕获热键切换窗口。
3. **未映射可执行内存与热键线程猎捕**：扫描 `MEM_PRIVATE` 可执行页及 `Win32StartAddress` 落于签名模块外的线程（如隐藏输入轮询线程）。

## 核心防御架构

| 攻击手法 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| `VirtualAlloc(..., PAGE_EXECUTE_READWRITE)` 构造 `Gateway32` | 启用 ACG（`ProcessDynamicCodePolicy`）禁止分配 RWX/动态可执行页 | 彻底消除进程内动态写入并执行汇编跳板的可能 |
| `Detour32` 写入 `0xE9` 相对跳转至汇编跳板 | 多点周期校验关键函数入口字节 + CFG + CET `/CETCOMPAT` | 检查必须内嵌在多个独立业务路径中，不能仅做启动单次校验 |
| `VK_HOME`/`VK_END` 热键按需恢复原始字节绕过单次检查 | 引入调用瞬时前置校验（Call-Site Prologue Check）与时间随机巡检 | 每次进入敏感函数前核验前 8 字节，捕获正在生效的劫持窗口 |
| 独立输入循环线程调用 `GetAsyncKeyState` | 枚举进程线程查询 `ThreadQuerySetWin32StartAddress` | 任何起始地址不在已签名 `MEM_IMAGE` 模块范围的线程均标记为异常注入 |

## 加固实现与检测代码

以下 C++ 代码展示进程内遍历内存区域检测未关联模块的 `MEM_PRIVATE` 可执行 Gateway，并结合线程起始地址校验捕捉非法热键轮询线程：

```cpp
// naked_gateway_detector.cpp: 检测未映射可执行跳板页与异常线程入口
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdint>

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

bool IsAddressInSignedModule(uintptr_t addr) {
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(addr), &hMod)) {
        return false; // 地址不属于任何已加载模块（典型的 MEM_PRIVATE 跳板/shellcode）
    }
    return true;
}

std::vector<uintptr_t> ScanUnbackedExecutablePages() {
    std::vector<uintptr_t> suspicious;
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    uintptr_t cur = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi = {};
    while (cur < maxAddr && VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi))) {
        bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (mbi.State == MEM_COMMIT && isExec && mbi.Type != MEM_IMAGE) {
            suspicious.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress));
        }
        cur += mbi.RegionSize;
    }
    return suspicious;
}

std::vector<DWORD> FindForeignThreads() {
    std::vector<DWORD> flagged;
    auto NtQIT = reinterpret_cast<pNtQueryInformationThread>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (!NtQIT) return flagged;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return flagged;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD selfPid = GetCurrentProcessId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            uintptr_t startAddr = 0;
            if (NtQIT(hThread, static_cast<THREADINFOCLASS>(9), &startAddr, sizeof(startAddr), nullptr) == 0) {
                if (!IsAddressInSignedModule(startAddr)) {
                    flagged.push_back(te.th32ThreadID);
                }
            }
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return flagged;
}
```

以下 Python 辅助脚本对可疑内存块扫描典型 32/64 位 Naked Gateway 机器码特征（`pushad; pushfd` 或 x64 批量 volatile 寄存器保存序列 + 尾随 `jmp`）：

```python
"""scan_naked_gateway.py: 离线扫描可疑内存页中的 Naked Hook Gateway 特征"""
from __future__ import annotations
import re

NAKED_X86_GATEWAY_RE = re.compile(rb"\x60\x9C.{1,64}\x9D\x61.{0,32}\xE9")
NAKED_X64_SPILL_RE = re.compile(rb"\x50\x51\x52\x41\x50\x41\x51")


def scan_gateway_patterns(blob: bytes) -> list[dict]:
    hits = []
    for m in NAKED_X86_GATEWAY_RE.finditer(blob):
        hits.append({"arch": "x86", "offset": hex(m.start()), "length": len(m.group(0))})
    for m in NAKED_X64_SPILL_RE.finditer(blob):
        hits.append({"arch": "x64", "offset": hex(m.start()), "length": len(m.group(0))})
    return hits


if __name__ == "__main__":
    # 模拟 x86 Gateway32 机器码片段: pushad; pushfd; push imm32; call rel32; popfd; popad; nop*2; jmp rel32
    sample = b"\x00" * 8 + b"\x60\x9C\x68\x10\x20\x30\x40\xE8\x01\x00\x00\x00\x9D\x61\x90\x90\xE9\xAA\xBB\xCC\xDD"
    res = scan_gateway_patterns(sample)
    assert len(res) == 1 and res[0]["arch"] == "x86" and res[0]["offset"] == "0x8"
    print("Naked gateway pattern scan self-check passed.")
```

## 防御工作流

```text
1. 启用硬件与系统缓解：编译加入 /CETCOMPAT 与 /guard:cf，运行时激活 ACG 阻断 VirtualAlloc(RWX) 分配
2. 模块与线程白名单核查：定期枚举线程 Win32StartAddress，确认不存在落于未映射区域的轮询/热键线程
3. 持续性入口验证：在敏感操作前内联前 8 字节哈希检查，消除热键开关（VK_HOME/VK_END）带来的检查盲区
4. 未映射执行页巡检：对 VirtualQuery 返回 MEM_PRIVATE 且具可执行属性的页面执行阻断与转储取证
```

## 验证与判定标准

- **Gateway 特征捕获**：将模拟的 `pushad; pushfd; ...; popfd; popad; ...; jmp` 机器码写入测试缓冲区后，`scan_gateway_patterns` 必须准确检出偏移与架构分类。
- **异常线程与页识别**：测试进程内存在 `MEM_PRIVATE` 可执行页或起始地址不在已加载模块中的线程时，`ScanUnbackedExecutablePages` 与 `FindForeignThreads` 必须返回对应基址与线程 ID。
- **热键切换检测**：在开启调用点前置入口校验后，按下切换热键安装 `Detour32` 的瞬间，下一次业务调用必须立即命中入口不匹配并中止敏感流程。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查 `/guard:cf` 与段属性 | `triage_pe` | 确认 CET/CFG 编译选项及各节区权限 |
| 提取高敏目标函数入口偏移 | `ghidra_headless_analyze`、`ghidra_summary_function_detail` | 生成需要做调用点字节核验的关键函数清单 |
| 搜索二进制或转储中的 Gateway 机器码 | `search_pattern`、`make_yara_stub` | 生成针对 `60 9C ... 9D 61` 与 `50 51 52 41 50 41 51` 的 YARA 规则 |
| 检索红蓝成对文档 | `kb_router` | 对照 [04-naked-function-hook.md](../../../../red/pe-reverse/techniques/04-dynamic-analysis/04-naked-function-hook.md) 校验防护覆盖 |
