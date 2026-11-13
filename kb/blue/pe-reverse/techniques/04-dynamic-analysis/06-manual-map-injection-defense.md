---
id: "pe-reverse/04-dynamic-analysis/06-manual-map-injection-defense"
title: "手动映射（Manual Map）无痕注入检测与防护"
title_en: "Manual Map Stealth Injection Detection and Defense"
summary: >
  针对绕过 LoadLibrary 与 LdrRegisterDllNotification 的 Manual Map 注入手法（VirtualAllocEx 分配
  RWX 映像、手写重定位与 IAT 填充、Shellcode 调用 DllMain），提供 ACG/CFG 拦截、MEM_PRIVATE
  可执行区段巡检、线程 Win32StartAddress 归属核验及 PE 残余特征扫描方案。
summary_en: >
  Defense and detection against Manual Map DLL injection that bypasses LoadLibrary and module
  lists via VirtualAllocEx, manual relocations, manual IAT resolution, and shellcode DllMain calls.
  Covers ACG/CFG enforcement, MEM_PRIVATE executable scanning, thread origin verification, and
  ETW-Ti correlation.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "manual map"
  - "MEM_PRIVATE"
  - "VirtualAllocEx"
  - "CFG"
  - "ACG"
  - "unbacked module"
  - "ETW-Ti"
  - "无痕注入检测"
mcp_tools:
  - triage_pe
  - search_pattern
  - make_yara_stub
  - make_sigma_stub
  - kb_router
keywords:
  - "manual map detection"
  - "unbacked executable memory"
  - "MEM_PRIVATE"
  - "CFG"
  - "ACG"
  - "ETW-Ti"
  - "thread start address"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "manual-map"
  - "memory-forensics"
  - "CFG"
  - "ACG"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/06-manual-map-injection"
  - "pe-reverse/04-dynamic-analysis/01-dll-injection-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/06-manual-map-injection"
---
# 手动映射（Manual Map）无痕注入检测与防护

## 防御目标与威胁面

在 [06-manual-map-injection.md](../../../../red/pe-reverse/techniques/04-dynamic-analysis/06-manual-map-injection.md) 中，攻击者规避 `LoadLibrary` 与 `LdrRegisterDllNotification`，通过在目标进程调用 `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)` 分配一块 `SizeOfImage` 大小的内存，手工复制 PE Header 与各节区、修正基址重定位（`IMAGE_DIRECTORY_ENTRY_BASERELOC`）、手动解析填充 IAT，并写入一小段 Shellcode 通过 `CreateRemoteThread` 执行 `DllMain`。

由于此类映射不进入 `PEB->Ldr` 链表，常规 `EnumProcessModules` 无法发现，但其在内存类型、页保护、控制流位图与线程源头上必然留下不可消除的异常指纹：

1. **非映像页类型（`MEM_PRIVATE`）**：`VirtualAllocEx` 分配的内存类型为 `MEM_PRIVATE`，而合法加载的 PE 模块由 Section 对象映射，类型必为 `MEM_IMAGE`。
2. **CFG 位图缺失**：手动映射代码及执行 `DllMain` 的 Shellcode 未在进程 CFG 位图中登记有效调用目标，`call rax` 在开启 CFG 的进程中会触发崩溃。
3. **跨进程 RWX 与线程异常**：`ETW-Ti` 与内核回调会忠实记录远程分配可执行内存与指向 `MEM_PRIVATE` 的远程线程。

## 核心防御架构

| 攻击特征 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)` 映射映像与 Shellcode | 启用 ACG（`ProcessDynamicCodePolicy`）+ 内核 `ObRegisterCallbacks` 剥离 `PROCESS_VM_OPERATION` | 阻止外部进程在目标地址空间申请可写可执行或未映射可执行页 |
| Shellcode `mov rax, entryPoint; call rax` 调用 `DllMain` | 启用 CFG（`/guard:cf` + `ProcessControlFlowGuardPolicy`） | CFG 校验 `rax` 不在系统登记的合法映像目标位图中，立即触发 Fast-Fail 终止 |
| 规避 `PEB->Ldr` 模块列表检查 | 运行时枚举所有 `MEM_COMMIT` 可执行页，校验 `mbi.Type == MEM_IMAGE` 且对应已签名模块 | 即使攻击者抹除内存中的 `MZ`/`PE` 魔数，`MEM_PRIVATE` + 可执行属性仍直接暴露 |
| 外部进程通过 `WriteProcessMemory` 写入节区与 IAT | 启用 ETW-Ti（`ALLOCVM_REMOTE` / `WRITEVM_REMOTE`）与堆栈回溯关联 | 将未关联磁盘映像的 `MEM_PRIVATE` 可执行区段和异常线程起始地址直接上报告警 |

## 加固实现与检测代码

以下 C++ 检测函数在进程内部或外部分析器中遍历虚拟内存页，结合 `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` 与 PE 特征启发式识别隐藏的手动映射模块，并检查当前进程是否受 CFG/ACG 保护：

```cpp
// manual_map_detector.cpp: 检测未通过 LoadLibrary 映射的 MEM_PRIVATE 可执行映像
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <vector>

struct SuspiciousRegion {
    uintptr_t base;
    SIZE_T size;
    DWORD protect;
    bool hasPeHeader;
};

static bool LooksLikePeHeader(const uint8_t* mem, SIZE_T avail) {
    if (avail < 0x100) return false;
    if (mem[0] == 'M' && mem[1] == 'Z') {
        uint32_t lfanew = *reinterpret_cast<const uint32_t*>(mem + 0x3C);
        if (lfanew < avail - 4 &&
            mem[lfanew] == 'P' && mem[lfanew + 1] == 'E' &&
            mem[lfanew + 2] == 0 && mem[lfanew + 3] == 0) {
            return true;
        }
    }
    return false;
}

std::vector<SuspiciousRegion> DetectManualMappedRegions() {
    std::vector<SuspiciousRegion> findings;
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    uintptr_t cur = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t maxA = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi = {};
    while (cur < maxA && VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi))) {
        bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        // 关键判定: 有效 PE 模块必须为 MEM_IMAGE；MEM_PRIVATE/MEM_MAPPED 上的可执行代码高度可疑
        if (mbi.State == MEM_COMMIT && isExec && mbi.Type != MEM_IMAGE) {
            bool hasPe = false;
            if (mbi.Protect != PAGE_EXECUTE) {
                hasPe = LooksLikePeHeader(reinterpret_cast<const uint8_t*>(mbi.BaseAddress), mbi.RegionSize);
            }
            findings.push_back({
                reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                mbi.RegionSize,
                mbi.Protect,
                hasPe
            });
        }
        cur += mbi.RegionSize;
    }
    return findings;
}
```

以下 Python 辅助脚本对进程内存区域清单与转储片段执行无痕注入判定（包括识别已被擦除 `MZ/PE` 头的节区模式，如 `.text`/`.rdata`/`.reloc` 残留或标准 `ExecuteDllMain` 引导 shellcode 模式）：

```python
"""detect_manual_map.py: 基于页类型与引导 Shellcode/PE 结构特征识别手动映射"""
from __future__ import annotations
import re

SHELLCODE_LOADER_RE = re.compile(rb"\x48\x83\xEC\x28\x48\xB9.{8}\x48\xC7\xC2\x01\x00\x00\x00")


def classify_memory_regions(regions: list[dict]) -> list[dict]:
    alerts = []
    for reg in regions:
        is_exec = reg.get("protect", "") in {"RX", "RWX", "X", "WCX"}
        mem_type = reg.get("type", "")
        data = reg.get("sample_bytes", b"")
        if is_exec and mem_type != "MEM_IMAGE":
            indicators = ["unbacked_exec_page"]
            if data.startswith(b"MZ"):
                indicators.append("pe_magic_in_private_mem")
            if SHELLCODE_LOADER_RE.search(data):
                indicators.append("dllmain_bootstrap_shellcode")
            alerts.append({"base": reg.get("base"), "indicators": indicators})
    return alerts


if __name__ == "__main__":
    mock_regions = [
        {"base": "0x7ff700000000", "type": "MEM_IMAGE", "protect": "RX", "sample_bytes": b"MZ\x90\x00"},
        {
            "base": "0x1d400000000",
            "type": "MEM_PRIVATE",
            "protect": "RWX",
            "sample_bytes": b"\x48\x83\xEC\x28\x48\xB9" + b"\x00" * 8 + b"\x48\xC7\xC2\x01\x00\x00\x00\x4D\x31\xC0",
        },
    ]
    hits = classify_memory_regions(mock_regions)
    assert len(hits) == 1
    assert "dllmain_bootstrap_shellcode" in hits[0]["indicators"]
    print("Manual map detection self-check passed.")
```

## 防御工作流

```text
1. 强制进程缓解：启用 CFG (/guard:cf) 与 ACG (ProcessDynamicCodePolicy)，在内核/操作系统层直接阻断手动映射所需的 RWX 分配与未登记间接跳转
2. 句柄访问控制：通过内核 ObRegisterCallbacks 对非白名单进程移除 PROCESS_VM_WRITE 与 PROCESS_VM_OPERATION
3. 周期内存巡检：扫描进程内所有 MEM_COMMIT 可执行页，对任何 Type != MEM_IMAGE 的区域立即标记并校验线程 StartAddress 归属
4. 擦头对抗检测：即使目标擦除了 MZ/PE 头，结合 MEM_PRIVATE + 节区对齐结构 + ETW-Ti 远程写内存关联事件直接锁定注入源
```

## 验证与判定标准

- **CFG 阻断验证**：在开启 CFG 的目标进程内，通过手动映射 Shellcode 执行 `mov rax, entryPoint; call rax` 时，必须触发控制流保护异常并立即终止恶意执行。
- **未映射页检出**：向测试进程注入 `MEM_PRIVATE` `RWX` 块或引导 Shellcode 后，`DetectManualMappedRegions` 与 `classify_memory_regions` 必须检出该区域基址并标注 `unbacked_exec_page` 指标。
- **无漏报擦头样本**：在人工抹除测试缓冲区前 0x400 字节的 `MZ/PE` 头部后，基于 `mbi.Type != MEM_IMAGE && isExec` 的判定仍必须稳定告警。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 验证目标二进制 CFG 与签名基线 | `triage_pe` | 检查 `GUARD_CF` 启用情况及合法依赖模块列表 |
| 生成手动映射与 Shellcode YARA 规则 | `search_pattern`、`make_yara_stub` | 捕获 `ExecuteDllMain` 引导序列与典型无头 PE 节特征 |
| 生成跨进程内存分配 Sigma 检测 | `make_sigma_stub` | 关联 Sysmon Event ID 8/10 与非映像可执行内存告警 |
| 检索红蓝成对参考 | `kb_router` | 对照 [06-manual-map-injection.md](../../../../red/pe-reverse/techniques/04-dynamic-analysis/06-manual-map-injection.md) 评估对抗效果 |
