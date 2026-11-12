---
id: "pe-reverse/04-dynamic-analysis/01-dll-injection-defense"
title: "DLL 注入纵深防御与检测"
title_en: "DLL Injection Defense-in-Depth and Detection"
summary: >
  针对 CreateRemoteThread + LoadLibrary、跨进程内存写入与 DllMain 线程委派三类 DLL 注入路径，
  提供进程缓解策略（CIG/ACG）、内核句柄权限收敛（ObRegisterCallbacks）、LdrRegisterDllNotification
  模块加载校验与 ETW-Ti 远程线程遥测检测方案，阻断未签名 DLL 落地与内存注入。
summary_en: >
  Defense-in-depth against DLL injection vectors including CreateRemoteThread + LoadLibrary,
  cross-process memory writes, and DllMain thread delegation. Covers Process Mitigation Policies
  (CIG/ACG), kernel handle stripping (ObRegisterCallbacks), LdrRegisterDllNotification signature
  verification, and ETW-Ti remote thread telemetry.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "CreateRemoteThread"
  - "LoadLibrary"
  - "ProcessSignaturePolicy"
  - "LdrRegisterDllNotification"
  - "WinVerifyTrust"
  - "ObRegisterCallbacks"
  - "ETW-Ti"
  - "DLL 注入防御"
mcp_tools:
  - triage_pe
  - ghidra_summary_imports
  - make_sigma_stub
  - make_yara_stub
  - make_procmon_filters
  - kb_router
keywords:
  - "DLL injection defense"
  - "CIG"
  - "ProcessSignaturePolicy"
  - "LdrRegisterDllNotification"
  - "WinVerifyTrust"
  - "ObRegisterCallbacks"
  - "ETW-Ti"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "anti-injection"
  - "CIG"
  - "ETW-Ti"
  - "Windows-security"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/01-dll-injection"
  - "pe-reverse/04-dynamic-analysis/06-manual-map-injection-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/01-dll-injection"
---
# DLL 注入纵深防御与检测

## 防御目标与威胁面

在 [01-dll-injection.md](01-dll-injection.md) 中，攻击者通常先通过 `CreateToolhelp32Snapshot` 定位目标 PID，再借助 `OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)`、`VirtualAllocEx`、`WriteProcessMemory` 与 `CreateRemoteThread(LoadLibraryA/W)` 将外部 DLL 载入目标进程空间，并在 `DllMain` 中派发工作线程或通过 `FreeLibraryAndExitThread` 卸载隐藏自身。

防御核心在于切断注入链路的三个环节：

1. **权限收敛**：阻断非受信任进程获取 `PROCESS_CREATE_THREAD` 与 `PROCESS_VM_WRITE` 句柄权限。
2. **加载准入**：在用户态与内核态强制校验加载模块的数字签名与路径白名单（CIG 与 `LdrRegisterDllNotification`）。
3. **行为遥测**：捕获 `LoadLibrary` 作为远程线程起始地址、`OpenProcess` 异常掩码及 `LoadImage` 时序异常。

## 核心防御架构

| 攻击环节 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| `OpenProcess` 提权与句柄获取 | 启用 PPL 保护或内核 `ObRegisterCallbacks` 剥离危险权限 | 对非白名单调用方剥离 `PROCESS_CREATE_THREAD`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION` |
| `LoadLibraryA/W` 载入未签名模块 | 启用 CIG（`ProcessSignaturePolicy`）强制仅加载微软或商店签名 DLL | 需在进程启动初期或编译链接阶段通过 `/INTEGRITYCHECK` 与策略 API 激活 |
| 动态生成加载器 stub / 卸载隐藏 | 启用 ACG（`ProcessDynamicCodePolicy`）并注册 `LdrRegisterDllNotification` | 模块加载回调内即刻执行 `WinVerifyTrust` 与路径白名单校验 |
| 扩展点与已知 DLL 劫持 | 禁用扩展点（`ProcessExtensionPointDisablePolicy`）与启用 SafeDllSearchMode | 禁止从非可信工作目录加载同名依赖 DLL |
| 远程线程创建与 `DllMain` 委派 | 启用 ETW-Ti 采集 `THREATINTELLIGENCE_TASK_CREATE_REMOTE_THREAD` 与内核线程回调 | 告警起始地址落于 `LoadLibraryA/W` 或非 `MEM_IMAGE` 区域的跨进程线程创建 |

## 加固实现与检测代码

以下 C++ 示例演示在进程启动入口启用代码完整性保护（CIG）与扩展点禁用策略，并结合 `WinVerifyTrust` 对动态载入模块进行签名校验；同时附带 Python 检测脚本用于在离线状态下核查 PE 编译加固标志与高风险注入导入特征：

```cpp
// dll_injection_hardening.cpp: 启动期启用 CIG 与动态模块签名校验
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <cstdio>

#pragma comment(lib, "wintrust.lib")

bool EnableAntiInjectionMitigations() {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = {};
    sigPolicy.MicrosoftSignedOnly = 1;
    // 若业务依赖第三方自签名插件，可改用 StoreSignedOnly 或配合内部公钥白名单校验
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy))) {
        return false;
    }

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy = {};
    extPolicy.DisableExtensionPoints = 1;
    SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extPolicy, sizeof(extPolicy));

    // 限制 DLL 搜索路径仅限系统目录与安全目录，防止工作目录劫持
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    return true;
}

bool VerifyModuleAuthenticode(LPCWSTR dllPath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = dllPath;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);
    return status == ERROR_SUCCESS;
}
```

以下 Python 校验脚本检查目标 PE 是否开启了基本编译期缓解标志（ASLR、DEP、CFG）以及检测外部注入器常见的 API 导入组合：

```python
"""check_dll_injection_posture.py: 检查 PE 缓解标志与跨进程注入风险导入特征"""
from __future__ import annotations
import struct
from typing import Dict, List, Set

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

INJECTION_API_SET = {
    "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "LoadLibraryA", "LoadLibraryW"
}


def inspect_pe_flags(pe_bytes: bytes) -> Dict[str, object]:
    if pe_bytes[:2] != b"MZ":
        raise ValueError("Not a valid PE header")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", pe_bytes, opt_off)[0]
    dll_char_off = opt_off + (70 if magic == 0x020B else 70)
    dll_chars = struct.unpack_from("<H", pe_bytes, dll_char_off)[0]
    return {
        "is_pe64": magic == 0x020B,
        "aslr": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "dep": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "cfg": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
    }


def score_injector_imports(imports: List[str]) -> Dict[str, object]:
    matched: Set[str] = set(imports) & INJECTION_API_SET
    has_alloc_write = {"VirtualAllocEx", "WriteProcessMemory"}.issubset(matched)
    has_exec = bool(matched & {"CreateRemoteThread", "NtCreateThreadEx"})
    return {
        "matched_apis": sorted(matched),
        "high_risk_injection_pattern": has_alloc_write and has_exec,
    }


if __name__ == "__main__":
    # 构造最小合法 PE64 头做自检
    stub = bytearray(0x200)
    stub[0:2] = b"MZ"
    struct.pack_into("<I", stub, 0x3C, 0x80)
    stub[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", stub, 0x80 + 24, 0x020B)
    struct.pack_into("<H", stub, 0x80 + 24 + 70, 0x4140)  # DYNAMIC_BASE + NX + GUARD_CF
    res = inspect_pe_flags(bytes(stub))
    assert res == {"is_pe64": True, "aslr": True, "dep": True, "cfg": True}
    sig = score_injector_imports(["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])
    assert sig["high_risk_injection_pattern"] is True
    print("DLL injection defense posture self-check passed.")
```

## 防御工作流

```text
1. 编译期加固：为目标二进制开启 /DYNAMICBASE、/NXCOMPAT、/GUARD:CF 与 /INTEGRITYCHECK，并签署 Authenticode 证书
2. 启动期策略激活：在 main/WinMain 最前端调用 SetProcessMitigationPolicy 启用 CIG 与扩展点禁用策略
3. 搜索路径收敛：调用 SetDefaultDllDirectories 锁定系统目录与应用目录，杜绝工作目录 DLL 劫持
4. 载入事件校验：注册 LdrRegisterDllNotification，在模块映射完成瞬间核验签名链与允许路径清单
5. 端点遥测部署：配置 Sysmon Event ID 8 (CreateRemoteThread) 与 ETW-Ti 采集跨进程内存分配与远程线程启动地址
```

## 验证与判定标准

- **CIG 拦截测试**：向已启用 `ProcessSignaturePolicy` 的目标进程执行标准 `CreateRemoteThread + LoadLibrary` 注入未签名 DLL，`LoadLibrary` 必须返回 `NULL` 且 `GetLastError()` 返回 `ERROR_INVALID_IMAGE_HASH`（`0x241`），目标进程内无新增未签名模块。
- **句柄权限收敛**：非特权进程调用 `OpenProcess(PROCESS_ALL_ACCESS, ...)` 时，内核回调生效后实际授予掩码不得包含 `PROCESS_VM_WRITE` 与 `PROCESS_CREATE_THREAD`。
- **遥测告警闭环**：使用 `make_sigma_stub` 或 Sysmon 规则回放注入测试时，日志必须在 5 秒内产出包含源进程、目标进程、`StartFunction=LoadLibraryA/W` 的高置信度告警。
- **编译标志核查**：对发布产物执行 `triage_pe` 与上述脚本检查，`aslr`、`dep`、`cfg` 均必须为 `True`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查目标 PE 编译缓解标志与导入表 | `triage_pe`、`ghidra_summary_imports` | 确认 ASLR/DEP/CFG 开启状态及排查外部注入器特征 API |
| 生成远程线程与 DLL 加载行为规则 | `make_sigma_stub`、`make_yara_stub` | 生成针对 `CreateRemoteThread` + `VirtualAllocEx` 的检测规则 |
| 配置运行时进程监控基线 | `make_procmon_filters` | 生成针对 `LoadImage` 与 `CreateRemoteThread` 的蓝队基线过滤集 |
| 检索红蓝成对参考 | `kb_router`、`kb_read_file` | 检索 [01-dll-injection.md](01-dll-injection.md) 对照攻击链步骤 |
