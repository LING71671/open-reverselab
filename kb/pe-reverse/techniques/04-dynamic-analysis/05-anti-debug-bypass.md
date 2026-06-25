# 反调试检测与绕过

## 场景

目标 PE 有反调试保护（IsDebuggerPresent、NtGlobalFlag、PEB 标志），附加调试器后立即退出/行为异常。

## 输入信号

- x64dbg 附加后目标闪退或静默退出
- 目标在无调试器时正常运行
- 导入表有 `IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`
- 代码中存在 `int 3` 或 `rdtsc` 时间差检测

## 反调试清单

### 1. PEB->BeingDebugged (最常用)

```cpp
// 目标检测方式:
BOOL IsDebugged_PEB() {
    // x64: PEB 在 GS:[0x60]
    // x86: PEB 在 FS:[0x30]
    PPEB peb = (PPEB)__readgsqword(0x60);
    return peb->BeingDebugged;  // +0x02
}

// 绕过: 直接清零
void Bypass_PEB() {
    uint8_t* peb = (uint8_t*)__readgsqword(0x60);
    *(uint8_t*)(peb + 0x02) = 0;  // BeingDebugged = 0
}
```

### 2. IsDebuggerPresent

```cpp
// 目标: IsDebuggerPresent() → 内部读 PEB.BeingDebugged
// 绕过: Hook IsDebuggerPresent 返回 FALSE
// 或: 在调用前 NOP 掉
```

### 3. NtGlobalFlag

```cpp
// 目标: PEB 中 +0xBC (x64: +0xBC, x86: +0x68)
// 调试器启动的进程被设置特定标志位:
// FLG_HEAP_ENABLE_TAIL_CHECK   = 0x10
// FLG_HEAP_ENABLE_FREE_CHECK   = 0x20
// FLG_HEAP_VALIDATE_PARAMETERS = 0x40
// 合计 = 0x70 (调试模式典型值)

// 绕过: 清零 NtGlobalFlag
void Bypass_NtGlobalFlag() {
    uint8_t* peb = (uint8_t*)__readgsqword(0x60);
    *(uint32_t*)(peb + 0xBC) = 0;   // x64 偏移
    // *(uint32_t*)(peb + 0x68) = 0; // x86 偏移
}
```

### 4. NtQueryInformationProcess

```cpp
// 目标: 用 NtQueryInformationProcess(ProcessDebugPort) 检测调试端口
// 调试器附加后内核设置 DebugPort 非零

// 绕过 Frida 脚本:
var NtQueryInfo = Module.findExportByName("ntdll.dll",
    "NtQueryInformationProcess")
Interceptor.attach(NtQueryInfo, {
    onLeave: function(ret) {
        // ProcessDebugPort = 7
        if (this.ProcessInformationClass === 7) {
            Memory.writeUInt(this.ProcessInformation, 0)
        }
    }
})
```

### 5. 时间差检测 (rdtsc / QueryPerformanceCounter)

```cpp
// 目标: 在两个检测点之间测时间, 如果过长→有调试器
// 绕过: 硬断不要停在检测区域内, 或 patch 阈值
```

### 6. 硬件断点检测

```cpp
// 目标: 读 DR0-DR7 调试寄存器, 非零→有硬件断点
// 绕过: Frida 不用硬件断点, or 在检测前清空 DR 寄存器
void ClearHWBp() {
    __asm {
        xor eax, eax
        mov dr0, eax
        mov dr1, eax
        mov dr2, eax
        mov dr3, eax
        mov dr7, eax
    }
}
```

## 绕过实战脚本

```javascript
// Frida 通用反调试绕过
function bypassAntiDebug() {
    // 1. PEB BeingDebugged
    var peb = Process.findModuleByName("target.exe").base
    // ... 但 PEB 不在模块中, 在 TEB 指向的位置
    // 方法: hook IsDebuggerPresent

    var isDebug = Module.findExportByName("kernel32.dll", "IsDebuggerPresent")
    Interceptor.replace(isDebug, new NativeCallback(function() {
        return 0
    }, 'int', []))

    // 2. NtQueryInformationProcess
    var NtQIP = Module.findExportByName("ntdll.dll",
        "NtQueryInformationProcess")
    Interceptor.attach(NtQIP, {
        onEnter: function(args) {
            this.infoClass = args[1].toInt32()
        },
        onLeave: function(ret) {
            if (this.infoClass === 7) { // ProcessDebugPort
                Memory.writeUInt(this.context.rdx, 0)
            }
            if (this.infoClass === 30) { // ProcessDebugObjectHandle
                Memory.writeUInt(this.context.rdx, 0)
            }
            if (this.infoClass === 31) { // ProcessDebugFlags
                Memory.writeUInt(this.context.rdx, 1)
            }
        }
    })

    // 3. CheckRemoteDebuggerPresent
    var checkDbg = Module.findExportByName("kernel32.dll",
        "CheckRemoteDebuggerPresent")
    Interceptor.replace(checkDbg, new NativeCallback(function() {
        return 0
    }, 'int', []))

    // 4. NtSetInformationThread (HideThreadFromDebugger)
    var NtSIT = Module.findExportByName("ntdll.dll",
        "NtSetInformationThread")
    Interceptor.attach(NtSIT, {
        onEnter: function(args) {
            if (args[1].toInt32() === 0x11) { // ThreadHideFromDebugger
                // 阻止隐藏
                args[1] = ptr(0xFFFFFFFF)
            }
        }
    })
}
```

## Patch 模式汇总

```cpp
// 常见反调试函数的 NOP Patch
struct AntiDebugPatch {
    const char* dll;
    const char* func;
    size_t patchLen;     // NOP 长度
} patches[] = {
    {"kernel32.dll", "IsDebuggerPresent", 5},
    {"kernel32.dll", "CheckRemoteDebuggerPresent", 5},
    {"ntdll.dll", "NtQueryInformationProcess", 5},
    {"kernel32.dll", "OutputDebugStringA", 5},   // 反反调试: 阻止字符串
};

// 批量 patch
for (auto& p : patches) {
    void* addr = GetProcAddress(GetModuleHandleA(p.dll), p.func);
    if (addr) WriteNOPSled(addr, p.patchLen);
}
```

## 攻击链

```
目标闪退 → 导入表搜 IsDebuggerPresent/NtQueryInformationProcess
→ Ghidra 搜 GS:[0x60] / FS:[0x30] 引用 → 确认反调试类型
→ x64dbg: 在这些函数设断点 → 回溯调用者
→ Frida: 替换/Hook 反调试函数 → 或 Patch 检测代码为 NOP
→ 验证目标不再闪退
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 搜索 antidebug 行为函数 | `ghidra_summary_call_focus` | 搜索 antidebug 行为函数（behavior="antidebug"） |
| 在反调试 API 处自动生成断点 | `make_x64dbg_breakpoint_script` | 在反调试 API 处自动生成断点（presets="antidebug"） |
| 生成包含反调试绕过的动态分析包 | `make_pe_crypto_unpack_plan` | 生成包含反调试绕过的动态分析包 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
