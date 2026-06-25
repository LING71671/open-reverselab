# 反作弊系统绕过

## 场景

目标游戏集成了商业反作弊系统（EAC、BattlEye、Vanguard、Ricochet），需要在保护下执行内存读写、代码注入或 hook。需要从 usermode 绕过、内核绕过和硬件级绕过多个层次进行对抗。

## 输入信号

- 游戏进程附带反作弊驱动（EAC 的 EasyAntiCheat.sys、BE 的 BEDaisy.sys）
- 反作弊附加后 OpenProcess 返回 ACCESS_DENIED
- 游戏启动时检查虚拟机、调试器、黑名单进程
- Vanguard 需要 TPM 2.0 + Secure Boot 才能启动
- Ricochet/Apex 在 kernel 层 + ML 行为分析

## EAC (Easy Anti-Cheat) 架构与绕过

### 架构概览

```
User Mode:
  EasyAntiCheat.exe — 用户态管理进程 (启动/更新/通信)
  EasyAntiCheat_EOS.dll —  注入游戏进程的检测 DLL

Kernel Mode:
  EasyAntiCheat.sys — 内核驱动 (主要检测层)
    ├── ObRegisterCallbacks → 阻止 handle 打开/读写
    ├── PsSetCreateProcessNotifyRoutine → 进程创建监控
    ├── PsSetCreateThreadNotifyRoutine → 线程创建监控
    ├── PsSetLoadImageNotifyRoutine → 模块加载监控
    ├── KeStackAttachProcess → VAD 验证
    ├── ETW 消费者 → 检测异常 syscall
    └── CmRegisterCallback → 注册表监控
```

### Handle Stripping

```cpp
// EAC 定期扫描系统 handle table 寻找对游戏的开放 handle:
// ZwQuerySystemInformation(SystemHandleInformation) → 遍历所有 HANDLE
// → 检查 HandleTableEntry 中 Object = 游戏 EPROCESS
// → 如果 ObjectType = PsProcessType
// → 且 HandleTable 不属于系统进程或白名单驱动
// → 强制关闭该 handle

// 绕过方法:
// 1. 在 EAC 扫描前关闭 handle, 使用时再打开 (race condition)
// 2. 使用 DuplicateHandle 创建伪装的 handle
// 3. 内核驱动直接使用 PsLookupProcessByProcessId 绕过 handle 层
// 4. DMA 读取 (完全绕过 handle)

// 方法1: 最小化 handle 暴露
HANDLE GetEphemeralHandle(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);
    if (h) {
        // 立即使用后关闭
        DoRead(h);
        CloseHandle(h);
    }
    // EAC 的扫描周期约 50-100ms
    // 在扫描间隙操作成功率最高
}

// 方法3: 内核驱动内部读写
NTSTATUS DrvReadProcessMemory(HANDLE pid,
    PVOID address, PVOID buffer, SIZE_T size) {
    
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
    if (!NT_SUCCESS(status)) return status;
    
    // 在内核中通过 EPROCESS 读写
    KAPC_STATE apc;
    KeStackAttachProcess(targetProcess, &apc);
    
    __try {
        ProbeForRead(address, size, 1);
        RtlCopyMemory(buffer, address, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(targetProcess);
    return status;
}
```

### Thread Hiding

```cpp
// EAC 枚举线程:
// 1. NtQuerySystemInformation(SystemProcessInformation) → 遍历进程线程
// 2. PsSetCreateThreadNotifyRoutine → 记录所有新线程
// 3. 扫描 ETHREAD → Win32StartAddress 是否在非白名单模块

// 线程隐藏:
// 1. 从 PspCidTable 移除 (内核级)
// 2. 设置线程为系统线程 (SystemThread = TRUE)
// 3. 使用 APC (异步过程调用) 执行而非创建线程
// 4. 池喷射 + DKOM (Direct Kernel Object Manipulation)

// APC 执行代码 (无线程创建):
void ApcWorker(HANDLE process, void* shellcode, size_t size) {
    // 将 shellcode 写入目标进程
    // 向目标进程的现有线程排队 APC
    // 线程下次 alertable wait 时执行 shellcode
    // 无 CreateRemoteThread → 无线程创建事件
}

// 从 PspCidTable 移除:
// ETHREAD 的 Cid 结构:
// +0x000 UniqueThread : 线程 ID
// +0x008 UniqueProcess : 进程 ID
// 将 UniqueProcess 设为 0 可绕过大多数枚举
// (但要保留正确值以便后续恢复)
```

## BattlEye 架构与绕过

### BEDaisy.sys 分析

```cpp
// BattlEye 内核驱动 BEDaisy.sys:
// 特征: 约 2-3MB, 频繁更新 (每 2-3 天新 hash)
// 静态反分析: VMP/themida 保护
// 加载方式: 通过 sxstrace.exe (越狱) 绕过驱动签名

// BE 检测层次:
// Layer 1: 用户态 — BEClient.dll (游戏进程内)
//   - 扫描窗口类名
//   - 扫描进程名/模块名
//   - 检测调试器 API (IsDebuggerPresent)
//   - CRC 校验游戏代码段
//
// Layer 2: 内核态 — BEDaisy.sys
//   - ObRegisterCallbacks (进程/线程/模块 handle 限制)
//   - 定期扫描 handle table
//   - 内存扫描: 检测特征码 (CE/ReClass/特定 DLL)
//   - 线程堆栈回溯: 检测异常调用链
//   - DPC 定时器: 周期性完整性校验
//   - 检测 MmGetSystemRoutineAddress 隐藏调用
//   - VAD 树验证: 检测隐藏内存区域
//
// Layer 3: 服务器端
//   - 行为分析: K/D 异常, 命中率异常, 视角异常
//   - 客户端完整性哈希校验
```

### ObRegisterCallbacks 绕过

```cpp
// BE 注册的回调:
OB_PREOP_PARAMETERS preParams;
NTSTATUS BePreCallback(PVOID context, POB_PRE_OPERATION_INFORMATION info) {
    if (info->ObjectType == *PsProcessType &&
        info->Operation == OB_OPERATION_HANDLE_CREATE) {
        
        PEPROCESS targetProcess = (PEPROCESS)info->Object;
        HANDLE pid = PsGetProcessId(targetProcess);
        
        // 阻止对受保护进程的特定访问
        if (pid == g_protectedPid) {
            ACCESS_MASK access =
                info->Parameters->CreateHandleInformation.DesiredAccess;
            
            // 阻止进程间操作
            access &= ~PROCESS_VM_READ;
            access &= ~PROCESS_VM_WRITE;
            access &= ~PROCESS_VM_OPERATION;
            access &= ~PROCESS_CREATE_THREAD;
            access &= ~PROCESS_SUSPEND_RESUME;
            
            info->Parameters->CreateHandleInformation.DesiredAccess = access;
        }
    }
    return STATUS_SUCCESS;
}

// 绕过方法 1: 卸载回调 (需内核 + PatchGuard 绕过)
// 从 ObpCalloutArray 移除条目
void RemoveBeCallback() {
    // ObpCalloutArray 未导出, 需硬编码偏移
    PVOID* calloutArray = FindObpCalloutArray();
    for (int i = 0; i < 32; i++) {
        POB_CALLBACK_REGISTRATION reg =
            (POB_CALLBACK_REGISTRATION)calloutArray[i];
        if (reg && IsBeCallback(reg)) {
            // 替换为 NULL 或串联链中移除
            InterlockedExchangePointer(&calloutArray[i], NULL);
        }
    }
}

// 绕过方法 2: 直接系统调用 (直接调用 NtReadVirtualMemory syscall)
// Be 不 hook syscall, 但 ETW 会记录
// 绕过方法 3: DKOM — 修改 EPROCESS 的 Protection 位
// Vista+: 设置 PS_PROTECTED 标志 (PsIsProtectedProcess)
// 使 ObRegisterCallbacks 不适用
```

## Vanguard (VALORANT) 架构

### 完整保护层次

```
Level 0: TPM + Secure Boot 验证
  └─ 启动时验证系统完整性
  
Level 1: VGK.sys (Kernel Driver)
  ├── 启动时加载，系统启动阶段
  ├── 禁用 Windows 内核调试器
  ├── Patch PatchGuard → 允许修改内核
  ├── 拦截 DbgUiRemoteBreakin / KdDebuggerEnabled
  ├── 系统调用过滤 (自定义 SSDT)
  ├── 阻止加载未签名驱动
  ├── 扫描 EPT (Extended Page Tables) 检测 hypervisor
  └── Hypervisor-level integrity monitoring
  
Level 2: VGK.sys VM 监控
  ├── HvCallVtlReturn (Hyper-V VBS) 调用
  ├── 使用 Hyper-V VT2 创建受保护的内存隔离区
  ├── 映射自身到 VTL1 (Virtual Trust Level 1)
  └── 使用 SLAT (Second Level Address Translation) 监控游戏内存
  
Level 3: User Mode — VALORANT.exe
  ├── 内存完整性校验 (CRC)
  ├── 扫描黑名单进程/驱动
  ├── 检测调试工具
  └── 报告异常给服务器

Level 4: Server Side
  ├── 行为分析 (ML)
  ├── 命中判定异常检测
  ├── 视角回溯检测
  └── 账号信用系统
```

### VGK.sys 绕过思路

```cpp
// Vanguard 最难绕过的点:
// 1. VGK 运行在 Hyper-V root partition → 无法轻易被用户态代码触碰
// 2. VTL1 保护: VGK 代码和数据结构映射到 VTL1
//    普通内核代码 (VTL0) 不可见
// 3. EPT hooking: VGK 使用 EPT 监控物理内存

// 已知绕过方向:
// 1. 启动时攻击: VGK 在系统启动早期加载
//    在 VGK 完全初始化前注入代码
//    使用 Windows Boot Manager 漏洞加载恶意驱动
    
// 2. UEFI 固件攻击:
//    修改 UEFI 固件 → 在 VGK 之前获得控制权
//    使用 SMM (System Management Mode) 后门
//    → SMM 代码在 VGK 的 VTL1 之下
    
// 3. Hardware漏洞:
//    Rowhammer → 物理内存位翻转
//    → 翻转 VGK 的完整性校验位
    
// 4. 虚拟化逃逸 (如果运行在 VM):
//    Hyper-V VM 逃逸 → 获取 root partition 控制权

// 实际可操作的: BootKit 加载器
// 在 Windows Boot Manager 阶段注入:
// 1. 创建 UEFI 启动项 → 加载自定义 bootkit
// 2. Bootkit 修改 Winload.efi → 在 VGK.sys 加载前 patch
// 3. 或修改注册表 HKLM\System\CurrentControlSet\Services\vgk → Start = 4 (禁用)
```

## Ricochet (Call of Duty)

### 内核驱动 + ML 行为分析

```cpp
// Ricochet 独特之处:
// 1. 不阻止作弊运行 (与 EAC/BE 不同)
// 2. 收集行为数据 → 云端 ML 分析 → 延迟封禁
// 3. 系统级 "mitigation" — 软封禁 (只匹配其他作弊者)
// 4. 内核驱动检测:
//    - 扫描特定特征码 (已知作弊)
//    - 扫描异常 DLL 加载
//    - 异常模式检测: 瞬间转身 180° 多次
//    - 检测显示驱动 hook (ESP 的 Present hook)
//    - 检测光标位置异常 (Aim assist 检测)

// 绕过 ML 检测:
// 1. 注入人类行为噪声:
//    - 随机延迟 (100-400ms) 在瞄准前
//    - 瞄准路径非直线 (模拟手部轨迹)
//    - 视线随机抖动 (模拟人类肌肉微动)
//    - 避免 100% 爆头率

// 2. 驱动签名绕过:
//    Ricochet 未签名驱动阻止:
//    - 使用泄露的微软证书签名
//    - 或使用 OSR 测试签名 (测试模式)
//    - 或漏洞驱动加载 (capcom.sys, aswSP.sys)

// 3. 内核通信绕过:
//    不使用 IOCTL/DeviceIoControl
//    使用共享内存 + 事件通知
//    或通过 Named Pipe 绕过 (Ricochet 不扫描)
```

## Manual Map Injector

```cpp
// 绕过模块加载检测 (LoadLibrary 触发 LdrLoadDll 通知)

class ManualMapper {
public:
    bool Inject(HANDLE process, const uint8_t* dllData, size_t dllSize) {
        // 1. 解析 PE
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dllData;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(dllData + dos->e_lfanew);
        
        // 2. 在目标进程中分配内存
        void* remoteBase = VirtualAllocEx(process, NULL,
            nt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        
        // 3. 写入 PE header + sections
        WriteProcessMemory(process, remoteBase, dllData,
            nt->OptionalHeader.SizeOfHeaders, NULL);
        
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt) + i;
            WriteProcessMemory(process,
                (uint8_t*)remoteBase + section->VirtualAddress,
                dllData + section->PointerToRawData,
                section->SizeOfRawData, NULL);
        }
        
        // 4. 修复重定位
        IMAGE_DATA_DIRECTORY* relocDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        uint64_t delta = (uint64_t)remoteBase - nt->OptionalHeader.ImageBase;
        // ... 遍历重定位块
        
        // 5. 修复 IAT
        // ... 遍历 IAT 条目, GetProcAddress 获取函数地址
        
        // 6. 执行 DllMain
        DllMain_t dllMain = (DllMain_t)((uintptr_t)remoteBase +
            nt->OptionalHeader.AddressOfEntryPoint);
        
        // 使用 CreateRemoteThread 或 APC 执行
        HANDLE hThread = CreateRemoteThread(process, NULL, 0,
            (LPTHREAD_START_ROUTINE)dllMain,
            remoteBase, DLL_PROCESS_ATTACH, NULL);
        
        // 7. 清理: 从 PEB 模块列表中移除
        // (EAC 遍历 LdrpHashTable 校验一致性)
        RemoveFromPebList(process, remoteBase);
        
        return true;
    }
};
```

## Direct Syscall

```cpp
// 绕过 EAC/BE 对 ntdll.dll 的 hook (EAC hook NtOpenProcess/NtReadVirtualMemory)

// 直接系统调用: 跳过 ntdll 的 syscall stub
// 需要 syscall number (每个 Windows 版本不同)

// 方法1: 从 ntdll 读取 syscall number
DWORD GetSyscallNumber(const char* name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* func = GetProcAddress(ntdll, name);
    
    // ntdll 的 syscall stub 格式:
    // mov eax, syscall_number  (B8 XX XX XX XX)
    // mov edx, 7FFE0300        (BA 00 03 FE 7F)
    // syscall                  (0F 05)
    // ret                      (C3)
    
    return *(uint32_t*)((uint8_t*)func + 1);
}

// 方法2: 硬编码 (需要按版本维护)
// Windows 10 20H2:
// NtReadVirtualMemory = 0x3C
// NtWriteVirtualMemory = 0x3D
// NtOpenProcess = 0x26

// 直接 syscall asm:
__declspec(naked) NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead) {
    
    __asm {
        mov r10, rcx
        mov eax, 0x3C       ; NtReadVirtualMemory syscall #
        syscall
        ret
    }
}

// 调用方:
void DirectRead(HANDLE process, uintptr_t addr, void* out, size_t size) {
    NTSTATUS status = Syscall_NtReadVirtualMemory(
        process, (PVOID)addr, out, size, &bytesRead);
    
    // EAC 无法拦截: 没有经过 ntdll 的 hook
    // 但 ETW 仍然可能记录
}
```

## ETW Patching

```cpp
// ETW (Event Tracing for Windows) 可以记录系统调用
// EAC/BE 订阅:
// - Microsoft-Windows-Kernel-Process (ReadProcessMemory 事件)
// - Microsoft-Windows-Sysmon (如果有安装)

// 禁用 ETW:
void PatchEtwEventWrite() {
    // EtwEventWrite 在 ntdll 中未导出
    // 通过特征码搜索:
    // 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ??
    
    uint8_t* etwFunc = (uint8_t*)FindPattern(
        "ntdll.dll",
        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9"
    );
    
    if (etwFunc) {
        DWORD oldProtect;
        VirtualProtect(etwFunc, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
        *etwFunc = 0xC3;  // RET → 禁用所有 ETW 日志
        VirtualProtect(etwFunc, 1, oldProtect, &oldProtect);
    }
    
    // 注意: EAC 部分版本校验 EtwEventWrite 的完整性
    // 需要在每次 EAC 校验后重新 patch
}
```

## PatchGuard / KPP 绕过基础

```cpp
// Kernel Patch Protection (PatchGuard):
// 在 x64 Windows 上保护内核代码不被修改
// 检查: SSDT, IDT, GDT, 内核模块, 系统进程

// 绕过思路:
// 1. 在 PatchGuard 定时检查前修改并恢复
//    利用 PG 的检查窗口 (~30秒间隔)
// 2. 使用 DKOM 避开被检查的结构
// 3. 虚拟化绕过: 在 hypervisor 层做 EPT hook
//    → 物理内存不变, 客户机看到的已被修改
// 4. Patch PatchGuard 本身 (Vanguard 的做法)

// 实际: 大多数作弊驱动不碰内核结构
// 而是使用 MmCopyVirtualMemory 等合法路径
// EAC/BE 不触发 PatchGuard
```

## 攻击链

```
信息收集: 识别反作弊类型与版本 (EAC/BE/VG/Ricochet)
→ 用户态分析: 检查进程/驱动/注册表/窗口残留
→ 决策绕过层次:
  ├─ 用户态: Manual map + direct syscall + ETW patch
  ├─ 内核态: 驱动加载 → 去除 ObCallback → EPT hook
  └─ 硬件级: DMA → PCILeech → 物理内存读取
→ 实现基础原语: RPM/WPM 或共享内存
→ 添加持久化: 启动项/Bootkit/UEFI
→ 行为层面规避服务器检测
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 反作弊环境检测 | `triage_pe` | 初筛分析反作弊 DLL/驱动特征 |
| 内核驱动分析 | `ghidra_headless_analyze` | 分析反作弊驱动的导入函数与行为 |
| 查找反作弊回调 | `ghidra_summary_call_focus` | 定位 ObRegisterCallbacks 等注册点 |
| 特征码定位 | `search_pattern` | 搜索 ETW 函数或其他关键地址 |
| 汇编指令验证 | `rizin_assemble_bytes` | 验证 syscall stub 或 JMP 指令 |
| PE 地址转换 | `pe_address_to_offset` | 定位 IAT 条目或系统调用号 |
| 当前环境工具状态 | `project_skills_status` | 检查 Frida/工具链安装状态 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
