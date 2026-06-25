# 内存搜索与修改

## 场景

目标游戏/应用在内存中存储关键数值（血量、弹药、坐标、金币），需要通过读取/写入进程内存来修改这些值。面对现代反作弊的硬件级保护（KVM、VBS、DMA 检测），需要跨越用户态 → 内核态 → 硬件级多层攻击面。

## 输入信号

- Cheat Engine 或类似工具能扫描到数值但反作弊频繁扫内存检测
- BattlEye/EAC 使用 ObRegisterCallbacks 阻止跨进程 RPM/WPM
- Vanguard/VGK 在 hypervisor 层拦截 handle open / 物理内存访问
- 游戏使用 VirtualAlloc + 加密堆或 XOR/CRC 护盾保护关键数值

## 多层指针扫描与解析

### Cheat Engine 指针图机制

CE 指针扫描生成 .PTR 文件，包含多级偏移链：

```
[base_addr] + offset0 → [ptr1] + offset1 → [ptr2] + offset2 → [value]
```

在反作弊环境下，基址可能是 ASLR 随机的模块基址。现代游戏使用**指针加固**：

- 每帧重新分配对象地址（sliding heap）
- 在指针链中插入 XOR key 中间层（`ptr = heap[X] ^ key`）
- 使用 tagged pointer（高位标记位做完整性校验）

### 多级指针解析器（C++）

```cpp
#include <vector>
#include <cstdint>
#include <Windows.h>

struct PointerChain {
    uintptr_t base_address;          // 模块基址或静态地址
    std::vector<uint32_t> offsets;   // 各级偏移
    uint32_t final_offset;           // 最终值偏移
};

class PointerResolver {
public:
    explicit PointerResolver(HANDLE process) : hProcess_(process) {}

    bool Resolve(const PointerChain& chain, void* out_value, size_t size) {
        uintptr_t addr = chain.base_address;
        
        for (size_t i = 0; i < chain.offsets.size(); ++i) {
            uintptr_t next_addr;
            if (!ReadMemory(addr + chain.offsets[i], &next_addr, sizeof(next_addr))) {
                return false;
            }
            // tagged pointer 检测: 清除高位标记位
            // BattlEye 使用 bit 63 作为指针完整性标记
            next_addr &= 0x7FFFFFFFFFFFFFFFULL;
            
            // 指针范围有效性检查
            if (next_addr < 0x10000 || next_addr > 0x7FFFFFFFFFFFULL) {
                return false; // 野指针
            }
            addr = next_addr;
        }
        return ReadMemory(addr + chain.final_offset, out_value, size);
    }

private:
    HANDLE hProcess_;

    bool ReadMemory(uintptr_t address, void* buffer, size_t size) {
        SIZE_T bytes_read = 0;
        return ReadProcessMemory(hProcess_, (LPCVOID)address, buffer, size, &bytes_read)
               && bytes_read == size;
    }
};
```

### SIMD 加速特征码扫描

```cpp
#include <immintrin.h>
#include <vector>
#include <cstdint>

// AVX2 加速的 pattern 扫描（支持 ?? 通配符）
class PatternScanner {
public:
    PatternScanner(const uint8_t* data, size_t size)
        : data_(data), size_(size) {}

    std::vector<uintptr_t> Scan(const std::string& pattern) {
        std::vector<uintptr_t> results;
        auto [bytes, mask] = CompilePattern(pattern);
        
        // AVX2: 一次 32 字节并行比较
        __m256i pat_vec = _mm256_loadu_si256((__m256i*)bytes.data());
        __m256i mask_vec = _mm256_loadu_si256((__m256i*)mask.data());
        
        for (size_t i = 0; i < size_ - bytes.size(); i += 32) {
            __m256i data_vec = _mm256_loadu_si256((__m256i*)(data_ + i));
            // mask 指定哪些字节需要比较（0 = wildcard）
            __m256i cmp = _mm256_cmpeq_epi8(
                _mm256_and_si256(data_vec, mask_vec),
                _mm256_and_si256(pat_vec, mask_vec)
            );
            int bitmask = _mm256_movemask_epi8(cmp);
            
            // 逐字节检查对齐
            while (bitmask) {
                int bit = __builtin_ctz(bitmask);
                bool match = true;
                for (size_t j = bit; j < bytes.size(); ++j) {
                    if (mask[j] && data_[i + j] != bytes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) results.push_back(i + bit);
                bitmask &= bitmask - 1;
            }
        }
        return results;
    }

private:
    const uint8_t* data_;
    size_t size_;

    // "48 89 5C 24 ?? 48 89 74 24 ??" → bytes + mask
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    CompilePattern(const std::string& pattern) {
        // ... hex parse with wildcards
    }
};
```

## Polymorphic 数据反混淆

现代游戏使用多种数据混淆技术对抗简单内存扫描：

### XOR 加密值

```cpp
// 游戏端加密:
uint32_t encrypted_hp = actual_hp ^ 0xDEADBEEF;

// 破解端:
uint32_t DecryptHP(uint32_t encrypted, uint32_t xor_key) {
    return encrypted ^ xor_key;
}

// 动态密钥变体: 每帧 XOR key 变化
struct EncryptedValue {
    uint32_t value_mask;  // 加密值
    uint32_t key;         // 当前 key（也可能加密）
    uint32_t counter;     // 帧计数器, key = base_key ^ counter
};
```

### Float 混淆

```cpp
// 游戏内 HP 用 float 但乘以一个隐藏系数
// 实际显示 = raw_float * 0.1734f
// 作弊者需要逆向出系数

// 更高级: union reinterpret
union FloatObfuscator {
    float f;
    uint32_t i;
};

// 存储为反转字节序
FloatObfuscator val;
val.f = 100.0f;  // 实际血量
val.i = _byteswap_ulong(val.i);  // 内存中不可读
```

### 数据结构偏移逆向

```cpp
// 典型 FPS 游戏玩家对象 vtable 布局:
struct Player_vtable {
    void* (*Update)(void*, float);         // +0x00
    void* (*OnDamage)(void*, float);      // +0x08
    bool  (*IsAlive)(void*);              // +0x10
    void* (*GetWeapon)(void*);            // +0x18
};

// 数据成员偏移 (IL2CPP/Unreal Engine):
// +0x00: vtable pointer
// +0x08: player name (FString: +0x00 ptr, +0x08 len)
// +0x18: health (float, 但可能加密)
// +0x1C: max_health
// +0x20: armor (float)
// +0x28: position (Vector3: x, y, z floats)
// +0x38: rotation (Vector3)
// +0x48: team_id (int32)
// +0x50: weapon_array (TArray ptr)
```

## External vs Internal 攻击面

### External RPM/WPM

```cpp
// 传统 external: 需要 OpenProcess(PROCESS_ALL_ACCESS)
// EAC/BE 通过 ObRegisterCallbacks 阻止:
// - ProcessOpen 回调: 检查 caller 是否在白名单驱动列表
// - 如果不是系统进程/白名单驱动 → STATUS_ACCESS_DENIED

// 绕过: 利用内核驱动的 MmCopyVirtualMemory
// 或: 通过漏洞驱动 (capcom.sys, gdrv.sys) 获取任意进程读写
```

### Internal DLL Injection

```cpp
// 内部注入优势: 进程内读写不需要 RPM
// 被反作弊检测的向量:
// 1. LoadLibrary → LdrLoadDll → 模块列表枚举
// 2. LdrpHashTable 不一致检测 (EAC 校验)
// 3. ETW-TI 日志: LoadLibrary 事件
// 4. KsCallbacks: 线程创建回调枚举 loaded modules

// 绕过: Manual Map (不使用 LoadLibrary)
// - 手动解析 PE → 重定位 → 修复 IAT → 调用 DllMain
// - 绕过 GetModuleHandle/PEB 枚举
// - 使用 VAD hide (内核中从 VAD 树移除)
```

### Kernel Driver

```cpp
// 内核驱动读写:
NTSTATUS KevReadProcessMemory(HANDLE pid, uintptr_t addr, void* buf, size_t size) {
    PEPROCESS target_process;
    PsLookupProcessByProcessId((HANDLE)pid, &target_process);
    
    KAPC_STATE apc;
    KeStackAttachProcess(target_process, &apc);
    
    // 直接读取目标进程虚拟地址
    ProbeForRead((void*)addr, size, 1);
    memcpy(buf, (void*)addr, size);
    
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target_process);
    return STATUS_SUCCESS;
}

// EAC/BE 检测内核驱动的常见方法:
// 1. 遍历内核模块 → 检查 hash 签名
// 2. 扫描 system thread → 检测隐藏线程
// 3. 利用 PatchGuard (KPP) 检测代码段修改
// 4. 检测 MmGetSystemRoutineAddress 异常调用
```

## DMA (Direct Memory Access) 攻击

使用 PCILeech / DMA 设备通过 PCIe 总线直接读取物理内存，完全绕过 CPU 和操作系统。

### 硬件配置

```
攻击链路:
[攻击机] ←USB→ [FPGA/DMA Board (Cyclone V/Artix-7)] ←PCIe→ [目标机]

常见硬件:
- PCIeScreamer (Cyclone V, ~$200)
- AC701 (Xilinx Artix-7, ~$800)
- Facedancer USB 中间人
- Thunderbolt DMA（通过 TB 控制器 DMA）
```

### PCILeech 使用

```python
# PCILeech 读取目标物理内存
# 需要: FPGA 固件加载, PCILeech 驱动程序安装

import leech

device = leech.Leech()
device.connect("pci")  # 或 "thunderbolt", "usb"

# 获取目标系统信息
target = device.get_target()
print(f"System: {target.get_os()}  {target.get_arch()}")

# 读取进程内存 (process_vm_readv via DMA)
process = target.get_process("exploit.exe")
base = process.get_base()
health_addr = base + 0x4BCB0
health = process.read_float(health_addr)
print(f"Current HP: {health}")

# 写入
process.write_float(health_addr, 9999.0)
```

### DMA 反制与绕过

```cpp
// 反作弊检测 DMA 的方法:
// 1. IOMMU/VT-d: 限制 PCIe 设备只能访问特定物理内存区域
// 2. ACPI DMAR table: 声明保留内存区域
// 3. 物理内存加密: AMD SME (Secure Memory Encryption)
//    Intel TME (Total Memory Encryption)
// 4. VBS (Virtualization-Based Security): 在 hypervisor 下运行,
//    DMA 只能看到 hypervisor 分配的物理页

// 绕过思路:
// 1. 攻击 IOMMU 配置: 修改 DMAR table
// 2. 定位未被加密的内存区域 (ACPI NVS, MMIO)
// 3. 使用 UEFI runtime service 读取
// 4. 利用 SMM (System Management Mode) 访问
```

## 反作弊 RPM 检测与绕过

### ETW 线程栈追踪

```cpp
// Windows ETW (Event Tracing for Windows) 可以记录:
// - ReadProcessMemory 调用
// - WriteProcessMemory 调用
// - OpenProcess 调用
// - NtReadVirtualMemory syscall

// EAC 启用 ETW 日志:
// GUID: {3AC66736-EDCC-4192-9BDE-6F4B0C810429}
// Provider: Microsoft-Windows-Kernel-Process

// 绕过: ETW 禁用
void DisableETW() {
    // 方法1: Patch EtwEventWrite (ntdll)
    uint8_t patch[] = { 0xC3 };  // RET
    WriteToProtectedMemory(&EtwEventWrite, patch, 1);
    
    // 方法2: 通过内核驱动清空 ETW 日志注册
    // 或: 在 EPROCESS 中关闭 trace 标志
}
```

### ObRegisterCallbacks

```cpp
// EAC/BE 注册的进程回调:
NTSTATUS EacProcessCallback(
    PVOID CallbackContext,
    POB_PRE_OPERATION_INFORMATION Info
) {
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        PEPROCESS target = (PEPROCESS)Info->Object;
        HANDLE target_pid = PsGetProcessId(target);
        
        // 如果目标是自己进程:
        if (target_pid == g_protected_pid) {
            POB_PRE_OPERATION_PARAMETERS params = Info->Parameters;
            ACCESS_MASK desired = params->CreateHandleInformation.DesiredAccess;
            
            // 阻止非系统进程获取 PROCESS_ALL_ACCESS
            if (!IsTrustedCaller(PsGetCurrentProcessId())) {
                params->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
                params->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
                params->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            }
        }
    }
    return STATUS_SUCCESS;
}

// 绕过:
// 1. 卸载回调 (需要内核权限 + 绕过回调保护)
// 2. 手动调用 syscall 绕过回调 (NtReadVirtualMemory 直接)
// 3. 利用 DMA 读取 (完全绕过操作系统)
```

## 攻击链

```
Cheat Engine 初步扫描 → 识别加密/混淆模式 → 逆向解密函数
→ 提取 XOR key / 浮点系数 → 构建指针链解析器
→ 决策: external vs internal vs kernel vs DMA
→ 实现读写原语 → 反反作弊: ETW bypass + ObCallback bypass
→ 持久化: 驱动加载 / 漏洞利用 → 正式作弊
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 样本初筛与特征扫描 | `triage_pe` | hash/DiE/节区/导入表/字符串 |
| 导入表分析定位 API | `rizin_imports` | 按 DLL 名过滤（kernel32!ReadProcessMemory） |
| 特征码搜索 | `search_pattern` | 十六进制 pattern 定位关键函数 |
| 反汇编与混淆解混淆 | `rizin_assemble_bytes` | 验证 patch 汇编 |
| 字节 Patch | `patch_bytes` | 修改内存读取/写入指令 |
| 函数阅读优先级 | `ghidra_summary_call_focus` | 按行为推荐阅读优先级（behavior="crypto"） |
| 查看函数详情 | `ghidra_summary_function_detail` | 含 decompile、callers、callees |
| 工具链状态检查 | `python_re_tool_install` | 安装 frida/lief/angr 等逆向库 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
