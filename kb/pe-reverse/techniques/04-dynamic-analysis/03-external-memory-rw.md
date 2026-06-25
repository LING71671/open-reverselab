# 外部进程内存读写

## 场景

从独立进程（外部 Trainer/工具）读写目标进程内存。不需要注入 DLL，通过 Windows API 跨进程访问。

## 输入信号

- 目标进程已运行
- 知道目标模块名和数据偏移
- 不需要在目标进程内执行代码

## 外部读写完整链路

```cpp
// 1. 按进程名获取 PID
DWORD pid = GetProcId("game.exe");  // 见 DLL 注入篇

// 2. 打开进程句柄
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// 3. 获取模块基址（外部）
uintptr_t base = GetModuleBaseExternal(pid, "game.dll");

// 4. 解析指针链 → 目标地址
uintptr_t addr = FindDMAAddy(hProc, base + 0x12345, {0x10, 0x8, 0x20});

// 5. 读写
int hp;
ReadProcessMemory(hProc, (LPCVOID)(addr + 0x36C), &hp, sizeof(hp), NULL);
hp += 100;
WriteProcessMemory(hProc, (LPVOID)(addr + 0x36C), &hp, sizeof(hp), NULL);
CloseHandle(hProc);
```

## FindDMAAddy：多级指针链解析

```cpp
// 外部版本的指针链遍历
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t base,
    const std::vector<uintptr_t>& offsets) {
    uintptr_t addr = base;

    for (size_t i = 0; i < offsets.size(); i++) {
        // 先读当前地址的 8 字节 (64-bit 指针)
        ReadProcessMemory(hProc, (LPCVOID)addr, &addr, sizeof(addr), NULL);
        if (!addr) return 0;  // 断链
        addr += offsets[i];   // 加本层偏移
    }
    return addr;  // 最终地址
}

// 使用:
// CheatEngine 找到: game.dll+0xABC → [+0x10] → [+0x8] → [+0x20] → value at +0x36C
auto chain = {0x10, 0x8, 0x20};
uintptr_t entity = FindDMAAddy(hProc, base + 0xABC, chain);
int hp;
ReadProcessMemory(hProc, (LPCVOID)(entity + 0x36C), &hp, sizeof(hp), NULL);
```

## 完整外部读写封装

```cpp
class ExternalMemory {
    HANDLE hProc;
public:
    ExternalMemory(const char* procName) {
        DWORD pid = GetProcId(procName);
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    ~ExternalMemory() { CloseHandle(hProc); }

    template<typename T>
    T Read(uintptr_t addr) {
        T val{};
        ReadProcessMemory(hProc, (LPCVOID)addr, &val, sizeof(T), NULL);
        return val;
    }

    template<typename T>
    void Write(uintptr_t addr, T val) {
        WriteProcessMemory(hProc, (LPVOID)addr, &val, sizeof(T), NULL);
    }

    uintptr_t ReadPtr(uintptr_t addr) {
        return Read<uintptr_t>(addr);
    }

    // 指针链解析内联
    uintptr_t FollowChain(uintptr_t base,
        const std::vector<uintptr_t>& offsets) {
        uintptr_t addr = base;
        for (auto off : offsets) {
            addr = ReadPtr(addr);
            if (!addr) return 0;
            addr += off;
        }
        return addr;
    }
};
```

## 内部 vs 外部对比

```
               外部 (External)              内部 (Internal/DLL)
读写方式:      ReadProcessMemory /           直接指针解引用 (reinterpret_cast)
               WriteProcessMemory
权限:         独立进程, 可独立运行           在目标进程内, 需注入
性能:         syscall 每读一次               直接内存访问, 极快
检测风险:     低 (正常 API 调用)             较高 (DLL 被扫描)
偏移追踪:     每次走完整 syscall             指针直接跳
代码注入:     不可直接执行                   可 Hook/修改执行流
适用场景:     Trainer/修改器/雷达            ESP/Wallhack/函数Hook
```

## 内部直接读写

```cpp
// 内部版本: 注入 DLL 后直接指针操作
template<typename T>
T ReadInternal(uintptr_t addr) {
    return *reinterpret_cast<T*>(addr);
}

template<typename T>
void WriteInternal(uintptr_t addr, T val) {
    *reinterpret_cast<T*>(addr) = val;
}

uintptr_t ReadPtrInternal(uintptr_t addr) {
    return ReadInternal<uintptr_t>(addr);
}

// 指针链: 直接多次解引用
uintptr_t FollowChainInternal(uintptr_t base,
    const std::vector<uintptr_t>& offsets) {
    uintptr_t addr = base;
    for (auto off : offsets) {
        addr = ReadPtrInternal(addr);
        if (!addr) return 0;
        addr += off;
    }
    return addr;
}

// 受保护内存写入
void WriteProtected(void* addr, const void* data, size_t size) {
    DWORD old;
    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, data, size);  // 不是 ReadProcessMemory!
    VirtualProtect(addr, size, old, &old);
}
```

## 分配可执行内存

```cpp
// 用于跳板/Shellcode/代码注入
void* AllocExecutable(size_t size) {
    return VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void FreeExecutable(void* addr) {
    VirtualFree(addr, 0, MEM_RELEASE);
}
```

## 攻击链

```
确定目标进程名 → GetProcId → OpenProcess(PROCESS_ALL_ACCESS)
→ GetModuleBaseExternal 获取模块基址 → FindDMAAddy 解析指针链
→ ReadProcessMemory 读取数据 → WriteProcessMemory 修改值
→ CloseHandle 清理
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 验证内存读写结果 | `toolbox_launch(x64dbg)` | 验证内存读写结果 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
