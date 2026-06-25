# DLL 注入三模式

## 场景

需要在目标进程地址空间执行自定义代码。注入 DLL 后获得与目标相同的权限级别，可读写内存、Hook 函数、修改行为。

## 输入信号

- 目标进程已启动或即将启动
- 已编译好需注入的 DLL
- 需要选择注入方式适配目标的反注入策略

## 模式 1: CreateRemoteThread + LoadLibrary（经典）

```cpp
// 最标准注入方式，兼容性最好，但易被检测
bool InjectDLL_Classic(pid_t pid, const char* dllPath) {
    // 1. 打开目标进程
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    // 2. 在目标进程中分配内存
    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteBuf = VirtualAllocEx(hProc, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 3. 写入 DLL 路径
    WriteProcessMemory(hProc, remoteBuf, dllPath, pathLen, NULL);

    // 4. 创建远程线程执行 LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        remoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    // 5. 清理
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}
```

核心:
- `LoadLibraryA` 的地址在 kernel32.dll 中，且 kernel32 在所有进程中加载地址相同（同一会话）
- `CreateRemoteThread` 让目标进程执行 `LoadLibraryA(dllPath)` → DLL 被加载 → `DllMain` 执行

## 模式 2: 进程快照枚举（找到目标 PID）

```cpp
// 按进程名查找 PID
DWORD GetProcId(const char* procName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// 等待进程启动
DWORD WaitForProcId(const char* procName) {
    DWORD pid = 0;
    while (!pid) {
        pid = GetProcId(procName);
        Sleep(500);
    }
    return pid;
}
```

## 模式 3: 注入 DLL 的自我弹出

```cpp
// 在注入的 DLL 中, DllMain 入口
HMODULE g_hThisModule = NULL;  // 全局保存自己的 HMODULE

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hThisModule = (HMODULE)hinstDLL;
        // 不能在 DllMain 中做重活 (loader lock!)
        // 创建独立线程执行主逻辑
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    return TRUE;
}

DWORD WINAPI MainThread(LPVOID) {
    // 在这里安全执行: hook、读写、UI 等
    RunCheat();
    return 0;
}

// 自弹出（卸载自己）
void EjectSelf() {
    // FreeLibraryAndExitThread 同时卸载 DLL 并结束调用线程
    FreeLibraryAndExitThread(g_hThisModule, 0);
}
```

## DllMain 线程委派模式

```
DllMain(DLL_PROCESS_ATTACH)
  └── CreateThread(MainThread)    ← 不能在 DllMain 中做复杂操作
      └── MainThread:
          ├── 等待目标模块加载 (while !GetModuleHandle)
          ├── Hook 目标函数
          ├── 创建 UI 线程
          └── 主循环 / 等待退出信号
```

为什么需要委派:
- `DllMain` 持有 loader lock，任何需要 loader lock 的 API（`LoadLibrary`、`CreateThread` 同步等待等）都会死锁
- `DllMain` 中调用了 `CreateThread` 后不能 `WaitForSingleObject` 该线程

## 外部模块基址定位

```cpp
// 获取目标进程中某模块的基址（外部视角）
uintptr_t GetModuleBaseExternal(DWORD pid, const char* moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    uintptr_t base = 0;

    if (Module32First(hSnapshot, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return base;
}
```

## 实战注入检查清单

```
1. 目标架构: 64-bit DLL 只能注入 64-bit 进程, 32-bit 同理
2. 权限: 需要 PROCESS_CREATE_THREAD + VM_OPERATION + VM_WRITE
3. 路径: 绝对路径或 DLL 在目标进程的搜索路径中
4. 依赖: 注入的 DLL 依赖的库必须在目标进程可访问位置
5. DllMain 时限: DllMain 执行不能太久
```

## 攻击链

```
确定目标进程名 → GetProcId 获取 PID → OpenProcess 获取句柄
→ VirtualAllocEx 分配远程内存 → WriteProcessMemory 写入 DLL 路径
→ CreateRemoteThread(LoadLibraryA) 加载 DLL → DllMain 执行
→ MainThread: 等待时机 → Hook/读写/UI → FreeLibraryAndExitThread 自弹出
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 动态调试验证注入 | `toolbox_launch(x64dbg)` | 动态调试验证注入是否成功 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
