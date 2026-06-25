# 手动映射 DLL 注入

## 场景

CreateRemoteThread + LoadLibrary 会被反作弊检测（LoadLibrary 触发 DLL 加载通知、DLL 在模块列表中可见）。手动映射（Manual Map）模拟 Windows Loader，在不调用 LoadLibrary 的前提下将 DLL 加载到目标进程。

## 输入信号

- 需要注入但不被发现（无模块列表记录）
- 目标有 `LdrRegisterDllNotification` 或模块扫描
- DLL 不需要被其他模块通过 GetProcAddress 找到

## 手动映射内核步骤

```
1. 读取 DLL 文件到本地缓冲区
2. 在目标进程中分配内存 (VirtualAllocEx, 大小 ≥ SizeOfImage)
3. 解析 PE header, 复制各节区到目标进程对应 RVA
4. 处理重定位 (如果 ImageBase 不匹配)
5. 解析导入表, 加载依赖 DLL 并填充 IAT
6. 调用 TLS 回调
7. 执行 DllMain(DLL_PROCESS_ATTACH)
```

## 核心实现

```cpp
struct ManualMapData {
    uint8_t* remoteImage;     // 目标进程中分配的内存基址
    uint8_t* localImage;      // 本地 raw PE 数据
    IMAGE_NT_HEADERS* nt;     // NT Headers 指针
    HANDLE hProc;             // 目标进程句柄
};

bool ManualMap(HANDLE hProc, const char* dllPath) {
    ManualMapData ctx;
    ctx.hProc = hProc;

    // 1. 读取 DLL 到本地
    FILE* f = fopen(dllPath, "rb");
    fseek(f, 0, SEEK_END);
    size_t fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    ctx.localImage = (uint8_t*)malloc(fileSize);
    fread(ctx.localImage, 1, fileSize, f);
    fclose(f);

    // 2. 解析 PE header → 获取 ImageSize
    auto dos = (IMAGE_DOS_HEADER*)ctx.localImage;
    ctx.nt = (IMAGE_NT_HEADERS*)(ctx.localImage + dos->e_lfanew);
    size_t imageSize = ctx.nt->OptionalHeader.SizeOfImage;

    // 3. 在目标进程中分配内存
    ctx.remoteImage = (uint8_t*)VirtualAllocEx(hProc, NULL, imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 4. 复制 PE Headers
    WriteProcessMemory(hProc, ctx.remoteImage, ctx.localImage,
        ctx.nt->OptionalHeader.SizeOfHeaders, NULL);

    // 5. 复制各节区
    auto section = IMAGE_FIRST_SECTION(ctx.nt);
    for (int i = 0; i < ctx.nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            WriteProcessMemory(hProc,
                ctx.remoteImage + section[i].VirtualAddress,
                ctx.localImage + section[i].PointerToRawData,
                section[i].SizeOfRawData, NULL);
        }
    }

    // 6. 处理重定位
    uintptr_t delta = (uintptr_t)ctx.remoteImage -
        ctx.nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        ProcessRelocations(&ctx, delta);
    }

    // 7. 解析并填充 IAT
    ProcessImports(&ctx);

    // 8. 在远程进程中执行 DllMain
    // 方式A: CreateRemoteThread(remoteImage + AddressOfEntryPoint, ...)
    // 方式B: shellcode 调用 DllMain(hinst, DLL_PROCESS_ATTACH, NULL)
    CallDllMainInRemote(&ctx);

    return true;
}
```

## 重定位处理

```cpp
void ProcessRelocations(ManualMapData* ctx, uintptr_t delta) {
    auto& opt = ctx->nt->OptionalHeader;
    auto relocDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!relocDir.VirtualAddress || !relocDir.Size)
        return;  // 不需要重定位 (ImageBase 匹配)

    auto reloc = (IMAGE_BASE_RELOCATION*)(ctx->remoteImage + relocDir.VirtualAddress);
    uint8_t* base = ctx->remoteImage;

    while (reloc->VirtualAddress && reloc->SizeOfBlock) {
        uint16_t* entries = (uint16_t*)(reloc + 1);
        int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

        for (int i = 0; i < count; i++) {
            int type = entries[i] >> 12;       // 高 4 位: 重定位类型
            int offset = entries[i] & 0xFFF;   // 低 12 位: 页内偏移

            if (type == IMAGE_REL_BASED_DIR64) {  // x64: 8 字节补丁
                uintptr_t* patch = (uintptr_t*)(base + reloc->VirtualAddress + offset);
                *patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {  // x86: 4 字节补丁
                uint32_t* patch = (uint32_t*)(base + reloc->VirtualAddress + offset);
                *patch += (uint32_t)delta;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
    }
}
```

## 导入表手动填充

```cpp
void ProcessImports(ManualMapData* ctx) {
    auto& opt = ctx->nt->OptionalHeader;
    auto importDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!importDir.VirtualAddress) return;

    auto import = (IMAGE_IMPORT_DESCRIPTOR*)(ctx->remoteImage + importDir.VirtualAddress);

    while (import->Name) {
        const char* dllName = (const char*)(ctx->remoteImage + import->Name);
        HMODULE hMod = LoadLibraryA(dllName);  // 注意: 这是本地加载!

        auto iat = (uintptr_t*)(ctx->remoteImage + import->FirstThunk);
        auto int_ = (IMAGE_THUNK_DATA*)(ctx->remoteImage +
            (import->OriginalFirstThunk ? import->OriginalFirstThunk : import->FirstThunk));

        while (int_->u1.AddressOfData) {
            FARPROC func;
            if (int_->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                func = GetProcAddress(hMod, (LPCSTR)(int_->u1.Ordinal & 0xFFFF));
            } else {
                auto importByName = (IMAGE_IMPORT_BY_NAME*)(ctx->remoteImage + int_->u1.AddressOfData);
                func = GetProcAddress(hMod, importByName->Name);
            }
            *iat = (uintptr_t)func;  // 填充 IAT
            iat++;
            int_++;
        }
        import++;
    }
}
```

## Shellcode 执行入口

```cpp
// 在远程进程中写一段 shellcode 来调用 DllMain
// 然后通过 CreateRemoteThread 执行它

struct ShellcodeEntry {
    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    uint8_t* remoteImage;
    DllMain_t entryPoint;
};

// x64 shellcode:
// sub rsp, 0x28           ; shadow space
// mov rcx, <imageBase>    ; hinstDLL
// mov rdx, 1              ; DLL_PROCESS_ATTACH
// xor r8, r8              ; lpvReserved = NULL
// mov rax, <entryPoint>
// call rax
// add rsp, 0x28
// ret

void ExecuteDllMain(ManualMapData* ctx) {
    // 构造 shellcode
    uint8_t shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
        0x48, 0xB9, 0,0,0,0,0,0,0,0,               // mov rcx, imageBase
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,   // mov rdx, 1
        0x4D, 0x31, 0xC0,                            // xor r8, r8
        0x48, 0xB8, 0,0,0,0,0,0,0,0,               // mov rax, entryPoint
        0xFF, 0xD0,                                  // call rax
        0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
        0xC3                                         // ret
    };

    // 填充参数
    uintptr_t entry = (uintptr_t)ctx->remoteImage +
        ctx->nt->OptionalHeader.AddressOfEntryPoint;
    *(uintptr_t*)(shellcode + 5) = (uintptr_t)ctx->remoteImage;
    *(uintptr_t*)(shellcode + 25) = entry;

    // 在目标进程分配 shellcode
    void* remoteSC = VirtualAllocEx(ctx->hProc, NULL,
        sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(ctx->hProc, remoteSC, shellcode, sizeof(shellcode), NULL);

    // 执行
    HANDLE hThread = CreateRemoteThread(ctx->hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteSC, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(ctx->hProc, remoteSC, 0, MEM_RELEASE);
}
```

## 攻击链

```
读取 DLL 文件 → 解析 PE header → 目标进程分配 SizeOfImage 内存
→ WriteProcessMemory 复制 header+节区 → 处理重定位(如有 delta)
→ 解析导入表, LoadLibrary 依赖 + 填充 IAT
→ Shellcode 调用 DllMain(DLL_PROCESS_ATTACH) → DLL 无痕注入完成
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| _（纯手工 PE 加载技术，无直接 MCP 等价物）_ | | |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
