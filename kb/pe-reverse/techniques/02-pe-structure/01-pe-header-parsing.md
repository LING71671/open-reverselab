# PE 头解析与节区定位

## 场景

需要手动解析 PE 文件的 DOS/NT 头、节区表、导入导出表，获取模块的完整内存布局。

## 输入信号

- 有模块基址或 PE 文件的原始字节
- 需要确定代码段位置、数据段范围
- 需要提取导入表 API 地址

## PE 结构速查

```
PE 文件布局:
┌─────────────────────┐ ← DOS_HEADER (e_magic = "MZ")
│  IMAGE_DOS_HEADER    │
│  e_lfanew → NT offset│
├─────────────────────┤ ← NT_HEADERS (Signature = "PE\0\0")
│  IMAGE_NT_HEADERS    │
│  FileHeader          │ Machine=0x8664(x64), NumberOfSections
│  OptionalHeader      │ ImageBase, SizeOfImage, EntryPoint
├─────────────────────┤ ← SECTION_HEADER[0..N-1]
│  IMAGE_SECTION_HEADER│ .text / .rdata / .data / .reloc ...
│  VirtualAddress      │ RVA (运行时相对基址偏移)
│  PointerToRawData    │ 文件偏移
│  VirtualSize         │ 运行时大小
├─────────────────────┤
│  节区数据            │
├─────────────────────┤
│  Import Directory    │ → IMAGE_IMPORT_DESCRIPTOR[]
├─────────────────────┤
│  Export Directory    │ → IMAGE_EXPORT_DIRECTORY
└─────────────────────┘
```

## 手动解析实现

```cpp
bool ParsePE(uintptr_t moduleBase) {
    // 1. DOS Header
    auto dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)  // 0x5A4D = "MZ"
        return false;

    // 2. NT Headers
    auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  // 0x00004550 = "PE\0\0"
        return false;

    printf("Machine: 0x%04X\n", nt->FileHeader.Machine);
    printf("Sections: %d\n", nt->FileHeader.NumberOfSections);
    printf("ImageBase: 0x%llX\n", nt->OptionalHeader.ImageBase);
    printf("EntryPoint: 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("SizeOfImage: 0x%X\n", nt->OptionalHeader.SizeOfImage);

    // 3. 节区遍历
    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, section[i].Name, 8);

        printf("  %s: VA=0x%X Size=0x%X RawOff=0x%X Flags=0x%X\n",
            name,
            section[i].VirtualAddress,
            section[i].Misc.VirtualSize,
            section[i].PointerToRawData,
            section[i].Characteristics);

        // 判断节区属性
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            printf("    EXECUTE\n");
        if (section[i].Characteristics & IMAGE_SCN_MEM_READ)
            printf("    READ\n");
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            printf("    WRITE\n");
    }
    return true;
}
```

## 按名称定位节区

```cpp
uintptr_t GetSectionVA(uintptr_t moduleBase, const char* name) {
    auto dos = (IMAGE_DOS_HEADER*)moduleBase;
    auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, name, strlen(name)) == 0) {
            return moduleBase + section[i].VirtualAddress;
        }
    }
    return 0;
}

// 使用
uintptr_t textSection = GetSectionVA(base, ".text");
uintptr_t dataSection = GetSectionVA(base, ".data");
uintptr_t rdataSection = GetSectionVA(base, ".rdata");
```

## 导入表遍历

```cpp
void DumpImports(uintptr_t moduleBase) {
    auto dos = (IMAGE_DOS_HEADER*)moduleBase;
    auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);

    // 导入表 RVA
    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return;

    auto import = (IMAGE_IMPORT_DESCRIPTOR*)(moduleBase + importRva);

    while (import->Name) {
        const char* dllName = (const char*)(moduleBase + import->Name);
        printf("%s:\n", dllName);

        // IAT (Import Address Table) 和 INT (Import Name Table)
        auto iat = (uintptr_t*)(moduleBase + import->FirstThunk);
        auto int_ = (IMAGE_THUNK_DATA*)(moduleBase +
            (import->OriginalFirstThunk ? import->OriginalFirstThunk : import->FirstThunk));

        int idx = 0;
        while (int_->u1.AddressOfData) {
            if (int_->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("  Ordinal: %llu\n", int_->u1.Ordinal & 0xFFFF);
            } else {
                auto importByName = (IMAGE_IMPORT_BY_NAME*)(moduleBase + int_->u1.AddressOfData);
                printf("  %s = 0x%llX\n", importByName->Name, iat[idx]);
            }
            int_++;
            idx++;
        }
        import++;
    }
}
```

## 导出表解析

```cpp
FARPROC GetExportByName(uintptr_t moduleBase, const char* funcName) {
    auto dos = (IMAGE_DOS_HEADER*)moduleBase;
    auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);

    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return NULL;

    auto exports = (IMAGE_EXPORT_DIRECTORY*)(moduleBase + exportRva);

    auto names = (DWORD*)(moduleBase + exports->AddressOfNames);
    auto ordinals = (WORD*)(moduleBase + exports->AddressOfNameOrdinals);
    auto functions = (DWORD*)(moduleBase + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(moduleBase + names[i]);
        if (strcmp(name, funcName) == 0) {
            return (FARPROC)(moduleBase + functions[ordinals[i]]);
        }
    }
    return NULL;
}
```

## 攻击链

```
获取模块基址 → DOS header 验证 "MZ" → e_lfanew 定位 NT header
→ FileHeader.NumberOfSections → IMAGE_FIRST_SECTION 遍历节区
→ 按名称/属性定位目标节区 → 在节区内扫描/读写
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| PE 初筛，输出 header/sections/imports | `triage_pe` | 自动输出 PE header/sections/imports |
| 节区详细信息 | `rizin_sections` | 节区详细信息 |
| PE 基础信息 | `rizin_bin_info` | PE 基础信息（entry point, image base 等） |
| 导入表枚举 | `rizin_imports` | 导入表枚举 |
| file offset / RVA / VA 互转 | `pe_address_to_offset` | file offset / RVA / VA 互转 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
