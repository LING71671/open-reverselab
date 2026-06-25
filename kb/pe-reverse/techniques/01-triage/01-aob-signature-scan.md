# AOB 特征码扫描

## 场景

目标模块因 ASLR 每次加载基址不同，硬编码地址失效。需通过特征码（Array of Bytes）在运行时定位代码/数据位置。

## 输入信号

- 已知目标指令的字节序列（从 Ghidra/x64dbg 提取）
- 需要运行时定位该指令并在不同版本间复用
- 特征码应选在版本更新中不变的区域

## 特征码提取原则

```
正确: 选唯一、跨版本稳定的字节序列，避免选偏移值（rel32/imm32）
├── 好的特征: 指令操作码 + ModRM + SIB（不含位移部分）
├── 避免: 包含绝对地址或变长偏移的字节
└── IDA/Ghidra: 选中指令 → Copy Bytes (避开 reloc 标记)

错误示例:
  48 8B 05 XX XX XX XX  → 包含 RIP-relative offset (版本间变化)
  E8 XX XX XX XX        → 包含 rel32 (call 的偏移)
```

## 模式字符串格式

```
标准 IDA 风格 mask:
  "48 8B 05 ? ? ? ? 48 89 45 F8"
  → 0x48 0x8B 0x05 (wildcard 4 bytes) 0x48 0x89 0x45 0xF8

Code style mask (x = must match, ? = wildcard):
  "xxxxxxxx????xxxx"
```

## 全模块扫描实现

```cpp
// 获取模块基址和大小
uintptr_t GetModuleBase(const char* moduleName) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    MODULEINFO info;
    GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info));
    return (uintptr_t)info.lpBaseOfDll;
}

size_t GetModuleSize(const char* moduleName) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    MODULEINFO info;
    GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info));
    return info.SizeOfImage;
}

// 特征码扫描
uintptr_t FindPattern(const char* moduleName, const char* pattern, const char* mask) {
    uintptr_t base = GetModuleBase(moduleName);
    size_t size = GetModuleSize(moduleName);
    size_t patLen = strlen(mask);

    for (size_t i = 0; i < size - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (mask[j] == 'x' &&
                *(uint8_t*)(base + i + j) != (uint8_t)pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

// 使用示例
// Ghidra 提取的目标指令: mov rax, [rcx+0x10] at game.dll+0x3A2B10
uintptr_t addr = FindPattern("game.dll",
    "\x48\x8B\x41\x10\x48\x89\x45\xF8",
    "xxxxxxxx");
if (addr) {
    // 找到: game.dll+0x3A2B10 (即使 ASLR 已经改变基址)
}
```

## 偏移定位模式

```cpp
// 常见: 找到特征码后加上相对偏移获取目标地址
// 适用: 特征码中包含 rel32 的 CALL/JMP
uintptr_t FindPatternWithOffset(const char* moduleName,
    const char* pattern, const char* mask, int offset) {
    uintptr_t match = FindPattern(moduleName, pattern, mask);
    if (!match) return 0;

    // 提取相对偏移: 指令地址 + 指令长度 + rel32
    int32_t rel = *(int32_t*)(match + offset - 4);
    return match + offset + rel;
}

// 例: CALL 0x12345 → E8 XX XX XX XX
// 目标地址 = 特征码地址 + 5 + rel32
uintptr_t callTarget = FindPatternWithOffset(
    "game.dll", "\xE8\x00\x00\x00\x00\x48", "x????x", 5);
```

## 优化: 按节区扫描

```cpp
// 只扫描 .text 节区（代码段），避免命中 .data/.rdata
uintptr_t FindPatternInSection(const char* moduleName, const char* sectionName,
    const char* pattern, const char* mask) {
    uintptr_t base = GetModuleBase(moduleName);
    // 解析 PE header 找到节区
    auto dosHeader = (IMAGE_DOS_HEADER*)base;
    auto ntHeaders = (IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, sectionName, strlen(sectionName)) == 0) {
            uintptr_t secBase = base + section[i].VirtualAddress;
            size_t secSize = section[i].Misc.VirtualSize;
            // 在节区内扫描 pattern...
        }
    }
    return 0;
}
```

## 实战: 生成特征码

```python
# 从二进制文件中提取字节序列
import struct

def extract_pattern(filepath, offset, length):
    with open(filepath, 'rb') as f:
        f.seek(offset)
        return f.read(length)

def bytes_to_ida_pattern(data):
    """转为 IDA 风格的 mask 字符串"""
    return ' '.join(f'{b:02X}' for b in data)

def bytes_to_code_pattern(data):
    """转为 C 风格的 \x 转义字符串"""
    return ''.join(f'\\x{b:02X}' for b in data)
```

## 攻击链

```
Ghidra 定位目标指令 → 复制字节序列 → 排除 rel32/imm32（用 ?? 代替）
→ 选择 8-16 字节唯一定位 → 编写 FindPattern → 运行时扫描 → 验证命中唯一
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Ghidra 定位目标指令 | `triage_pe` | 一键 hash/DiE/rz-bin info/sections/imports/strings 初筛 |
| Ghidra 分析提取特征码 | `ghidra_headless_analyze` | Ghidra 导入+自动分析，定位目标指令提取特征码 |
| 按行为推荐函数阅读优先级 | `ghidra_summary_call_focus` | 按行为推荐函数阅读优先级 |
| 搜索特定函数获取地址 | `ghidra_summary_functions` | 搜索特定函数，获取地址用于特征码提取 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
