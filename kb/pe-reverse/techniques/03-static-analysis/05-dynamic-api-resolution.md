---
id: "pe-reverse/03-static-analysis/05-dynamic-api-resolution"
title: "动态 API 解析链还原"
title_en: "Dynamic API Resolution Chain Recovery"
summary: >
  PE 样本通过 PEB 遍历、hash API、LoadLibrary/GetProcAddress、手写 export parser 隐藏导入表时，恢复 API 名称、hash 常量、调用表和动态断点路径。
summary_en: >
  Recover API names, hash constants, call tables, and dynamic breakpoint paths when PE samples hide imports via PEB walking, API hashing, LoadLibrary/GetProcAddress, or custom export parsing.
board: "pe-reverse"
category: "03-static-analysis"
signals:
  - "GetProcAddress"
  - "LoadLibraryA"
  - "PEB_LDR_DATA"
  - "api hash"
  - "ROR13"
  - "Export Address Table"
  - "import table empty"
mcp_tools:
  - "triage_pe"
  - "ghidra_headless_analyze"
  - "make_x64dbg_breakpoint_script"
  - "kb_router"
keywords:
  - "dynamic API resolution"
  - "API hashing"
  - "PEB walk"
  - "GetProcAddress"
  - "EAT parser"
  - "Ghidra"
difficulty: "advanced"
tags:
  - "pe"
  - "static-analysis"
  - "api"
  - "hash"
  - "ghidra"
language: "zh-CN"
last_updated: "2026-07-03"
related_articles:
  - "pe-reverse/03-static-analysis/02-disasm-jit-asm"
  - "pe-reverse/04-dynamic-analysis/03-external-memory-rw"
---
# 动态 API 解析链还原

## 1. 入口信号

```text
Import Table 很少或为空
字符串里没有 WinAPI 名称，但行为明显调用网络/进程/注册表
Ghidra 看到 fs:[0x30] / gs:[0x60] / PEB_LDR_DATA
循环遍历 export name table 并计算 hash
大量常量形如 0xEC0E4E8E、0x7C0DFCAA
```

目标是把 hash/函数指针恢复成 API 名称，并给后续 x64dbg/Frida 断点提供真实函数表。

## 2. 静态定位

```powershell
python scripts/misc/ai_tool.py run triage_pe -- samples/app.exe --out exports/pe/app/triage.json
python scripts/misc/ai_tool.py run ghidra_headless_analyze -- samples/app.exe --out exports/pe/app/ghidra
rg -n "GetProcAddress|LoadLibrary|VirtualAlloc|WinHttp|RegSetValue" exports/pe/app
```

Ghidra 里优先找这些形态：

```c
// PEB walk
peb = *(longlong *)(in_GS_OFFSET + 0x60);
ldr = *(longlong *)(peb + 0x18);

// export parser
names = image + export->AddressOfNames;
ordinals = image + export->AddressOfNameOrdinals;
functions = image + export->AddressOfFunctions;

// hash loop
hash = ror(hash, 13);
hash += tolower(ch);
```

## 3. Hash 反解脚本

```python
import pefile

def ror32(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xffffffff

def api_hash(name: str) -> int:
    h = 0
    for ch in name:
        h = ror32(h, 13)
        h = (h + ord(ch.lower())) & 0xffffffff
    return h

targets = {0xec0e4e8e, 0x7c0dfcaa}
for dll in ["C:/Windows/System32/kernel32.dll", "C:/Windows/System32/advapi32.dll", "C:/Windows/System32/wininet.dll"]:
    pe = pefile.PE(dll)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode(errors="ignore")
        h = api_hash(name)
        if h in targets:
            print(hex(h), dll, name)
```

把匹配结果回填到 Ghidra：

```text
api_hash_0xec0e4e8e -> VirtualAlloc
api_hash_0x7c0dfcaa -> CreateThread
```

## 4. 动态断点

```text
bp kernel32.LoadLibraryA
bp kernel32.LoadLibraryW
bp kernel32.GetProcAddress
bp ntdll.LdrGetProcedureAddress
bp kernel32.VirtualAlloc
bp kernel32.WriteProcessMemory
```

如果样本手写 EAT parser，不会命中 `GetProcAddress`。改断 hash compare：

```text
findallmem 8E4E0EEC
bp <hash_compare_addr>
```

命中后记录：

```text
module base:
export name candidate:
computed hash:
matched constant:
resolved function pointer:
```

## 5. 路径分叉

| 解析结果 | 下一跳 |
|---|---|
| `VirtualAlloc/VirtualProtect` | unpack / shellcode dump |
| `CreateRemoteThread/WriteProcessMemory` | injection 行为链 |
| `WinHttpSendRequest/InternetOpenUrl` | C2 / protocol |
| `RegSetValueEx/CreateService` | persistence / IOC |
| `BCrypt/CryptDecrypt` | crypto replay |

## 6. 攻击链 / 工作流

```text
Import Table 稀疏 / 行为与导入不匹配
  → Ghidra 找 PEB walk、EAT parser 或 hash loop
  → 用脚本反解 hash 常量并回填 API 名称
  → x64dbg 断 LoadLibrary/GetProcAddress 或 hash compare
  → 建立函数指针表
  → 按解析结果跳到 unpack、network、injection、persistence 或 crypto
```

## 7. Evidence

| 项 | 记录内容 |
|---|---|
| Hash 算法 | rotate、大小写、初始值、DLL 名是否参与 |
| 常量表 | hash 常量、匹配 API、DLL |
| 函数指针表 | table VA/RVA、slot、写入位置 |
| 动态命中 | `GetProcAddress` 参数或 hash compare |
| 下一跳 | unpack、IOC、crypto、patch |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| 初筛 | `triage_pe` | 判断 import 稀疏、节区异常 |
| 静态图 | `ghidra_headless_analyze` | 定位 PEB walk 和 hash loop |
| 断点 | `make_x64dbg_breakpoint_script` | 生成 LoadLibrary/GetProcAddress 断点 |
| 知识路由 | `kb_router` | 按 api hash、PEB、resolver 查下一篇 |
