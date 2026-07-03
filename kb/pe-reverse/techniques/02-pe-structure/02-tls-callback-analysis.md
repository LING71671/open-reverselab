---
id: "pe-reverse/02-pe-structure/02-tls-callback-analysis"
title: "TLS Callback 定位与早期执行链"
title_en: "TLS Callback Location and Early Execution Chain"
summary: >
  PE TLS Directory 与 TLS Callback 分析卡片，覆盖入口点前执行、反调试、解密 stub、OEP 跳转和 x64dbg/Ghidra 打点路径。
summary_en: >
  PE TLS Directory and TLS Callback analysis card covering pre-entry execution, anti-debug, decrypt stubs, OEP transfer, and x64dbg/Ghidra instrumentation paths.
board: "pe-reverse"
category: "02-pe-structure"
signals:
  - "TLS Directory"
  - "TLS Callback"
  - "AddressOfCallBacks"
  - "EntryPoint 前执行"
  - "反调试早期触发"
mcp_tools:
  - "triage_pe"
  - "ghidra_headless_analyze"
  - "make_x64dbg_breakpoint_script"
  - "kb_router"
keywords:
  - "TLS Callback"
  - "PE TLS Directory"
  - "AddressOfCallBacks"
  - "OEP"
  - "x64dbg"
  - "Ghidra"
difficulty: "intermediate"
tags:
  - "pe"
  - "tls"
  - "entrypoint"
  - "anti-debug"
  - "unpack"
language: "zh-CN"
last_updated: "2026-07-03"
related_articles:
  - "pe-reverse/02-pe-structure/01-pe-header-parsing"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass"
---
# TLS Callback 定位与早期执行链

## 1. 入口信号

```text
程序在 EntryPoint 前退出或弹窗
DiE/PE-bear 显示 TLS Directory 非空
Ghidra Memory Map 有 .tls / IMAGE_DIRECTORY_ENTRY_TLS
x64dbg 停在 ntdll!LdrpCallTlsInitializers
OEP 前发生解密、反调试或进程环境检查
```

TLS Callback 是 PE 入口点之前的执行节点。遇到早期崩溃、OEP 不落地、反调试先触发时，先看 TLS。

## 2. 静态定位

```powershell
python scripts/misc/ai_tool.py run triage_pe -- samples/app.exe --out exports/pe/app/triage.json
python scripts/misc/ai_tool.py run ghidra_headless_analyze -- samples/app.exe --out exports/pe/app/ghidra
```

手动结构字段：

```text
OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
  VirtualAddress -> IMAGE_TLS_DIRECTORY
  AddressOfCallBacks -> callback pointer array
```

Python 快速列 TLS callback：

```python
import pefile

pe = pefile.PE("samples/app.exe")
tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
if tls:
    callbacks = tls.struct.AddressOfCallBacks
    va = callbacks
    while True:
        off = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
        ptr = int.from_bytes(pe.__data__[off:off + pe.OPTIONAL_HEADER.Magic.to_bytes(2, "little")[0] // 0x10], "little")
        if ptr == 0:
            break
        print(hex(ptr))
        va += 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
```

## 3. x64dbg 打点

```text
bp ntdll.LdrpCallTlsInitializers
bp ntdll.LdrpCallInitRoutine
bp kernel32.IsDebuggerPresent
bp ntdll.NtQueryInformationProcess
bp kernel32.VirtualProtect
```

命中后记录：

```text
callback VA:
return address:
RCX/EDX/R8 参数:
是否修改 .text/.rdata:
是否跳转到 unpacked OEP:
```

## 4. Ghidra 命名策略

```text
tls_callback_0_anti_debug
tls_callback_1_decrypt_text
tls_callback_2_resolve_imports
```

对 callback 输出：

```text
作用:
输入:
输出:
副作用:
调用者:
被调用者:
下一跳:
```

## 5. 路径分叉

| TLS 行为 | 打点动作 | 下一跳 |
|---|---|---|
| 调 `IsDebuggerPresent` | patch 返回值 / 条件断点 | anti-debug bypass |
| 调 `VirtualProtect` 后写 `.text` | dump 内存 | unpack |
| 遍历 PEB / BeingDebugged | 断在 PEB 读取 | patch flag |
| 解密字符串 | hook 解密函数返回 | IOC/crypto |
| 动态解析 API | 跟 `GetProcAddress` | API resolver |

## 6. 攻击链 / 工作流

```text
EntryPoint 前退出 / OEP 不落地
  → triage_pe / PE-bear 确认 TLS Directory
  → x64dbg 断 LdrpCallTlsInitializers / LdrpCallInitRoutine
  → 记录 callback VA、参数和节区改写
  → 若触发反调试则 patch 条件；若解密代码则 dump 内存
  → 回到 Ghidra 重命名 callback 和下一跳函数
```

## 7. Evidence

| 项 | 记录内容 |
|---|---|
| TLS Directory | RVA、file offset、AddressOfCallBacks |
| Callback | VA/RVA、函数名、调用顺序 |
| 动态命中 | x64dbg 断点、寄存器、调用栈 |
| 副作用 | 改写节区、解密字符串、解析 API |
| 下一跳 | anti-debug、unpack、crypto、IOC |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| PE 初筛 | `triage_pe` | 抽取 TLS Directory、节区和入口信息 |
| 静态分析 | `ghidra_headless_analyze` | callback 函数和调用图 |
| 断点脚本 | `make_x64dbg_breakpoint_script` | 生成 TLS/anti-debug 断点 |
| 知识路由 | `kb_router` | 按 TLS callback、OEP、anti-debug 查下一篇 |
