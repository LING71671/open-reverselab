# PE 逆向技术库

Windows PE/二进制逆向技术库。覆盖 triage、静态/动态分析、脱壳、IOC、检测规则与 Patch。

## 完整目录（9 类 / 19 篇）

### 01-triage — 初筛（1）

- [`01-triage/01-aob-signature-scan.md`](01-triage/01-aob-signature-scan.md) — AOB 特征码扫描

### 02-pe-structure — PE 结构（1）

- [`02-pe-structure/01-pe-header-parsing.md`](02-pe-structure/01-pe-header-parsing.md) — PE 头解析与节区定位

### 03-static-analysis — 静态分析（4）

- [`03-static-analysis/01-struct-reconstruction.md`](03-static-analysis/01-struct-reconstruction.md) — 内存结构体逆向重建
- [`03-static-analysis/02-disasm-jit-asm.md`](03-static-analysis/02-disasm-jit-asm.md) — 反汇编（Zydis）与 JIT 汇编（Xbyak）
- [`03-static-analysis/03-x64dbg-breakpoints.md`](03-static-analysis/03-x64dbg-breakpoints.md) — x64dbg 断点策略
- [`03-static-analysis/04-reclass-reconstruction.md`](03-static-analysis/04-reclass-reconstruction.md) — ReClass 结构体实时重建

### 04-dynamic-analysis — 动态分析（8）

- [`04-dynamic-analysis/01-dll-injection.md`](04-dynamic-analysis/01-dll-injection.md) — DLL 注入三模式
- [`04-dynamic-analysis/02-trampoline-detour.md`](04-dynamic-analysis/02-trampoline-detour.md) — Trampoline Hook（函数劫持）
- [`04-dynamic-analysis/03-external-memory-rw.md`](04-dynamic-analysis/03-external-memory-rw.md) — 外部进程内存读写
- [`04-dynamic-analysis/04-naked-function-hook.md`](04-dynamic-analysis/04-naked-function-hook.md) — Naked 函数 Hook（内联汇编）
- [`04-dynamic-analysis/05-anti-debug-bypass.md`](04-dynamic-analysis/05-anti-debug-bypass.md) — 反调试检测与绕过
- [`04-dynamic-analysis/06-manual-map-injection.md`](04-dynamic-analysis/06-manual-map-injection.md) — 手动映射 DLL 注入
- [`04-dynamic-analysis/07-direct-syscall.md`](04-dynamic-analysis/07-direct-syscall.md) — Direct Syscall：绕过用户态 Hook
- [`04-dynamic-analysis/08-procmon-patterns.md`](04-dynamic-analysis/08-procmon-patterns.md) — Procmon 行为监控与过滤

### 05-crypto-unpack — 加密/脱壳（1）

- [`05-crypto-unpack/01-pe-unpack-dump.md`](05-crypto-unpack/01-pe-unpack-dump.md) — PE 脱壳与内存 Dump

### 06-ioc-extraction — IOC 提取（1）

- [`06-ioc-extraction/01-ioc-extraction.md`](06-ioc-extraction/01-ioc-extraction.md) — IOC 提取技巧

### 07-yara-sigma — YARA/Sigma（1）

- [`07-yara-sigma/01-yara-rule-writing.md`](07-yara-sigma/01-yara-rule-writing.md) — YARA 规则编写（逆向视角）

### 08-patch — Patch（1）

- [`08-patch/01-code-patching.md`](08-patch/01-code-patching.md) — 代码 Patch 与字节修改

### 09-av-evasion — AI 免杀（1）

- [`09-av-evasion/01-ai-powered-evasion.md`](09-av-evasion/01-ai-powered-evasion.md) — AI 驱动免杀：Shellcode 处理 + Loader 编写

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
Hash/类型/保护 → Ghidra 静态分析 → x64dbg/Frida/Procmon 验证 → IOC/YARA/Sigma → Patch 副本
```
