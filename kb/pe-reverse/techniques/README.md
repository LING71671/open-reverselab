# PE 逆向技术库

Windows PE/二进制实战逆向 Lab。每个文件 = 可复制运行的 C++/Frida 代码。攻击视角，可实战。

## 目录 (9 篇)

```
01-triage/            (1)   aob-signature-scan
02-pe-structure/      (1)   pe-header-parsing
03-static-analysis/   (2)   struct-reconstruction + disasm-jit-asm
04-dynamic-analysis/  (3)   dll-injection + trampoline-detour + external-memory-rw
05-crypto-unpack/     (1)   pe-unpack-dump
06-ioc-extraction/    (0)   待补充
07-yara-sigma/        (0)   待补充
08-patch/             (1)   code-patching
```

## 分类索引

### 01-triage — 初筛与特征码
- `01-aob-signature-scan.md`: IDA/Ghidra 提取特征码, mask 模式, 全模块扫描, 按节区扫描, FindPatternWithOffset

### 02-pe-structure — PE 结构解析
- `01-pe-header-parsing.md`: DOS/NT Header 手动解析, 节区遍历, 导入表导出表枚举, IAT 解析

### 03-static-analysis — 静态分析
- `01-struct-reconstruction.md`: 从汇编偏移推断结构体, 类型推断(int/float/pointer), 指针链 vs 内嵌, 链表遍历
- `02-disasm-jit-asm.md`: Zydis 反汇编, Xbyak JIT 汇编, 指令边界判定, 字节级编码

### 04-dynamic-analysis — 动态分析
- `01-dll-injection.md`: CreateRemoteThread+LoadLibrary, Toolhelp32 进程枚举, DllMain 委派, 自弹出
- `02-trampoline-detour.md`: Trampoline 函数劫持, 寄存器保存/恢复, JMP 偏移计算, NOP sled
- `03-external-memory-rw.md`: ReadProcessMemory/WriteProcessMemory, FindDMAAddy, 内部 vs 外部

### 05-crypto-unpack — 脱壳/Dump
- `01-pe-unpack-dump.md`: x64dbg+Scylla, Frida 运行时 dump, ProcDump, IAT 修复, 壳行为追踪

### 08-patch — Patch 与修改
- `01-code-patching.md`: VirtualProtect 写保护内存, NOP/JMP/立即数 patch, 函数劫持, 安装/卸载模板

## 工具映射

```
x64dbg / Scylla              → 动态调试 + dump + IAT 修复
Ghidra / IDA                 → 静态反编译
DiE / diec                   → 壳检测
Zydis                        → 反汇编库
Xbyak                        → JIT 汇编库
Frida                        → 运行时 Hook
ProcDump (Sysinternals)      → 全内存 dump
Cheat Engine                 → 内存扫描/修改
ReClass                      → 结构体重建
```

## 分析链总览

```
PE 文件 → DiE triage → 特征码提取 → PE 头解析
→ 加壳检测 → 脱壳/dump → Ghidra 静态分析 → 结构体重建
→ DLL 注入 → Trampoline Hook → 外部/内部内存读写 → Patch/修改
```
