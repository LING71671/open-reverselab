---
id: "pe-reverse/05-crypto-unpack/02-vmp-virtualization-analysis"
title: "VMP 虚拟化原理与 VM Entry 定位"
title_en: "VMProtect Virtualization Internals and VM Entry Location"
summary: >
  VMProtect 虚拟化保护原理（VM entry/VM context/dispatcher/handler 轮换/加密字节码/VM exit）、VMP 2.x 与 3.x 差异、版本识别、VM entry 定位四步法（上下文保存序列、间接跳转表、VM key、断点策略）以及 VMP SDK 自检反调试绕过，附 x64dbg 特征搜索、Frida 自检 Hook 和 IDAPython 定位脚本。
summary_en: >
  VMProtect virtualization internals (VM entry / VM context / dispatcher / handler rotation / encrypted bytecode / VM exit), VMP 2.x vs 3.x differences, version identification, a four-step VM entry location method (context save sequence, indirect jump table, VM key, breakpoint strategy), and VMP SDK self-check anti-debug bypass, with x64dbg pattern search, Frida self-check hook, and IDAPython scripts.
board: "pe-reverse"
category: "05-crypto-unpack"
signals:
  - "VMProtect"
  - "VMP"
  - "virtualization"
  - "VM entry"
  - "handler"
  - "dispatcher"
  - "VMProtectIsDebuggerPresent"
  - "虚拟化"
  - "vmp0"
  - "vmp1"
  - ".vmp"
mcp_tools:
  - die_scan
  - make_pe_crypto_unpack_plan
  - make_x64dbg_breakpoint_script
  - ghidra_summary_call_focus
keywords:
  - "VMProtect"
  - "VMP"
  - "virtualization"
  - "VM entry"
  - "dispatcher"
  - "handler"
  - "bytecode"
  - "anti-debug"
  - "VMProtectIsDebuggerPresent"
  - "ScyllaHide"
difficulty: "advanced"
tags:
  - "vmprotect"
  - "virtualization"
  - "packer"
  - "anti-debug"
  - "unpacking"
  - "dynamic-analysis"
language: "zh-CN"
last_updated: "2026-08-09"
related_articles:
  - "pe-reverse/05-crypto-unpack/01-pe-unpack-dump"
  - "pe-reverse/05-crypto-unpack/03-vmp-devirtualization-toolchain"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass"
---
# VMP 虚拟化原理与 VM Entry 定位

## 场景

目标 PE 被 VMProtect 虚拟化保护：关键函数被编译为自定义字节码，由内置解释器（VM）执行。x64dbg 单步看到的是 handler 循环而不是原始指令，Ghidra 反编译结果为垃圾代码。需要在理解 VMP 执行模型的基础上定位 VM entry，为后续去虚拟化（见 `03-vmp-devirtualization-toolchain`）或手动还原做准备。

## 输入信号

- DiE 输出 `VMProtect(3.x)` / `VMProtect(2.x)` 签名（`diec -b target.exe`）
- 节区名为 `.vmp0` / `.vmp1`（2.x）或 `VMProtect` 自定义节区（3.x）
- 导入表极简：只剩 `LoadLibraryW`/`GetProcAddress`/少数系统 API
- 入口点在壳节区；函数入口处是 `push rbx ... mov [rsp+xx], rXX` 的上下文保存序列而非标准 prologue
- 被保护函数调用点出现 `call sub_XXXX`（VM entry 桩），被调函数内部是大循环 + 大量间接跳转
- 程序运行正常但任何调试器附加后闪退/卡死（VMP 自检）

## VMP 虚拟化执行模型

```
正常执行:  真实代码指令 → CPU 直接执行

VMP 虚拟化: 被保护函数 → 编译为自定义字节码(加密) → VM entry 桩
              → 保存真实寄存器/栈到 VM context(虚拟寄存器数组)
              → 跳入 dispatcher(取指循环)
              → 按 opcode 分发到 handler(mov/push/pop/add/xor/jmp/call/ret...)
              → handler 内部执行被 mutation 混淆的指令序列
              → VM exit 时从 context 恢复寄存器 → 跳回真实代码
```

关键点：

1. **VM entry**：被保护函数的原始入口被替换为"进入 VM"的桩代码。桩内做两件事：把真实寄存器/栈上下文写入 VM context；把 VM key（解密字节码/立即数的密钥）装入寄存器，然后跳 dispatcher。
2. **VM context**：一片内存区域充当虚拟寄存器数组（VMP 2.x 约 16+ 个虚拟寄存器，布局随版本/变异变化）。真实寄存器与虚拟寄存器之间没有固定映射，每次编译都可能不同。
3. **Dispatcher**：取指循环。VMP 2.x 常见形式是 `movzx eax, byte ptr [vm_ip]` + `jmp [handler_table + rax*8]` 的间接跳转；3.x 改为加密/运行时计算的间接跳转（见下）。
4. **Handler 轮换**：同一语义（如 `mov`）存在多个变体 handler（可达数十个），编译时按上下文随机选择；每次重新加壳 handler 顺序与数量都变。**不要试图对 handler 地址建立跨样本指纹**。
5. **加密字节码与立即数**：opcode 和立即数被 VM key 做算术变换（XOR/ADD/乘），运行时在 handler 内解出。静态看到的"立即数"不是真值。
6. **VM exit**：字节码流中的 exit 指令触发：从 context 恢复真实寄存器、返回真实代码地址。调用点通常表现为 `jmp [rsp+xx]` 或 `ret` 到真实代码。

## VMP 2.x 与 3.x 差异

| 特征 | VMP 2.x | VMP 3.x |
|---|---|---|
| 节区 | `.vmp0` / `.vmp1` | 节区名更隐蔽，需看特征字节 |
| dispatcher | `jmp [reg+offset]` 跳转表，静态可见 | 间接跳转被加密/运行时计算，静态看不出目标 |
| VM context | 固定布局，研究资料多 | context 进入/退出时被 XOR/ADD 变换（解密后才可用） |
| handler | 数量有限，已有公开指纹 | 数量更多、轮换更强、每样本差异更大 |
| 反调试 | SDK 自检可选 | 自检默认更强，含虚拟化工具检测 |
| 去虚拟化难度 | 社区工具可部分处理 | NoVmp 类工具大概率失效，需动态 DSE/trace |

版本判断：DiE 输出 + `x64dbg → 选项 → 检查 VMProtect 区段`；也可用 `rizin_strings` 找 `VMProtect`/`VMP` 字样和 SDK 版本资源。

## VM entry 定位四步法

### 第 1 步：上下文保存序列（静态特征）

VM entry 桩开头是"把全部通用寄存器压入 VM context"的序列，x86 下类似：

```asm
; x86 VMP 2.x 常见形态（每样本不同，看结构不看字节）
pushad                    ; 或逐寄存器 push
mov esi, <VM_KEY>         ; VM key → esi
mov edi, <VM_CONTEXT_ADDR>
; 然后写入 context 槽位, 跳 dispatcher
jmp <dispatcher>
```

x64 下没有 pushad，表现为 `push rbx; push rsi; push rdi; ... mov [rsp+offset], rXX` 的寄存器搬运序列。x64dbg 特征搜索（Ctrl+B，支持通配符）：

```
搜索 mov esi/edi 加载常量后紧跟间接跳转:
8B 35 ?? ?? ?? ??          mov esi, dword ptr [imm32]   ; VM key 常见 esi
FF 25 ?? ?? ?? ??          jmp qword ptr [rip+imm32]    ; 间接跳转
```

### 第 2 步：间接跳转表（dispatcher 定位）

在函数调用点 `call sub_XXXX` 进入后，观察前几十条指令：若出现"取字节 → 查表跳转"循环，即为 dispatcher：

```asm
; 2.x dispatcher 骨架
vm_loop:
  movzx eax, byte ptr [rdi]   ; 取 opcode (rdi = vm_ip)
  inc rdi
  jmp qword ptr [r12 + rax*8] ; r12 = handler_table, 8 字节指针表
```

x64dbg 断点策略：在 dispatcher 的取指处下断，`RDI`（或对应寄存器）就是 VM 指令指针；配合内存 dump 可以看到字节码流。字节码区域通常在 `.vmp0` 或堆上。

### 第 3 步：VM key 追踪

handler 内解立即数的算术混淆以 VM key 为种子。在 VM entry 桩里 key 被装入固定寄存器（2.x 常见 `esi`/`edx`），在 handler 入口观察该寄存器的值即为当前 VM key。不同 VM 实例（不同被保护函数）key 可能不同。

### 第 4 步：动态断点组合

```
bp VirtualAlloc          → 壳分配 VM context/字节码缓冲
bp VirtualProtect        → 改页属性时机 = 解密完成点
bp GetProcAddress        → 3.x 常见 API 解析
硬件断点(内存) 于 context 地址 → 观察 handler 读写虚拟寄存器
```

## VMP 自检与反调试绕过

VMP SDK 自检独立于虚拟化，运行时检测调试器：

| 检测手段 | 说明 | 绕过 |
|---|---|---|
| `VMProtectIsDebuggerPresent()` | SDK API，内部组合 PEB/异常链/时间检测 | Frida hook 返回 0；或 patch 调用点 |
| `int 2d` / `int 3` 异常链 | 未接调试器时异常处理链吞掉，接了则断下 | ScyllaHide 的异常链伪造选项 |
| RDTSC 时间差 | 检测单步/断点延迟 | 硬断不停检测区；patch 阈值 |
| NtQueryInformationProcess(DebugPort) | 内核调试端口非零 | hook 返回 0（见 `04-dynamic-analysis/05-anti-debug-bypass`） |
| 虚拟化工具检测 | 检测 VM 环境（VMP 3.x 新增） | 用真实物理机/关闭检测项 |

绕过工具：**ScyllaHide**（x64dbg/IDA 插件，外部工具）一键勾选全部隐藏选项即可过大部分 VMP 自检；更隐蔽的方案是 bochscpu（x64dbg 插件，在 Bochs 模拟器中全系统执行，调试器对目标完全不可见，但速度慢）。Frida 通用 Hook：

```javascript
// 在进程启动早期替换 VMP SDK 自检导出（若导出存在）
var names = ["VMProtectIsDebuggerPresent", "VMProtectIsVirtualMachinePresent"]
names.forEach(function (n) {
    var p = Module.findExportByName(null, n)
    if (p) Interceptor.replace(p, new NativeCallback(function () {
        return 0
    }, 'int', []))
})
// 兜底: 直接清 PEB 标志
var peb = Process.findModuleByName("ntdll.dll").base.add(0x20000) // x64 PEB 近似定位不可靠, 优先用上面的 API 替换
```

## IDAPython 快速定位 VM entry

```python
# 在 IDA 中对被保护函数的全部调用点下标注, 输出候选 VM entry
import idautils, idc
for f in idautils.Functions():
    # 上下文保存特征: 函数开头大量 push + mov [esp+..], reg
    head = idc.get_bytes(idc.get_func_attr(f, idc.FUNCATTR_START), 64)
    if not head:
        continue
    pushes = head.count(b'\x53') + head.count(b'\x56') + head.count(b'\x57')  # push rbx/rsi/rdi
    if pushes >= 3 and b'\xff\x25' in head:  # 且含间接跳转
        print(f"[?] {hex(f)} pushes={pushes} 疑似 VM entry")
```

## 攻击链

```
DiE 确认 VMProtect 版本 → 记下节区/EP
→ x64dbg + ScyllaHide 加载（先过自检）
→ 在目标函数调用点 call 处 F7 进入 → 观察上下文保存序列 → 确认 VM entry
→ 记录 VM key 寄存器、dispatcher 取指位置、handler 表地址
→ 内存 dump 字节码区 → 结合 handler 分析/去虚拟化工具链（03 篇）还原语义
→ 输出: VM entry 地址表 + dispatcher 分析笔记 → 供 devirt 或手动还原
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| DiE 确认 VMProtect 版本与节区 | `die_scan` | DiE 检测 VMP 签名（支持 deep/entropy） |
| 一键生成脱壳/动态分析包 | `make_pe_crypto_unpack_plan` | 生成 x64dbg 断点 + Frida hook + 重点函数队列（mode="unpack"） |
| 生成 VM entry/API 断点脚本 | `make_x64dbg_breakpoint_script` | 按函数地址/API 生成断点脚本 |
| 从 Ghidra summary 找被保护函数 | `ghidra_summary_call_focus` | 按 behavior/query 筛选重点函数（body 巨大、间接跳转多的函数即候选） |

## 证据与验证闭环

- 记录样本 SHA256、架构、VMP 版本（DiE 输出）、节区名、EP RVA/文件偏移。
- VM entry 定位结论必须绑定：调用点地址、entry 地址、上下文保存序列字节、VM key 寄存器与值、dispatcher 取指地址、handler 表地址。
- 反调试绕过结论绑定：自检 API 名称、hook/patch 的原始字节与新字节、绕过前后行为差异（附加不闪退）。
- 将 x64dbg 日志、字节码 dump、断点命中记录保存到 `exports/windows/`，按同一输入重跑确认可复现。
