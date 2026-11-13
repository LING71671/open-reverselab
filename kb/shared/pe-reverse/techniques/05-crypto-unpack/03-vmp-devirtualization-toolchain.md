---
id: "pe-reverse/05-crypto-unpack/03-vmp-devirtualization-toolchain"
title: "VMP 去虚拟化工具链（Devirtualization）"
title_en: "VMProtect Devirtualization Toolchain"
summary: >
  VMP 去虚拟化三级降级策略：NoVmp/NoVmpy 静态 devirtualization（VTIL 流水线）→ Triton 符号执行 DSE→LLVM → trace 语义折叠，附各外部工具的安装方式、可运行脚本骨架、handler 指纹思路与输入输出等价性验证，明确区分 ReverseLab 已集成工具与需自行安装的外部开源工具。
summary_en: >
  Three-tier VMP devirtualization strategy: NoVmp/NoVmpy static devirtualization (VTIL pipeline) → Triton symbolic execution DSE→LLVM → trace-based semantic folding, with install commands, runnable script skeletons, handler fingerprint ideas, and I/O equivalence verification, clearly separating integrated ReverseLab tools from external open-source tools requiring manual install.
board: "pe-reverse"
category: "05-crypto-unpack"
signals:
  - "devirtualization"
  - "deobfuscation"
  - "Triton"
  - "VTIL"
  - "NoVmp"
  - "angr"
  - "symbolic execution"
  - "trace"
  - "去虚拟化"
  - "DSE"
mcp_tools:
  - python_re_tool_install
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
  - carve_payloads_from_dump
keywords:
  - "VMProtect"
  - "devirtualization"
  - "Triton"
  - "VTIL"
  - "NoVmp"
  - "angr"
  - "symbolic execution"
  - "DSE"
  - "trace"
  - "LLVM"
difficulty: "advanced"
tags:
  - "vmprotect"
  - "devirtualization"
  - "triton"
  - "vtl"
  - "novmp"
  - "symbolic-execution"
  - "trace"
language: "zh-CN"
last_updated: "2026-08-09"
related_articles:
  - "pe-reverse/05-crypto-unpack/01-pe-unpack-dump"
  - "pe-reverse/05-crypto-unpack/02-vmp-virtualization-analysis"
---
# VMP 去虚拟化工具链（Devirtualization）

## 场景

已按 `02-vmp-virtualization-analysis` 定位 VM entry 与 dispatcher，但 handler 数量多、mutation 重，纯手工还原不可行。需要用自动化工具把"handler 序列"还原为高层指令/IR。本文给出**三级降级策略**与配套外部开源工具链，并明确工具归属（ReverseLab 已集成 vs 需自行安装）。

## 输入信号

- 已确认 VMP 2.x/3.x 且拿到 VM entry 地址表
- 需要还原语义的函数是纯函数（输入输出可枚举、无系统调用副作用）——这是 DSE 路线的必要条件
- 被保护函数含调用外部 API（call handler）→ 静态 devirt 可能失败，需动态 trace 兜底

## 三级降级策略总览

```
第 1 级: 静态 devirtualization (NoVmp/NoVmpy + VTIL)
         快, 适合 VMP 2.x/3.0-3.5 x64; 新版 VMP 3.8+ 大概率失败 → 降级
第 2 级: 符号执行 DSE (Triton / angr)
         以 VM entry 寄存器为符号输入跑解释器, 求解后化简为 LLVM IR/表达式
         适合纯函数; 性能开销大
第 3 级: trace 语义折叠 (bochscpu/PIN + 模式匹配, VMHunt 思路)
         记录 VM 循环指令 trace, 按 handler 指纹折叠为高层指令
         适合任何函数, 但人工校对量大
```

每一级失败立即降级到下一级，不要在一级上死磕。

## 第 1 级：静态 devirt（NoVmp / NoVmpy）

> **外部工具**：以下工具不在 ReverseLab 工具箱内，需自行编译/安装。star 数据为 2026-08 GitHub 快照，适用性随 VMP 版本变化，落地前先在样本上验证。

| 工具 | URL | 语言 | 功能 | 维护状态 |
|---|---|---|---|---|
| NoVmp | github.com/can1357/NoVmp | C++ | VTIL 驱动 VMP 3.x x64 静态 devirt | 2021 后停更；对 VMP 3.8+ 大概率失效 |
| NoVmpy | github.com/wallds/NoVmpy | Python | NoVmp 的 Python 移植（含 VTIL 绑定） | 2025 仍有提交 |
| VTIL-Core | github.com/vtil-project/VTIL-Core | C++ | 虚拟化翻译 IR + 优化/反混淆后端（NoVmp 依赖） | 活跃（2026-07） |
| Triton | github.com/JonathanSalwan/Triton | C++ | DBA 符号执行库（第 2 级核心） | 活跃 |
| VMProtect-devirtualization | github.com/JonathanSalwan/VMProtect-devirtualization | C++/LLVM | Triton DSE + LLVM 自动去虚拟化纯函数 | 2022 停更，参考实现 |
| VMHunt | github.com/s3team/VMHunt | C++ | PIN trace + 符号执行 + 语义验证（CCS'18） | 2018 停更，思路参考 |
| ScyllaHide-IDA7.5 | github.com/notify-bibi/ScyllaHide-IDA7.5 | C++ | 反反调试插件（前置步骤） | 2021 停更 |

NoVmp 运行流水线（x64 样本、Visual Studio 构建）：

```
1. git clone --recursive https://github.com/can1357/NoVmp
2. VS 打开 NoVmp.sln 编译 (Release x64)
3. NoVmp.exe <sample.exe> <function_rva>
   → 输出 <sample>.devirt.exe + <sample>.devirt.ll (LLVM IR)
4. 用 Ghidra/IDA 加载 devirt 产物, 或直接读 .ll 验证语义
5. 失败特征: 输出与原始行为不符 / 崩溃 / 空 IR → 降级到第 2 级
```

## 第 2 级：符号执行 DSE（Triton）

原理：以 VM entry 处寄存器为符号值，让 VMP 解释器在符号引擎中执行，handler 展开的表达式被求解并化简，输出"输入寄存器 → 输出寄存器"的语义公式。参考 JonathanSalwan/VMProtect-devirtualization 的流程（Triton 脚本 → LLVM IR → 验证）。

Python 骨架（Triton 有 Python 绑定，但**未列入 MCP 安装 allowlist**：PyPI 的 `triton` 包名与 OpenAI GPU 编译器冲突，需要时从源码构建，或用 angr 作为 DSE 替代）：

```python
# 思路骨架: 用 Triton 仿真 VM entry 到 VM exit, 提取符号表达式
from triton import TritonContext, ARCH, Instruction, MODE
ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ONLY_SYMBOLIZE_INDEXED_MEMORY, True)

# 1. 把样本加载到模拟内存(可用 unicorn 先 dump 运行态内存)
# 2. 在 VM entry 处开始, 通用寄存器符号化:
#    for reg in ctx.getParentRegisters(): ctx.symbolizeRegister(reg)
# 3. 单步执行到 VM exit (结束地址 = entry 的 ret 目标):
#    while ctx.getConcreteRegisterValue(ctx.registers.rip) != exit_addr:
#        insn = Instruction(bytes=ctx.getConcreteMemoryAreaValue(pc, 15), address=pc)
#        ctx.processing(insn)
# 4. 对目标寄存器取表达式并化简:
#    expr = ctx.getSymbolicExpression(ctx.getSymbolicRegister(ctx.registers.rax)).getAst()
#    print(ctx.getAstContext().unroll(expr))   # 化简后的语义公式
```

关键约束：**只对纯函数做 DSE**（无系统调用、无内存副作用依赖）；VM context 在 3.x 中进出被变换，符号化起点选在 dispatcher 入口而非函数入口更稳。执行前先过反调试（ScyllaHide / patch 自检）。

## 第 3 级：trace 语义折叠（VMHunt 思路）

```
1. bochscpu (x64dbg 插件, 外部工具) 或 PIN 记录 VM 循环内全部指令 trace
   → 得到 (内存地址, 指令字节) 序列
2. 按 handler 边界切分 trace: dispatcher 跳转目标即 handler 起点
3. 对每个 handler 片段做符号执行/模式匹配, 得到该 handler 的语义
   (mov x, imm / add r, c / jmp label / call api ...)
4. 折叠: 把连续 handler 序列翻译为高层指令流, 人工校对
5. 验证: 同一输入分别跑原始样本与还原代码, 比较输出 (见下)
```

VMHunt 的语义验证思路可直接复用：还原代码与原始样本在全部测试向量上输出一致才算还原成功。

## 结果验证（输入输出等价性）

无论哪一级还原，都必须做等价性验证：

```python
# 伪代码: 对比原始与还原结果的输入输出对
test_vectors = [v1, v2, v3]          # 覆盖边界值/随机值
for v in test_vectors:
    orig_out = run_original(v)       # x64dbg/独立进程调用被保护函数
    dev_out   = run_devirt(v)        # 运行还原后的函数/IR
    assert orig_out == dev_out, f"mismatch on {v}"
print("devirtualization verified")
```

验证失败 = 还原不完整（漏 handler 语义、VM key 解错、字节码错位），回到对应级别修正。

## 攻击链

```
样本 + VM entry 地址表 (来自 02 篇)
→ 前置: ScyllaHide/bochscpu 过自检
→ 第 1 级 NoVmp: 静态 devirt → 成功? → 等价性验证 → 完成
→ 失败 → 第 2 级 Triton DSE (纯函数) → LLVM IR → 验证
→ 失败 → 第 3 级 trace 折叠 → 人工校对 → 验证
→ 还原结果回填 Ghidra: 给被保护函数重命名/重定义, 继续常规静态分析
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 安装 angr/unicorn Python 库 | `python_re_tool_install` | allowlist 安装逆向库（angr/unicorn/capstone 等），供 DSE/仿真脚本使用；Triton 未纳入 allowlist（PyPI 包名冲突），需源码构建 |
| 分析 devirt 产物 | `ghidra_headless_analyze` | 对 `.devirt.exe`/还原后样本做无头分析导出 summary |
| 读取还原目标函数反编译 | `ghidra_summary_function_detail` | 按地址/函数名读取 callers/callees/decompile 核对还原结果 |
| 从运行态 dump 中 carve 还原 payload | `carve_payloads_from_dump` | 从 dump 自动提取 PE 供后续分析 |

> 说明：NoVmp/VTIL/Triton C++/bochscpu 等外部工具未集成进 ReverseLab MCP；如需自动化，先人工安装验证工具可用性，再考虑封装为 MCP 工具（工具测试闭环见 `scripts/misc/lab_healthcheck.py`）。

## 证据与验证闭环

- 记录样本 SHA256、VMP 版本、被还原函数 RVA、所用工具与版本（NoVmp/VTIL/Triton commit hash）。
- 每一级的结果绑定：输入 RVA、输出文件路径（`.devirt.exe`/`.ll`/trace 文件）、失败模式与降级原因。
- 等价性验证必须记录测试向量集合、原始输出、还原输出、断言结果。
- 工具安装/测试记录：命令、版本输出、样本上是否生效；未验证的工具明确标注"未测试"。
- 全部产物（devirt 输出、trace、验证脚本）保存到 `exports/windows/`。
