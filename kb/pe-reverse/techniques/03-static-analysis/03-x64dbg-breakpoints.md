# x64dbg 断点策略

## 场景

在 x64dbg 中附加/启动目标 PE，需要在关键 API 设断点观察行为、在游戏逻辑点设断修改数据。

## 输入信号

- 目标 PE 已加载到 x64dbg
- 知道关键 API（Ghidra 导入表分析得出）
- 需要自动化的条件/日志断点

## 断点类型速查

```
软件断点 (INT3):  0xCC 替换目标指令首字节, 无数量限制
硬件断点 (DR0-3): CPU 调试寄存器, 仅 4 个, 不修改代码
内存断点:         对指定地址范围设置 PAGE_NOACCESS/PAGE_GUARD
条件断点:         软件断点 + 条件表达式, 满足条件才中断
日志断点:         不中断执行, 仅输出日志 (x64dbg "Trace")
```

## 关键 API 断点集

```
# 反调试相关
bp kernel32.IsDebuggerPresent
bp ntdll.NtQueryInformationProcess
bp kernel32.CheckRemoteDebuggerPresent

# 内存分配
bp kernel32.VirtualAlloc      # 壳解密缓冲区
bp kernel32.VirtualProtect    # 改代码段保护 → 准备写入/Patch
bp kernel32.VirtualAllocEx    # 外部进程分配内存

# 进程操作
bp kernel32.OpenProcess       # 谁在打开进程
bp kernel32.CreateRemoteThread # 谁在远程注入
bp kernel32.ReadProcessMemory
bp kernel32.WriteProcessMemory

# 模块加载
bp ntdll.LdrLoadDll           # 所有 DLL 加载都过这里
bp kernel32.LoadLibraryA/W

# 文件操作
bp kernel32.CreateFileA/W     # 文件创建/打开
bp kernel32.ReadFile
bp kernel32.WriteFile         # 尤其是写入其他文件

# 注册表
bp advapi32.RegOpenKeyExA
bp advapi32.RegSetValueExA
```

## 条件断点

```
# x64dbg 条件表达式:
# 1. 在 API 上设断点, 右键 → Conditional
# 2. 输入条件:

# 例: 只在打开特定文件时中断
bp kernel32.CreateFileA
条件: ascii([esp+4]) == 'C:\important.dat'

# 例: 只在写入特定值时中断
bp kernel32.WriteProcessMemory
条件: dword([esp+0x10]) == 0xDEADBEEF

# 例: 只在第 100 次调用时中断
# 先在断点设置 Log Text, 再设 Counter
```

## 日志断点（不中断）

```python
# x64dbg 脚本 (.txt 文件, 通过 Script 窗口加载)
# 记日志而不暂停:
bp kernel32.CreateFileA
SetBreakpointLogCondition breakpoint, "CreateFileA: {a:[arg0]}"
SetBreakpointSilent breakpoint, 1    # 静默, 不解锁调试目标

# 批量 Trace 记录
# 所有 VirtualAlloc 调用:
bp kernel32.VirtualAlloc
SetBreakpointLogCondition breakpoint, "VA: addr={a:[arg0]} size={arg1}"
SetBreakpointCommand breakpoint, "continue"  # 自动继续
```

## 追踪壳行为

```
# 1. 在 VirtualAlloc/VirtualProtect 设日志断点
# 2. 运行到壳解密完成
# 3. 在 .text 段或可疑可执行区域设内存访问断点
# 4. 运行 → 断在 OEP (原入口点)

# x64dbg 命令:
# 设内存断点: 选中代码区域 → 右键 → Memory → Break on Access
# 硬件断点: hwbp OEP_ADDR (先猜测或等壳跑完)
```

## 修改调试目标

```
# 在断点处直接修改值/寄存器
# 例: 修改 eax 返回值绕过检测
bp kernel32.IsDebuggerPresent
SetBreakpointCommand breakpoint, "eax=0; run"  # 设 eax=0 并继续

# 例: 修改内存
# 在断点处: 右键 → Modify Value → 输入新值
```

## x64dbg 脚本示例

```txt
// anti-debug-bypass.txt
// 加载: Script → Load Script

init:
mov tmp, 0

// Hook IsDebuggerPresent → 返回 0
bp kernelbase.IsDebuggerPresent
SetBreakpointCommand $breakpoint, "eax=0; mov [rsp], ret_addr; run"

// Log ALL VirtualProtect calls
bp kernelbase.VirtualProtect
Log "VirtualProtect: {a:[rcx]} sz:{rdx} prot:{r8:x}"

// Dump shellcode regions
bp kernelbase.VirtualAlloc
Log "VirtualAlloc: {a:rip} ret={a:[rsp]} sz:{rdx} prot:{r8:x}"
SetBreakpointCommand $breakpoint, "savedata dump_{ret}.bin, ret, rdx; run"

ret:
```

## 快速定位要点

```
1. "运行到用户代码": F9 后按 F12 (暂停) → 如果停在系统 DLL → Alt+F9 (Run to user code)
2. "返回到调用者": Ctrl+F9 (Execute till return) → F8 (单步回调用者)
3. "跳过 CALL": F8 单步过 (Step Over)
4. "进入 CALL": F7 单步入 (Step Into)
5. "搜索字符串引用": 右键 → Search For → All References → String References
6. "搜索跨模块调用": 右键 → Search For → Intermodular Calls
```

## 攻击链

```
x64dbg 加载 PE → 导入表分析 → 在关键 API 设条件断点
→ F9 运行 → 观察参数/返回值 → 日志断点记录行为
→ 定位关键调用点 → 修改寄存器/内存 → 验证效果 → 记录地址做 Patch
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 自动生成 x64dbg 断点脚本 | `make_x64dbg_breakpoint_script` | **根据 triage/Ghidra summary 自动生成 x64dbg 断点脚本** → `scripts/windows/debug/` |
| 启动 x64dbg 加载目标 | `toolbox_launch(x64dbg)` | 启动 x64dbg 并加载目标文件 |
| 推荐断点位置 | `ghidra_summary_call_focus` | 推荐断点位置（按行为过滤） |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
