---
id: "pe-reverse/10-license-keygen/02-validation-function-location"
title: "许可证校验函数定位"
title_en: "Locating the License Validation Function"
summary: >
  攻击者视角的校验函数定位手册：静态信号（字符串、导入表、控件事件回调、xrefs 反查）
  与动态手段（输入 API 断点、Frida 调用栈回溯、探针分化）相结合，
  在数分钟内把"校验函数"从目标程序中挖出来，并给出校验函数的三条典型形态特征。
summary_en: >
  Attacker-oriented manual for locating the license validation function: static signals
  (strings, imports, control event callbacks, xref backtracking) combined with dynamic
  methods (input API breakpoints, Frida stack backtrace, probe differential).
  Includes the three typical shapes of a validation function.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "校验函数定位"
  - "CheckKey"
  - "注册码校验函数"
  - "GetDlgItemText"
  - "GetWindowText"
  - "Invalid key"
  - "Thank you"
  - "xref 反查"
  - "调用栈回溯"
  - "激活按钮回调"
  - "memcmp 校验"
mcp_tools:
  - rizin_strings
  - rizin_imports
  - rizin_xrefs
  - ghidra_headless_analyze
  - ghidra_summary_functions
  - ghidra_summary_function_detail
  - make_x64dbg_breakpoint_script
  - debug_script
keywords:
  - "validation function"
  - "CheckKey"
  - "xref"
  - "call stack"
  - "GetDlgItemText"
  - "export"
  - "license"
  - "registration"
  - "breakpoint"
difficulty: "beginner"
tags:
  - "license-keygen"
  - "validation-function"
  - "static-location"
  - "dynamic-location"
  - "xref"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/01-license-mechanism-classification"
  - "pe-reverse/03-static-analysis/05-dynamic-api-resolution"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass"
---
# 许可证校验函数定位

## 场景

已按 `01-license-mechanism-classification` 判定目标属于本地校验（A/B 类）。
`CheckKey` 类校验函数是第一攻击目标：还原它 = 拿到全部算法。本文给出
"静态信号 → xrefs 反查 → 动态确认" 三步定位法，常见目标 5~30 分钟内出结果。

## 输入信号

- 注册码输入控件（编辑框、按钮）
- "Invalid key / Thank you / 注册成功" 类字符串
- 授权相关导入调用点（字符串比较、加密库）

## 攻击链：定位三步走

```text
静态信号（字符串/导入/控件回调）
  → xrefs 反查（失败文案 → wrapper → 校验函数）
  → 动态确认（输入 API 断点 / Frida 栈回溯 / 探针分化）
  → 记录地址与形态特征
```

## 第一步：静态信号收集

### 字符串信号（最高优先级）

```powershell
python tools/... # 或底层命令:
rizin -zz target.exe | findstr /i "license key serial activat register invalid thank"
```

出现以下字符串时，其 **xrefs 指向的代码**就是定位起点：

| 信号字符串 | 含义 | 攻击价值 |
|---|---|---|
| `Invalid license key` / `Invalid serial` | 校验失败分支的弹窗文案 | 直接指向失败路径尾端，反查调用者=校验函数 |
| `Thank you` / `Registration successful` | 成功分支文案 | 同上，成功路径 |
| `License expired` / `trial` / `30-Day` | 期限/试用判定 | 指向 second 校验（启动时判定） |
| `name=` / `email=` / `key=` | license 文件/注册表键名 | 指向配置读写与校验交界 |

**反查动作**：在 Ghidra/rizin 中对该字符串地址做 xrefs → 得到引用它的函数 →
沿调用图向上找"接收 key、返回真/假"的节点，通常只隔 0~2 层。

### 导入表信号

- `GetDlgItemTextW/A`、`GetWindowTextW/A`：注册窗口读取输入 → **断点设这里最快**
- `lstrcmpW`、`CompareStringW`、`memcmp`：逐字节比较点（常量表比对常见）
- `bcrypt.dll`、`advapi32`（Crypt*）、OpenSSL 导出：B 类签名链迹象
- `RegGetValueW`、`RegOpenKeyExW`：授权读注册表

### 控件事件回调（GUI 目标必杀技）

注册窗口中"确定/激活"按钮的点击回调 = 校验入口。定位：

1. 对话框资源（`dialog` 资源 ID）→ `DialogFunc` 的 `WM_COMMAND` 分支
2. 偏好：`GetDlgItemTextW` 断点 → 栈回溯直接看到按钮回调地址（动态法，见下）

## 第二步：xrefs 反查（还原调用链）

以"失败文案字符串"为例的完整反查：

```text
"Invalid license key"          # 数据地址 0x14000A100
  └─ xrefs → 0x140002F90        # push 该字符串的函数（失败弹窗 wrapper）
       └─ 调用者 0x140002F60    # ← CheckKey：把 key 放进去，返回 EAX=0/1
            └─ 更上层调用者     # 按钮回调 / 启动初始化
```

**校验函数的三个形态特征**（用于确认你没找错）：

1. **入参是"内容"而非"控件"**：参数是 key 字符串/长度，而不是 HWND——
   说明它已脱离 UI 层，纯逻辑校验（还原它=还原算法）。
2. **单点返回零一**：函数体末尾 `test eax,eax / jz fail / jnz success`，
   或 `setne al; ret` —— 布尔校验语义。
3. **内部有常量表/魔数**：CRC 表、XOR 常量、字符集串（`0123456789ABCDEF...`）、
   大整数（公钥），见 `03-key-algorithm-recovery` 的识别清单。

## 第三步：动态确认（最快路径，推荐先做）

### 输入 API 断点 + 栈回溯

用 x64dbg 对 `GetDlgItemTextW`（或 `GetWindowTextW`）下断，点激活按钮后：

```text
GetDlgItemTextW 命中，缓冲区=输入的 key
  栈回溯:
    → 0x140004100  (按钮回调 WM_COMMAND)
    → 0x140002F60  (CheckKey(key) ← 从这里开始单步)
```

拿到 CheckKey 地址后 `bp 0x140002F60`，重跑，单步跟踪即可看到完整算法。

### Frida 回溯（无 GUI 调试器时的替代）

```python
import frida, sys

session = frida.attach("target.exe")
script = session.create_script("""
Interceptor.attach(Module.findExportByName("user32.dll", "GetDlgItemTextW"), {
    onEnter(args) {
        var buf = Memory.readUtf16String(args[2]);
        if (buf && buf.length > 4) {
            console.log("[input] " + buf);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\\n"));
        }
    }
});
""")
script.load()
sys.stdin.read()
```

回溯中的模块内地址就是按钮回调链，同样反查即得校验函数。

### 探针分化（确认校验语义）

对候选函数下条件断点，观察"输入正确 key / 错误 key"两次调用的**参数与返回值差异**：

```text
正确 key:   f(key_ok)   → EAX=1
错误 key:   f(key_bad)  → EAX=0
其余参数相同
```

→ 确认这就是校验函数；同时若参数完全一致、仅返回值不同，说明**没有隐藏状态
依赖**（若有 RNG/时间/线程局部队列，需注意每次调用结果不可复现——见 03 的
"非确定性校验"陷阱）。

## 反调试注意事项

部分目标的校验函数会先做反调试自检（`IsDebuggerPresent`、`NtQueryInformationProcess`、
时间差），或在 key 校验路径上做 `int3` 花指令混淆。对策见
`04-dynamic-analysis/05-anti-debug-bypass`；Frida 注入方式天然绕开大部分
`IsDebuggerPresent` 系检测（不同进程上下文），适合作为首选动态手段。

## 证据与验证

- 记录：CheckKey 地址、入参 key、寄存器/栈中间值、返回布尔
- 用官方公开 key（若可得）做基线：`f(官方key)=TRUE` 必须成立，后续算法还原以此校准
- 若定位出"输入窗口校验"与"启动校验"两个独立函数 → 立即升格为 C 类机制
  （自引用），转 `07-self-referencing-signature-convergence`

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 字符串/导入扫描 | `rizin_strings`、`rizin_imports` |
| xrefs 反查 | `rizin_xrefs`、`ghidra_summary_function_detail` |
| 反编译候选函数 | `ghidra_headless_analyze`、`ghidra_summary_functions` |
| 生成 x64dbg 断点脚本 | `make_x64dbg_breakpoint_script`、`debug_script` |
| 记录证据 | `analysis_note`、`workspace_write_text` |

## 下一跳

- 校验函数已定位 → `03-key-algorithm-recovery` 还原算法
- 发现公钥/签名现场 → `04-signature-chain-pubkey-swap`
- 发现双机制（输入+启动）→ `07-self-referencing-signature-convergence`