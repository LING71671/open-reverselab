---
id: "apk-reverse/07-packer/04-vmp-dump-trace-recovery"
title: "VMP 脱壳与语义还原（Dump/Trace/Recovery）"
title_en: "VMP Unpacking and Semantic Recovery (Dump/Trace/Recovery)"
summary: >
  商业 VMP/dex2c 壳下 dump 类工具失效的机理与判定，frida-dexdump/BlackDex/FART/Youpk 适用场景对比，unidbg 指令 trace 还原解释器语义的完整流程（Java 配置骨架），Frida Stalker trace dispatch 脚本，handler 映射表构建方法与 dex2c 还原现状说明。
summary_en: >
  Why dump tools fail under commercial VMP/dex2c (no dumpable CodeItem), a comparison of frida-dexdump/BlackDex/FART/Youpk, a full unidbg instruction-trace recovery workflow (Java config skeleton), a Frida Stalker dispatch tracing script, handler mapping table construction, and the current state of dex2c recovery.
board: "apk-reverse"
category: "07-packer"
signals:
  - "VMP"
  - "dex2c"
  - "脱壳"
  - "BlackDex"
  - "FART"
  - "Youpk"
  - "frida-dexdump"
  - "unidbg"
  - "Stalker"
  - "trace"
  - "dump"
  - "解释器"
mcp_tools:
  - android_pull_package_apk
  - android_crypto_unpack_recipe
  - android_frida_run_script
  - carve_payloads_from_dump
keywords:
  - "VMP"
  - "dex2c"
  - "unpack"
  - "BlackDex"
  - "FART"
  - "Youpk"
  - "frida-dexdump"
  - "unidbg"
  - "Stalker"
  - "trace"
  - "interpreter"
difficulty: "advanced"
tags:
  - "vmprotect"
  - "dex2c"
  - "unpacking"
  - "unidbg"
  - "frida"
  - "stalker"
  - "trace"
language: "zh-CN"
last_updated: "2026-08-09"
related_articles:
  - "apk-reverse/07-packer/03-vmp-dex2c-detection"
  - "apk-reverse/07-packer/05-vmp-anti-debug-bypass"
  - "apk-reverse/02-native/06-jni-register-natives-tracing"
---
# VMP 脱壳与语义还原（Dump/Trace/Recovery）

## 场景

已按 `03-vmp-dex2c-detection` 确认目标为 VMP/dex2c 形态。现在需要拿到被虚拟化方法的真实语义。**先明确结论：VMP 下整体 dump 路线必然失败**——被虚拟化的方法在 dex 里没有可 dump 的 CodeItem，自定义字节码存在于 so 数据段；正确路线是"dump 摸底 → 判定 VMP → trace 解释器 → 语义还原"。

## 输入信号

- BlackDex/frida-dexdump dump 出的 dex 中目标方法仍无 CodeItem（只有 stub）
- `lib/*.so` 内存在 dispatch 大循环（取 opcode → 跳转表 → handler）
- RegisterNatives 动态绑定的方法名与 `Java_com_*` 命名规则不符
- unidbg/Stalker trace 可见重复的"取指→分发→执行"模式

## dump 摸底工具对比（外部工具，需自行安装）

| 工具 | 仓库 | 语言 | 原理 | 适用 | 维护状态 |
|---|---|---|---|---|---|
| frida-dexdump | github.com/hluwa/frida-dexdump | Python/JS | 内存模糊搜索 dex 特征 dump | 抽取壳/普通壳快检 | **2023 已归档**，仍可用 |
| BlackDex | github.com/CodingGay/BlackDex | Java | DexFile cookie 定位，免刷机，深度脱壳回填抽取指令 | 抽取壳主力（5.0~12） | 可用（~6.4k stars） |
| FART | github.com/hanbinglengyue/FART | C++/Frida | ART 主动调用 + 解释器插桩 dump CodeItem | 抽取壳深度还原 | 有 frida 版（~2.7k stars） |
| Youpk | github.com/Youlor/Youpk | C++/Java | 改 ROM 主动调用，强制 switch 解释器插桩 | 抽取壳最强，**仅 Pixel 1 刷机** | 早期（~800 stars） |

```bash
# 快检: frida-dexdump (Python)
pip install frida-dexdump
frida-dexdump -FU -d    # 附加前台应用 dump

# 深度: BlackDex (Android APK)
# 安装 BlackDex APK → 选择目标 → 点脱壳 → dump 到 /sdcard/BlackDex
```

**VMP 失效判定**：dump 完成后用 jadx 打开，目标方法仍是空/native stub → 确认虚拟化，dump 路线到此为止，转 trace。

## 路线：unidbg 指令 trace（推荐主路线）

> **unidbg**（zhkl0228/unidbg，Java，~5.1k stars，活跃）是外部工具：模拟 JNI 环境 + syscall 运行 so，支持 instruction trace、memory trace、Dobby inline hook，2025 年起支持 MCP（AI 辅助调试）。

思路：在 unidbg 中加载 so → 定位解释器 dispatch 入口 → 开 instruction trace → 记录"字节码地址 + handler 跳转"序列 → 分析语义。

```java
// unidbg 配置骨架 (Java)
// 依赖: github.com/zhkl0228/unidbg (README Utilities64 示例起步)
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorFactory;
import com.github.unidbg.linux.android.dvm.DalvikVM64;
import com.github.unidbg.linux.android.dvm.VM;

AndroidEmulator emulator = AndroidEmulatorFactory.createARM64Emulator();
VM vm = emulator.createDalvikVM();
DalvikVM64 dalvikVM = (DalvikVM64) vm;
dalvikVM.setVerbose(false);

// 1. 加载加固 so（JNI_OnLoad 自动执行）
Module mod = emulator.loadLibrary(new File("libtarget.so"), true);

// 2. 调被保护方法（走 RegisterNatives 绑定的入口）
//    先 hook RegisterNatives 拿到 native 方法地址:
//    emulator.getMemory().addHookListener(...) 或
//    DobbyHook: emulator.getMemory().hookFunction(mod.base + 0xXXXX, args -> {...});

// 3. 开指令 trace（只 trace 解释器所在地址范围, 避免噪音爆炸）
emulator.getMemory().addInstructionTrace(mod.base + 0x1000, mod.base + 0x2000);

// 4. 调用目标方法 → 导出 trace 文件分析
```

trace 输出按行含 `PC + 指令字节 + 汇编`。解释器 dispatch 模式在 trace 中表现为：

```
0x7f00: LDR W1, [X2], #1      ; 取 opcode (X2 = 字节码指针)
0x7f04: AND W1, W1, #0xff
0x7f08: ADR X3, handler_table
0x7f0c: LDR X4, [X3, W1, UXTW #3]
0x7f10: BR  X4                  ; 分发到 handler
0x7f14: ... handler 体 ...
```

## 路线：Frida Stalker trace dispatch（真机）

```javascript
// Frida Stalker: trace so 内解释器循环 (JS, 通过 android_frida_run_script 运行)
var base = Module.findBaseAddress("libtarget.so")
var dispatchStart = base.add(0xXXXX)   // 解释器入口(从 Ghidra 静态定位)
var dispatchEnd   = base.add(0xYYYY)

function traceDispatch() {
    Stalker.follow(Process.getCurrentThreadId(), {
        events: { call: true, compile: true },
        onCallSummary: function (summary) {
            // summary 按目标地址统计调用次数 → handler 热度图
        },
        onReceive: function (events) {
            var ev = Stalker.parse(events, { annotate: true })
            ev.forEach(function (e) {
                if (e[0] === 'call' && e[1].compare(dispatchStart) >= 0 && e[1].compare(dispatchEnd) <= 0)
                    console.log(e[1].sub(base).toString(16), e[2])  // handler 地址 → 汇编
            })
        }
    })
}
traceDispatch()
// 触发被保护方法 → 收集"字节码地址 → handler"序列
```

Stalker 注意事项：性能开销大（解释器循环高频触发），用 `onCallSummary` 先做热度统计缩小 handler 范围，再对热点 handler 单独 `Stalker.follow` 细看。

## 语义还原：handler 映射表

```
1. 从 trace 提取全部 handler 入口地址（dispatch 跳转目标去重）
2. 对每个 handler 静态分析（Ghidra 打开 so）: 观察其读写的虚拟寄存器/内存槽位
3. 建立映射表: handler 地址 → 语义 (mov_imm / add_reg / jmp_rel / call_native / ret)
4. 把字节码流按映射表翻译为高层伪代码
5. 用输入输出等价性验证还原正确性 (参考 PE 侧 03 篇验证思路)
```

字节码 → 语义映射示例：

```
0x00 0x01 0x2A      →  handler@0x7f40 (mov reg0, imm=0x2A)  →  reg0 = 42
0x00 0x02 0x10      →  handler@0x7f60 (add reg0, imm=0x10)  →  reg0 += 16
0x00 0x03 0x14      →  handler@0x7f80 (jmp_rel 0x14)        →  pc += 0x14
```

## dex2c 还原现状

把 so 中 C++ 代码还原回 smali/dex 属研究性课题：GitHub 上**没有成熟开源还原器**（2026-08 搜索确认，仅加固侧参考实现 `codehasan/dex2c` 和混淆侧 `NP-Manager`）；社区成果以文章形式存在（奇安信 A-TEAM《dex2c 还原》系列、看雪相关文章）。实操上对目标方法走"trace + handler 映射"手工还原，而不是指望一键工具。

## 攻击链

```
dump 摸底 (frida-dexdump/BlackDex) → 目标方法仍无 CodeItem → VMP 确认
→ 静态: Ghidra 打开 so → 定位解释器 dispatch 入口/RegisterNatives 绑定
→ unidbg 加载 so + instruction trace (首选, 可脚本化)
  └─ 或真机 Frida Stalker trace dispatch
→ 提取 handler 集合 → 静态分析 handler 语义 → 建映射表
→ 翻译字节码为伪代码 → 等价性验证 → 还原结果回填分析
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 回拉设备上 APK | `android_pull_package_apk` | 从设备拉 base.apk 到 exports/android/packages |
| Frida 解密/脱壳 recipe | `android_crypto_unpack_recipe` | 抓 Cipher/key/dex loader/dlopen/mmap/RegisterNatives 证据 |
| 运行 Stalker trace 脚本 | `android_frida_run_script` | 对目标进程跑一次性 Frida JS（含 Stalker）收集 send 消息 |
| 从 trace/dump 中 carve DEX/PE | `carve_payloads_from_dump` | 从 dump 自动提取 DEX/PE payload 供 Ghidra 分析 |

> 说明：BlackDex/FART/Youpk/unidbg 均为外部工具，未集成进 ReverseLab MCP；unidbg 是 Java 项目（装 JDK 即可跑），建议作为"工具测试"候选逐步接入（测试闭环见 `scripts/misc/lab_healthcheck.py`）。

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、ABI、unidbg/Frida 版本、解释器入口 RVA、handler 表地址。
- dump 失效判定绑定：dump 工具输出路径 + jadx 中目标方法仍无 CodeItem 的原文。
- trace 证据绑定：dispatch 入口地址、trace 文件路径、handler 热度统计、映射表条目（handler 地址 → 语义）。
- 还原结论必须过等价性验证（原始 vs 还原的输入输出对），验证脚本与结果落盘 `exports/android/`。
