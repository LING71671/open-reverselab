---
id: "apk-reverse/07-packer/03-vmp-dex2c-detection"
title: "VMP/dex2c 加固识别与形态判定"
title_en: "VMP/dex2c Protection Detection and Form Identification"
summary: >
  识别 Android 两类 VMP 形态：商业加固 dex2c/VMP 壳（爱加密/梆梆/乐固/易盾等，方法体转自定义字节码由 native 解释器执行）与 VMProtect 商品对 ARM64 so 的虚拟化，给出 jadx/apktool/readelf/DiE 判定命令、nop 比例统计脚本、与抽取壳的区分表及判定决策树。
summary_en: >
  Identifying the two Android VMP forms: commercial dex2c/VMP packers (ijiami/bangcle/legu/dunpai, methods compiled to custom bytecode executed by a native interpreter) and commercial VMProtect virtualization of ARM64 .so, with jadx/apktool/readelf/DiE commands, nop-ratio statistics script, a comparison table against extraction packers, and a decision tree.
board: "apk-reverse"
category: "07-packer"
signals:
  - "VMP"
  - "dex2c"
  - "加固"
  - "libjiagu"
  - "libDexHelper"
  - "libshell"
  - "nop 填充"
  - "native stub"
  - "虚拟化"
  - "VMProtect"
mcp_tools:
  - android_app_baseline
  - die_scan
  - android_package_fs_recipe
  - ghidra_headless_analyze
keywords:
  - "VMP"
  - "dex2c"
  - "加固"
  - "packer"
  - "ijiami"
  - "bangcle"
  - "legu"
  - "VMProtect"
  - "native stub"
  - "CodeItem"
difficulty: "advanced"
tags:
  - "vmprotect"
  - "dex2c"
  - "packer"
  - "obfuscation"
  - "android"
  - "detection"
language: "zh-CN"
last_updated: "2026-08-09"
related_articles:
  - "apk-reverse/07-packer/01-obfuscation-detection"
  - "apk-reverse/07-packer/04-vmp-dump-trace-recovery"
  - "apk-reverse/07-packer/05-vmp-anti-debug-bypass"
---
# VMP/dex2c 加固识别与形态判定

## 场景

目标 APK 疑似 VMP 加固：jadx 打开后大量方法体为空/nop，关键逻辑"消失"。需要先判定是哪种形态（商业 dex2c/VMP 壳 vs VMProtect 商品保护 so），因为两者的分析路线完全不同。**判定错误会浪费大量时间**（用 dump 工具去处理 VMP 必然失败，见 `04-vmp-dump-trace-recovery`）。

## 输入信号

- jadx 中目标方法体是空/nop 填充，或只剩 `return-void`/`native stub`
- 方法声明为 `native` 但 JNI 命名不符合 `Java_com_*`（走 RegisterNatives 动态注册）
- `lib/` 下出现加固特征 so：`libjiagu.so`（爱加密）、`libDexHelper.so`（梆梆）、`libshell*.so`/`libtprt.so`（腾讯乐固）、`libnqshield.so`（网易易盾）等
- dex 中方法数量巨大但 CodeItem 很小/缺失；`nop` 指令占比异常高
- strings 输出 so 无可读字符串；so 内有 dispatch 大循环特征
- 运行时行为正常但静态完全不可读

## 两种形态判定

### 形态 A：商业加固 dex2c/VMP 壳（最普遍）

原理：Java 方法在编译期/壳加载期被转换为 **dex2c**（转 C++ 编译进 so）或**自定义字节码**（由 so 内 native 解释器 dispatch 执行）。特征：

```
- dex 中方法体被 nop 填充或替换为 stub（静态看不到逻辑）
- 方法以 native 形式存在, 通过 RegisterNatives 动态绑定 so 内实现
- so 内有解释器: 取 opcode → switch/跳转表 → handler 的 dispatch 循环
- 字符串池加密, 运行时解密
```

参考实现（理解原理用）：`codehasan/dex2c`（dalvikvm → C++ AOT 翻译器，Python，~350 stars，2025 仍活跃）。

### 形态 B：VMProtect 商品保护（保护 so 本体）

VMProtect 官方明确支持 Android/ARM64 二进制虚拟化（vmpsoft.com，2026 年验证）。此形态下 **dex 是正常的**，被保护的是 so 内 C/C++/Rust 函数（如 license 校验、协议加密）：

```
- dex/Java 层完全正常, jadx 可读
- lib/*.so 内关键函数被虚拟化: 函数入口是 VM entry 桩 + 解释器循环
- so 可能带调试器检测/内存保护/整体打包
```

判定要点：**Java 层逻辑是否可读**。可读 → 形态 B（转去分析 so）；不可读 → 形态 A（先走脱壳/还原流程）。

## 判定命令

```bash
# 1. 解包
apktool d target.apk -o target_apk
# 或 jadx -d target_src target.apk

# 2. 看加固 so
ls target_apk/lib/arm64-v8a/
# libjiagu.so / libDexHelper.so / libshell*.so → 商业壳确认

# 3. DiE 扫 so（识别编译器/加壳特征）
diec -b target_apk/lib/arm64-v8a/libtarget.so

# 4. readelf 看 so 结构
readelf -S target_apk/lib/arm64-v8a/libtarget.so
# .init_array 有解密函数 / 节区异常 → 壳或打包

# 5. Ghidra 无头分析 so（找 dispatch 循环）
# ghidra_headless_analyze 后查大循环 + 间接跳转函数
```

## nop 比例统计脚本（判定 dex 是否被掏空）

```python
# 统计 smali 方法中 nop 占比: 高 nop + 缺失逻辑 = 方法体被虚拟化/抽取
import re, sys
from pathlib import Path

def method_stats(smali_path):
    text = Path(smali_path).read_text(encoding='utf-8', errors='ignore')
    methods = re.findall(r'\.method.*?(?=\.end method)', text, re.S)
    empty = 0
    for m in methods:
        body = m.split('.end method')[0]
        # 只有 nop/return 的方法视为空壳
        ops = re.findall(r'^\s{4}(\S+)', body, re.M)
        ops = [o for o in ops if o not in ('.locals', '.param', '.line', '.prologue')]
        if not ops or set(ops) <= {'nop', 'return-void', 'return'}:
            empty += 1
    return len(methods), empty

total, empty = method_stats(sys.argv[1])
print(f"methods={total} empty={empty} empty_ratio={empty/max(total,1):.0%}")
# empty_ratio > 30% → 疑似抽取壳/VMP; 结合 so 特征确认形态
```

## 与抽取壳的区分表

| 特征 | 抽取壳（DexProtector 类） | VMP/dex2c |
|---|---|---|
| dex 方法体 | nop 填充（被抽走） | nop 或 native stub（被转换） |
| 指令在哪里 | 壳运行后回填回 dex 内存 | 自定义字节码/C++ 在 so 内，**不回填 dex** |
| dump 是否有效 | 有效（FART/Youpk/BlackDex 回填） | **无效**（dump 不到 CodeItem） |
| 特征 so | 任意壳 so | libjiagu/libDexHelper/解释器 so |
| 还原难度 | 低（主动调用即可） | 高（需 trace 解释器，见 04 篇） |

## 判定决策树

```
jadx 打开目标方法
├─ Java 层可读 → 形态 B: VMProtect 保护 so → 转 02-native/* 分析 so 内虚拟化函数
└─ Java 层不可读(空/nop/stub)
    ├─ 有加固 so (jiagu/DexHelper/shell*) → 形态 A 商业壳
    │    ├─ 方法体 nop + 抽取型特征 → 抽取壳 → dump 路线 (BlackDex/FART/Youpk)
    │    └─ native stub + 解释器 so → VMP/dex2c → trace 路线 (04 篇)
    └─ 无加固 so 但逻辑缺失 → 自定义 classloader/其他混淆 → 03-manifest 入口追踪
```

## 攻击链

```
APK → apktool/jadx → 目标方法可读性判定 → 形态 A/B 分流
→ A: so 特征确认 → 抽取 or VMP 判定 → dump 路线 or trace 路线 (04 篇)
→ B: 转 so 静态分析 → Ghidra 找 VM entry → PE 侧 02 篇思路复用 (ARM64 适配)
→ 全程前置: 反调试绕过 (05 篇) 保证动态分析可执行
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 安装/启动 APK 收集基线 | `android_app_baseline` | 安装、启动、logcat 基线（确认运行时行为正常） |
| DiE 扫描 so 签名 | `die_scan` | 识别加固 so/编译器特征 |
| 取证包私有目录 | `android_package_fs_recipe` | 拉 shared_prefs/databases/files 找解密产物/配置 |
| Ghidra 无头分析 so | `ghidra_headless_analyze` | 对 lib/*.so 分析，导出函数/字符串/导入供判定 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、加固厂商 so 名称与版本特征。
- 形态判定必须绑定证据：jadx 中方法体截图/原文、nop 比例统计输出、so 列表、DiE/readelf 输出。
- 区分"抽取壳 vs VMP"的结论要落到下一步动作（dump 工具选择 or trace 路线），并标注 dump 失效时的观察证据（dump 结果中方法仍无 CodeItem）。
- 所有产物保存到 `exports/android/`，可重放复现。
