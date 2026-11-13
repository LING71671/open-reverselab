---
id: "pe-reverse/09-av-evasion/01-evasion-indicator-detection"
title: "规避与混淆特征静态识别（Shellcode / Syscall / 反沙箱）"
title_en: "Static Detection of Evasion & Obfuscation Indicators"
summary: >
  从防御与样本研判视角静态识别 PE 样本中的规避与混淆特征：高熵加密段、XOR/RC4 解密循环、UUID/IPv4/MAC 数组伪装表、Direct Syscall 指令 stub、VEH 异常劫持及反沙箱 API 组合，配套静态检测脚本与 YARA 规则落盘闭环。
summary_en: >
  Defensively detect evasion and obfuscation indicators in PE samples: high-entropy sections, XOR/RC4 decryption loops, UUID/IPv4/MAC array camouflage tables, direct syscall stubs, VEH handler abuse, and anti-sandbox API patterns, with static scanning and YARA output.
board: "pe-reverse"
category: "09-av-evasion"
signals:
  - "high entropy"
  - "xor loop"
  - "rc4 ksa"
  - "uuid table"
  - "direct syscall"
  - "veh"
  - "anti-sandbox"
  - "混淆识别"
  - "规避特征检测"
mcp_tools:
  - triage_pe
  - ghidra_headless_analyze
  - extract_iocs_from_summary
  - hash_file
  - make_yara_stub
keywords:
  - "static detection"
  - "entropy analysis"
  - "syscall stub"
  - "anti-sandbox"
  - "VEH"
  - "obfuscation detection"
  - "YARA"
difficulty: "advanced"
tags:
  - "detection"
  - "static-analysis"
  - "obfuscation"
  - "anti-sandbox"
  - "syscall"
  - "yara"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/01-triage/01-aob-signature-scan"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass"
  - "pe-reverse/04-dynamic-analysis/07-direct-syscall"
  - "pe-reverse/07-yara-sigma/01-yara-rule-writing"
track: "blue"
defends: "pe-reverse/09-av-evasion/01-ai-powered-evasion"
---
# 规避与混淆特征静态识别（Shellcode / Syscall / 反沙箱）

## 场景

拿到未知 PE 样本（疑似加载器、加密荷载或带反分析保护的二进制）时，静态识别其是否包含高熵加密数据、编码伪装表、Direct Syscall 桩、VEH 异常劫持或反沙箱环境探针，并产出可复现检测特征与 YARA 规则。

## 输入信号

- 某节区（`.rdata`/`.data`/自定义节）熵值 ≥ 7.2 且几乎无可读字符串
- `.rdata` 中出现密集连续的 UUID、IPv4 或 MAC 格式字符串数组
- 导入表缺失 `VirtualAlloc`/`CreateThread`，但存在 `AddVectoredExceptionHandler` 或 `Nt*` API 哈希/直接 `syscall` 指令
- 同时出现多组硬件/时间检测 API（`GetSystemInfo` + `GlobalMemoryStatusEx` + `GetTickCount64`）

## 识别维度矩阵

| 维度 | 静态特征 / 字节模式 | 常见用途判定 | 下一步分析 |
|---|---|---|---|
| 熵值与解码循环 | 节区熵 ≥ 7.2，伴随 `xor reg, key` / 256 字节 S-Box 初始化 | XOR / RC4 / AES 荷载加密 | Ghidra 定位解码循环与密钥偏移 |
| 数组伪装编码 | 连续 8+ 条 UUID / IPv4 / MAC 字符串，伴 `UuidFromStringA` / `RtlIpv4StringToAddressA` | 将二进制字节伪装为配置表 | 提取数组按转换规则还原原始字节 |
| Direct Syscall 桩 | x64 字节序列 `4C 8B D1 B8 ?? ?? 00 00 ... 0F 05` | 绕过用户态 EDR Hook | 核对 SSN 编号对应内核调用 |
| VEH 异常驱动执行 | 注册 `AddVectoredExceptionHandler` 并主动触发除零/硬件断点异常 | 隐藏控制流或延迟解密执行 | 在 Ghidra 中追踪 Handler 回调地址 |
| 反沙箱探针组合 | `GetSystemInfo`（核数）+ `GlobalMemoryStatusEx`（内存）+ `GetTickCount64`（延时差） | 逃避自动化沙箱运行 | 标记条件跳转与阈值常量 |

## 静态特征扫描脚本

使用仓库内 [detect_evasion_indicators.py](../../../../../scripts/windows/detect_evasion_indicators.py) 对样本进行只读静态特征扫描：

```python
# 示例：直接调用静态扫描函数验证特征命中
from pathlib import Path
import sys
sys.path.insert(0, "scripts/windows")
from detect_evasion_indicators import scan_bytes

synthetic = b"A" * 64 + b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05" + b"VirtualAlloc\x00GetTickCount64\x00GlobalMemoryStatusEx\x00"
report = scan_bytes(synthetic)
assert report["syscall_stub_offsets"] == ["0x40"]
assert len(report["api_hits"]) == 3
print(report)
```

命令行运行：

```powershell
python scripts/windows/detect_evasion_indicators.py samples/<sample.exe>
```

## 静态识别工作流

```text
1. triage_pe / hash_file 计算样本哈希并检查节区熵值与导入表异常
2. 运行 detect_evasion_indicators.py 提取高熵、伪装数组、syscall stub 偏移与敏感 API 命中
3. 对命中偏移在 Ghidra 中核对交叉引用（确认解码函数、VEH Handler 与反沙箱分支条件）
4. 若确认恶意特征组合，调用 make_yara_stub 生成并验证 YARA 检测规则
```

## 验证与判定标准

- 熵值与伪装表：命中高熵节或连续伪装字符串表，且交叉引用指向解码/解析函数
- Syscall 桩确认：字节序列 `4C 8B D1 B8 .. 00 00 .. 0F 05` 所在函数反编译后确认为系统调用包装而非普通数据
- 产物要求：保留样本 SHA256、节区熵值、命中文件偏移、API 列表与生成的 YARA 规则（不修改原样本）

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---|---|---|
| PE 结构与节区熵初筛 | `triage_pe` | 获取节区熵、导入表与打包特征 |
| 解码与异常回调静态还原 | `ghidra_headless_analyze` | 定位解码循环、VEH 回调与系统调用桩 |
| 特征与 IOC 提取 | `extract_iocs_from_summary` | 从静态摘要抽取疑似配置与特征串 |
| 检测规则生成 | `make_yara_stub` | 输出用于样本族检出的 YARA 规则草案 |
