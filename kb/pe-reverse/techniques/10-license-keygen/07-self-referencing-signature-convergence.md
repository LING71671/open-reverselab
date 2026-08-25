---
id: "pe-reverse/10-license-keygen/07-self-referencing-signature-convergence"
title: "自引用签名嵌入与单步迭代收敛"
title_en: "Self-Referencing Signature Embedding and One-Shot Iterative Convergence"
summary: >
  攻击者视角的高级许可证机制：自引用签名嵌入（key 的某切片在冷启动时由程序根据
  key 自身重新计算）。无需还原签名算法——利用签名对切片位置的局部不变性，
  写入占位 key → 运行抓取程序计算的签名切片 → 回填 → 下次启动必然通过。
  给出收敛定理、抓取回填脚本模板与两类典型形态。
summary_en: >
  Advanced attacker-oriented license mechanism: self-referencing signature
  embedding (a key slice is recomputed by the program at cold start from the key
  itself). No signature recovery needed — exploit local invariance of the signature
  over the slice position: write a placeholder key, run to capture the program
  computed slice, backfill it, and the next start always passes. Includes the
  convergence argument, capture-and-backfill script template and two typical shapes.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "自引用签名"
  - "签名嵌入"
  - "迭代收敛"
  - "冷启动重算"
  - "占位 key"
  - "抓取回填"
  - "双机制"
  - "局部不变性"
  - "签名切片"
mcp_tools:
  - ghidra_summary_function_detail
  - ghidra_summary_functions
  - ghidra_headless_analyze
  - workspace_write_text
  - analysis_note
keywords:
  - "self-referencing signature"
  - "embedding"
  - "iteration convergence"
  - "placeholder key"
  - "backfill"
  - "cold start"
  - "local invariance"
  - "signature slice"
  - "dual mechanism"
difficulty: "advanced"
tags:
  - "license-keygen"
  - "self-referencing"
  - "convergence"
  - "advanced"
  - "backfill"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/01-license-mechanism-classification"
  - "pe-reverse/10-license-keygen/02-validation-function-location"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
---
# 自引用签名嵌入与单步迭代收敛

## 场景

目标存在**两套独立授权判定**：注册窗口输入校验（通过即可弹"Thank you"）与
**冷启动自引用校验**（真实授权判定）。冷启动时程序根据 key 自身某切片重新计算
签名串，并要求"签名串对应切片 == key 对应切片"。表面看必须还原签名算法——
但这类机制存在一个致命的攻击捷径：**对切片位置的局部不变性**。

攻击流程（单次运行即收敛）：

```text
写入占位 key（任意合法格式）
  → 冷启动，程序计算签名串 X
  → 抓取 X 中与 key 切片同位的内容
  → 回填进 key
  → 下次冷启动必然通过（无需理解算法）
```

## 攻击链：抓取-回填收敛流程

```text
确认双机制（输入校验 + 冷启动自引用）
  → 定位 pos 计算式与切片宽度
  → 验证局部不变性（两次抓取比对）
  → 写入占位 key
  → 冷启动抓取签名切片 X
  → 回填 key 同位
  → 重启验证（标志位 0 + 试用标记消失）
```

## 收敛定理（为什么一次就够）

设程序计算：`X = GEN(name, code, version, ...)`，判定条件：

```text
fc90 = ENCODE(code[pos : pos+4])     # key 自身切片编码
fc88 = ENCODE(X[pos : pos+4])        # 签名串同位切片编码
激活判定: fc88 == fc90               # 仅比较同位切片
```

若 `GEN` 对输入 `code` 的 `pos` 处 4 字符变化**局部不变**（即
`X[pos:pos+4]` 不随 `code[pos:pos+4]` 改变，只随其余输入决定），则：

1. 写入任意占位 key（其 `pos` 切片为任意值）
2. 冷启动 → 程序算出确定的 `X`
3. 把 `X[pos:pos+4]` 回填到 key 的同位
4. 下次启动：`fc90 == fc88` 恒成立，且 `X` 不变（占位期间其余字段未变）

**关键步骤是验证局部不变性**，而非还原 `GEN`。验证方法：抓取两次
（两次不同占位切片的 `X`），比较 `X[pos:pos+4]` 是否恒定。

## 第一步：确认双机制与定位切片参数

- 输入窗口校验与冷启动校验是两个独立函数（`02` 定位时若发现两个校验点，
  立即怀疑 C 类）
- 定位 `pos` 计算逻辑：反编译中常见形态
  `pos = 11 + (date % 91) / 9`（日期派生的切片位置）——用固定日期可预测；
  或常量位置 `pos = 15`
- 定位 `ENCODE` 与切片宽度（4 字符常见）：`code[pos:pos+4]` 参与比较的现场

## 第二步：抓取-回填脚本（Frida 模板）

```python
# capture_backfill.py — 占位注入 → 抓取签名切片 → 回填 key 文件
import frida, sys, json, re
from pathlib import Path

PLACEHOLDER = "xy05-AAAAA-BBB-2061-PQ-RS-TU-OP-28.30-VW"  # 合法格式占位 key
POS, WIDTH = 15, 4                                        # 由反编译确定
KEYFILE = Path.home() / "AppData" / "Roaming" / "TargetApp" / "key.ini"

# ① 写入占位
cfg = KEYFILE.read_text(encoding="utf-8")
KEYFILE.write_text(re.sub(r"(?m)^Code=.*", f"Code={PLACEHOLDER}", cfg), encoding="utf-8")

# ② 抓取程序计算的签名串 X（hook 计算签名后的写入/比较点）
hook = """
Interceptor.attach(ptr("%s"), {          // ENCODE(X[...]) 比较点或 X 生成函数
    onLeave(retval) {
        var x = retval.toInt32();
        console.log(JSON.stringify({x: x, hex: "0x" + x.toString(16)}));
    }
});
""" % ("0x14066CFEC")

session = frida.spawn(["target.exe"]), None
session = frida.attach("target.exe")
script = session.create_script(hook)
script.load()
# 等待冷启动计算完成（超时保护）
# ③ 解析 X → 切出 X[pos:pos+4] → 回填 key 文件
```

回填逻辑（伪代码）：

```python
def backfill(key: str, x_slice: str, pos: int, width: int) -> str:
    parts = list(key)
    parts[pos:pos + width] = list(x_slice)
    return "".join(parts)

# ④ 重启目标 → 验证: 标题栏试用标记消失 / 状态位 DAT_1422E9936 == 0
```

## 两类典型形态

| 形态 | 特征 | 收敛策略 |
|---|---|---|
| **日期派生切片** | `pos = f(date)`，位置每天变化 | 抓取时记录日期与 pos；回填与验证在同一日期完成；或构造 key 时按目标日期算 pos |
| **固定切片** | `pos` 为常量（如 15） | 一次收敛，长期有效 |

## 与"还原 GEN"的取舍

| 路径 | 成本 | 风险 |
|---|---|---|
| 迭代收敛（本文） | 数小时，无需理解算法 | 依赖局部不变性成立；日期派生场景需当日完成 |
| 完整还原 GEN | 数天，需处理强混淆 | 通用、可生成任意 key |

先验收敛（20 分钟），失败再考虑完整还原。

## 证据与验证

- 局部不变性证据：两次不同占位 key 抓取的 `X[pos:pos+4]` 相同
- 回填后冷启动：标志位 `0`（已注册）、试用标记消失
- 重启两次以上保持（排除"单次侥幸"）
- 记录：pos 计算式、切片宽度、X 抓取点、回填前后 key 全文差异

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 定位 GEN/比较点 | `ghidra_summary_function_detail`、`ghidra_summary_functions` |
| 反编译 pos 计算 | `ghidra_headless_analyze` |
| 脚本与证据落盘 | `workspace_write_text`、`analysis_note` |

## 下一跳

- 收敛成功 → 完整攻击链（`05` 的 L4/L5 验收）
- 局部不变性不成立 → 尝试完整还原 GEN（`03-key-algorithm-recovery` 的思路扩展）