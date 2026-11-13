---
id: "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
title: "注册码算法还原与 keygen 复现"
title_en: "License Key Algorithm Recovery and Keygen Replication"
summary: >
  攻击者视角的注册码算法还原手册：从校验函数反编译结果中识别位域字段布局、
  CRC 截断校验、XOR+移位混淆、自定义哈希链、5-bit 字符集映射五类构件，
  并给出可直接套用的 Python 复现模板（parse → verify → generate 三段式 +
  自校验断言）。覆盖 A 类本地算法机制的全部攻击路径。
summary_en: >
  Attacker-oriented manual for license key algorithm recovery: identify the five
  building blocks (bit-field layout, truncated CRC, XOR+shift obfuscation, custom
  hash chains, 5-bit alphabet mapping) from decompiled validation functions, with
  a drop-in Python replication template (parse → verify → generate + self-check
  assertions). Covers every attack path for type-A local algorithm mechanisms.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "CRC 校验"
  - "异或常量"
  - "循环移位"
  - "位域"
  - "字符集映射"
  - "哈希拼接"
  - "keygen"
  - "注册码生成"
  - "校验串"
  - "混淆解密"
  - "parseVal"
  - "5-bit"
mcp_tools:
  - ghidra_summary_function_detail
  - rizin_strings
  - rizin_xrefs
  - make_pe_crypto_unpack_plan
  - solve_crypto_from_evidence
  - python_re_tool_status
  - sample_full_workup
keywords:
  - "key algorithm"
  - "CRC-32"
  - "bit-field"
  - "XOR"
  - "rotation"
  - "hash chain"
  - "alphabet mapping"
  - "keygen"
  - "parseVal"
  - "obfuscation"
  - "truncated checksum"
difficulty: "intermediate"
tags:
  - "license-keygen"
  - "algorithm-recovery"
  - "CRC"
  - "bitfield"
  - "obfuscation"
  - "keygen-template"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/02-validation-function-location"
  - "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop"
  - "pe-reverse/05-crypto-unpack/01-pe-unpack-dump"
---
# 注册码算法还原与 keygen 复现

## 场景

已定位校验函数（`02`），反编译输出在手。目标：把"输入 key → 输出 TRUE"的映射完整
还原成 Python，并**反向**构造任意合法 key。本文以攻击者拆解过的多个真实目标为样本，
提炼五类通用构件与可直接复用的三段式 Python 模板。

## 输入信号（反编译产物中的识别清单）

| 构件 | 反编译中的形态 | 含义 |
|---|---|---|
| 位域字段布局 | `(x >> 21) & 0x7FF`、`(x >> 5) & 0x7FF` | key 内嵌"授权类型/期限/版本"字段 |
| CRC 截断校验 | `crc32(buf) & 0x1FFFFFF == A` | 校验串只取 CRC 的低 25~31 bit |
| XOR+移位混淆 | `ebx = ((A << 7) ^ A) & 0xFFFFFFFF` | 防直接读字段的轻量混淆 |
| 常量异或 | `C ^ ebx ^ 0x12345678` | 与魔数异或还原明文 |
| 自定义哈希链 | 3~4 个 32 位哈希拼成 96~128 位 | 无签名时最常见的"伪签名" |
| 字符集映射 | 查表 `0123456789ABCDEFGHJKMNPQRSTUVWXYZ` 或 5-bit 分组 | key 文本 ↔ 二进制数值互转 |

**关键判断**：若反编译中**没有**模幂/椭圆曲线/验签调用，仅由上述构件组成 →
A 类本地算法，key 可由输入（用户名/邮箱）完全推导 → 直接 keygen。

## 攻击链：还原流水线

```text
反编译校验函数
  → 构件识别（位域 / CRC 截断 / XOR 混淆 / 哈希链 / 字符集）
  → 逐构件还原 + 魔数/掩码/表记录
  → 套用三段式 Python 模板（parse → verify → generate）
  → 回归（官方 key VALID）+ 实机验证（Frida 替换 TRUE）
```

## 五类构件的还原模板

### 1. 位域字段布局

典型的"注册码 = 若干 32 位字段拼接"结构：

```python
# 反编译: r15 = C ^ ebx ^ 0x12345678
#         lic0 = (r15 >> 21) & 0x7FF   # 授权类型
#         lic8 = (r15 >> 5)  & 0x7FF   # 期限标志 (0x7FF = 永久)
#         year = (r15 >> 0)  & 0x1F    # 年份/保留
def parse_fields(r15: int) -> dict:
    return {
        "type":  (r15 >> 21) & 0x7FF,
        "permanent": (r15 >> 5) & 0x7FF == 0x7FF,
        "reserved":  r15 & 0x1F,
    }
```

还原要点：逐条把 `>> n`、`& mask` 提取为字段表；**字段语义靠枚举验证**——
构造不同值观察程序行为（type=0 标准版 vs type=1 便携版）。

### 2. CRC 截断校验

```python
import binascii

def crc32_trunc(buf: bytes, mask: int) -> int:
    return binascii.crc32(buf) & mask   # 如 mask = 0x1FFFFFF (25-bit)

# 校验现场: crc32(r15_le + r10_le + field_le) & 0x1FFFFFF == key 中的校验串 A
```

要点：先确定 CRC 变体（poly/init/xorout/refin/refout，常见 BZIP2/标准/自定义），
用**已知明文对**（官方 key + 其校验串）暴力比对 poly 变体即可锁定；
Python `binascii.crc32` 是标准变体，其他变体用 `crcmod` 或手写查表实现。

### 3. XOR+移位混淆与常量异或

```python
def deobf(ebx: int, val: int, magic: int) -> int:
    return (val ^ ebx ^ magic) & 0xFFFFFFFF

# 还原调用点: ebx = ((A << 7) ^ A) & 0xFFFFFFFF
#             r15 = deobf(ebx, C, 0x12345678)
```

要点：混淆通常只是"防肉眼直读"，不增加安全性——还原后直接得到明文字段。

### 4. 自定义哈希链（伪签名）

```python
def h1(data: bytes) -> int: ...   # 从反编译还原的三个 32 位哈希之一
def h2(data: bytes) -> int: ...
def h3(data: bytes) -> int: ...
def make_96bit(email: str) -> int:
    return (h1(email.encode()) << 64) | (h2(email.encode()) << 32) | h3(email.encode())
```

要点：若 key 中只有**部分字符参与校验**（如 192 字符中仅 19 字符参与），
其余字符是自由熵——keygen 只需精确复现被校验切片，剩余位可任意（或填随机）。

### 5. 5-bit 字符集映射

```python
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ"   # 32 字符集（去 I/L/O）

def to_base32(value: int, width: int) -> str:
    out = []
    for i in range(width - 1, -1, -1):
        out.append(ALPHABET[(value >> (5 * i)) & 0x1F])
    return "".join(out)

def from_base32(text: str) -> int:
    value = 0
    for ch in text:
        value = (value << 5) | ALPHABET.index(ch)
    return value
```

要点：见到"每 5 bit 查 32 字符表"就想到 base32 风格编码；`width` 由 key 段长度
反推（25 字符 × 5bit = 125 bit = 四段字段）。

## Python 通用模板（三段式 keygen）

```python
"""keygen 骨架: parse → verify → generate，全程自校验断言。"""
from __future__ import annotations
import argparse
from dataclasses import dataclass


@dataclass
class KeyFields:
    checksum: int   # A 段: 校验串
    entropy: int    # B 段: 自由熵/保留
    c: int          # C 段: 加密字段
    d: int          # D 段: 加密字段


def normalize(raw: str) -> str:
    """归一化: 大写 + 去分隔符，得到 25 字符。"""
    return "".join(ch for ch in raw.upper() if ch.isalnum())


def parse(key: str) -> KeyFields:
    up = normalize(key)
    # 注意: 有些实现解析前有"游离置换"，如 up[2] := up[14]，逐目标确认
    return KeyFields(
        checksum=from_base32(up[20:25]),
        entropy=from_base32(up[15:20]),
        c=from_base32(up[0:7]),
        d=from_base32(up[7:14]),
    )


def compute_checksum(f: KeyFields) -> int:
    """按还原出的校验公式复算校验串。"""
    ebx = ((f.checksum << 7) ^ f.checksum) & 0xFFFFFFFF
    r15 = (f.c ^ ebx ^ 0x12345678) & 0xFFFFFFFF
    r10 = (f.d ^ ebx ^ 0x87654321) & 0xFFFFFFFF
    buf = r15.to_bytes(4, "little") + r10.to_bytes(4, "little") + f.entropy.to_bytes(4, "little")
    return crc32_trunc(buf, 0x1FFFFFF)


def verify(key: str) -> bool:
    f = parse(key)
    return compute_checksum(f) == f.checksum   # 自洽断言: 复算 == 内嵌


def generate(fields: KeyFields) -> str:
    """先定 C/D/熵，再反解校验串 A，最后拼回 25 字符。"""
    # 从字段反推满足校验的 checksum: 对 25-bit 空间做约束求解或直接构造
    # 当校验公式可逆时: A = crc32(r15_le|r10_le|B_le) & mask（此处为演示，按真实公式调整）
    f = KeyFields(checksum=compute_checksum(fields), entropy=fields.entropy,
                  c=fields.c, d=fields.d)
    up = to_base32(f.c, 7) + to_base32(f.d, 7) + to_base32(f.entropy, 5) + to_base32(f.checksum, 5)
    return "-".join(up[i:i + 5] for i in range(0, 25, 5))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen", action="store_true")
    ap.add_argument("--verify", metavar="KEY")
    args = ap.parse_args()
    if args.gen:
        key = generate(KeyFields(checksum=0, entropy=0x12345, c=0x7FF << 21, d=0x2025))
        assert verify(key), "self-check failed"
        print(key)
    elif args.verify:
        print("VALID" if verify(args.verify) else "INVALID")
```

**模板使用三步**：① 把 parse 的切段/置换按目标调整；② 把 compute_checksum 的
公式/常量按反编译替换；③ 跑 `--gen` 断言自洽 → 用官方 key 做 `--verify` 回归
（官方 key 必须 VALID，这是还原正确性的硬证据）。

## 非确定性校验陷阱

- **时间/计数依赖**：校验函数内部读系统时间（期限判定）→ 还原时把时间作为显式参数
- **RNG/会话状态**：启动校验与输入校验共用某个随机种子 → 复现需先锁定种子来源
- **多线程竞争**：校验结果写入共享标志位，再次读取时被覆盖 → 以"标志位最终状态"
  为验证基准（配合 `05` 的内存监听）

遇到以上任一项，先做"确定性测试"：同一 key 连续调用校验函数 N 次，
返回值/中间值是否恒定；不恒定则按上表定位污染源。

## 证据与验证

- 记录：魔数（0x12345678 等）、掩码（0x1FFFFFF）、字符集、切段索引、字段表
- 必做回归：官方 key 批量 `verify` 全 VALID；生成 key 自校验通过
- 必做实机：Frida 进程内把官方 key 替换为生成 key，校验函数返回 TRUE
  （`05-keygen-frida-verification-loop`）

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 反编译校验函数 | `ghidra_summary_function_detail` |
| 提取常量/字符串（魔数、字符集） | `rizin_strings`、`rizin_xrefs` |
| 从证据自动求解变换 | `solve_crypto_from_evidence`、`make_pe_crypto_unpack_plan` |
| 生成 Frida 验证脚本 | `android_frida_*`（Windows 场景用 `tools/frida` 手写模板，见 05） |
| 分析笔记落盘 | `analysis_note`、`workspace_write_text` |

## 下一跳

- 算法还原完成 → `05-keygen-frida-verification-loop` 做实机验证闭环
- 还原中发现签名/大整数 → 升级为 B 类，转 `04-signature-chain-pubkey-swap`