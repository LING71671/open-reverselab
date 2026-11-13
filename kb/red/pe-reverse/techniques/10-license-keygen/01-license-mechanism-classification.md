---
id: "pe-reverse/10-license-keygen/01-license-mechanism-classification"
title: "许可证机制分类与攻击路径选择"
title_en: "License Mechanism Classification and Attack Path Selection"
summary: >
  攻击者视角的许可证机制分类法：纯本地算法、签名链、自引用签名嵌入、云端校验四类，
  每类给出可观察特征、攻击路径决策树与对应武器（keygen / 公钥替换 / 逻辑 patch /
  Frida hook）。正确分类是后续一切动作的第一步——选错路径等于浪费时间。
summary_en: >
  Attacker-oriented license mechanism taxonomy: pure local algorithm, signature chain,
  self-referencing signature, and cloud validation. Each class comes with observable
  fingerprints, an attack decision tree, and matching weapons (keygen / pubkey swap /
  logic patch / Frida hook). Correct classification is the first step of everything
  that follows.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "激活码"
  - "注册码"
  - "license key"
  - "serial"
  - "activation"
  - "keygen"
  - "注册机"
  - "Ed25519"
  - "RSA 签名"
  - "PGP 签名"
  - "云端授权"
  - "试用重置"
  - "注册表授权"
  - "MachineGuid"
mcp_tools:
  - triage_pe
  - die_scan
  - rizin_strings
  - ghidra_headless_analyze
  - ghidra_summary_functions
  - procmon_start_capture
  - hash_file
keywords:
  - "license mechanism"
  - "keygen"
  - "activation"
  - "serial validation"
  - "pubkey swap"
  - "cloud licensing"
  - "Ed25519"
  - "PGP clearsign"
  - "trial reset"
  - "local validation"
  - "signature chain"
difficulty: "beginner"
tags:
  - "license-keygen"
  - "mechanism-classification"
  - "attack-decision-tree"
  - "keygen"
  - "activation-bypass"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/02-validation-function-location"
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
  - "pe-reverse/10-license-keygen/06-cloud-license-frida-hook"
---
# 许可证机制分类与攻击路径选择

## 场景

拿到一个商业软件，目标是在不购买授权的前提下获得完整功能。**动手之前的第一个决策
不是"怎么破解"，而是"它属于哪类机制"**——四类机制的攻击成本从"半小时写个 keygen"
到"纯算法 keygen 不可行、只能换路径"不等。先分类，再选武器。

本文给出攻击者视角的四分类法：可观察特征、判定流程、对应武器与预期成本。

## 输入信号

- 激活窗口/注册码输入框（"输入注册码"、"激活"、"Thank you" 弹窗语义）
- license 文件（明文属性文本、PGP 清文签名、加密 BLOB）
- 注册表/配置文件中的授权键（名称、邮箱、key 三段式常见）
- 试用模式（30-Day Trial、剩余天数、功能锁定）
- 网络请求（激活时是否发包、验证 URL）

## 四分类总览

```text
许可证校验机制
├── A 纯本地算法校验     → 武器: keygen（还原公式）/ 逻辑 patch
├── B 签名链校验         → 武器: 公钥替换 + 自签名 / 逻辑 patch
├── C 自引用签名嵌入     → 武器: 迭代收敛（写入→抓取→回填）
└── D 云端校验           → 武器: Frida hook / 状态伪造 / 试用重置（无 keygen）
```

### A 类：纯本地算法校验

校验函数完全在客户端，输入 key + 用户名/邮箱 → 输出布尔。**特征**：

- 无签名算法现场（无大整数模幂、无密码库调用，纯位运算/CRC/自定义哈希）
- key 中携带校验串（CRC 截断、校验位）与字段位（版本号、授权类型、期限）
- 同一 key 在任意机器验证结果一致（无硬件绑定）或有确定性硬件绑定（如注册表
  MachineGuid 派生）
- 典型弱点：**只有部分字段参与校验**（例如 192 字符中仅 19 字符被校验）、
  校验值截断（25-bit CRC）、无 RSA 签名 → **可由邮箱/用户名完全推导 key**

**攻击路径**：还原校验函数算法 → 写 keygen（Python 复现 + 自校验断言）。详见
`03-key-algorithm-recovery`。成本：数小时~数天，取决于混淆强度。

### B 类：签名链校验

key 或 license 文件带**数字签名**（Ed25519 / RSA / DSA / PGP 清文签名），公钥内嵌在
程序中。**特征**：

- 二进制中存在公钥 blob（Ed25519 32B、RSA 模数 128~256B、PGP 公钥环）
- 导入/调用密码库：`bcrypt.dll`、OpenSSL、BouncyCastle、自实现签名例程
- 修改 key 任一字符 → 校验失败（签名覆盖全部内容，与 A 类的"部分校验"相反）
- 验证时流程固定：提取属性 → 验签 → 比对属性字段

**攻击路径**（两条）：

1. **公钥替换**：从程序提取内嵌公钥 → 生成自持密钥对 → 把程序中公钥 patch 成自己的
   → 用私钥签发合法 key。详见 `04-signature-chain-pubkey-swap`。
2. **逻辑 patch**：让验签结果恒为真（改跳转/返回值）。成本低但要面对可能的
   **库级完整性自检**（对 jar/exe 做 SHA-256 白名单），见 `04`。

### C 类：自引用签名嵌入

key 的一部分由程序**启动时根据 key 自身切片重新计算**（自我引用）。**特征**：

- 冷启动时重算授权状态（不是仅在输入时校验一次）
- key 中存在一段与"由 key 前部字段派生"等价的签名切片
- 输入窗口校验（通过）与启动校验（真实判定）是**两套独立机制**

**攻击路径**：利用**签名对切片位置的局部不变性**：写入任意占位 key → 运行抓取程序
计算的签名切片 → 回填到 key → 下次启动必然通过。单次迭代收敛，无需还原签名算法。
详见 `07-self-referencing-signature-convergence`。

### D 类：云端校验

key 有效性由厂商服务器判定（激活时 POST key → 服务器验库/签名 → 返回授权）。
**特征**：

- 激活流程必然发包，断网激活失败或降级
- 客户端**没有可复刻的校验公式**（License Code 仅做格式面检查）
- 离线激活证书为服务端私钥签名（如 RSA），客户端只有验签公钥且私钥不在本地；
  但注意：若公钥内嵌，B 类公钥替换仍可用；若授权状态文件本身可伪造，可走状态伪造
- 典型弱点：授权状态存本地文件 → 可备份/修改/重置试用

**攻击路径**：keygen 基本不可行（无本地公式）；转换目标：

1. **Frida 运行时挂钩**：拦截授权查询函数，让程序判定"已激活"（`06`）
2. **本地状态伪造**：解析授权状态文件格式，构造"已激活"状态（`06`）
3. **试用重置**：备份→删除→重启，循环试用（`06`）

## 攻击链：从信号到武器

```text
激活窗口/文件/注册表信号
  → 断网重试判定本地 vs 云端
  → 特征归类（字符串/公钥/自我引用）
  → 选武器（keygen / 公钥替换 / 迭代收敛 / hook）
  → 实机验证（Frida 替换 + 标志位）
```

## 判定决策树（攻击者视角）

```text
激活时是否发包？
├─ 是 → 断网重试：仍能激活 → A/B/C（本地为主，网络请求可能只是格式校验）
│       断网失败 → D 云端校验 → hook/状态伪造/试用重置（06）
└─ 否 → 本地校验
       ├─ key 中含可解析字段（类型/期限/CRC）→ A 本地算法 → keygen（03）
       ├─ 二进制中有公钥 blob / 密码库调用 → B 签名链 → 公钥替换（04）
       ├─ 冷启动重算 + key 自我引用 → C 自引用 → 迭代收敛（07）
       └─ 无法命名 → 按 02 定位校验函数再归类
```

## 武器选择与成本对照

| 机制 | 首选武器 | 备选 | 典型成本 |
|---|---|---|---|
| A 本地算法 | keygen（Python 复现） | 逻辑 patch | 数小时~数天 |
| B 签名链 | 公钥替换 + 自签名 | 逻辑 patch | 数小时~数天 |
| C 自引用 | 迭代收敛（抓取回填） | 还原签名算法 | 数小时 |
| D 云端 | Frida hook / 状态伪造 | 试用重置 | 数小时 |

## 证据与验证

无论走哪条路径，攻击成功的判定必须落在**程序真实运行上下文**：

- 进程内动态替换：用 Frida 把官方 key 替换为自生成 key，校验函数返回 `TRUE`
- 内存标志位监听：注册状态位（如 0=已注册）在激活后的值
- 行为验证：试用标记消失、功能解锁、重启后状态保持

详见 `05-keygen-frida-verification-loop`。

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 初筛与类型识别 | `triage_pe`、`die_scan`、`hash_file` |
| 字符串/导入扫描（找激活相关信号） | `rizin_strings`、`rizin_imports` |
| 反编译定位校验函数 | `ghidra_headless_analyze`、`ghidra_summary_functions`、`ghidra_summary_function_detail` |
| 网络行为确认（是否云校验） | `procmon_start_capture`、`http_probe` |
| 后续算法还原 | `python_re_tool_status`、`make_pe_crypto_unpack_plan` |

## 下一跳

- 已判 A/B → `02-validation-function-location` 定位校验函数
- 已判 D → `06-cloud-license-frida-hook` 直接看 hook 路径