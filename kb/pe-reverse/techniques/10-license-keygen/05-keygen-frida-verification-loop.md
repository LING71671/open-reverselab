---
id: "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop"
title: "keygen 实机验证闭环（Frida 进程内替换）"
title_en: "Keygen Verification Loop with In-Process Frida Swap"
summary: >
  攻击者视角的 keygen 验收标准：不是"算法自洽"就够了，而是要在程序真实运行上下文
  中证明——Frida 把官方 key 替换为自生成 key 后校验函数返回 TRUE、内存注册标志位
  翻转、重启状态保持。给出替换脚本模板、标志位监听、硬件指纹绑定（MachineGuid）
  处理与配置写入激活路径四件套。
summary_en: >
  Attacker-oriented acceptance criteria for keygens: algorithmic self-consistency is
  not enough; you must prove it in the real process context — after swapping the
  official key with the generated one via Frida, the validation function returns TRUE,
  the in-memory registration flag flips, and the state survives restart. Includes the
  swap script template, flag monitoring, hardware fingerprint (MachineGuid) handling,
  and the config-file activation path.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "Frida 验证"
  - "进程内替换"
  - "内存标志位"
  - "MachineGuid"
  - "硬件指纹"
  - "配置写入激活"
  - "Preferences.json"
  - "注册状态位"
  - "替换验证"
  - "重启保持"
mcp_tools:
  - android_frida_run_script
  - android_frida_status
  - debug_script
  - workspace_write_text
  - analysis_note
keywords:
  - "frida"
  - "in-process swap"
  - "validation function"
  - "memory flag"
  - "MachineGuid"
  - "hardware fingerprint"
  - "config activation"
  - "restart persistence"
  - "acceptance"
  - "Interceptor"
difficulty: "intermediate"
tags:
  - "license-keygen"
  - "frida-verification"
  - "in-process-swap"
  - "memory-flag"
  - "hardware-binding"
  - "config-activation"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/03-key-algorithm-recovery"
  - "pe-reverse/10-license-keygen/04-signature-chain-pubkey-swap"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass"
---
# keygen 实机验证闭环（Frida 进程内替换）

## 场景

keygen 写好了，`--verify` 自洽断言也过了——但这只证明"算法复现正确"。
攻击成立的硬标准是：**目标程序真实运行时接受生成的 key**。本文给出验收四件套：
进程内替换、标志位监听、硬件指纹处理、配置写入激活。

## 输入信号

- 校验函数地址（`02` 定位结果）与官方 key（基线）
- 授权状态文件/注册表键位置
- 硬件绑定来源（注册表 MachineGuid、网卡/磁盘序列号派生）

## 攻击链：验收流水线

```text
keygen 自校验（L1）
  → 官方 key 回归（L2）
  → Frida 进程内替换（L3，核心验收）
  → 内存标志位监听（L4）
  → 重启保持（L5）
  → 硬件指纹/配置写入分支处理
```

## 验证层级（由弱到强）

| 层级 | 手段 | 说明 |
|---|---|---|
| L1 | keygen 自校验断言 | 算法自洽，弱证据 |
| L2 | 官方 key 批量回归 | 还原正确性，强证据 |
| L3 | 进程内替换（Frida） | 真实上下文校验通过，**核心验收** |
| L4 | 标志位监听 | 注册状态生效（非仅函数返回） |
| L5 | 重启保持 | 冷启动后仍为已注册 |

## L3：进程内替换（核心验收）

原理：挂到目标进程，`Interceptor.replace` 校验函数——参数不变（官方 key 原样保留），
**只替换函数逻辑**为"用自生成 key 再调原逻辑"不可能（原逻辑在替换中丢失）；
标准做法是**拦截输入 API，把官方 key 文本替换为自生成 key**，让原校验函数
在真实上下文处理我们的 key：

```python
# verify_swap.py — 官方 key → 自生成 key，进程内替换验证
import frida, sys

TARGET = "target.exe"
OFFICIAL = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"   # 官方基线 key（可公开样本）
GENERATED = "YYYYY-YYYYY-YYYYY-YYYYY-YYYYY"   # keygen 输出

hook = """
Interceptor.attach(Module.findExportByName("user32.dll", "GetDlgItemTextW"), {
    onEnter(args) {
        var buf = Memory.readUtf16String(args[2]);
        if (buf && buf.indexOf("-") > 0) {
            Memory.writeUtf16String(args[2], "%s");
            console.log("[swap] official->generated");
        }
    }
});
// 可选: 直接挂钩校验函数，观察入参/返回值
if (Module.findBaseAddress("%s")) {
    Interceptor.attach(ptr("%s"), {
        onEnter(a) { console.log("[check] enter key=" + Memory.readUtf8String(a[0])); },
        onLeave(r) { console.log("[check] ret=" + r.toInt32()); }
    });
} else {
    console.log("[warn] base not resolved, adjust address");
}
""" % (GENERATED, "target.exe", "0x140002F60")

session = frida.attach(TARGET)
script = session.create_script(hook)
script.load()
print("attached; now trigger activation in the UI...")
sys.stdin.read()
```

判定：日志出现 `[check] ret=1`（且必须**出现在未手动改动官方 key 的情况下**）。
若程序在启动时直接校验配置中的 key（无 UI），改为 hook `ReadFile`/`RegGetValueW`
替换读到的内容，思路一致。

## L4：内存标志位监听

校验函数往往把结果写入**全局注册标志位**（如 `DAT_1422E9936`，0=已注册）。
监听它比监听函数返回值更接近真实判定：

```javascript
// 在 L3 脚本基础上追加:
setTimeout(function () {
    var flag = ptr("0x1422E9936");
    Interceptor.attach(flag, {   // 数据断点: frida 不支持，改用轮询
    });
    var timer = setInterval(function () {
        var v = flag.readU8();
        if (v === 0) { console.log("[flag] REGISTERED (0)"); clearInterval(timer); }
    }, 200);
}, 1000);
```

标志位地址来源：`02` 定位时记录校验函数写入的全局；或用
`ghidra` 对校验结果引用反查。轮询而非数据断点，避免 Frida 版本兼容问题。

## 硬件指纹绑定处理

若 key 与机器绑定（派生自注册表 `MachineGuid` / 磁盘序列号）：

1. **确认绑定来源**：hook 读硬件 ID 的 API（`RegQueryValueExW` 读 `MachineGuid`、
   `DeviceIoControl` 取序列号），记录程序实际取到的指纹值
2. **绑定派生**：keygen 增加 `--guid <指纹>` 参数，按还原算法对指定指纹生成
   （算法还原时不把指纹当常数，而是显式输入）
3. **验证**：L3 替换时同时把指纹值对齐，确认校验通过；换一台机器/改 GUID 后
   同一 key 必须 FAIL（证明绑定关系被正确复现）

```powershell
python keygen.py gen --name Test --email a@b.c --guid 00000000-0000-0000-0000-000000000001
```

## 配置写入激活（离线本地校验场景）

当校验在启动时读配置文件（如 `Preferences.json` 的三键 `Name/Email/Key`），
且**手工粘贴激活码会触发联网二次校验**时，直接写配置是正确路径：

```python
import json, shutil
from pathlib import Path

cfg = Path.home() / "AppData" / "Roaming" / "TargetApp" / "UserProfile" / "Settings" / "Preferences.json"
shutil.copy2(cfg, cfg.with_suffix(".json.bak"))       # ① 备份
data = json.loads(cfg.read_text(encoding="utf-8"))
data.setdefault("Settings", {})["ProLicense"] = {
    "Name": "Pro User",
    "Email": "user1234@example.com",
    "Key": generate_key("Pro User", "user1234@example.com"),
}
cfg.write_text(json.dumps(data, indent=2), encoding="utf-8")  # ② 写回
# ③ 复读校验: 重新解析并断言三键一致
```

注意：**写入前先结束目标进程**（避免退出时内存数据覆盖配置）；
写入后复读校验；重启目标确认生效（L5）。

## 证据与验证

- L3 日志：swap 行 + `ret=1`
- L4 日志：`[flag] REGISTERED (0)`
- L5：重启后标题栏试用标记消失 / 功能解锁 / 状态页显示已授权
- 全部证据落盘 `exports/windows/`，配合 `analysis_note` 生成笔记

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 编写/运行 Frida 脚本 | `android_frida_run_script`、`android_frida_status`（Windows 目标用 `tools/frida` 本地运行） |
| 生成断点脚本辅助定位 | `debug_script`、`make_x64dbg_breakpoint_script` |
| 证据落盘 | `workspace_write_text`、`analysis_note` |

## 下一跳

- L3/L4 通过 → 攻击闭环完成，写分析与防御建议（`09-av-evasion` 视角的反面教材）
- L3 失败 → 回到 `03-key-algorithm-recovery` 检查非确定性/字段语义遗漏