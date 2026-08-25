---
id: "pe-reverse/10-license-keygen/06-cloud-license-frida-hook"
title: "云端授权识别与 Frida hook 替代路径"
title_en: "Cloud License Identification and Frida Hook Alternatives"
summary: >
  攻击者视角的云端授权（反 keygen）场景手册：识别云校验特征（无本地公式、证书私钥
  在服务端、激活必发包）、判断"纯 keygen 不可行"的依据，然后切换武器——
  本地状态伪造、授权查询函数 Frida 挂钩、试用状态重置三条替代路径，
  以及各自的可观测验证方法。
summary_en: >
  Attacker-oriented manual for cloud-license (anti-keygen) scenarios: identifying
  cloud validation fingerprints (no local formula, private key stays server-side,
  activation always sends traffic), establishing why pure keygen is infeasible,
  then switching weapons — local state forgery, Frida hooking of the licensing
  query surface, and trial-state reset, with observable verification for each.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "云端授权"
  - "在线激活"
  - "NSL"
  - "LicensingService"
  - "授权证书"
  - "状态文件"
  - "试用重置"
  - "云校验"
  - "服务端校验"
  - "状态伪造"
  - "hook 查询面"
mcp_tools:
  - http_probe
  - procmon_start_capture
  - rizin_strings
  - ghidra_summary_function_detail
  - workspace_read_text
  - analysis_note
keywords:
  - "cloud license"
  - "server-side validation"
  - "activation certificate"
  - "offline activation"
  - "state file"
  - "trial reset"
  - "licensing service"
  - "hook"
  - "NSL SDK"
  - "query surface"
difficulty: "intermediate"
tags:
  - "license-keygen"
  - "cloud-license"
  - "frida-hook"
  - "state-forgery"
  - "trial-reset"
language: "zh-CN"
last_updated: "2026-08-12"
related_articles:
  - "pe-reverse/10-license-keygen/01-license-mechanism-classification"
  - "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop"
  - "pe-reverse/04-dynamic-analysis/07-direct-syscall"
---
# 云端授权识别与 Frida hook 替代路径

## 场景

目标激活时必发包、断网即失败——**D 类云端校验**。此时"写个 keygen"不成立：
客户端没有可复刻的校验公式，授权有效性由厂商服务器判定。本文先给出
"放弃 keygen" 的证据链，再给出三条真正可行的替代攻击路径。

## 攻击链：云端授权替代路径

```text
确认云校验（网络/私钥/无公式证据链）
  → 侦察本地信任锚（公钥/状态文件）
  → 路径一: 本地状态伪造
  → 路径二: 授权查询面 Frida hook
  → 路径三: 试用状态重置
  → 真实上下文验证
```

## 输入信号与"不可 keygen"判定

| 信号 | 含义 |
|---|---|
| 激活流程必然发包（`POST .../verify/{Order}` 类） | 服务器参与校验 |
| 断网激活失败或降级（提示网络错误） | 本地无完整校验面 |
| License Code 仅"格式面"检查，无算法校验错误提示语义 | 公式不在客户端 |
| 离线激活证书为 RSA 签名、私钥在服务端 | 无法本地签发 |

**证据链（写进笔记的三条）**：
1. Procmon/抓包确认激活请求发出且响应决定状态
2. 反编译确认客户端"证书验签"只有公钥、无私钥材料
3. 修改 License Code 单字符，客户端不产生算法级错误（只有格式错误）→
   不存在本地公式

> 注意区分：若**公钥内嵌**且程序接受"离线激活证书"（如 RSA 签名证书），
> 则 B 类公钥替换仍可行（见 `04`）——"云校验"并非自动等于"无解"，
> 取决于是否存在可替换/可伪造的本地信任锚。

## 替代路径一：本地状态伪造

多数云授权把"已激活"判定落为**本地授权状态文件/注册表**（缓存、证书、
会话数据）。伪造它 = 让程序启动时读到的状态就是"已激活"。

```python
# 状态目录侦察（示例形态，逐目标调整）
from pathlib import Path

state_dir = Path.home() / "AppData" / "Local" / "TargetApp" / "License"
for p in sorted(state_dir.iterdir()):
    data = p.read_bytes()
    print(f"{p.name:40s} size={len(data):6d} hex={data[:8].hex()}")
```

分析状态文件三要素：**格式**（明文/加密 BLOB/二进制）、**字段**（激活标志、
许可证内容、机器标识）、**写入时机**（哪个函数在激活成功后写它——用 Frida
hook 写文件 API 抓取活跃写入者）。然后构造"已激活"状态：
- 明文/结构简单：直接构造同构文件
- 加密 BLOB：hook 编码函数，让程序自己"帮我们加密"（把伪造内容送入编码器）

## 替代路径二：授权查询面 Frida 挂钩

绕过状态判定，直接在查询面撒谎——拦截"程序询问授权"的所有出口：

```python
# hook 授权查询函数，恒返回"已激活"
import frida, sys

LICENSE_QUERY = "0x140045000"   # LicensingService 查询函数（反编译定位）

hook = """
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        console.log("[lic] query called arg0=" + args[0] + " arg1=" + args[1]);
        this.state = args[0];      // 可能是指向输出结构的指针
    },
    onLeave(retval) {
        // 情况A: 返回布尔 → 置 1
        retval.replace(ptr(1));
        // 情况B: 填充输出结构 → 在 onEnter 已记录指针，此处写"已激活"字段
        // this.state.writeU32(1);
        console.log("[lic] forced activated");
    }
});

// 同时hook“许可证状态查询”字符串路径（部分程序走字符串判定）
["Licensed", "Activated", "Trial"].forEach(function (s) {
    var addr = Memory.scanSync(Process.enumerateModules()[0].base,
        Process.enumerateModules()[0].size, strToUtf8(s))[0];
    if (addr) console.log("[str] " + s + " @ " + addr.address);
});
""" % LICENSE_QUERY

session = frida.attach("target.exe")
script = session.create_script(hook)
script.load()
sys.stdin.read()
```

要点：
- **hook 面选择**：优先 hook"查询函数"而非"激活函数"——查询每次启动/功能触发
  都走，一次 hook 全覆盖；激活只在首次调用。
- **spawn 模式**：授权状态在启动早期读取，用 `frida -f` spawn 并尽早 attach，
  避免错过初始化窗口。
- **多进程**：部分目标授权查询在工作进程（非主进程）→ 对所有目标进程注入。

## 替代路径三：试用状态重置

若目标只锁定"试用期"，重置本地试用状态可循环试用：

```powershell
# 侦察 → 备份 → 清理 → 重启（示例）
# 1) 找到试用状态文件/注册表键
# 2) 备份
Copy-Item "$env:APPDATA\TargetApp\state.dat" "$env:APPDATA\TargetApp\state.dat.bak"
# 3) 清理
Remove-Item "$env:APPDATA\TargetApp\state.dat"
# 4) 重启目标 → 恢复满额试用
```

注意事项：清理前确认目标进程已退出；若状态写入注册表，用
`RegDeleteValue`/`reg delete` 对应清理；多组件目标（主程序+插件）需要
清全部状态点。

## 证据与验证

| 路径 | 判定标准 |
|---|---|
| 状态伪造 | 重启后状态页显示"已授权"、功能解锁、无网络请求 |
| 查询面 hook | 日志出现 `[lic] forced activated`，标题栏试用标记消失 |
| 试用重置 | 重启后试用天数恢复满额（记录前后剩余天数） |

所有验证在同一**真实运行上下文**完成，避免"看起来通过"。

## MCP 工具映射

| 步骤 | 工具 |
|---|---|
| 确认网络校验行为 | `http_probe`、`procmon_start_capture` |
| 定位查询函数/状态写入者 | `ghidra_summary_function_detail`、`rizin_strings` |
| 证据落盘 | `workspace_read_text`、`workspace_write_text`、`analysis_note` |

## 下一跳

- 云授权场景的对抗加深 → `04-dynamic-analysis/07-direct-syscall`（挂钩面升级）
- 若发现目标其实有公钥信任锚 → 转 `04-signature-chain-pubkey-swap`