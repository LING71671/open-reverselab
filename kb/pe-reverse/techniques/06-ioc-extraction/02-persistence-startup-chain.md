---
id: "pe-reverse/06-ioc-extraction/02-persistence-startup-chain"
title: "持久化与启动链 IOC 提取"
title_en: "Persistence and Startup Chain IOC Extraction"
summary: >
  PE 行为分析中的持久化路径卡片，覆盖 Run Key、服务、计划任务、启动目录、WMI Event、IFEO、AppInit_DLLs 与 Procmon/x64dbg 证据落盘。
summary_en: >
  PE behavior-analysis field card for persistence paths, covering Run Keys, services, scheduled tasks, startup folders, WMI events, IFEO, AppInit_DLLs, and Procmon/x64dbg evidence capture.
board: "pe-reverse"
category: "06-ioc-extraction"
signals:
  - "RegSetValueEx"
  - "CreateService"
  - "schtasks"
  - "Startup folder"
  - "WMI EventFilter"
  - "Image File Execution Options"
  - "AppInit_DLLs"
mcp_tools:
  - "triage_pe"
  - "make_procmon_filters"
  - "extract_iocs_from_summary"
  - "make_sigma_stub"
  - "kb_router"
keywords:
  - "persistence"
  - "startup"
  - "Run Key"
  - "service"
  - "scheduled task"
  - "WMI"
  - "IOC"
difficulty: "intermediate"
tags:
  - "pe"
  - "ioc"
  - "persistence"
  - "procmon"
  - "sigma"
language: "zh-CN"
last_updated: "2026-07-03"
related_articles:
  - "pe-reverse/04-dynamic-analysis/08-procmon-patterns"
  - "pe-reverse/06-ioc-extraction/01-ioc-extraction"
---
# 持久化与启动链 IOC 提取

## 1. 入口信号

```text
Procmon: RegSetValue / CreateFile / Process Create
strings: Software\Microsoft\Windows\CurrentVersion\Run
strings: schtasks /Create /SC /TN
imports: RegSetValueExW / CreateServiceW / StartServiceW
行为: 重启后进程恢复、服务多出、任务计划多出
```

目标是把“启动路径”拆成可查询 IOC：注册表键、服务名、任务名、文件落点、命令行和触发条件。

## 2. 静态打点

```powershell
python scripts/misc/ai_tool.py run triage_pe -- samples/app.exe --out exports/pe/app/triage.json
strings samples/app.exe | rg -i "Run\\|RunOnce|Services|schtasks|Startup|WMI|CurrentVersion|Image File Execution Options|AppInit_DLLs"
```

Ghidra 中优先追：

```text
RegCreateKeyExW
RegSetValueExW
CreateServiceW
OpenSCManagerW
ShellExecuteW("schtasks")
IWbemServices::PutInstance
CopyFileW / MoveFileExW
```

## 3. Procmon 过滤器

```text
Process Name is sample.exe Include
Operation is RegSetValue Include
Operation is RegCreateKey Include
Operation is CreateFile Include
Operation is Process Create Include
Path contains \CurrentVersion\Run Include
Path contains \Services\ Include
Path contains \Startup Include
Path contains \Schedule\TaskCache Include
```

导出 CSV 后提取 IOC：

```python
import csv
from pathlib import Path

rows = csv.DictReader(Path("exports/pe/app/procmon.csv").open(encoding="utf-8", errors="replace"))
for r in rows:
    path = r.get("Path", "")
    op = r.get("Operation", "")
    if any(x.lower() in path.lower() for x in ["currentversion\\run", "\\services\\", "\\startup", "taskcache"]):
        print(op, path, r.get("Detail", ""))
```

## 4. 常见路径表

| 路径 | 成功标志 | 下一跳 |
|---|---|---|
| `HKCU/HKLM\...\Run` | 值名 + 命令行落盘 | Sigma registry rule |
| `CreateServiceW` | 服务名、ImagePath、StartType | service IOC |
| `schtasks /Create` | 任务名、触发器、Action | task XML |
| Startup folder | `.lnk` 或 exe 落地 | file IOC |
| WMI EventFilter | Filter/Consumer/Binding | WMI IOC |
| IFEO Debugger | 目标进程 + Debugger 值 | hijack chain |
| AppInit_DLLs | DLL 路径 + LoadAppInit_DLLs | DLL load chain |

## 5. 攻击链 / 工作流

```text
strings/imports/Procmon 出现启动项信号
  → 过滤 RegSetValue/CreateService/schtasks/CreateFile
  → 提取 key、value、service name、task name、file path
  → x64dbg 断对应 API 回溯 caller
  → Ghidra 命名 persistence 函数
  → 输出 IOC 表并生成 Sigma/YARA 草案
```

## 6. x64dbg 断点

```text
bp advapi32.RegSetValueExW
bp advapi32.CreateServiceW
bp kernel32.CreateFileW
bp kernel32.CopyFileW
bp shell32.ShellExecuteW
bp kernel32.CreateProcessW
```

命中时记录：

```text
API:
caller VA:
key/path:
value name:
data/command:
return code:
```

## 7. Evidence

| 项 | 记录内容 |
|---|---|
| 文件落点 | path、size、SHA256、创建 API |
| 注册表 | hive、key、value、data、caller |
| 服务 | service name、display name、ImagePath、StartType |
| 任务计划 | task name、trigger、action、XML path |
| WMI | Filter、Consumer、Binding |
| 检测产物 | YARA/Sigma 草案路径 |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| 初筛 | `triage_pe` | imports/strings/节区线索 |
| Procmon | `make_procmon_filters` | 生成行为过滤器 |
| IOC 汇总 | `extract_iocs_from_summary` | 从摘要提取键值、路径和命令 |
| Sigma | `make_sigma_stub` | 生成注册表/服务/任务规则草案 |
| 知识路由 | `kb_router` | 按 persistence、Run Key、service 查下一篇 |
