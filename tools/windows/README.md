# Windows Tools

Windows PE/二进制逆向工程工具集。

## 工具列表

| 工具 | 用途 | 安装说明 |
|---|---|---|
| **静态分析** | | |
| Cutter | Rizin 图形化反汇编器 | [Cutter/README.md](Cutter/README.md) |
| PE-bear | PE 结构查看器 | [PE-bear/README.md](PE-bear/README.md) |
| DiE | Detect It Easy — 文件类型/加壳识别 | [die/README.md](die/README.md) |
| HxD | 十六进制编辑器 | [HxD/README.md](HxD/README.md) |
| **动态调试** | | |
| x64dbg / x32dbg | Windows 用户态调试器，断点/单步/patch/插件 | [x64dbg/README.md](x64dbg/README.md) |
| Scylla | IAT 修复 / 进程 dump 工具（常与 x64dbg 插件联用） | [scylla/README.md](scylla/README.md) |
| Frida | 跨平台动态插桩框架，Windows 侧用 `frida-tools` | [frida/README.md](frida/README.md) |
| **行为监控** | | |
| ProcessMonitor | Sysinternals 进程/文件/注册表行为监控 | [ProcessMonitor/README.md](ProcessMonitor/README.md) |
| ProcDump | Sysinternals 进程内存 dump 工具 | [procdump/README.md](procdump/README.md) |
| **辅助工具** | | |
| Cheat Engine | 内存扫描/修改器 | 手动安装，见 [cheat-engine/README.md](cheat-engine/README.md) |
| ReClass | 运行时结构体重建工具 | 手动安装，见 [reclass/README.md](reclass/README.md) |

## 安装

```powershell
.\scripts\misc\install_tools.ps1 -Windows
```

手动下载链接见各工具 README。x64dbg、Scylla、ProcDump、Cheat Engine、ReClass 需手动下载安装。`frida-tools` 通过 pip 安装：`pip install frida-tools`。
