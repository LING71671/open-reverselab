# x64dbg

Windows 用户态调试器，支持 x64 和 x86。

## 用途

- 动态调试 PE/二进制
- 断点、单步、寄存器/内存查看
- Patch 验证
- 反调试绕过测试
- 配合 Scylla 插件做进程 dump + IAT 修复

## 下载

- 官网：https://x64dbg.com/
- GitHub Releases：https://github.com/x64dbg/x64dbg/releases
- Chocolatey：`choco install x64dbg`

## 安装

下载 `snapshot_*.zip`，解压到 `tools/windows/x64dbg/`。

## 常用插件

- **ScyllaHide** — 反反调试（https://github.com/x64dbg/ScyllaHide）
- **Scylla** — IAT 修复/进程 dump（内置在 x64dbg 插件目录）

## 在 MCP 中使用

AI 可以通过 `toolbox_launch x64dbg` 启动，通过 `make_x64dbg_breakpoint_script` 自动生成断点脚本。

## 常用断点

```
bp MessageBoxA
bp MessageBoxW
bp GetProcAddress
bp LoadLibraryA
bp CreateFileW
bp RegSetValueExW
bp InternetOpenUrlW
bp WinHttpSendRequest
bp strcmp
bp memcmp
bp IsDebuggerPresent
bp VirtualProtect
bp VirtualAlloc
bp CreateRemoteThread
bp WriteProcessMemory
```

详见 `AGENTS.md` 第 2.2 节。
