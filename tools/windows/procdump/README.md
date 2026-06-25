# ProcDump

Sysinternals 进程内存 dump 工具。

## 用途

- 按条件触发进程内存 dump（CPU、内存阈值、时间等）
- 全内存 dump 用于后续静态分析
- 配合 PE 知识库 `pe-unpack-dump.md` 使用

## 下载

- Sysinternals：https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
- 直接下载：https://download.sysinternals.com/files/Procdump.zip

## 安装

解压 `Procdump.zip` 到 `tools/windows/procdump/`。

或通过 `install_tools.ps1 -Windows` 自动下载安装。

## 常用命令

```cmd
# 按进程名 dump
procdump -ma notepad.exe

# 按 PID dump
procdump -ma 1234

# CPU 触发 dump
procdump -c 50 -ma notepad.exe
```
