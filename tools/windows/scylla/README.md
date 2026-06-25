# Scylla

IAT 修复与进程 dump 工具。

## 用途

- 从运行中的进程 dump 完整内存镜像
- 修复导入地址表（IAT）
- 配合 x64dbg 或独立使用
- 脱壳后的 PE 重建

## 下载

- GitHub：https://github.com/NtQuery/Scylla/releases

## 安装

下载 `Scylla_*.zip`，解压到 `tools/windows/scylla/`。

## 相关工具

- **ScyllaHide** — x64dbg 反反调试插件（https://github.com/x64dbg/ScyllaHide）

## 在知识库中的引用

PE 知识库 `kb/pe-reverse/techniques/05-crypto-unpack/01-pe-unpack-dump.md` 描述了 Scylla dump + IAT 修复的完整流程。
