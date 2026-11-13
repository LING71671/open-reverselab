---
title: 桌面端安装与更新
description: 从源码构建 Open ReverseLab 桌面预览版，配置模型、创建工作区并运行 Goal。
---
# 桌面端安装与更新

桌面端正在准备 `v2.0.0-beta.1`，安装包尚未发布。当前可从源码体验；已发布的版本统一列在 [Releases](https://github.com/LING71671/open-reverselab/releases)。

## 从源码运行

安装 Node.js 22+、pnpm、Python 3.10+ 和 Rust 工具链。Windows 还需要 Microsoft C++ Build Tools 与 WebView2 Runtime。克隆仓库后执行：

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
```

[完整构建步骤](https://github.com/LING71671/open-reverselab#build-the-desktop)包含资源准备与打包命令。Ghidra、Frida 等外部工具按分析任务单独安装。

首次启动会创建默认工作区，也可以新建或打开其他目录。样本、Goal、证据与报告保存在工作区中。配置模型提供商、API 地址、Key 和模型 ID 后，新建 Goal，填写目标与希望得到的结果。

## red / blue / both

左上角切换分析模式。red 选择分析与验证路径；blue 使用防御知识与检查方法；both 并行运行两条分支并汇合证据。实时流程画板显示分支状态。多个 Goal 可进入队列，默认每个工作区同时运行两个。

时间和 Token 默认不限，可在“运行限制”中设置。运行期间可以补充要求或调整目标，保留同一个 Goal 的证据与历史，也可以手动停止。跨分支协作与完成核验仍在验证中，试用陌生任务时建议设置运行限制并查看实际证据。

## 应用更新

源码预览通过拉取更新后重新构建。安装版的签名更新机制见[更新说明](https://github.com/LING71671/open-reverselab/blob/main/desktop/UPDATES.md)，可下载版本以 Releases 为准。工作区应放在源码与安装目录之外。

## 数据与平台

配置的模型端点会收到任务上下文和分析证据。API Key 保存在本机 WebView 存储中。生成的 Python 以当前用户权限执行。

桌面打包目标为 Windows x64；macOS / Linux 可以使用仓库脚本，原生桌面包尚未提供。

[桌面开发说明](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent 架构](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
