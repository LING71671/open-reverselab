---
title: 桌面端安装与更新
description: 下载 Open ReverseLab v2.0.0-beta.1 Windows 桌面版，配置模型、创建工作区并运行 Goal。
---
# 桌面端安装与更新

[下载 v2.0.0-beta.1](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0-beta.1) 提供 Windows x64 安装包与便携 ZIP。版本说明、签名文件和 SHA256 校验值位于同一发布页。

## 安装 Windows 版

1. 安装 Python 3.11+，确保终端能执行 `python`，并安装 Microsoft Edge WebView2 Runtime。
2. 下载并运行 `OpenReverseLab-v2.0.0-beta.1-windows-x64-setup.exe`。使用便携版时，完整解压 ZIP 后运行 `OpenReverseLab.exe`。
3. 启动应用，在设置中保存模型提供商的 API 地址、API Key 和模型 ID。模型使用已保存配置，不会代选提供商。
4. 选择工作区，新建 Goal，分别填写文件、目录或 URL 目标，以及希望完成的结果。基础 SHA256 核验可以在本地完成。

首次启动会创建默认工作区，也可以新建或打开其他目录。样本、Goal、证据与报告保存在工作区中。工作区放在安装目录之外；Ghidra、Frida 等外部工具按任务单独安装。

## red / blue / both

左上角选择策略。red 组织分析假设与观察路径；blue 使用防御知识检查行为与控制措施。both 并行运行两方策略，每方可规划多个动作，执行中交换证据，各自核验后再核验完整目标。

Goal 与就绪动作的并发数量默认不设上限。时间和 Token 预算也默认留空，需要时可以设置。运行期间补充要求或调整目标会保留同一个 Goal 的证据与历史，在执行边界应用新要求；手动停止会取消执行并保留进展。

正文展示分析进展，计划、脚本、工具输出与核验明细按需展开。流程画板展示真实依赖与证据连线，支持卡片详情、缩放、跟随流程和全屏。

## 应用更新

在设置 → 应用更新中选择渠道。测试版默认选择“测试版”渠道，接收 beta 与正式版本；“稳定版”只接收正式版本。两个渠道都只提供更高版本，切换渠道不会降级。

应用从 GitHub 实际 Release 资产读取更新清单。用户选择下载后获取安装包并验证签名；安装前等待所有已打开工作区的任务结束与记录保存。便携版通过发布页下载新包后完整解压升级，源码构建通过拉取更新并重新构建升级。

详见[应用更新](https://github.com/LING71671/open-reverselab/blob/main/desktop/UPDATES.zh-CN.md)。更新签名用于核对包与发布密钥，不代表 Windows Authenticode 代码签名。

## 从源码运行

安装 Node.js 22+、pnpm、Python 3.11+ 和 Rust 工具链。Windows 构建还需要 Microsoft C++ Build Tools。克隆仓库后执行：

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
```

[完整构建步骤](https://github.com/LING71671/open-reverselab#build-the-desktop)包含资源准备与打包命令，`pnpm dev` 可启动浏览器开发预览。

## 数据与平台

配置的模型端点会收到任务上下文和选定证据。API Key 保存在本机 WebView 存储中，生成的 Python 使用当前用户权限执行。性能异常提醒和 Sentry 诊断均默认关闭，可在设置中独立开启。

本版桌面包支持 Windows x64。macOS / Linux 可以使用仓库 CLI/MCP 工作流，暂未提供原生桌面包。

[桌面指南](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.zh-CN.md) · [开发指南](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.zh-CN.md) · [Agent 运行机制](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.zh-CN.md)
