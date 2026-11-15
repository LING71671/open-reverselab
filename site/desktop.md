---
title: 桌面端安装与更新
description: 下载 Open ReverseLab Windows 桌面测试版，安装知识库扩展、配置模型并运行 Goal。
---
# 桌面端安装与更新

[下载 v2.0.0-beta2](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0-beta2)，提供 Windows x64 安装版与便携版。桌面包不内置知识库或 MCP 服务；安装后可在应用中导入知识包、添加 MCP 连接。

## Windows 安装

1. 安装 Python 3.11+，确保终端能执行 `python`，并安装 Microsoft Edge WebView2 Runtime。
2. 从发布页下载 `-setup.exe` 安装包并运行，或完整解压便携 ZIP 后启动 `OpenReverseLab.exe`。
3. 启动应用，在设置中保存模型提供商的 API 地址、API Key 和模型 ID。提供商支持模型列表时，可在 Goal 输入区直接切换模型。
4. 选择工作区，新建 Goal，分别填写文件、目录或 URL 目标，以及希望完成的结果。基础 SHA256 核验可以在本地完成。

首次启动会创建默认工作区，也可以新建或打开其他目录。样本、Goal、证据与报告保存在工作区中。工作区放在安装目录之外；Ghidra、Frida 等外部工具按任务单独安装。

## red / blue / both

左上角选择策略。red 组织分析假设与观察路径；blue 使用防御知识检查行为与控制措施。both 并行运行两方策略，每方可规划多个动作，执行中交换证据，各自核验后再核验完整目标。

一方阻塞后，另一方新取得的工具证据可以触发它重新规划，继续分叉与汇合；重复观察不会反复启动相同路线。目标文件已取得 SHA256 时，观察与核验会关联该内容版本。

Goal 与就绪动作的并发数量默认不设上限。时间和 Token 预算也默认留空，需要时可以设置。运行期间补充要求或调整目标会保留同一个 Goal 的证据与历史，在执行边界应用新要求；手动停止会取消执行并保留进展。

正文展示分析进展，计划、脚本、工具输出与核验明细按需展开。流程画板展示真实依赖与证据连线，支持卡片详情、缩放、跟随流程和全屏。

切换 red、blue、both 会恢复各自上次选中的任务。未发送的草稿按工作区与 Goal 保存在本机，切换工作区或刷新后可继续编辑。

## 安装知识库与 MCP

桌面运行时与知识包独立分发。打开侧栏**扩展 → 市场源**，浏览 **Open ReverseLab 官方知识库**并安装。也可导入其他仓库、文件夹或 ZIP；市场源用于保存和浏览扩展目录。

知识包可启用、停用、移除和导出。GitHub 安装可点击**检查更新**，再点击**更新到…**，安装来源仓库默认分支上的新版。选择网络导出时会带上引用的方法与文档，ZIP 可再次导入。进行中的 Goal 固定文档、方法与网络版本，后续更新不会替换已有引用。

在 MCP 页导入描述包或添加独立连接，配置 stdio 命令或 Streamable HTTP 地址，验证连接后即可发现工具与资源。连接参数保存在本机，不进入知识包导出。

[扩展协议与导入说明](https://github.com/LING71671/open-reverselab/blob/main/EXTENSIONS.zh-CN.md) · [创建扩展的 skill](https://github.com/LING71671/open-reverselab/tree/main/tools/skills/create-reverselab-extension)

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

本版提供 Windows x64 安装包与便携 ZIP。macOS / Linux 可以使用仓库 CLI/MCP 工作流，暂未提供原生桌面包。

[桌面指南](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.zh-CN.md) · [开发指南](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.zh-CN.md) · [Agent 运行机制](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.zh-CN.md)
