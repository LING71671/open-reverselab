---
title: 桌面端安装与更新
description: 安装 ReverseLab Windows 桌面端，创建工作区并配置应用更新。
---
# 桌面端安装与更新

[下载 v1.3.0](https://github.com/LING71671/open-reverselab/releases/tag/v1.3.0)

## Windows 安装

下载 Windows x64 安装包并运行，按安装程序完成安装。安装包包含桌面界面、知识库与项目脚本。需要 Python 3.10+ 在 PATH 中，以及 Microsoft Edge WebView2 Runtime。Ghidra、Frida 等外部工具按需单独安装。

首次启动会创建默认工作区，也可以新建或打开其他目录。样本、Goal、证据与报告保存在工作区中。配置模型提供商、API 地址、Key 和模型 ID 后，新建 Goal，填写目标与希望得到的结果。

## red / blue / both

左上角切换分析模式。red 选择分析与验证路径；blue 使用防御知识与检查方法；both 并行运行两条分支并汇合证据。实时流程画板显示分支状态。多个 Goal 可进入队列，默认每个工作区同时运行两个。

时间和 Token 上限可选；未设置时使用运行器默认值。遇到无进展或重复动作会尝试其他路径，可用路径或限制耗尽时保存已有结果。

## 应用更新

在设置中检查新版本、阅读发布说明和下载更新。安装版使用签名校验，安装前需等待运行任务结束并保存记录。便携版通过新版安装包迁移；不要把工作区放进安装目录。

## 数据与平台

配置的模型端点会收到任务上下文和分析证据。API Key 保存在本机 WebView 存储中。生成的 Python 以当前用户权限执行。

本次提供 Windows x64 安装包；macOS / Linux 可以使用仓库脚本，桌面构建仍需在对应系统验证。

[桌面开发说明](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent 架构](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
