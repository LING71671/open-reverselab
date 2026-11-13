# 常见问题

## Open ReverseLab 提供什么？

桌面工作区、红蓝知识库，以及供外部 AI 客户端使用的 CLI/MCP 工具。桌面端围绕 target 创建 Goal，展示执行分支、证据、核验结果和报告。知识库覆盖 Web、APK、PE、密码学和协议等领域。

## 从哪里下载桌面端？

[v2.0.0-beta.1 发布页](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0-beta.1) 提供 Windows x64 安装包与便携 ZIP，安装与配置见[桌面指南](./desktop.md)。也可[从源码运行](./desktop.md#从源码运行)。

macOS/Linux 可使用仓库的 CLI/MCP 工作流，目前没有这两个平台的桌面二进制。完整说明见 [桌面端指南](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.zh-CN.md)。

## red、blue、both 有什么区别？

red 与 blue 使用独立分析策略。both 中两方可各自规划多个动作，执行中交换证据，各自核验后再核验完整目标。知识库的 `both` 文档代表共享知识；攻击与防御文章通过关联路径连接。桌面选择不会改写外部 MCP 客户端的模式。

## 必须设置预算吗？

不必。默认不设时间和 Token 上限。需要限制时，在“运行限制”中填写相应数值；留空的项目保持不限。失败路径、重复脚本和证据变化会反馈到后续规划。目标通过独立核验后完成；达到已设置的上限、手动停止和路线耗尽会分别保留状态。

## 能同时运行多个任务吗？

每个工作区支持多个 Goal 并行，应用不设置并发数量上限。每个 both Goal 内的 red、blue 策略可各自展开多个动作；独立动作同时启动，有前置依赖的动作等待所需结果。切换任务或工作区不会改变后台输出归属。关闭应用会中断运行；下次启动保留历史记录，继续分析需创建新 Goal。

## 文件和模型数据保存在哪里？

默认工作区为 `~/.open-reverselab/workspaces/Default`，也可另选目录。样本原件、工作副本、任务和报告放在工作区的 `.reverselab/` 下。模型辅助任务会将任务上下文和选中的证据发送至配置的端点。API Key 保存在 WebView 本地存储，当前未接入系统密钥库。

## 桌面端会自动调用所有 MCP 工具吗？

当前桌面适配器执行目标初筛与 Python 动作，默认不设工具时限；知识文档列出的工具需要相应适配器与本机安装。外部 Codex、Claude Code 等客户端可以通过 `reverse_lab_tools` 调用 MCP 工具。Python 动作继承当前用户权限，应用未提供操作系统级沙箱。

## 如何验证安装和参与贡献？

Windows 使用 `START_HERE.bat`，macOS/Linux 使用 `./START_HERE.sh` 检查 CLI/MCP。开发修改运行相关测试及 `python scripts/misc/public_release_check.py`；具体入口见[贡献指南](https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md)。
