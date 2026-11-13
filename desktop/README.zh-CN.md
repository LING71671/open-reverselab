# ReverseLab 桌面端

桌面端围绕工作区内的 target 创建 Goal，由 AI 规划、执行、收集证据并核验目标。左上角选择 `red / blue / both`，中间保留实时流程画板。

## 使用

1. 首次启动创建默认工作区。点击左侧工作区名称，可以新建或打开其他工作区。
2. 在“样本”中导入文件或目录。软件保存原件并创建工作副本；也可以在 Goal 中直接填写文件路径、目录或 URL。
3. 在设置中配置兼容 chat-completions 的 API 地址、模型 ID 和 API Key。
4. 填写 target 和 Goal 后开始。运行上限可选，留空采用 10 分钟和 32,000 tokens。
5. 从流程画板查看节点，在执行记录中查看工具输出、核验条件与报告路径。任务可并行，切换工作区不会改变后台任务的归属。

`both` 同时运行独立的 red、blue 分支，保留各自结果后合流。知识库读取仓库实际索引，blue 包括 defense 文档，共享知识在两种策略下均可检索。

当前直接执行适配器为 Python 观察脚本；需要调试器、真机控制或发布产物加固的动作仍需增加对应适配器。普通目标采用独立模型核验，SHA256 目标可由本地确定性检查完成。BLA / REA 是新增的对抗测试对象，尚未完成对上游工具的实测。

## 开发

在本目录运行 `pnpm install`，然后运行 `pnpm dev` 预览或 `pnpm tauri dev` 启动原生桌面。Python 需要在 PATH 中，原生构建需要 Rust 与 Tauri 对应平台工具链。知识库路径可通过 `REVERSELAB_ROOT` 指向仓库。

架构图见 [ARCHITECTURE.md](ARCHITECTURE.md)，运行规则见 [AGENT_SYSTEM.md](AGENT_SYSTEM.md)，工作区见 [WORKSPACES.md](WORKSPACES.md)，错误码见 [ERROR_CODES.md](ERROR_CODES.md)。

## v2.0.0 发布包

在 [Releases](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0) 下载 Windows x64 安装包，运行后启动 ReverseLab。设置中的应用更新支持版本检查、签名下载与安装，详见 [UPDATES.md](UPDATES.md)。需要 Python 3.10+（命令名 `python`）及 [WebView2 Runtime](https://v2.tauri.app/start/prerequisites/#webview2)。外部逆向工具单独安装。

安装版在设置中升级；便携 ZIP 需要完整解压并保留根目录 `ReverseLab.exe` 旁的 `kb/` 和 `scripts/`，通过新版安装包迁移或退出后解压到新目录。默认工作区在程序目录之外；备份自选工作区的 `.reverselab/` 后再打开。历史运行不会自动恢复外部进程，当前格式不支持路径自动重定位。不要在任务运行时替换 EXE 或移动工作区。

## 模型与本地执行

配置的 API Key 保存在 WebView 本地存储，未接入系统密钥库。模型辅助任务会发送任务上下文与所选证据给该端点；程序不是离线隔离环境。Python 动作使用当前用户权限。切换页面可保留未提交草稿与阅读位置，这些临时界面状态仅保留在本次工作区会话中。

发布检查和打包方法见 [RELEASING.md](../RELEASING.md)。
