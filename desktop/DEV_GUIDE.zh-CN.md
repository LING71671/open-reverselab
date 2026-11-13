# 桌面开发指南

[English](DEV_GUIDE.md) · [桌面指南](README.zh-CN.md)

## 本地启动

使用 pnpm，以及 `package.json` 和锁文件支持的工具版本。当前 Windows 检查使用 Node 22、Rust 1.93 和 Python 3.13。Vite 与原生进程都需要能通过 `python` 调用 Python 3.11+；样本导入使用 `hashlib.file_digest`。原生构建需要 [Tauri 平台工具链](https://v2.tauri.app/start/prerequisites/)，Windows 构建需要 MSVC C++ 工具，运行时需要 WebView2。

在 `desktop/` 目录运行：

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm tauri dev
pnpm build
```

`pnpm dev` 启动浏览器预览；`pnpm tauri dev` 启动原生应用及开发服务。浏览器预览与原生桌面使用相同的工作区、知识库 Python 服务。浏览器接口用于本机开发中间件。

## 添加工具或策略

1. 在 `src/core/contracts` 定义请求与结果契约。
2. 在 `NativeBridge` 或注入执行器后实现工具适配器，传递取消信号与显式配置的剩余时间预算，保留输出、结果来源和错误分类。未设置超时时，适配器与子进程都应保持不限时。
3. 在 `src/engine/tracks` 添加或更新策略，保持 red/blue 独立。
4. 使用 `DagScheduler` 编排有依赖的并行动作。需要独占资源时，接入资源 key 和共享的 `DagResourcePool`；执行器实际结束前，不能因已发送取消请求就释放资源。
5. 通过回调发出结构化步骤、工具记录、健康事件与证据。引擎使用自己绑定的 Goal 和工作区，不读取当前界面选中的会话。
6. 验收条件绑定原目标，通过独立核验器评估实际输出。进程成功退出本身不能完成 Goal。
7. 更新相关 Markdown 契约，并验证新增能力实际涉及的失败、取消或隔离场景。

现有内置适配器提供 Python 执行与目标初筛。Python 脚本使用当前账户调用已安装的库和命令行工具。知识库中的 MCP 工具名称用于定位相关能力，桌面调用仍需要已接入的适配器。调试器、设备与加固集成须实现相同的执行与取消契约。

## 检查命令

在 `desktop/` 目录运行：

```sh
pnpm build
node --test src/services/goals/goalManager.test.mjs src/engine/tests/pipeline.test.mjs src/engine/tests/dagScheduler.test.mjs tests/*.test.mjs
node --experimental-strip-types --test tests/*.test.ts
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
```

在仓库根目录运行：

```sh
python -m pytest tests/test_desktop_kb.py tests/test_desktop_workspace.py tests/test_desktop_triage.py
python scripts/misc/public_release_check.py
```

引擎测试使用合成目标与模拟模型响应。真实提供商行为和 BLA/REA 验收需要各自的实跑记录。私人端到端目标、日志和截图不进入公开改动。

`tests/test_desktop_triage.py` 覆盖目标不存在、文件元数据未知、空目录以及 ZIP/APK 识别。目标文件不存在时必须停止发现流程；架构、编译器、导入与加壳状态来自实际观察的元数据。

## 配置

| 配置 | 用途 |
| --- | --- |
| `REVERSELAB_ROOT` | 定位仓库知识库与脚本 |
| `REVERSELAB_DATA_DIR` | 设置本机工作区登记表根目录 |
| `REVERSELAB_WORKSPACE_DIR` | 设置默认工作区目录 |
| `VITE_LLM_BASE_URL` | 初始化开发模型地址 |
| `VITE_LLM_API_KEY` | 初始化开发模型凭据 |
| `VITE_LLM_MODEL` | 显式选择开发模型 ID |
| `VITE_SENTRY_DSN` | 提供公开的诊断接收 DSN |

已保存模型配置优先。手动配置的提供商使用自己的凭据，不继承其他提供商的环境变量密钥。模型来自已保存配置或明确设置的环境变量 ID；启动模型辅助任务前填写地址、密钥和模型。

Vite 会将 `VITE_*` 值写入前端构建。运行凭据保存在本机设置，不进入版本管理文件和分发构建。提供 Sentry DSN 不会自动开启采集，诊断开关默认关闭。

相关契约见[工作区存储](WORKSPACES.zh-CN.md)、[Agent 执行](AGENT_SYSTEM.zh-CN.md)、[错误码](ERROR_CODES.zh-CN.md)、[代理路由](NETWORK.zh-CN.md)与[诊断](DIAGNOSTICS.zh-CN.md)。

## 发布

发布版本须同步 `package.json`、`src-tauri/Cargo.toml`、`src-tauri/Cargo.lock` 与 `src-tauri/tauri.conf.json`。本地可执行文件使用 `pnpm tauri build --no-bundle`。签名安装包与更新版本先暂存已提交的运行时源码，再执行 `pnpm tauri build --bundles nsis --config src-tauri/tauri.release.conf.json`。

打包与发布遵循 [RELEASING.md](../RELEASING.md)，更新渠道与安装行为见[更新说明](UPDATES.zh-CN.md)。修改源码版本号不会自动发布安装包。
