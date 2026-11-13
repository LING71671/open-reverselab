# 应用更新

[English](UPDATES.md)

设置 → 应用更新显示当前版本、更新渠道、版本说明和下载进度。启动 20 秒后检查所选渠道，后续最多每天检查一次；可关闭自动检查。手动检查可在桌面端使用，跳过某个版本只隐藏该版本的提醒。后台检查不会下载、安装或停止 Goal。

## 更新渠道

- **稳定版**仅接受公开正式 Release，排除 GitHub 标记的预发布和版本号中的预发布标识。
- **测试版**接受公开测试版与正式版。预发布构建（如 `2.0.0-beta.1`）首次启动默认选此渠道；正式构建默认选稳定版。手动选择会保留。
- 两个渠道都按 SemVer 比较版本，仅升级到更高版本。测试版可以升级到同一版本的正式版；切换到稳定版不会安装旧版本。

检查通过不带账户凭据的 GitHub Releases API 查找已上传的 `latest.json`，草稿 Release 不参与选择。清单和安装包地址来自同一条实际发布记录。没有可用清单时显示“当前渠道尚未发布可安装更新”，不生成版本链接；网络故障仍显示错误。有效清单版本不比当前构建高时显示“当前渠道没有更新的版本”。

切换渠道会清除已选版本、跳过状态、检查时间与当前下载就绪状态，需重新检查和下载。检查、下载或安装进行中不能切换渠道。更新请求使用系统网络/代理，与模型和目标访问代理池分开。

## 安装流程

Windows x64 安装版使用 Tauri 官方 updater：

1. 从所选渠道的实际 Release 资产读取 `latest.json`，核对清单版本与发布标签，以及安装包是否属于同一 Release。
2. 用户点击下载后获取 NSIS 安装包，显示实际接收字节数；服务未提供总长度时显示已下载大小。
3. Tauri 使用应用内置的公开密钥验证 Minisign 签名，同时验证签名绑定的版本。验证失败的包不能进入安装状态。
4. 用户点击“安装并重新打开”后，检查所有已打开工作区的运行和排队 Goal，等待工作区保存完成，再检查一次任务状态。
5. 原生侧确认没有 Python 执行，锁住新执行并启动安装程序。安装器关闭当前应用、替换程序与随包资源，然后重新打开应用。

更新不会自动停止任务。可以在任务运行时下载，安装按钮须等待所有任务结束。默认工作区、模型设置和更新偏好位于程序目录外，升级保留这些数据。不要把自定义工作区放在安装程序管理的 `runtime/` 目录内。

便携版和源码构建可以检查版本、阅读版本说明；升级通过发布页下载新包完成。只有通过 NSIS 安装、包含 `runtime/kb/`、`runtime/scripts/` 和 `uninstall.exe` 的 Windows x64 版本开放应用内安装。浏览器开发预览会明确显示不支持安装。

## 模块职责

| 模块 | 职责 |
| --- | --- |
| `src/services/updates/updateController.ts` | 与平台无关的状态机、检查频率、跳过版本、用户操作与安装前保存 |
| `src/services/updates/updateService.ts` | Tauri IPC 适配器与跨工作区任务保护 |
| `src/views/settings/UpdatesPane.tsx` | 更新操作、状态、进度和错误详情 |
| `src-tauri/src/updates.rs` | HTTPS 更新请求、包来源限制、下载和签名验证、安装锁 |
| `src/services/goals/workspaceRuntime.ts` | 所有加载中和已打开工作区的保存及运行状态 |

状态依次为 `idle → checking → available → downloading → ready → installing`；没有更高版本时为 `current`，渠道未发布安装更新时为 `unpublished`。检查失败进入 `error`；下载失败回到 `available`，工作区保存失败保持 `ready`。安装器启动或其临时文件写入失败后需重新下载。关闭设置不会取消下载，也不会丢失下载状态。下载包暂存在应用进程内存，退出后需重新下载。不做增量更新。

更新诊断独立于单个 Goal 的健康事件，显示在“应用更新”的错误详情中；当前错误也会显示在健康监控页。它不把网络失败伪装为“已是最新版本”。应用使用单实例运行，第二次启动会聚焦已有窗口。

| 错误码 | 含义与恢复 |
| --- | --- |
| `UPDATE_NETWORK` | 更新服务或网络不可达；检查网络后重试 |
| `UPDATE_MANIFEST` | 发布信息无效、平台缺失或下载地址不属于官方仓库；维护者修复发布资产后重试 |
| `UPDATE_SIGNATURE` | 包签名、签名版本或公开密钥不匹配；重新检查并下载正确资产 |
| `UPDATE_DOWNLOAD` | 下载失败；重新下载 |
| `UPDATE_INSTALL` | 安装器未能启动；重新下载或手动运行官方安装包 |
| `UPDATE_STORAGE` | 工作区保存或本地临时文件操作失败；检查目录权限和可用空间 |
| `UPDATE_TASKS_ACTIVE` | 仍有运行或排队任务；等待所有工作区任务结束 |
| `UPDATE_BUSY` | 另一个更新操作正在执行；等待当前操作结束 |
| `UPDATE_UNSUPPORTED` | 当前运行方式不能应用内安装；使用发布页安装包 |
| `UPDATE_NOT_READY` | 尚未下载并验证包；先下载 |

## 发布合同

`package.json`、Cargo 包及 lockfile、`tauri.conf.json` 的版本必须一致。Windows 发布同时提供安装包、安装包 `.sig`、`latest.json` 和 SHA256 校验值；可继续附带便携 ZIP。

安装包包含 `src-tauri/release-resources/`，映射到安装目录的 `runtime/`。该暂存目录已忽略，不得提交。应从最终发布 commit 的 `git archive` 构建允许公开的资源，至少包含完整 `kb/` 与 `scripts/` 及它们引用的根配置、板块文档和工具索引；不直接递归打包开发工作区。外部逆向工具、Python 和私人数据不在资源包内。

签名私钥只保存在维护者本机或 CI secret，公开密钥写入 `plugins.updater.pubkey`。构建进程的 `TAURI_SIGNING_PRIVATE_KEY` 环境变量指向本机私钥文件，`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` 提供私钥密码；无密码时为空。随后运行：

```powershell
pnpm tauri build --bundles nsis --config src-tauri/tauri.release.conf.json
```

Tauri CLI 2.12+ 的 `build` 会把应用版本绑定到签名。手动签名必须传 `--app-version <version>`，本应用启用了 `requireSignedVersion`。应备份私钥；丢失私钥后，已安装版本无法验证新密钥签发的更新。更新签名与 Windows Authenticode 代码签名是两套机制。

`latest.json` 示例中的 `signature` 必须替换为本次 `.sig` 文件的完整内容：

```json
{
  "version": "2.0.0",
  "notes": "本次发布的版本说明",
  "pub_date": "2026-11-13T00:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "url": "https://github.com/LING71671/open-reverselab/releases/download/v2.0.0/ReverseLab-v2.0.0-windows-x64-setup.exe",
      "signature": "<本次安装包的签名内容>"
    }
  }
}
```

先完整上传并核对这些资产，再发布 Release。正式版本使用正式标签并标为稳定发布；测试版本使用如 `v2.0.0-beta.1` 的标签并勾选预发布。两个渠道均使用各自 Release 下的 `latest.json`；既有稳定版客户端的 `releases/latest/download/latest.json` 入口仍依赖 GitHub 最新正式发布。草稿或仅推送标签不会向用户提供更新。不要只改 JSON 的版本号并复用旧包或旧签名。

## 验证

```sh
pnpm build
node --experimental-strip-types --test tests/updateController.test.ts
cargo test --manifest-path src-tauri/Cargo.toml --lib updates::tests
```

状态机和原生选择测试覆盖渠道迁移、草稿过滤、版本比较、缺失发布、下载失败与签名失败、并发点击、任务保护、保存失败和安装前二次检查。测试使用合成发布信息和模拟适配器。

实际公开元数据读取可单独运行：

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib updates::tests::public_release_discovery -- --ignored --nocapture
```

该检查只访问公开 API，不下载或安装程序。完整升级验收仍需在隔离的 Windows 安装目录验证实际签名安装包及下一版本升级。首个支持 updater 的版本无法通过旧版本中不存在的更新模块升级。

实现依据：[Tauri updater](https://v2.tauri.app/plugin/updater/)。
