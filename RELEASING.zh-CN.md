# 桌面发布

[English](RELEASING.md)

`v2.0.0-beta2` 仅打包桌面运行时，知识包与 MCP 服务作为扩展独立分发。此前的 `v2.0.0-beta.1` 标签保持不变。

Python 3.11+、WebView2 与外部分析工具另行安装，详见[桌面端说明](site/desktop.md)。

## 准备发布提交

1. 将 `desktop/package.json`、`desktop/src-tauri/Cargo.toml`、对应 lockfile 与 `desktop/src-tauri/tauri.conf.json` 统一为本次新的发布版本。
2. 在[更新日志](CHANGELOG.zh-CN.md)和英文版记录实际功能与完成的检查，用户验收和未执行评测与回归结果分别描述。
3. 遵循[更新签名契约](desktop/UPDATES.zh-CN.md)，私钥只保存在发布机器或 CI secret。
4. 提交前运行 `python scripts/misc/public_release_check.py`，私人目标、凭据、报告和本机截图不进入发布。公开提交使用 GitHub noreply 作者邮箱。

相关开发检查见[桌面开发指南](desktop/DEV_GUIDE.zh-CN.md)。未变化的输入复用已有检查，记录本次实际完成的检查。

## 暂存与构建

从已提交的发布源码在干净 checkout 中构建，安装 frozen-lockfile 依赖。打包器会拒绝工作树中已跟踪或未跟踪的改动。根 README 与官网下载入口可以独立准备，在 Release 公开后发布。

在仓库根目录执行：

```sh
python scripts/misc/package_desktop_release.py stage
```

暂存从 `git archive HEAD` 中按 `RUNTIME_FILES` 明确清单选取文件，填充 `desktop/src-tauri/release-resources/`，并写入含版本和 commit 的 `RELEASE.json`。知识文章、MCP 服务源码、示例与工作区数据不进入桌面包。生成目录已忽略，安装后映射为 `runtime/` 资源树。

构建进程的 `TAURI_SIGNING_PRIVATE_KEY` 指向本机私钥文件，`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` 提供对应密码，不回显这些值。在 `desktop/` 执行：

```sh
pnpm install --frozen-lockfile
pnpm tauri build --config src-tauri/tauri.release.conf.json --bundles nsis
```

NSIS 安装包与 `.sig` 位于 `desktop/src-tauri/target/release/bundle/nsis/`。回到仓库根目录执行：

```sh
python scripts/misc/package_desktop_release.py package --installer <NSIS-EXE> --notes <release-notes.md>
```

打包器核对暂存 commit 与版本、源码和构建先后、安装包内的 `RELEASE.json` 及签名版本元数据。读取安装包资源需要 7-Zip。

## 发布资产

`dist/release/` 输出：

| 资产 | 用途 |
| --- | --- |
| `OpenReverseLab-v<VERSION>-windows-x64-setup.exe` | Windows 安装包 |
| `OpenReverseLab-v<VERSION>-windows-x64-setup.exe.sig` | 完整更新签名 |
| `OpenReverseLab-v<VERSION>-windows-x64.zip` | 便携包 |
| `latest.json` | 版本、说明、时间、平台地址与签名 |
| `SHA256SUMS` | 发布资产的哈希 |

便携 ZIP 解压为 `OpenReverseLab-<VERSION>/`，入口为 `OpenReverseLab.exe`。需要完整解压，资源与脚本保留打包时相对可执行文件的位置。

## 发布与更新渠道

将 `v<VERSION>` 标签指向暂存和构建使用的同一提交。先创建草稿 GitHub Release，通过 `--notes-file` 提供说明并上传完整资产；确认清单版本、平台、安装包地址、签名及校验值对应这些资产。`v2.0.0-beta2` 取消 GitHub 预发布标记并设为 Latest，使仓库侧栏展示当前桌面下载；版本和标题仍保留 beta 测试版标识，桌面的稳定版渠道仍按 SemVer 排除该测试版。

桌面通过公开 GitHub Releases API 查找发布：

- **稳定版**选择公开正式发布，排除 GitHub 预发布和带 SemVer 预发布标识的版本。
- **测试版**选择公开测试版与正式版。beta 构建初始选择测试版渠道，正式构建初始选择稳定版，用户的手动选择会保留。
- 两个渠道只选择更高的 SemVer 版本，并读取所选 Release 附带的 `latest.json`。草稿和单独的标签不提供可安装更新。

当前渠道不依赖单一固定的 `releases/latest/download/latest.json` 地址。使用旧入口的客户端跟随 GitHub 的 Latest 选择，包括本次 beta。

Release 和资产公开后，再发布根 README 与官网对应下载入口。发布官网本身不会发布安装包；已发布标签及安装包／签名组合保持不变。

## 单独发布知识包

官方内容在 [open-reverselab-knowledge](https://github.com/LING71671/open-reverselab-knowledge) 独立维护，版本由该仓库的 `reverselab.extension.json` 声明。在知识库的干净克隆中校验、构建 ZIP：

```sh
python scripts/build.py --version <CONTENT-VERSION> --output ../knowledge.kbpack.zip
python scripts/extension_protocol.py check ../knowledge.kbpack.zip
```

知识修改提交到独立仓库。更新应用引用的内容时，同步更新 `kb` 子模块提交和 `reverselab.registry.json` 中的仓库链接、版本；官网构建该固定提交的内容。应用可通过主仓库目录或知识库仓库链接导入，无需发布桌面版本。若发布 ZIP，将其作为独立知识包资产上传，目录的 artifact 条目填写对应 SHA256。MCP 描述包沿用扩展协议并单独管理版本；两种包均不携带本机连接凭据。

## 安装与平台范围

安装版核对更新签名与签名绑定版本，等待运行／排队 Goal 和工作区写入完成后安装。便携版和源码构建通过发布页或重新构建升级，详见[应用更新](desktop/UPDATES.zh-CN.md)。

更新签名与 Windows Authenticode 代码签名分别处理。应备份更新私钥，已有客户端无法自动信任新密钥的签名。本次 Windows 发布不包含 macOS/Linux 桌面二进制，不上传占位包或空平台项。
