# Desktop 发布

v2.0.0 同时发布项目源码、Windows x64 安装包和便携 ZIP。安装包支持签名更新；便携 ZIP 供完整解压使用。Python、WebView2 和外部逆向工具的依赖见 [桌面安装说明](site/desktop.md)。

## 发布前

1. 同步 desktop/package.json、Cargo.toml、Cargo.lock、tauri.conf.json 版本，以及 README、官网与 CHANGELOG。
2. 检查 desktop/UPDATES.md 的密钥与更新协议。私钥只放在发布机器的用户目录，不能提交或上传。
3. 运行下列检查，并复核本次 diff。截图只能包含合成样本和公开文档。

```sh
python scripts/misc/public_release_check.py
python scripts/misc/lab_healthcheck.py
python scripts/misc/kb_doc_audit.py
python scripts/misc/add_frontmatter.py --verify
python scripts/misc/seo_audit.py
python -m pytest
pnpm --dir desktop build
pnpm --dir site build
```

在 desktop/ 中运行 Node 测试，命令见 [desktop/README.md](desktop/README.md)。Windows 运行 scripts/ctf-website/smoke_cve_pipeline.ps1。公开提交使用 GitHub noreply 地址。

## 构建与校验

先提交已复核的源码，再从该提交 fresh clone，安装 frozen lockfile 依赖并重复核心检查。构建前从 Git 归档生成 runtime/，避免夹带本机缓存与私人数据：

```sh
python scripts/misc/package_desktop_release.py stage
```

在构建进程设置 TAURI_SIGNING_PRIVATE_KEY 为本机私钥文件路径，按密钥配置 TAURI_SIGNING_PRIVATE_KEY_PASSWORD。不要回显环境变量。然后在 desktop/ 运行：

```sh
pnpm tauri build --config src-tauri/tauri.release.conf.json --bundles nsis
```

生成的 NSIS EXE 与 .sig 位于 desktop/src-tauri/target/release/bundle/nsis/。安装资源来自 src-tauri/release-resources/，该目录不入库。在仓库根执行：

```sh
python scripts/misc/package_desktop_release.py package --installer <NSIS-EXE> --notes <release-notes.md>
```

dist/release/ 输出统一命名的安装包、签名、便携 ZIP、latest.json 与 SHA256SUMS。打包器要求工作树干净、暂存 runtime 与 HEAD/版本一致，并拒绝早于 runtime 的构建。发布前在临时目录解压便携 ZIP，检查 kb/scripts 与桌面启动。

## 发布

推送已验证提交，等待 CI。创建与提交一致的 vX.Y.Z 标签，再使用 gh release create，正文用 --notes-file 传入；上传 dist/release/ 的本版产物。检查 Release 附件、SHA256、latest.json 的版本/平台/下载地址，以及 GitHub Pages 部署。

latest.json 使用 releases/latest/download/latest.json 为安装版提供更新。不得移动已发布标签或用不匹配的签名替换附件。签名私钥需要由维护者备份；丢失后旧客户端不能自动信任新密钥。

## 平台范围

Windows 更新签名用于校验包与发布密钥的一致性，不等同于 Windows Authenticode 代码签名。macOS / Linux 桌面二进制尚未经过本项目发布验证，不上传占位产物或空平台配置。
