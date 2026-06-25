# Android Board

Android APK/DEX 逆向分析板块。

## 工具链

- `tools/android/apktool/` — APK 解包/重打包
- `tools/android/jadx/` — DEX 反编译
- `tools/android/uber-apk-signer/` — APK 签名
- `tools/android/mobile/` — Frida 移动端工具

## MCP 工具

Android APK 分析有一整套 MCP 自动化工具链，涵盖 ADB 连接、包管理、基线收集、Frida 动态插桩、运行时观察（HTTP/WebView/crypto unpack）、文件系统取证和后处理。详见 [AI-USAGE.md](AI-USAGE.md)。

## 知识库

APK 逆向知识库 `kb/apk-reverse/`：17 篇 Frida 可运行技术文件，8 个分类覆盖 DEX/Java、Native、Manifest、Crypto、Network、Dynamic、Packer、Patch/Repack。

## 分析流程

1. 样本放入 `samples/android/`
2. 解包 → `exports/android/` 或 `projects/android/`
3. 静态分析 (jadx) → 笔记写入 `notes/android/`
4. 动态分析 (Frida) → 脚本放入 `scripts/android/`
5. Patch/重打包 → 产物放入 `patches/android/`
6. 最终报告 → `reports/android/`

## 参考

- 笔记模板：`templates/notes/android-apk-analysis.md`
- AI 操作指南：[AI-USAGE.md](AI-USAGE.md)
