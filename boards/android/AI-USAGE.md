# Android AI Usage

分析 Android 应用时的 AI 工作约定。

## 默认工具路径

- apktool: `tools/android/apktool/apktool.jar`
- jadx: `tools/android/jadx/`
- uber-apk-signer: `tools/android/uber-apk-signer/uber-apk-signer.jar`
- frida-server: 通过 MCP `android_frida_ensure_server` 部署
- frida-tools: 桌面端通过 `pip install frida-tools` 安装

## 分析流程

1. 先用 apktool 解包 APK
2. 用 jadx 打开 DEX 反编译
3. 关注 AndroidManifest.xml、入口 Activity、native 库
4. Frida 动态 hook 时脚本保存到 `scripts/android/`
5. 重打包产物放入 `patches/android/apk-builds/`

## MCP 工具链（AI 可自动调用）

分析 Android APK 时，优先用 MCP 工具自动完成设备连接、基线收集、动态插桩等步骤。

### 设备与连接

| MCP 工具 | 作用 |
|---|---|
| `android_mumu_instance_info` | 读取 MuMu 当前实例状态和 adb 可达性 |
| `android_adb_connect` | 连接 MuMu/Android ADB 端点 |
| `android_adb_devices` | 列出当前 adb devices |
| `android_device_info` | 读取设备 model/sdk/abi/fingerprint/root 状态 |

### 包管理

| MCP 工具 | 作用 |
|---|---|
| `android_list_packages` | 列出设备上安装的包名，可按 query 过滤 |
| `android_install_apk` | 安装 APK 到设备 |
| `android_uninstall_package` | 卸载包 |
| `android_start_package` | 启动 app |
| `android_force_stop` | 强制停止 app |
| `android_current_activity` | 读取当前前台 Activity |
| `android_package_paths` | 读取包对应的 base.apk / split APK 路径 |
| `android_package_info` | 导出 dumpsys package，分析权限、组件、安装状态 |

### 信息收集

| MCP 工具 | 作用 |
|---|---|
| `android_app_baseline` | **一键基线**：安装/启动 + Activity + APK 路径 + package info + logcat + Frida 进程列表 |
| `android_pull_artifact_recipe` | 按包名回拉 APK + 截图 + package info + logcat，写出 manifest |
| `android_pull_package_apk` | 从设备拉取 APK → `exports/android/packages/` |
| `android_capture_screenshot` | 抓取当前屏幕截图 |
| `android_logcat_dump` / `android_clear_logcat` | logcat 导出/清空 |
| `android_push_file` / `android_pull_file` | 文件推送到设备 / 从设备拉取 |

### 文件系统取证

| MCP 工具 | 作用 |
|---|---|
| `android_package_fs_recipe` | 列私有目录结构 + 回拉 shared_prefs/databases/files |
| `android_runtime_file_watch_recipe` | 运行前后快照对比，输出文件变化差异清单 |

### Frida 动态插桩

| MCP 工具 | 作用 |
|---|---|
| `android_frida_ensure_server` | 部署并启动 frida-server |
| `android_frida_status` | 检查 frida-server + 桌面端 Frida 连接状态 |
| `android_frida_processes` | 枚举设备进程 |
| `android_frida_template_library` | 列出可复用 Frida JS 模板 |
| `android_frida_render_template` | 渲染模板为可直接运行的 JS 源码 |
| `android_frida_run_script` | 对指定进程/包运行 Frida JS，收集 send() 消息 |

### 运行时观察

| MCP 工具 | 作用 |
|---|---|
| `android_http_observation_recipe` | HTTP/WebView/OkHttp 运行时观察（Frida + logcat） |
| `android_crypto_unpack_recipe` | **解密/去壳**：Frida 抓 Cipher/key/iv/hash/dex loader/dlopen/mmap/RegisterNatives |

### 后处理

| MCP 工具 | 作用 |
|---|---|
| `parse_android_crypto_unpack_result` | 解析 Frida JSON，提取 key/iv、crypto op、动态 dex、native loader 证据 |
| `solve_crypto_from_evidence` | 从 key/IV/input/output 自动尝试常见解密/hash/HMAC |
| `make_crypto_replay_scaffold` | 从 Frida crypto 证据生成 Python 复现脚本 |
| `postprocess_frida_crypto_result` | 一键 parse → solve → replay scaffold → buffer extract/carve |
| `extract_frida_buffers` | 从 Frida JSON data_hex 落盘二进制 buffer |
| `carve_payloads_from_dump` | 从 dump/decrypted buffer 自动 carve PE/DEX → `samples/unpacked/` |

### APK Patch

| MCP 工具 | 作用 |
|---|---|
| `patch_bytes` / `patch_pattern` | 按 offset/pattern 打补丁（自动复制到 patches 目录） |
| `copy_sample_to_patches` | 复制样本到 patches 并记 audit log |

### 知识库

APK 逆向知识库位于 `kb/apk-reverse/`，8 个分类 17 篇技术文件（每篇含可运行 Frida 代码）。详见 `kb/apk-reverse/README.md`。
