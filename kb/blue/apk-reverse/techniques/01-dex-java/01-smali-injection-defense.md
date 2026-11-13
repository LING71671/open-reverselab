---
id: "apk-reverse/01-dex-java/01-smali-injection-defense"
title: "Smali 代码注入与 DEX 篡改防御"
title_en: "Smali Code Injection and DEX Tampering Defense"
summary: >
  针对 apktool 解包、Application/Activity/clinit 注入 System.loadLibrary 及新增 Smali 类的篡改手法，提供 R8/ProGuard 全量混淆、Native 层 classes.dex CRC32/SHA-256 校验、ClassLoader 与动态库加载白名单核查以及 CI 产物基线比对方案。
summary_en: >
  Defense-in-depth against apktool unpacking, System.loadLibrary injection into Application/Activity/clinit, and rogue Smali class insertion. Covers R8/ProGuard full-mode hardening, native classes.dex CRC32/SHA-256 verification, ClassLoader and shared library allowlist checks, and CI artifact baseline verification.
board: "apk-reverse"
category: "01-dex-java"
signals:
  - "smali injection"
  - "DEX 篡改防护"
  - "classes.dex CRC32"
  - "R8 fullMode"
  - "Application.attachBaseContext"
  - "dl_iterate_phdr"
  - "ClassLoader 完整性"
mcp_tools:
  - "android_app_baseline"
  - "android_package_info"
  - "ghidra_headless_analyze"
  - "hash_file"
  - "kb_router"
keywords:
  - "Smali注入防御"
  - "DEX完整性校验"
  - "R8混淆"
  - "loadLibrary白名单"
  - "抗重打包"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "dex-integrity"
  - "r8"
  - "anti-repack"
  - "android"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/01-dex-java/01-smali-injection"
  - "apk-reverse/08-patch-repack/01-so-injection-repack-defense"
  - "apk-reverse/08-patch-repack/02-signature-integrity-bypass-defense"
track: "blue"
defends: "apk-reverse/01-dex-java/01-smali-injection"
---
# Smali 代码注入与 DEX 篡改防御

## 防御目标与威胁面

Smali 注入的常见落点高度集中于三个早期执行点：`Application.attachBaseContext`、`MainActivity.onCreate` 以及高频加载类的 `static <clinit>` 块，常配合新增独立包名下的辅助类（如 `com.inject.InjectHelper`）调用 `System.loadLibrary` 拉起恶意 `.so`。若应用仅依赖 Java 层布尔校验或未对 DEX 与加载库做完整性验证，攻击者只需修改几行指令并重新签名即可持久化控制执行流。

核心防御原则是将**编译期混淆加固**、**Native 层 DEX 字节完整性校验**与**运行时类/SO 白名单检测**联动，并由服务端对高风险会话校验 Play Integrity 令牌。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| `jadx` 快速定位入口类与关键方法 | 启用 R8 `fullMode` + 字符串加密 + 控制流平坦化 | 移除调试行号/局部变量表（除混淆映射外），避免暴露语义化类名 |
| 修改 `attachBaseContext` / `onCreate` / `<clinit>` | Native `JNI_OnLoad` 与 `.init_array` 读取 `base.apk` 计算 `classes*.dex` CRC32/SHA-256 | 校验逻辑下沉至无导出符号的 C++ 内联函数，预期哈希通过构建脚本拆分混淆写入 |
| 新增 Smali 类并注入 `loadLibrary` | 运行时核对 `BaseDexClassLoader` DexPathList 数量与 `dl_iterate_phdr` 已加载 SO 白名单 | 禁止 `/data/local/tmp` 或未知命名 SO 出现在进程内存映射中 |
| 重打包后替换签名证书 | APK Signature Scheme v2/v3 + Native 校验 SigningInfo 公钥摘要 | 结合服务端 Play Integrity API 判定 `APP_RECOGNIZED_VERSION` |

## 加固代码与离线基线校验示例

### 1. R8 / ProGuard 构建加固（Gradle 与规则片段）

```text
# gradle.properties
android.enableR8.fullMode=true

# proguard-rules.pro
-optimizationpasses 5
-overloadaggressively
-repackageclasses 'o'
-allowaccessmodification
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
```

### 2. Native 层校验 `base.apk` 内 DEX CRC32 与未授权 SO

```cpp
// dex_guard.cpp — 在 Native 侧核验进程加载的 SO 白名单与 DEX CRC
#include <link.h>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

static bool is_allowed_so(const char* name) {
    if (!name || name[0] == '\0') return true;
    if (strstr(name, "/system/") || strstr(name, "/apex/") || strstr(name, "/vendor/")) {
        return true;
    }
    static const char* kAllowlist[] = {"libappcore.so", "libc++_shared.so"};
    for (const char* allowed : kAllowlist) {
        if (strstr(name, allowed) != nullptr) return true;
    }
    return false;
}

static int phdr_cb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* rogue = static_cast<std::vector<std::string>*>(data);
    if (info->dlpi_name && !is_allowed_so(info->dlpi_name)) {
        rogue->emplace_back(info->dlpi_name);
    }
    return 0;
}

extern "C" int check_runtime_modules_clean() {
    std::vector<std::string> rogue_libs;
    dl_iterate_phdr(phdr_cb, &rogue_libs);
    return rogue_libs.empty() ? 0 : -1;
}
```

### 3. Python 发布产物 DEX/SO 基线比对脚本

```python
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Dict


def snapshot_apk_dex_and_libs(apk_bytes: bytes) -> Dict[str, dict]:
    """提取 APK 内所有 classes*.dex 与 lib/*.so 的 CRC32 和 SHA-256。"""
    import io

    report: Dict[str, dict] = {"dex": {}, "so": {}}
    with zipfile.ZipFile(io.BytesIO(apk_bytes), "r") as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                raw = zf.read(info.filename)
                report["dex"][info.filename] = {
                    "crc32": info.CRC,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            elif info.filename.startswith("lib/") and info.filename.endswith(".so"):
                raw = zf.read(info.filename)
                report["so"][info.filename] = {
                    "crc32": info.CRC,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
    return report


def verify_against_baseline(candidate_apk: bytes, baseline: Dict[str, dict]) -> list[str]:
    current = snapshot_apk_dex_and_libs(candidate_apk)
    anomalies: list[str] = []
    if current["dex"] != baseline["dex"]:
        anomalies.append("dex_modified_or_added")
    extra_so = set(current["so"].keys()) - set(baseline["so"].keys())
    if extra_so:
        anomalies.append(f"unexpected_so:{sorted(extra_so)}")
    for so_name, meta in baseline["so"].items():
        if current["so"].get(so_name) != meta:
            anomalies.append(f"so_tampered:{so_name}")
    return anomalies


if __name__ == "__main__":
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"A" * 32)
        zf.writestr("lib/arm64-v8a/libappcore.so", b"\x7fELF" + b"\x00" * 16)
    base_bytes = buf.getvalue()
    baseline = snapshot_apk_dex_and_libs(base_bytes)
    assert verify_against_baseline(base_bytes, baseline) == []

    tampered = io.BytesIO()
    with zipfile.ZipFile(tampered, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"B" * 32)
        zf.writestr("lib/arm64-v8a/libappcore.so", b"\x7fELF" + b"\x00" * 16)
        zf.writestr("lib/arm64-v8a/libinject.so", b"\x7fELF")
    res = verify_against_baseline(tampered.getvalue(), baseline)
    assert "dex_modified_or_added" in res
    assert any(item.startswith("unexpected_so:") for item in res)
    print(json.dumps({"status": "ok", "detected": res}))
```

## 防御工作流

```text
1. 编译加固：在 release 构建开启 R8 fullMode，压缩并重命名包结构，剥离日志与调试信息
2. 基线生成：CI 构建签名 APK 后提取 classes*.dex 与 lib/*.so 的 CRC32/SHA-256 存入制品清单
3. 原生校验：将预期 DEX 摘要拆分编码至 Native 层，在 JNI_OnLoad 与核心业务前多点复核
4. 加载监控：通过 dl_iterate_phdr 拦截未在白名单中的 .so，结合签名公钥校验阻断重打包产物
5. 远端判定：关键登录与交易接口要求携带 Play Integrity 凭证，发现非官方包摘要直接拒绝服务
```

## 验证与判定标准

- **静态产物核查**：对照 Release 构建基线运行 `snapshot_apk_dex_and_libs`，`classes*.dex` 数量与哈希、`lib/*/*.so` 列表必须 100% 一致。
- **Smali 注入阻断测试**：向实验副本的 `Application.attachBaseContext` 插入额外类加载或修改单条指令并重签名后，客户端应在进入主业务前触发完整性失败并退出或上报风控。
- **SO 白名单测试**：将未授权的实验用 `.so` 加入 `lib/` 目录并通过 `<clinit>` 加载时，`check_runtime_modules_clean()` 必须返回非零并阻断关键会话。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 采集基线与加载进程信息 | `android_app_baseline` | 收集包信息、启动 Activity 与进程加载状态 |
| 读取包与签名元数据 | `android_package_info` | 核对目标 APK 的包名、版本与签名摘要 |
| 计算制品与 DEX 哈希 | `hash_file` | 生成构建产物与参考文件 SHA-256 基线 |
| 检查 Native 校验逻辑 | `ghidra_headless_analyze` | 确认校验函数未被暴露明文符号或单点分支 |
| 关联红蓝对抗文档 | `kb_router` / `kb_read_file` | 对照 [01-smali-injection.md](../../../../red/apk-reverse/techniques/01-dex-java/01-smali-injection.md) 检查注入面覆盖 |
