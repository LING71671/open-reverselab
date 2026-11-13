---
id: "apk-reverse/08-patch-repack/01-so-injection-repack-defense"
title: "Native SO 注入与 APK 重打包防御"
title_en: "Native SO Injection and APK Repacking Defense"
summary: >
  针对 apktool 解包向 lib/<abi>/ 置入 libinject.so、修改 Smali 加载入口、利用 constructor/JNI_OnLoad 执行以及 mprotect+RET 绕过单点校验的手法，提供 ELF .text 节区自校验、dl_iterate_phdr 动态库白名单、多点交织校验与产物 ABI/SO 清单比对方案。
summary_en: >
  Defense-in-depth against apktool SO injection into lib/<abi>/, smali loadLibrary hooks, constructor/JNI_OnLoad execution, and mprotect+RET single-check patching. Covers ELF .text section self-checksumming, dl_iterate_phdr library allowlisting, distributed inline integrity checks, and APK lib/ manifest verification.
board: "apk-reverse"
category: "08-patch-repack"
signals:
  - "SO injection 防护"
  - "dl_iterate_phdr 白名单"
  - "ELF .text 自校验"
  - "constructor 注入检测"
  - "抗重打包"
  - "extractNativeLibs"
mcp_tools:
  - "android_app_baseline"
  - "android_package_info"
  - "ghidra_headless_analyze"
  - "hash_file"
  - "kb_router"
keywords:
  - "SO注入防御"
  - "APK抗重打包"
  - "ELF完整性"
  - "dl_iterate_phdr"
  - "多点校验"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "so-injection"
  - "anti-repack"
  - "elf-integrity"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/08-patch-repack/01-so-injection-repack"
  - "apk-reverse/08-patch-repack/02-signature-integrity-bypass-defense"
  - "apk-reverse/01-dex-java/01-smali-injection-defense"
track: "blue"
defends: "apk-reverse/08-patch-repack/01-so-injection-repack"
---
# Native SO 注入与 APK 重打包防御

## 防御目标与威胁面

Native SO 注入配合 `apktool` 重打包的经典流程是：解包 APK → 将 `libinject.so` 放入对应 ABI 的 `lib/` 目录（必要时改写 `AndroidManifest.xml` 中 `extractNativeLibs="true"`）→ 在 `onCreate` 或 `<clinit>` 插入 `System.loadLibrary("inject")` → 利用 `__attribute__((constructor))` 早于 `JNI_OnLoad` 启动 Hook 或使用 `mprotect` 将单点校验函数入口改写为 `RET`（ARM64 `0xD65F03C0`）→ 重新签名安装。

仅在单一函数中校验签名极易被 `RET` 指令直接旁路。有效防御必须做到**已加载 SO 白名单核验**、**自身 ELF `.text` 节区内存完整性校验**以及**校验逻辑内联分散且绑定业务密钥派生**。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 向 `lib/<abi>/` 植入额外 `libinject.so` | 通过 `dl_iterate_phdr` 枚举进程全部已映射 ELF，校验路径与白名单 | 非系统目录（非 `/system/`、`/apex/`、`/vendor/`）仅允许已知构建期签名 SO |
| Patch 单一校验函数为 `RET` | 消除独立 `verify_integrity()` 导出函数，将哈希校验内联至多处核心算法与协议封包前 | 若校验未参与后续关键状态/密钥计算，攻击者仍可直接跳过分支 |
| 利用 `mprotect` 修改代码页权限并打补丁 | 运行时核对自身 `.text` 节区字节 CRC32/SHA-256 并检查 `/proc/self/maps` 代码段权限是否出现 `w` | 正常 `.text` 段权限固定为 `r-xp`，若被改为 `rwxp` 说明正在或曾被写入补丁 |
| 修改 `AndroidManifest.xml` 的 `extractNativeLibs` | 在校验清单中纳入 `AndroidManifest.xml` 编译后二进制哈希与 `lib/` 目录完整清单 | 发布签名统一使用 v2/v3 方案，服务端配合 Play Integrity 验证包完整度 |

## 加固代码与产物核验示例

### 1. Native 层检查自身代码段内存完整性（C++）

```cpp
// elf_text_guard.cpp — 验证自身代码段只读属性并计算内存代码窗口校验值
#include <cstdint>
#include <cstring>

static uint32_t fnv1a_32(const uint8_t* data, size_t len) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x01000193u;
    }
    return h;
}

extern "C" uint32_t compute_critical_code_digest(const void* fn_start, size_t byte_len) {
    // 将代码段摘要直接混入后续业务密钥派生，避免单独布尔判断被 RET 绕过
    return fnv1a_32(static_cast<const uint8_t*>(fn_start), byte_len);
}
```

### 2. Python 检查 APK `lib/` 目录多余 SO 与跨架构不一致

```python
import hashlib
import zipfile
from collections import defaultdict
from typing import Dict, List


def verify_apk_native_inventory(
    apk_bytes: bytes, expected_so_hashes: Dict[str, str]
) -> List[str]:
    """比对 APK 内所有 lib/<abi>/*.so 与发布基线，检出注入库、缺失库及哈希篡改。"""
    import io

    issues: List[str] = []
    seen: Dict[str, str] = {}
    abi_libs: Dict[str, set[str]] = defaultdict(set)

    with zipfile.ZipFile(io.BytesIO(apk_bytes), "r") as zf:
        for info in zf.infolist():
            if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                digest = hashlib.sha256(zf.read(info.filename)).hexdigest()
                seen[info.filename] = digest
                parts = info.filename.split("/")
                if len(parts) == 3:
                    abi_libs[parts[1]].add(parts[2])

    extra = sorted(set(seen.keys()) - set(expected_so_hashes.keys()))
    missing = sorted(set(expected_so_hashes.keys()) - set(seen.keys()))
    if extra:
        issues.append(f"injected_so:{extra}")
    if missing:
        issues.append(f"missing_so:{missing}")

    for path, expected_hash in expected_so_hashes.items():
        if path in seen and seen[path] != expected_hash:
            issues.append(f"tampered_so:{path}")

    if len(abi_libs) > 1:
        union_names = set.union(*abi_libs.values())
        for abi, libs in abi_libs.items():
            diff = union_names - libs
            if diff:
                issues.append(f"abi_mismatch:{abi}:{sorted(diff)}")
    return issues


if __name__ == "__main__":
    import io

    def build_apk(files: Dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for k, v in files.items():
                zf.writestr(k, v)
        return buf.getvalue()

    clean_files = {
        "lib/arm64-v8a/libcore.so": b"\x7fELF-arm64",
        "lib/armeabi-v7a/libcore.so": b"\x7fELF-armv7",
    }
    baseline = {k: hashlib.sha256(v).hexdigest() for k, v in clean_files.items()}
    assert verify_apk_native_inventory(build_apk(clean_files), baseline) == []

    injected_files = dict(clean_files)
    injected_files["lib/arm64-v8a/libinject.so"] = b"\x7fELF-rogue"
    res = verify_apk_native_inventory(build_apk(injected_files), baseline)
    assert any(r.startswith("injected_so:") for r in res)
    assert any(r.startswith("abi_mismatch:armeabi-v7a:") for r in res)
    print("SO inventory defense check passed:", res)
```

## 防御工作流

```text
1. 构建基线锁定：CI 输出签名 APK 时固化各 ABI 下 lib/*/*.so 的 SHA-256 清单与预期权限
2. 加载白名单校验：在核心 Native 模块早期通过 dl_iterate_phdr 拒绝未列入白名单的动态库
3. 代码段防 Patch 绑定：计算关键函数字节与 .text 节区摘要，并将其作为业务密钥派生输入之一
4. 内存权限监测：检查自身代码映射是否出现异常 rwxp 写权限变更（拦截 mprotect 现场修改）
5. 签名与远端核验：结合 APK v2/v3 签名校验与 Play Integrity 阻止重打包产物访问线上核心接口
```

## 验证与判定标准

- **注入库检出**：向实验包任意 `lib/<abi>/` 写入测试 `libinject.so` 后，`verify_apk_native_inventory` 与运行期 `dl_iterate_phdr` 均必须检出未授权库。
- **Patch 抗性**：若外部强行修改关键校验函数任一指令字节，`compute_critical_code_digest` 输出变化将导致后续密钥派生或校验失败，不得出现跳过单条分支即完全放行的情况。
- **跨 ABI 一致性**：多架构安装包中各 ABI 目录应保持预期 SO 集合一致，无单架构额外残留注入库。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 对比原始与产物哈希 | `hash_file` | 计算各 ABI SO 文件与 APK 的 SHA-256 基线 |
| 检查 Native 防护耦合度 | `ghidra_headless_analyze` | 核实不存在可被单一 `RET` 指令绕过的明文校验导出函数 |
| 读取包与环境基线 | `android_app_baseline` / `android_package_info` | 收集设备加载库状态与签名信息 |
| 检索关联红蓝文档 | `kb_router` | 对照 [01-so-injection-repack.md](../../../../red/apk-reverse/techniques/08-patch-repack/01-so-injection-repack.md) 核验覆盖范围 |
