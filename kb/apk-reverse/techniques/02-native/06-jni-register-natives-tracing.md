---
id: "apk-reverse/02-native/06-jni-register-natives-tracing"
title: "JNI RegisterNatives 追踪与 Native 入口还原"
title_en: "JNI RegisterNatives Tracing and Native Entry Recovery"
summary: >
  从 Java native 方法、JNI_OnLoad、RegisterNatives 和导出符号还原 APK native 调用链，快速定位加密、校验、协议封包和完整性检查入口。
summary_en: >
  Recover APK native call chains from Java native methods, JNI_OnLoad, RegisterNatives, and exported symbols to locate crypto, verification, packet, and integrity-check entry points.
board: "apk-reverse"
category: "02-native"
signals:
  - "JNI_OnLoad"
  - "RegisterNatives"
  - "native method"
  - "Java_com_"
  - "UnsatisfiedLinkError"
  - "System.loadLibrary"
mcp_tools:
  - "android_crypto_unpack_recipe"
  - "ghidra_headless_analyze"
  - "android_frida_run_script"
  - "kb_router"
keywords:
  - "JNI"
  - "RegisterNatives"
  - "JNI_OnLoad"
  - "native entry"
  - "Ghidra"
  - "Frida"
difficulty: "intermediate"
tags:
  - "apk"
  - "native"
  - "jni"
  - "frida"
  - "ghidra"
language: "zh-CN"
last_updated: "2026-07-31"
related_articles:
  - "apk-reverse/02-native/01-il2cpp-offset-discovery"
  - "apk-reverse/04-crypto/01-game-encryption-patterns"
---
# JNI RegisterNatives 追踪与 Native 入口还原

## 1. 入口信号

```text
jadx: native byte[] encrypt(byte[] in)
jadx: System.loadLibrary("guard")
logcat: UnsatisfiedLinkError / JNI DETECTED ERROR
readelf: JNI_OnLoad exported
strings: Java_com_vendor_app_Sign_sign
Ghidra: RegisterNatives xref 指向函数表
```

目标是把 “Java native 方法名” 映射到 “SO 内真实函数地址”，再沿调用者/被调用者走到 crypto、license、packet 或 anti-tamper 节点。

## 2. 静态定位

```powershell
jadx -d exports/android/app-jadx samples/app.apk
rg -n "native |loadLibrary|System\\.load|JNI" exports/android/app-jadx
apktool d samples/app.apk -o exports/android/app-apktool
llvm-readelf -Ws exports/android/app-apktool/lib/arm64-v8a/*.so | rg "JNI_OnLoad|Java_"
strings exports/android/app-apktool/lib/arm64-v8a/*.so | rg -i "RegisterNatives|encrypt|sign|verify|packet|token"
```

如果导出表只有 `JNI_OnLoad`，说明很可能使用动态注册；下一步 hook `RegisterNatives`。

## 3. MCP 模板：加载器与 RegisterNatives 证据

优先使用 MCP 模板，而不是复制临时脚本。先检查可用模板：

```text
android_frida_template_library
android_frida_render_template(template_id="native_module_load_hook", substitutions_json='{"library_name":"libguard.so"}')
android_frida_render_template(template_id="native_register_natives")
```

`native_module_load_hook` 先检查目标 SO 是否已加载；未加载时仅观察 `android_dlopen_ext` / `dlopen`，在加载返回后记录路径、模块基址和大小。它不会 hook `.init_array`、构造函数或修改目标行为。

`native_register_natives` 对每次注册最多解析 64 项，输出 declaring Java class、方法名、JNI 签名、native 运行时地址、模块路径、模块基址、架构和 RVA；每一项的字符串/指针读取失败会单独标为 unresolved，字符串读取上限为 256 bytes，不会中止整次观察。

```text
# 对已运行的受控 app：将两个已渲染模板合并后交给 android_frida_run_script，
# 但 attach 只能观察 attach 之后的新注册。
# 要捕获 JNI_OnLoad 的启动期注册：先 android_force_stop，再使用
# android_frida_run_script(target=<package>, mode="spawn")；该模式会先加载脚本、
# 再 resume 进程。仅在受控环境显式选择 spawn，避免静默改变 app 生命周期。
# crypto/unpack 场景：android_crypto_unpack_recipe 已包含 native_dlopen、
# native_memory_map 与 native_register_natives，适合先取得基础证据。
```

成功标志不是单一 `dlopen` 句柄，而是可审计的映射（Java class 必须包含在身份中，避免不同 class 的同名方法混淆）：

```text
Java class + method name + JNI signature
  -> module path + runtime base
  -> native runtime VA + derived RVA
```

## 4. Ghidra 静态关联与 ASLR/PIE 归一化

对动态观察到的实际 `.so` 做 Ghidra 分析，而不是只分析 APK 容器：

```text
1. ghidra_headless_analyze：导入观察到的 SO，生成 summary。
2. ghidra_summary_functions：查 JNI_OnLoad、RegisterNatives、Java_ 或观察到的方法名。
3. ghidra_summary_strings：查 JNI 签名、方法名、库标识。
4. ghidra_summary_function_detail：读取候选函数的 signature、callers/callees、imports、strings、decompile。
5. ghidra_summary_call_focus：以 JNI/native/crypto 等关键词排序后续函数。
```

运行时地址受 PIE/ASLR 影响，不能直接当作 Ghidra 静态地址。关联前先确认 runtime VA 位于记录模块的映射范围：

```text
module base <= runtime native VA < module base + module size
RVA = runtime native VA - runtime module base
Ghidra candidate = Ghidra image base + RVA
```

RVA 只可用于同一二进制：记录并核对 SO 的完整路径、架构、SHA256 或 build ID，再把该文件导入 Ghidra。模块路径相同不代表内容相同；hash/build ID、架构或地址范围不一致时，保留 unresolved，不要进行地址关联。

Ghidra 中按这个顺序建立候选命名：

```text
JNI_OnLoad
  -> candidate_register_native_methods
     -> candidate_native_sign
     -> candidate_native_encrypt_packet
```

对每个 native 函数记录：

```text
Java class / method name / JNI signature:
SO path / SHA256 or build ID / architecture:
Runtime module base / module size / runtime VA / derived RVA:
Ghidra function entry / current name / signature:
Callers, callees, imports, strings, decompile evidence:
Confidence / unresolved assumptions:
```

地址、模块或函数不能匹配时保留 unresolved 状态；不要把运行时 VA 与静态 Ghidra 地址直接等同，也不要把候选名称写成已确认符号。

## 5. 参数/返回值打点

```javascript
const target = ptr("0x7a12345678"); // RegisterNatives 输出的函数地址
Interceptor.attach(target, {
  onEnter(args) {
    console.log("[native] enter target");
    this.arg2 = args[2];
  },
  onLeave(ret) {
    console.log("[native] ret=" + ret);
  }
});
```

Java 层 byte[] 参数可以再 hook 调用者：

```javascript
Java.perform(function () {
  const C = Java.use("com.vendor.app.NativeBridge");
  C.sign.implementation = function (data) {
    console.log("[java] sign len=" + data.length);
    const out = this.sign(data);
    console.log("[java] sign ret len=" + out.length);
    return out;
  };
});
```

## 6. 分析流程与路径分叉

| 发现 | 下一跳 |
|---|---|
| `sign(String, byte[])` | 请求签名、重放、参数篡改 |
| `encrypt/decrypt` | `android_crypto_unpack_recipe` 捕获 key/input/output |
| `checkLicense` | 在线验证绕过或 patch |
| `checkSignature/checkRoot` | 完整性路径 |
| `pack/unpack` | 协议字段还原 |

## 7. Evidence

| 项 | 记录内容 |
|---|---|
| Java 入口 | 类名、方法名、JNI 签名 |
| Native 映射 | Java class、方法名、JNI 签名、SO path、架构、SHA256/build ID、module base/size、VA/RVA、RegisterNatives 输出 |
| 参数 | Java 入参长度、hex 摘要、返回值类型 |
| Ghidra | 函数名、调用者、被调用者、关键字符串 |
| 下一跳 | crypto、network、license、patch 或 packer |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| JNI/crypto 模板 | `android_crypto_unpack_recipe` | 生成 RegisterNatives 和 crypto hook |
| SO 静态分析 | `ghidra_headless_analyze` | 函数边界、xref、伪代码 |
| 动态执行 | `android_frida_run_script` | attach 观察后续注册；受控环境显式 `spawn` 捕获启动期注册 |
| 知识路由 | `kb_router` | 按 JNI/native/crypto 信号查文档 |

