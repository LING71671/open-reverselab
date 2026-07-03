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
last_updated: "2026-07-03"
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

## 3. RegisterNatives Frida 打点

```javascript
function readJniString(ptrValue) {
  return ptrValue.isNull() ? "" : ptrValue.readCString();
}

const reg = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi")
  || Module.findExportByName("libart.so", "RegisterNatives");

Interceptor.attach(reg, {
  onEnter(args) {
    const env = args[0];
    const clazz = args[1];
    const methods = args[2];
    const count = args[3].toInt32();
    console.log("[jni] RegisterNatives count=" + count + " methods=" + methods);
    for (let i = 0; i < count; i++) {
      const item = methods.add(i * Process.pointerSize * 3);
      const name = readJniString(item.readPointer());
      const sig = readJniString(item.add(Process.pointerSize).readPointer());
      const fn = item.add(Process.pointerSize * 2).readPointer();
      const mod = Process.findModuleByAddress(fn);
      console.log("[jni] " + name + sig + " -> " + fn + " " + (mod ? mod.name : "unknown"));
    }
  }
});
```

成功标志：输出 `nativeName(signature) -> address module`，地址可直接丢给 Ghidra/x64dbg 风格的函数定位。

## 4. JNI_OnLoad 调用链

```powershell
# Ghidra headless 后搜索 JNI_OnLoad、RegisterNatives xref
python scripts/misc/ai_tool.py run ghidra_headless_analyze -- samples/app.apk --out exports/android/ghidra
```

Ghidra 中按这个顺序命名：

```text
JNI_OnLoad
  -> register_native_methods
     -> native_sign
     -> native_encrypt_packet
     -> native_check_license
```

对每个 native 函数记录：

```text
Java method:
JNI signature:
SO:
VA/RVA:
Inputs from Java:
Return to Java:
Next hop:
```

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

## 6. 路径分叉

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
| Native 映射 | SO、VA/RVA、RegisterNatives 输出 |
| 参数 | Java 入参长度、hex 摘要、返回值类型 |
| Ghidra | 函数名、调用者、被调用者、关键字符串 |
| 下一跳 | crypto、network、license、patch 或 packer |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| JNI/crypto 模板 | `android_crypto_unpack_recipe` | 生成 RegisterNatives 和 crypto hook |
| SO 静态分析 | `ghidra_headless_analyze` | 函数边界、xref、伪代码 |
| 动态执行 | `android_frida_run_script` | spawn 早期捕获注册表 |
| 知识路由 | `kb_router` | 按 JNI/native/crypto 信号查文档 |

