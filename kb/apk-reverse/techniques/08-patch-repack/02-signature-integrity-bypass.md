---
id: "apk-reverse/08-patch-repack/02-signature-integrity-bypass"
title: "签名与完整性检查绕过"
title_en: "Signature and Integrity Check Bypass"
summary: >
  APK patch/repack 后启动失败、功能锁定或闪退时，定位签名证书、包体 hash、classes.dex hash、so hash、Installer 来源和 Play Integrity 相关检查的打点路径。
summary_en: >
  Field path for locating signature, package hash, classes.dex hash, so hash, installer source, and Play Integrity related checks when a patched/repacked APK crashes or locks features.
board: "apk-reverse"
category: "08-patch-repack"
signals:
  - "signature check"
  - "getPackageInfo"
  - "SigningInfo"
  - "MessageDigest"
  - "classes.dex hash"
  - "Play Integrity"
  - "installer package"
mcp_tools:
  - "android_crypto_unpack_recipe"
  - "android_frida_run_script"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "APK signature"
  - "integrity check"
  - "repack"
  - "patch"
  - "SigningInfo"
  - "MessageDigest"
difficulty: "intermediate"
tags:
  - "apk"
  - "patch"
  - "repack"
  - "integrity"
  - "frida"
language: "zh-CN"
last_updated: "2026-07-03"
related_articles:
  - "apk-reverse/08-patch-repack/01-so-injection-repack"
  - "apk-reverse/01-dex-java/01-smali-injection"
---
# 签名与完整性检查绕过

## 1. 入口信号

```text
repack 后安装成功但启动闪退
logcat: signature mismatch / integrity failed / invalid channel
jadx: getPackageInfo(..., GET_SIGNATURES|GET_SIGNING_CERTIFICATES)
jadx: MessageDigest.getInstance("SHA-256")
native: open/read classes.dex 或 lib*.so 后计算 hash
网络: 启动请求携带 sign_hash / cert_md5 / channel
```

先定位检查点，再选择 Java hook、smali patch、native patch 或签名参数重算。

## 2. 静态定位

```powershell
jadx -d exports/android/app-jadx samples/app.apk
rg -n "GET_SIGNATURES|GET_SIGNING_CERTIFICATES|SigningInfo|getInstallerPackageName|MessageDigest|SHA-256|MD5|integrity|signature" exports/android/app-jadx
apktool d samples/app.apk -o exports/android/app-apktool
rg -n "signature|digest|hash|classes.dex|base.apk|sourceDir" exports/android/app-apktool
strings exports/android/app-apktool/lib/arm64-v8a/*.so | rg -i "signature|sha256|md5|classes.dex|base.apk|integrity"
```

## 3. Java 层打点

```javascript
Java.perform(function () {
  const PM = Java.use("android.app.ApplicationPackageManager");
  PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
    const r = this.getPackageInfo(pkg, flags);
    if ((flags & 0x40) || (flags & 0x08000000)) {
      console.log("[sig] getPackageInfo pkg=" + pkg + " flags=0x" + flags.toString(16));
    }
    return r;
  };

  const MD = Java.use("java.security.MessageDigest");
  MD.getInstance.overload("java.lang.String").implementation = function (alg) {
    console.log("[digest] getInstance " + alg);
    return this.getInstance(alg);
  };
});
```

成功标志：能看到检查发生在哪个类/线程，结合堆栈定位调用者。

```javascript
function printStack(tag) {
  const Exception = Java.use("java.lang.Exception");
  const Log = Java.use("android.util.Log");
  console.log(tag + "\n" + Log.getStackTraceString(Exception.$new()));
}
```

## 4. Native 层文件 hash 打点

```javascript
["open", "openat", "read", "fopen"].forEach(function (name) {
  const p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      const path = name === "openat" ? args[1].readCString() : args[0].readCString();
      if (path && (path.indexOf("base.apk") >= 0 || path.indexOf("classes.dex") >= 0 || path.indexOf(".so") >= 0)) {
        console.log("[file] " + name + " " + path);
      }
    }
  });
});
```

如果后续进入 `SHA256_Update` / `MD5_Update`，继续 hook 输入长度和调用者地址：

```javascript
["SHA256_Update", "MD5_Update"].forEach(function (name) {
  const p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      console.log("[hash] " + name + " len=" + args[2] + " caller=" + this.returnAddress);
    }
  });
});
```

## 5. 路径分叉

| 检查类型 | 打点动作 | 下一跳 |
|---|---|---|
| APK 签名证书 | hook `getPackageInfo` / `SigningInfo` | 返回原证书摘要或 patch 比较分支 |
| `classes.dex` hash | hook `MessageDigest` / native hash | 重新计算白名单或 patch 结果 |
| SO hash | hook `open/read` + `SHA256_Update` | Ghidra 定位校验函数 |
| Installer 来源 | hook `getInstallerPackageName` | 返回期望 installer |
| Play Integrity | 定位 nonce/request token | 网络验证或响应处理路径 |

## 6. 攻击链 / 工作流

```text
repack 后闪退 / 功能锁定
  → logcat 找 signature/hash/integrity 关键字
  → hook getPackageInfo / MessageDigest / open(base.apk)
  → 结合堆栈定位 Java 类或 native VA
  → smali patch、native patch 或返回原始摘要
  → reinstall 后复验启动、目标功能和网络请求
```

## 7. Smali patch 模式

```smali
# 原始：if-eqz v0, :fail
# 修改：强制进入 pass 分支
const/4 v0, 0x1
if-nez v0, :pass
```

记录 patch：

```text
file: smali_classes*/com/vendor/Guard.smali
method: checkSignature()Z
old: if-eqz v0, :cond_fail
new: const/4 v0, 0x1
effect: repack 后启动进入主界面
```

## 8. Evidence

| 项 | 记录内容 |
|---|---|
| 检查点 | Java 类/方法或 native VA/RVA |
| 原始值 | 原证书 hash、原 dex hash、期望 channel |
| 运行证据 | hook 日志、调用堆栈、文件访问路径 |
| Patch | smali diff、SO offset、原始字节/新字节 |
| 复验 | install、launch、目标功能、网络响应 |

## 9. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| 动态打点 | `android_frida_run_script` | 捕获签名/hash/installer 调用 |
| crypto/hash 证据 | `android_crypto_unpack_recipe` | 生成 MessageDigest/native hash hook |
| SO 定位 | `ghidra_headless_analyze` | 找比较分支和返回值 |
| 知识路由 | `kb_router` | 按 signature、integrity、repack 查下一篇 |
