# Smali 代码注入与 DEX 修改

## 场景

需要在目标 APK 中注入 Java 层代码（加载 native 库、修改逻辑、插桩日志），通过修改 smali 字节码实现。

## 输入信号

- 已解包 APK（apktool d）
- 需要在特定 Activity/Service/Application 生命周期插入代码
- 目标是 Java/Kotlin 层逻辑修改

## Smali 基础速查

| Java | Smali |
|------|-------|
| `String s = "hello"` | `const-string v0, "hello"` |
| `int a = 5` | `const/4 v0, 0x5` |
| `System.out.println(s)` | `invoke-virtual {v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V` |
| `new Intent()` | `new-instance v0, Landroid/content/Intent;` |
| `if (x == 0) {}` | `if-eqz v0, :cond_0` |
| `return x` | `return v0` |

## 注入点选择

### 1. Application.attachBaseContext (最早)

```smali
# 最早执行点, 早于所有 Activity
.class public Lmyapp/MyApplication;
.super Landroid/app/Application;

.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 1
    # 注入: 在此处加载 native lib
    const-string v0, "inject"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    # 继续原始逻辑
    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    return-void
.end method
```

### 2. MainActivity.onCreate (界面入口)

```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2
    # 注入: 启动后台线程
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lmyapp/InjectRunnable;
    invoke-direct {v1}, Lmyapp/InjectRunnable;-><init>()V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    # 原始代码继续
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
.end method
```

### 3. static 代码块 (类加载时)

```smali
# 在任意会在进程启动时加载的类中
.method static constructor <clinit>()V
    .locals 1
    const-string v0, "inject"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
```

## 直接修改 vs 新增 Smali 文件

```bash
# 方式1: 修改现有 smali (快速, 适合小改动)
vim target_unpacked/smali/com/target/MainActivity.smali

# 方式2: 新增 smali 类 (推荐, 隔离性好)
# 将 inject.smali 放到对应包路径下
target_unpacked/smali/com/inject/InjectHelper.smali
```

## 注入类模板

```java
// 原始 Java → 编译 → dx/d8 → smali
package com.inject;

public class InjectHelper {
    public static void init() {
        System.loadLibrary("inject");
    }

    public static String getDeviceInfo() {
        return android.os.Build.MODEL + "|" +
               android.os.Build.FINGERPRINT;
    }
}
```

```bash
# 编译注入类为 DEX
javac InjectHelper.java
d8 InjectHelper.class --lib $ANDROID_JAR
# 或直接复制 class 到 smali 目录, apktool b 会自动处理
```

## 常见坑

1. **寄存器冲突**: 注入代码使用的 vN 寄存器可能与原始代码冲突 → 从大号开始用 (v10+)
2. **try-catch 破坏**: smali 中修改 try 块边界需同步更新 `.catch` 指令
3. **label 重复**: 注入新代码段的 label 名不能与原文件重复
4. **签名验证**: 重打包后签名变化 → 先 bypass 签名校验函数

## 工具映射

```
apktool d/b → APK 解包/打包
jadx-gui → 查看 Java 反编译, 定位注入点
ApkEditor/MT管理器 → Android 侧直接改 smali
uber-apk-signer/apksigner → 重签名
```

## 攻击链

```
jadx 定位目标类/方法 → apktool d 解包 → 编辑 smali 注入代码
→ apktool b 打包 → apksigner 签名 → adb install → 验证注入代码执行
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 安装 APK 并收集基线 | `android_app_baseline` | 安装 APK + 收集基线（Activity/package info/logcat/Frida 进程） |
| 复制样本到 patches 目录 | `copy_sample_to_patches` | 复制样本到 patches 目录 |
| 修改 smali 字节 | `patch_bytes` / `patch_pattern` | 修改 smali 字节 |
| 安装修改后的 APK | `android_install_apk` | 安装修改后的 APK |
| 读取现有笔记 | `workspace_read_text` | 读取现有笔记 |
| 写入分析笔记 | `workspace_write_text` | 写入分析笔记 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
