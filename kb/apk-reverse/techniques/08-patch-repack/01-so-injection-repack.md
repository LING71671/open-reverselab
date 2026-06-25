# Native SO 注入与 APK 重打包

## 场景

需要向目标 APK 注入自定义 native 库（`.so`），使注入代码在目标进程空间内运行。常见于插桩分析、功能注入、行为监控。

## 输入信号

- 目标 APK 已有 native 库
- 需要在目标进程上下文执行代码
- 静态修改（重打包）比动态注入更稳定

## 完整工作流

### 1. APK 解包

```bash
apktool d target.apk -o target_unpacked/
# 目录结构:
# target_unpacked/
# ├── AndroidManifest.xml
# ├── smali/             # DEX smali 代码
# ├── lib/               # 各架构 native lib
# │   ├── arm64-v8a/
# │   ├── armeabi-v7a/
# │   └── x86_64/
# ├── assets/
# └── res/
```

### 2. Native 库注入

```bash
# 复制注入 so 到各架构目录
cp libinject.so target_unpacked/lib/arm64-v8a/
cp libinject.so target_unpacked/lib/armeabi-v7a/
# 注意: 必须覆盖全部目标架构

# 修改 AndroidManifest.xml 声明 native 使用
# <application android:extractNativeLibs="true" ...>
```

### 3. 加载入口注入 (Smali 层)

```smali
# 找到 Activity 的 onCreate 或 Application.onCreate
# 在 smali 中添加 System.loadLibrary("inject")

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1

    # 注入: 在最前面添加
    const-string v0, "inject"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    # ... 原始代码
.end method
```

或使用 `static` 块自动加载:
```java
// 注入到任意会加载的 DEX 类
static {
    System.loadLibrary("inject");
}
```

### 4. JNI_OnLoad: 注入代码入口

```c
// libinject.so 中
#include <jni.h>
#include <dlfcn.h>
#include <pthread.h>

__attribute__((constructor))
void init() {
    // constructor 自动执行, 早于 JNI_OnLoad
    // 适合 hook dlopen/dlsym 等早期操作
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6);

    // 注册 native 方法 (可选)
    // 启动主逻辑线程
    pthread_t thread;
    pthread_create(&thread, NULL, main_loop, NULL);

    return JNI_VERSION_1_6;
}

void *main_loop(void *arg) {
    // 主逻辑: 等待目标初始化完成后执行
    sleep(3);  // 等待游戏加载完
    // ... hook / 读写 / 注入逻辑
    return NULL;
}
```

### 5. 重打包与签名

```bash
# 重打包
apktool b target_unpacked/ -o target_repacked.apk

# 签名 (需要生成或使用已有 keystore)
uber-apk-signer -a target_repacked.apk --allowResign
# 或
apksigner sign --ks debug.keystore target_repacked.apk

# 安装
adb install -r target_repacked.apk
```

## 对抗完整性校验

```c
// 常见: 目标检测 APK 签名变化
// 绕过1: Frida hook PackageManager.getPackageInfo
// 绕过2: native 中 hook __system_property_get + 返回假签名

// 绕过3: 注入 lib 中 patch 校验函数
void bypass_integrity_check() {
    // 在 lib 中找到校验函数 (Ghidra 定位)
    void *addr = base + 0x12345;  // 校验函数偏移
    // NOP 掉返回值检查
    mprotect((void*)((long)addr & ~0xFFF), 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    *(uint32_t*)addr = 0xD65F03C0;  // arm64: RET
}
```

## 常见坑

1. **架构不匹配**: arm64 so 不能注入 armeabi-v7a 进程 → 编译全部架构
2. **签名校验**: 目标检测签名后闪退 → 找到校验函数先 bypass
3. **SELinux 限制**: 无法 `dlopen` 某些路径 → 用 `/data/local/tmp/` 或 `LD_PRELOAD`
4. **linker namespace**: Android 7+ 限制了 `dlopen` 来源 → 注入到 APK lib 目录内

## 攻击链

```
APK → apktool d 解包 → 放置 inject.so → smali 注入 loadLibrary
→ apktool b 重打包 → 签名 → adb install → 启动验证 JNI_OnLoad 执行 → 目标逻辑运行
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 安装原始 APK 收集基线 | `android_app_baseline` | 安装原始 APK 收集基线 |
| 复制到 patches 目录 | `copy_sample_to_patches` | 复制到 patches 目录 |
| 修改 smali/so 字节 | `patch_bytes` / `patch_pattern` | 修改 smali/so 字节 |
| 安装重打包 APK | `android_install_apk` | 安装重打包 APK |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
