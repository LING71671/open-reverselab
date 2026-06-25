# 入口点追踪与组件分析

## 场景

面对一个未知 APK，需要追踪其完整启动链：从 Application→Activity→Service→native 加载路径，确定分析起点。

## 输入信号

- AndroidManifest.xml 已解码
- 需要理解应用启动后执行的完整路径
- 需要找出是否有隐藏的 Receiver/Service

## 启动链追踪

### 1. Manifest 入口提取

```bash
# 一键提取所有入口点
aapt dump xmltree target.apk AndroidManifest.xml | grep -E "activity|service|receiver|provider|application"

# 关键信息:
# - package name
# - android:name (Application 类)
# - LAUNCHER Activity
# - exported Service/Receiver
```

### 2. Application 初始化链

```java
// 标准启动顺序
Application.attachBaseContext()
→ Application.onCreate()
  → initThirdPartySDK()
  → System.loadLibrary("xxx")  // native 加载入口
    → .init_array (constructor 函数)
    → JNI_OnLoad (JNI 注册)

// 分析重点:
// 1. attachBaseContext 中通常加载反作弊/加固 SDK
// 2. onCreate 中初始化业务模块
// 3. loadLibrary 触发 native 层初始化
```

### 3. Native 加载追踪

```bash
# 列出 APK 中所有 native 库
unzip -l target.apk | grep "lib/.*\.so"

# 在 smali 中搜索 loadLibrary 调用
grep -r "loadLibrary" target_unpacked/smali/

# 结果示例:
# smali/com/target/GameApp.smali: System.loadLibrary("cocos2djs")
# smali/com/target/GameApp.smali: System.loadLibrary("NativeProtect")
# → 加载顺序: cocos2djs 先, NativeProtect 后
```

## 组件导出风险分析

```bash
# 找出所有 exported 组件 (潜在攻击面)
aapt dump xmltree target.apk AndroidManifest.xml | grep -B1 "android:exported.*true"

# 检查点:
# - exported Provider → 可能泄露数据
# - exported Service → 可能被外部启动执行
# - exported Receiver → 可能被外部广播触发
# - intent-filter → 隐式启动入口
```

```java
// 检测公开 Provider 的典型漏洞
// content://com.target.provider/data
// → 如果没有权限保护，外部应用可直接读取

// Frida 快速测试:
var resolver = Java.use("android.content.ContentResolver")
// hook query 查看谁在访问
```

## 真实启动链示例 (Cocos/Unity 游戏)

```
AndroidManifest:
  Application: android:name=".Cocos2dxApplication"
  Activity: android:name=".Cocos2dxActivity" (LAUNCHER)

→ Cocos2dxApplication.attachBaseContext()
  → System.loadLibrary("cocos2djs")  // 主引擎
  → System.loadLibrary("NativeProtect") // 加固/反调试

→ Cocos2dxActivity.onCreate()
  → Cocos2dxHelper.init()  // 初始化渲染
  → GLSurfaceView 创建

→ libcocos2djs.so JNI_OnLoad
  → JNI_RegisterNatives 注册 native 方法
  → 启动游戏主循环线程

→ libNativeProtect.so .init_array
  → ptrace(PTRACE_TRACEME, ...)  // 反调试
  → 签名校验启动
```

## 分析工具

```
jadx → 查看 Java 启动链
aapt → 提取 Manifest 组件
readelf -d → 查看 so 的 init_array/fini_array
objdump -T → 查看 so 导出的 JNI 函数
strings → 搜索可疑字符串
Frida → 动态 Hook 各阶段入口
```

## 攻击链

```
aapt 提取 Manifest → 锁定 Application/LAUNCHER Activity
→ jadx 分析 Java 启动链 → 搜索 System.loadLibrary → 确定 native 加载顺序
→ readelf -d 提取 init_array → 用 Frida 在 JNI_OnLoad 前 Hook
→ 确定完整的执行路径 → 按入口点优先级进行逆向
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 一键收集 Activity/package info/manifest | `android_app_baseline` | 一键收集 Activity/package info/manifest |
| 导出 dumpsys package（权限/组件/intent-filter） | `android_package_info` | 导出 dumpsys package（权限、组件、intent-filter） |
| Hook Application.onCreate / JNI_OnLoad | `android_frida_run_script` | Hook Application.onCreate / JNI_OnLoad |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
