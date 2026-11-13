# APK 逆向技术库

- [攻击网](../../../red/apk-reverse/techniques/attack-network.md)
- [防御网](../../../blue/apk-reverse/techniques/defense-network.md)

APK/DEX/SO 逆向技术库。覆盖静态分析、Frida 动态验证、脱壳、Patch 与重打包。

## 完整目录（9 类 / 36 篇）

### 01-dex-java — DEX/Java（2）

- [`01-dex-java/01-smali-injection-defense.md`](../../../blue/apk-reverse/techniques/01-dex-java/01-smali-injection-defense.md) — Smali 代码注入与 DEX 篡改防御
- [`01-dex-java/01-smali-injection.md`](../../../red/apk-reverse/techniques/01-dex-java/01-smali-injection.md) — Smali 代码注入与 DEX 修改

### 02-native — Native/SO（6）

- [`02-native/01-il2cpp-offset-discovery.md`](02-native/01-il2cpp-offset-discovery.md) — Unity IL2CPP 静态逆向与偏移发现
- [`02-native/02-pointer-chain-patterns.md`](02-native/02-pointer-chain-patterns.md) — 指针链遍历模式
- [`02-native/03-ue4-offset-hunting.md`](02-native/03-ue4-offset-hunting.md) — UE4 引擎游戏偏移发现
- [`02-native/04-kernel-procfs-driver.md`](02-native/04-kernel-procfs-driver.md) — Kernel Driver 注入：proc 节点读写
- [`02-native/05-virt-phys-memory.md`](02-native/05-virt-phys-memory.md) — 虚拟地址 → 物理地址转换
- [`02-native/06-jni-register-natives-tracing.md`](02-native/06-jni-register-natives-tracing.md) — JNI RegisterNatives 追踪与 Native 入口还原

### 03-manifest — Manifest/入口（1）

- [`03-manifest/01-entry-point-tracing.md`](03-manifest/01-entry-point-tracing.md) — 入口点追踪与组件分析

### 04-crypto — 加密（2）

- [`04-crypto/01-game-encryption-patterns.md`](04-crypto/01-game-encryption-patterns.md) — 游戏数据加解密识别与绕过
- [`04-crypto/02-rc4-custom-crypto.md`](04-crypto/02-rc4-custom-crypto.md) — 自定义对称加密：RC4 与组合模式

### 05-network — 网络协议（6）

- [`05-network/01-game-protocol-hook-defense.md`](../../../blue/apk-reverse/techniques/05-network/01-game-protocol-hook-defense.md) — 游戏协议防 Hook、抗重放与端到端加固
- [`05-network/01-game-protocol-hook.md`](../../../red/apk-reverse/techniques/05-network/01-game-protocol-hook.md) — 游戏协议 Hook 与封包分析
- [`05-network/02-license-verification-bypass-defense.md`](../../../blue/apk-reverse/techniques/05-network/02-license-verification-bypass-defense.md) — 在线许可证与授权校验加固
- [`05-network/02-license-verification-bypass.md`](../../../red/apk-reverse/techniques/05-network/02-license-verification-bypass.md) — 在线验证系统分析与绕过
- [`05-network/03-tls-pinning-unpinning-defense.md`](../../../blue/apk-reverse/techniques/05-network/03-tls-pinning-unpinning-defense.md) — TLS 证书固定（Pinning）多层加固与防绕过
- [`05-network/03-tls-pinning-unpinning.md`](../../../red/apk-reverse/techniques/05-network/03-tls-pinning-unpinning.md) — TLS Pinning 定位与 Unpinning

### 06-dynamic — 动态插桩（6）

- [`06-dynamic/01-memory-rw-hook-defense.md`](../../../blue/apk-reverse/techniques/06-dynamic/01-memory-rw-hook-defense.md) — 进程内存读写防护、反附加与敏感内存保护
- [`06-dynamic/01-memory-rw-hook.md`](../../../red/apk-reverse/techniques/06-dynamic/01-memory-rw-hook.md) — 进程内存读写检测与 Hook
- [`06-dynamic/02-overlay-rendering-hook-defense.md`](../../../blue/apk-reverse/techniques/06-dynamic/02-overlay-rendering-hook-defense.md) — 悬浮窗覆盖与图形渲染管线劫持防御
- [`06-dynamic/02-overlay-rendering-hook.md`](../../../red/apk-reverse/techniques/06-dynamic/02-overlay-rendering-hook.md) — Overlay 渲染与 ImGui 检测
- [`06-dynamic/03-touch-input-hook-defense.md`](../../../blue/apk-reverse/techniques/06-dynamic/03-touch-input-hook-defense.md) — 触摸输入注入防护与异常手势识别
- [`06-dynamic/03-touch-input-hook.md`](../../../red/apk-reverse/techniques/06-dynamic/03-touch-input-hook.md) — 触摸输入 Hook 与注入分析

### 07-packer — 壳与混淆（5）

- [`07-packer/01-obfuscation-detection.md`](07-packer/01-obfuscation-detection.md) — 编译期混淆检测与识别
- [`07-packer/02-self-extracting-payload.md`](07-packer/02-self-extracting-payload.md) — 自解压 Payload 与脚本嵌入
- [`07-packer/03-vmp-dex2c-detection.md`](07-packer/03-vmp-dex2c-detection.md) — VMP/dex2c 加固识别与形态判定
- [`07-packer/04-vmp-dump-trace-recovery.md`](07-packer/04-vmp-dump-trace-recovery.md) — VMP 脱壳与语义还原（Dump/Trace/Recovery）
- [`07-packer/05-vmp-anti-debug-bypass.md`](07-packer/05-vmp-anti-debug-bypass.md) — Android 反调试检测与绕过（VMP 场景）

### 08-patch-repack — Patch/重打包（4）

- [`08-patch-repack/01-so-injection-repack-defense.md`](../../../blue/apk-reverse/techniques/08-patch-repack/01-so-injection-repack-defense.md) — Native SO 注入与 APK 重打包防御
- [`08-patch-repack/01-so-injection-repack.md`](../../../red/apk-reverse/techniques/08-patch-repack/01-so-injection-repack.md) — Native SO 注入与 APK 重打包
- [`08-patch-repack/02-signature-integrity-bypass-defense.md`](../../../blue/apk-reverse/techniques/08-patch-repack/02-signature-integrity-bypass-defense.md) — APK 签名与包体完整性多层加固
- [`08-patch-repack/02-signature-integrity-bypass.md`](../../../red/apk-reverse/techniques/08-patch-repack/02-signature-integrity-bypass.md) — 签名与完整性检查绕过

### 09-hybrid-frameworks — 跨平台/Hybrid 框架（4）

- [`09-hybrid-frameworks/01-webview-attacks-defense.md`](../../../blue/apk-reverse/techniques/09-hybrid-frameworks/01-webview-attacks-defense.md) — 移动 WebView 桥接、协议与证书安全加固
- [`09-hybrid-frameworks/01-webview-attacks.md`](../../../red/apk-reverse/techniques/09-hybrid-frameworks/01-webview-attacks.md) — WebView 攻击全技术
- [`09-hybrid-frameworks/02-cordova-reactnative-defense.md`](../../../blue/apk-reverse/techniques/09-hybrid-frameworks/02-cordova-reactnative-defense.md) — 跨平台混合框架（Cordova/RN/Flutter/Electron）加固
- [`09-hybrid-frameworks/02-cordova-reactnative.md`](../../../red/apk-reverse/techniques/09-hybrid-frameworks/02-cordova-reactnative.md) — 跨平台框架攻击面 — Cordova / React Native / Flutter / Electron

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

## 实战写法

每篇文章按“入口信号 → 静态定位 → 动态 Hook/打点 → dump/patch/repack → 复验 → Evidence → MCP 工具映射”组织。正文优先给出 jadx/apktool/readelf/Ghidra/Frida 的落点，而不是只解释概念。

记录证据时写包名、组件名、类/方法签名、SO 名称、偏移、hook 输出、dump 文件路径、patch 字节或 smali diff、安装/运行结果。每一节都要能把读者带到下一跳：Java 层、Native 层、网络协议、壳、加密或重打包。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
APK → jadx/apktool → Java/Native 静态分析 → Frida 验证 → dump/patch → 重打包验活
```
