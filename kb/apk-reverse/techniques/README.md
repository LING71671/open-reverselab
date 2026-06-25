# APK 逆向技术库

APK/DEX/SO 逆向技术库。覆盖静态分析、Frida 动态验证、脱壳、Patch 与重打包。

## 完整目录（8 类 / 17 篇）

### 01-dex-java — DEX/Java（1）

- [`01-dex-java/01-smali-injection.md`](01-dex-java/01-smali-injection.md) — Smali 代码注入与 DEX 修改

### 02-native — Native/SO（5）

- [`02-native/01-il2cpp-offset-discovery.md`](02-native/01-il2cpp-offset-discovery.md) — Unity IL2CPP 静态逆向与偏移发现
- [`02-native/02-pointer-chain-patterns.md`](02-native/02-pointer-chain-patterns.md) — 指针链遍历模式
- [`02-native/03-ue4-offset-hunting.md`](02-native/03-ue4-offset-hunting.md) — UE4 引擎游戏偏移发现
- [`02-native/04-kernel-procfs-driver.md`](02-native/04-kernel-procfs-driver.md) — Kernel Driver 注入：proc 节点读写
- [`02-native/05-virt-phys-memory.md`](02-native/05-virt-phys-memory.md) — 虚拟地址 → 物理地址转换

### 03-manifest — Manifest/入口（1）

- [`03-manifest/01-entry-point-tracing.md`](03-manifest/01-entry-point-tracing.md) — 入口点追踪与组件分析

### 04-crypto — 加密（2）

- [`04-crypto/01-game-encryption-patterns.md`](04-crypto/01-game-encryption-patterns.md) — 游戏数据加解密识别与绕过
- [`04-crypto/02-rc4-custom-crypto.md`](04-crypto/02-rc4-custom-crypto.md) — 自定义对称加密：RC4 与组合模式

### 05-network — 网络协议（2）

- [`05-network/01-game-protocol-hook.md`](05-network/01-game-protocol-hook.md) — 游戏协议 Hook 与封包分析
- [`05-network/02-license-verification-bypass.md`](05-network/02-license-verification-bypass.md) — 在线验证系统分析与绕过

### 06-dynamic — 动态插桩（3）

- [`06-dynamic/01-memory-rw-hook.md`](06-dynamic/01-memory-rw-hook.md) — 进程内存读写检测与 Hook
- [`06-dynamic/02-overlay-rendering-hook.md`](06-dynamic/02-overlay-rendering-hook.md) — Overlay 渲染与 ImGui 检测
- [`06-dynamic/03-touch-input-hook.md`](06-dynamic/03-touch-input-hook.md) — 触摸输入 Hook 与注入分析

### 07-packer — 壳与混淆（2）

- [`07-packer/01-obfuscation-detection.md`](07-packer/01-obfuscation-detection.md) — 编译期混淆检测与识别
- [`07-packer/02-self-extracting-payload.md`](07-packer/02-self-extracting-payload.md) — 自解压 Payload 与脚本嵌入

### 08-patch-repack — Patch/重打包（1）

- [`08-patch-repack/01-so-injection-repack.md`](08-patch-repack/01-so-injection-repack.md) — Native SO 注入与 APK 重打包

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
APK → jadx/apktool → Java/Native 静态分析 → Frida 验证 → dump/patch → 重打包验活
```
