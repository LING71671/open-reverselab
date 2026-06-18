# APK 逆向技术库

APK/DEX 实战逆向 Lab。每个文件 = 可复制运行的 Frida/分析代码。攻击视角，可实战。

## 目录 (17 篇)

```
01-dex-java/       (1)   smali-injection
02-native/         (5)   il2cpp-offset-discovery + pointer-chain-patterns + ue4-offset-hunting + kernel-procfs-driver + virt-phys-memory
03-manifest/       (1)   entry-point-tracing
04-crypto/         (2)   game-encryption-patterns + rc4-custom-crypto
05-network/        (2)   game-protocol-hook + license-verification-bypass
06-dynamic/        (3)   memory-rw-hook + overlay-rendering-hook + touch-input-hook
07-packer/         (2)   obfuscation-detection + self-extracting-payload
08-patch-repack/   (1)   so-injection-repack
```

## 分类索引

### 01-dex-java — DEX/Java 反编译与注入
- `01-smali-injection.md`: smali 语法速查, 三注入点 (Application/Activity/static), loadLibrary 注入, 打包签名流程

### 02-native — Native 库逆向与偏移发现
- `01-il2cpp-offset-discovery.md`: libil2cpp.so 分析, global-metadata.dat, 模块基址获取, 五级指针链实例
- `02-pointer-chain-patterns.md`: process_vm_readv vs ioctl 两种读写, getZZ 递归指针解引用, 数组遍历
- `03-ue4-offset-hunting.md`: GWorld/GObjects, Actor 链表遍历, RootComponent→坐标, 武器链
- `04-kernel-procfs-driver.md`: 自解压 shell 注入, proc 节点创建, 用户态 ioctl 通信, 21 内核版本适配
- `05-virt-phys-memory.md`: pagemap 虚拟地址→物理地址转换, 页表遍历, 批量免 attach 读取

### 03-manifest — Manifest 与组件分析
- `01-entry-point-tracing.md`: Application 启动链, attachBaseContext→JNI_OnLoad, 组件导出分析

### 04-crypto — 加密识别与绕过
- `01-game-encryption-patterns.md`: SSL Pinning 绕过, Cipher.init Hook 抓 Key/IV, 算法速查表, Python 离线验证
- `02-rc4-custom-crypto.md`: RC4 KSA+PRGA 识别, Ghidra 扫描 256 循环, Frida Hook 自定义加密, API 签名伪造

### 05-network — 协议 Hook 与封包分析
- `01-game-protocol-hook.md`: OkHttp/Retrofit Hook, native socket sendto/recvfrom Hook, Protobuf 逆向
- `02-license-verification-bypass.md`: 微验 API 签名验证, Telegram 频道验证, curl 连通性检查, 通用绕过模板

### 06-dynamic — Frida 动态分析
- `01-memory-rw-hook.md`: process_vm_readv Hook, /proc/pid/mem 读写, ioctl 内核驱动分析
- `02-overlay-rendering-hook.md`: ANativeWindow 创建, Vulkan/OpenGLES 渲染管线, ImGui 帧循环
- `03-touch-input-hook.md`: InputManager.injectInputEvent, /dev/input 注入, AI vs 人工触摸模式

### 07-packer — 混淆与脱壳
- `01-obfuscation-detection.md`: oxorany 编译期 XOR, OLLVM 控制流平坦化, UPX/魔改壳, Frida 通用 dump
- `02-self-extracting-payload.md`: Shell 嵌入 .ko, gzip 自解压, C Header 嵌入驱动, 编译产物加密

### 08-patch-repack — Patch 与重打包
- `01-so-injection-repack.md`: apktool 解包/打包, smali 注入 loadLibrary, JNI_OnLoad 模板, 完整性校验绕过

## 工具映射

```
Frida                             → 动态 Hook (核心)
Ghidra/IDA                        → Native 静态分析
jadx                              → DEX 反编译
apktool / uber-apk-signer         → APK 解包/打包/签名
DiE/diec                          → 文件类型/壳识别
Wireshark/tcpdump                 → 网络抓包
protobuf-inspector/protoc         → Protobuf 逆向
UE4Dumper / Il2CppInspector       → 引擎 SDK dump
strace                            → syscall 追踪
```

## 分析链总览

```
APK 入口追踪 → DEX smali 注入 → Native SO 逆向
→ 引擎偏移发现 → 内存读写 Hook → 加密算法提取
→ 协议抓包分析 → 验证系统绕过 → 混淆识别/脱壳
→ 驱动注入分析 → 重打包验活
```
