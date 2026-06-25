# 拿到样本的前30分钟清单

## 场景

你刚刚获得一个未知样本（PE/ELF/APK/IPA），需要在30分钟内建立完整的初始信息集，判断样本类型、保护强度、关键入口点，并制定后续分析计划。

## 输入信号

- 未知来源样本，可能加壳/混淆/反调试
- 需要快速判断样本是否恶意及复杂度
- 需要决定使用哪些工具和板（PE / APK / General）

## Minute 0-5: 初始初筛

### 哈希与文件类型

```bash
# 不可逆哈希用于后续 IoC 追踪
sha256sum suspicious.exe
# → 输出: 存入 notes 作为 sample ID

# 文件类型识别
file suspicious.exe
# PE32+ executable (GUI) x86-64, for MS Windows

# 查看文件大小
ls -lh suspicious.exe
# < 100KB → 可能是 shellcode loader 或 stub
# 100KB-2MB → 正常编译的 PE
# > 10MB → 可能是打包的资源或完整引擎
# 大小异常: 游戏作弊通常是 100KB-2MB (DLL) 或 5-20MB (带资源)
```

### Strings 预览

```bash
# 快速字符串提取 (前 100 行查看关键线索)
strings suspicious.exe | head -100

# 重点关注:
# - 路径名: %USERPROFILE% → 开发者机器路径
# - 调试符号: .pdb 路径 → 直接暴露符号
# - URL/IP: http://, 192.168., 10.0. → C2/更新服务器
# - 反作弊名: EAC, BattlEye, Vanguard, BE, EOS
# - 内核相关: \\Driver, \\Device, NtCreateFile, ObRegister
# - 窗口类名: 游戏窗口类名 → 针对特定游戏
# - 加密常量: AES, RSA, DES, XOR key 模式
# - 游戏引擎: Unity, Unreal, Source

# 实操中: game cheats 的 strings 会包含:
# - "GetTickCount" "ReadProcessMemory" → 功能特征
# - 作弊菜单字符串: "ESP", "Aimbot", "Wallhack"
# - 目标游戏名: "csgo.exe", "VALORANT", "Fortnite"
```

### 熵值检查

```cpp
// entropy > 7.0 → 加壳/压缩/加密
// entropy 6.0-7.0 → 部分混淆
// entropy 4.0-6.0 → 正常编译

// DiE 内置熵值扫描
// 重点: 检查各个节区的独立熵值
// .text 正常 ~6.5 (编译代码)
// .text > 7.0 → VM 保护 (VMP/Themida)
// .rsrc > 7.5 → 加密资源
// .data 高熵 → 嵌入加密 payload

// 工具: die_scan --entropy
```

## Minute 5-10: Packer/Obfuscation 检测

### 节区分析

```cpp
// PE 节区特征识别:

// 未加壳 PE (Visual Studio):
// .text   — 代码 (R-X)
// .rdata  — 只读数据 (R--)
// .data   — 读写数据 (RW-)
// .pdata  — 异常处理 (R--)
// .rsrc   — 资源 (R--)

// UPX 特征:
// UPX0 — 虚拟代码段 (---)
// UPX1 — 压缩/代码 (RWX)
// 入口点 OEP 特征: pushad (0x60)

// VMP/Themida 特征:
// 节名随机: .vmp0, .vmp1, .themida
// 所有可执行节区 RWX
// 入口点在 vmp0 段
// 大量高熵代码 (混淆)

// ConfuserEx (.NET):
// 大量混淆的 metadata
// 方法体被空 NOP 填充或 goto 跳转

// 工具: rizin_sections
```

### 导入表检查

```cpp
// 未加壳 PE 导入表: 清晰, 函数名可见
// 加壳 PE: 只有 kernel32!LoadLibraryA + kernel32!GetProcAddress
//          → 壳负责动态解析后续 API

// 反作弊特有的导入特征:
// EAC: EasyAntiCheat*.sys 无用户态导出
// BE: BEDaisy.sys — 只有基本 ntoskrnl 导入
// VGK: vgk.sys — 导入极少量 ntoskrnl 函数

// 工具: rizin_imports --limit 300

// 可疑导入 (作弊软件典型):
// WriteProcessMemory, ReadProcessMemory → RPM/WPM
// CreateRemoteThread, WriteProcessMemory → 注入
// VirtualAllocEx, NtUnmapViewOfSection → 手动映射
// SetWindowsHookEx → 全局钩子
// GetProcAddress → 动态 API 解析 (壳特征)
// LdrLoadDll, LdrUnloadDll → 隐藏注入
// DeviceIoControl → 驱动通信
```

### 反调试/反分析检测

```cpp
// 快速扫描函数中的反调试模式:
// Ghidra 或 IDA 搜索:
// 1. IsDebuggerPresent → PEB 检测
// 2. NtQueryInformationProcess → ProcessDebugPort
// 3. NtSetInformationThread → ThreadHideFromDebugger
// 4. __rdtsc → 时间差检测
// 5. OutputDebugStringA → 异常触发检测

// 工具: ghidra_summary_call_focus behavior="antidebug"

// 反调试存在 → 分析绕过方案 (见 anti-debug-bypass.md)
// 无反调试 → 可能仅有基本保护或非对抗样本
```

## Minute 10-15: 静态概览

### 入口点分析

```cpp
// PE 入口点 (OEP):
// 正常编译: 指向 CRT 启动代码
//   call __security_init_cookie
//   call _mainCRTStartup → main
// 加壳: 指向壳的 stub (节区偏移在最后一节)

// 在 Ghidra 中导航到 entry:
// 如果是直接 JMP → OEP (快速劫持)
// 如果是 pushad → UPX/VMP 壳
// 如果是 call + pop → 定位代码 (常见混淆)

// 工具: ghidra_headless_analyze → 自动分析入口
```

### Main 函数定位

```cpp
// 对于未加壳 PE:
// 1. entry 向上回溯 → 找到 main 或 wWinMain
// 2. 搜索字符串: "main", "WinMain", "DllMain"
// 3. 从 GetModuleHandle + GetCommandLineA/W 交叉引用
// 4. 有 PDB: 直接引用符号名

// 对于加壳 PE:
// 1. 先脱壳 (UnpacMe, 手动 ESP 定律)
// 2. 或动态分析: x64dbg 在 OEP 下断点

// 游戏作弊特别关注:
// - DllMain → 如果是 DLL → 注入型作弊
// - WinMain → EXE → 外部 overlay 或 launcher
// - 检查是否隐藏控制台窗口 (作弊配置)
```

### Interesting Strings → Xrefs

```cpp
// 经验法则: 所有可疑字符串做交叉引用
// → 找到引用该字符串的函数
// → 该函数就是对应功能的实现

// 优先级排序:
// High: 网络相关 ("http://", "connect", "send", "recv")
// High: 进程/内存操作 ("OpenProcess", "CreateFile")
// High: 注册表/文件路径 → 配置存储
// Medium: 错误信息 → 功能分支调试
// Low: 版权/版本字符串

// Tools: ghidra_summary_strings → 搜索 + xrefs 查看
```

## Minute 15-25: 关键函数识别

### 加密函数识别

```cpp
// 加密函数特征:
// 1. 导入: CryptEncrypt, BCryptEncrypt, EVP_EncryptInit
// 2. 常量: AES S-box (0x63, 0x7C, ...), CRC32 表
// 3. 循环中的位运算: XOR, SHIFT, rotate
// 4. 固定魔术数: 0x67452301 (MD5), 0x6A09E667 (SHA256)
// 5. 密钥派生: PBKDF2, scrypt 调用

// 工具: ghidra_summary_call_focus behavior="crypto"

// 解密方法:
// - 已知算法: 直接参数提取 → Python 重放
// - 自定义算法: 动态分析 → Frida hook 输入输出
```

### 网络函数识别

```cpp
// 网络功能特征:
// 1. Winsock: socket, connect, send, recv
// 2. WinHTTP: WinHttpOpen, WinHttpSendRequest
// 3. Steam: SteamNetworking, ISteamNetworking
// 4. 自定义: 原始 TCP/UDP 封装

// 工具: rizin_imports → 过滤 ws2_32 / winhttp

// 如果样本有加密网络通信:
// → 需要 SSL unpinning (见 packet-interception.md)
// → 或 Frida hook 加密函数
```

### 文件 I/O 操作

```cpp
// 关注的文件操作:
// CreateFile: 日志文件, 配置, 驱动设备
// WriteFile: 日志, dump, crash report
// ReadFile: 配置, 黑名单

// 特别关注:
// - 创建 \\\\.\\ 设备 → 驱动通信
// - 写 .log / .cfg / .ini → 持久化配置
// - Self-deletion → 反取证
```

### 反分析/自我保护函数

```cpp
// 针对反作弊软件的检测:
// - 搜索窗口: FindWindowA("EasyAntiCheat"), EnumWindows
// - 搜索进程: CreateToolhelp32Snapshot → 遍历进程
// - 注册表: 扫描反作弊残留
// - 驱动检测: NtQuerySystemInformation → 枚举驱动
// - 调试器检测: NtQueryInformationProcess

// 工具: ghidra_summary_call_focus behavior="antidebug"

// 自我保护:
// - SetUnhandledExceptionFilter → crash handler
// - 完整性校验: CRC 自身代码段
// - 心跳线程: 周期性校验
```

## Minute 25-30: 动态分析计划

### 断点规划

```cpp
// 基于前 25 分钟的发现, 制定断点计划:

// 1. 网络断点:
//    send / recv → 捕获通信
//    WSASend / WSARecv → Winsock hook
//    SSL_write / SSL_read → TLS 解密
    
// 2. 加密断点:
//    Hook 加密函数的入口/出口
//    记录: key, IV, plaintext, ciphertext
    
// 3. 反调试断点:
//    IsDebuggerPresent → 修改返回
//    NtQueryInformationProcess → 隐藏调试器
    
// 4. 功能断点:
//    ReadProcessMemory → 捕获读取目标
//    WriteProcessMemory → 捕获写入目标
//    VirtualAllocEx → 注入目标

// 工具: make_x64dbg_breakpoint_script (如果 PE)
// 工具: android_frida_run_script (如果 Android)
// 工具: make_pe_crypto_unpack_plan (如果加密)
```

### 动态观察策略

```cpp
// 根据样本类型选择:

// PE — Windows:
// - x64dbg + ScyllaHide
// - API Monitor (注册所有 API)
// - Procmon (文件/注册表/进程事件)
// - Wireshark (网络流量)
// - Frida (Hook 关键函数)
// - API 跟踪: 优先 Nt 系列 (绕过用户态 hook)

// APK — Android:
// - Frida: Java/Native hook
// - logcat: 应用日志
// - strace: 系统调用跟踪
// - tcpdump: 网络流量

// ELF — Linux:
// - LD_PRELOAD hook
// - strace / ltrace
// - GDB + GEF
// - eBPF (内核级跟踪)

// macOS/iOS:
// - Frida
// - dtruss (DTrace)
// - lldb
```

### 记录与文档

```cpp
// 前 30 分钟输出文档应包括:

// 元数据:
// - 文件名 / 哈希 (SHA256)
// - 文件大小 / 时间戳
// - 检测到的保护类型
// - YARA 匹配结果

// 结构摘要:
// - PE/ELF/APK 基本结构
// - 节区 / 段
// - 导入/导出 API
// - 重要字符串

// 功能推断:
// - 潜在的正向功能 (作弊功能类型)
// - 反分析技术
// - 网络通信协议

// 计划:
// - 目标源代码 / 函数列表
// - 需要设置的断点
// - 需要观察的行为
// - 需要运行的 Frida 脚本
```

## 决策树

```
样本入口
  ↓
文件类型?
  ├─ PE  (EXE/DLL/SYS) → windows 板
  │   ├─ 加壳? → 脱壳计划 + DiE 识别壳类型
  │   │   ├─ UPX → 一键脱壳
  │   │   ├─ VMP → 动态分析 + 内存 dump
  │   │   └─ Themida → 类似 VMP
  │   └─ 未加壳 → 直接 Ghidra 静态分析
  │       ├─ 有 PDB → 符号加载 → 快速分析
  │       └─ 无 PDB → 函数特征 + 偏移逆向
  │
  ├─ APK/AAB → android 板
  │   ├─ Unity IL2CPP? → libil2cpp.so + global-metadata
  │   ├─ Unreal? → libUE4.so
  │   └─ Native? → JNI + so 分析
  │
  ├─ ELF → general 板
  │   ├─ x86/x64 → LD_PRELOAD + GDB
  │   └─ ARM/ARM64 → QEMU user mode / 嵌入式分析
  │
  └─ Mach-O → general 板
      ├─ macOS → Frida + dtruss
      └─ iOS → Frida + lldb
```

## 常见陷阱与误判

```
1. 误判加壳: 某些编译器 (Delphi, Go) 生成的节区特征类似加壳
   → 检查导入表: 如果有大量导入 → 未加壳

2. 混淆代码误判为加密: OLLVM 混淆会产生高熵节区
   → 实际在执行, 不是加密数据
   → 检查是否有明显的控制流结构

3. 误判良性样本为恶意: 测试工具, 调试器, 监控软件
   → 检查数字签名
   → 检查是否有目标游戏特定的字符串

4. 漏判 VM 保护: VMP 保护后的 .text 区高熵但有导入表
   → 执行时动态解密 → 需要通过内存 dump 获取真代码

5. 误判语言: .NET 程序编译为 native (IL2CPP/Burst)
   → 没有 .NET metadata 但实际是 C# 逻辑

6. 反调试触发导致样本在分析时表现异常
   → 先 bypass 反调试再分析
   → 或使用硬件分析环境 (Intel PT / ETW 记录)
```

## MCP 工具映射

| 阶段 | MCP 工具 | 说明 |
|-----|---------|------|
| 0-5min 哈希/初筛 | `hash_file` | 计算 SHA256 作为样本 ID |
| 0-5min 壳/类型 | `die_scan` | 带 --entropy 检查节区熵值 |
| 0-5min 类型 | `rizin_bin_info` | 基本 PE/ELF/APK 结构信息 |
| 5-10min 节区 | `rizin_sections` | 检查节区名称与权限 |
| 5-10min 导入表 | `rizin_imports` | 分析 API 使用模式 |
| 5-10min 字符串 | `rizin_strings` | 输出原始字符串 |
| 10-15min 静态分析 | `ghidra_headless_analyze` | 完整自动分析 |
| 15-20min 函数 | `ghidra_summary_call_focus` | 按行为推荐重点函数 |
| 15-20min 函数详情 | `ghidra_summary_function_detail` | 含反编译/调用链/导入引用 |
| 15-25min 函数列表 | `ghidra_summary_functions` | 按查询过滤函数 |
| 25-30min 知识查找 | `kb_router` | 搜索已知技术方案 |
| 全程 | `python_re_tool_install` | 安装缺失工具链 |

## 工作流

建立 baseline → 锁定一个可观察信号 → 执行单变量最小实验 → 保存证据 → 复现关键分支 → 将结果回填分析笔记。


## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
