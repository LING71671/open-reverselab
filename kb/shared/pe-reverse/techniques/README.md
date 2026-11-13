# PE 逆向技术库

- [攻击网](../../../red/pe-reverse/techniques/attack-network.md)
- [防御网](../../../blue/pe-reverse/techniques/defense-network.md)

Windows PE/二进制逆向技术库。覆盖 triage、静态/动态分析、脱壳、IOC、检测规则、Patch 与许可证/keygen。

## 完整目录（10 类 / 49 篇）

### 01-triage — 初筛（1）

- [`01-triage/01-aob-signature-scan.md`](01-triage/01-aob-signature-scan.md) — AOB 特征码扫描

### 02-pe-structure — PE 结构（2）

- [`02-pe-structure/01-pe-header-parsing.md`](02-pe-structure/01-pe-header-parsing.md) — PE 头解析与节区定位
- [`02-pe-structure/02-tls-callback-analysis.md`](02-pe-structure/02-tls-callback-analysis.md) — TLS Callback 定位与早期执行链

### 03-static-analysis — 静态分析（6）

- [`03-static-analysis/01-struct-reconstruction.md`](03-static-analysis/01-struct-reconstruction.md) — 内存结构体逆向重建
- [`03-static-analysis/02-disasm-jit-asm.md`](03-static-analysis/02-disasm-jit-asm.md) — 反汇编（Zydis）与 JIT 汇编（Xbyak）
- [`03-static-analysis/03-x64dbg-breakpoints.md`](03-static-analysis/03-x64dbg-breakpoints.md) — x64dbg 断点策略
- [`03-static-analysis/04-reclass-reconstruction.md`](03-static-analysis/04-reclass-reconstruction.md) — ReClass 结构体实时重建
- [`03-static-analysis/05-dynamic-api-resolution.md`](03-static-analysis/05-dynamic-api-resolution.md) — 动态 API 解析链还原
- [`03-static-analysis/06-electron-asar-reverse.md`](03-static-analysis/06-electron-asar-reverse.md) — Electron 应用 asar 静态还原与混淆破解

### 04-dynamic-analysis — 动态分析（16）

- [`04-dynamic-analysis/01-dll-injection-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/01-dll-injection-defense.md) — DLL 注入纵深防御与检测
- [`04-dynamic-analysis/01-dll-injection.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/01-dll-injection.md) — DLL 注入三模式
- [`04-dynamic-analysis/02-trampoline-detour-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/02-trampoline-detour-defense.md) — Trampoline Inline Hook 防护与代码段完整性检测
- [`04-dynamic-analysis/02-trampoline-detour.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/02-trampoline-detour.md) — Trampoline Hook（函数劫持）
- [`04-dynamic-analysis/03-external-memory-rw-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/03-external-memory-rw-defense.md) — 跨进程内存读写防护与敏感数据混淆
- [`04-dynamic-analysis/03-external-memory-rw.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/03-external-memory-rw.md) — 外部进程内存读写
- [`04-dynamic-analysis/04-naked-function-hook-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/04-naked-function-hook-defense.md) — Naked 汇编跳板 Hook 防护与未映射代码检测
- [`04-dynamic-analysis/04-naked-function-hook.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/04-naked-function-hook.md) — Naked 函数 Hook（内联汇编）
- [`04-dynamic-analysis/05-anti-debug-bypass-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/05-anti-debug-bypass-defense.md) — 反调试机制加固与抗 Frida/ScyllaHide 绕过检测
- [`04-dynamic-analysis/05-anti-debug-bypass.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/05-anti-debug-bypass.md) — 反调试检测与绕过
- [`04-dynamic-analysis/06-manual-map-injection-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/06-manual-map-injection-defense.md) — 手动映射（Manual Map）无痕注入检测与防护
- [`04-dynamic-analysis/06-manual-map-injection.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/06-manual-map-injection.md) — 手动映射 DLL 注入
- [`04-dynamic-analysis/07-direct-syscall-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/07-direct-syscall-defense.md) — Direct Syscall 检测与内核态调用链溯源防护
- [`04-dynamic-analysis/07-direct-syscall.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/07-direct-syscall.md) — Direct Syscall：绕过用户态 Hook
- [`04-dynamic-analysis/08-procmon-patterns-defense.md`](../../../blue/pe-reverse/techniques/04-dynamic-analysis/08-procmon-patterns-defense.md) — 行为监控暴露面收敛与持久化检测防御
- [`04-dynamic-analysis/08-procmon-patterns.md`](../../../red/pe-reverse/techniques/04-dynamic-analysis/08-procmon-patterns.md) — Procmon 行为监控与过滤

### 05-crypto-unpack — 加密/脱壳（3）

- [`05-crypto-unpack/01-pe-unpack-dump.md`](05-crypto-unpack/01-pe-unpack-dump.md) — PE 脱壳与内存 Dump
- [`05-crypto-unpack/02-vmp-virtualization-analysis.md`](05-crypto-unpack/02-vmp-virtualization-analysis.md) — VMP 虚拟化原理与 VM Entry 定位
- [`05-crypto-unpack/03-vmp-devirtualization-toolchain.md`](05-crypto-unpack/03-vmp-devirtualization-toolchain.md) — VMP 去虚拟化工具链（Devirtualization）

### 06-ioc-extraction — IOC 提取（2）

- [`06-ioc-extraction/01-ioc-extraction.md`](06-ioc-extraction/01-ioc-extraction.md) — IOC 提取技巧
- [`06-ioc-extraction/02-persistence-startup-chain.md`](06-ioc-extraction/02-persistence-startup-chain.md) — 持久化与启动链 IOC 提取

### 07-yara-sigma — YARA/Sigma（1）

- [`07-yara-sigma/01-yara-rule-writing.md`](07-yara-sigma/01-yara-rule-writing.md) — YARA 规则编写（逆向视角）

### 08-patch — Patch（2）

- [`08-patch/01-code-patching-defense.md`](../../../blue/pe-reverse/techniques/08-patch/01-code-patching-defense.md) — 代码篡改防护与 PE 节区完整性自检
- [`08-patch/01-code-patching.md`](../../../red/pe-reverse/techniques/08-patch/01-code-patching.md) — 代码 Patch 与字节修改

### 09-av-evasion — 规避与检测（2）

- [`09-av-evasion/01-ai-powered-evasion.md`](../../../red/pe-reverse/techniques/09-av-evasion/01-ai-powered-evasion.md) — AI 驱动免杀：Shellcode 处理 + Loader 编写
- [`09-av-evasion/01-evasion-indicator-detection.md`](../../../blue/pe-reverse/techniques/09-av-evasion/01-evasion-indicator-detection.md) — 规避与混淆特征静态识别（Shellcode / Syscall / 反沙箱）

### 10-license-keygen — 许可证与 keygen（14）

- [`10-license-keygen/01-license-mechanism-classification-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/01-license-mechanism-classification-defense.md) — 商业软件授权架构纵深防御选型
- [`10-license-keygen/01-license-mechanism-classification.md`](../../../red/pe-reverse/techniques/10-license-keygen/01-license-mechanism-classification.md) — 许可证机制分类与攻击路径选择
- [`10-license-keygen/02-validation-function-location-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/02-validation-function-location-defense.md) — 授权校验逻辑隐匿与抗静态/动态定位加固
- [`10-license-keygen/02-validation-function-location.md`](../../../red/pe-reverse/techniques/10-license-keygen/02-validation-function-location.md) — 许可证校验函数定位
- [`10-license-keygen/03-key-algorithm-recovery-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/03-key-algorithm-recovery-defense.md) — 注册码算法加固与防 Keygen 密码学设计
- [`10-license-keygen/03-key-algorithm-recovery.md`](../../../red/pe-reverse/techniques/10-license-keygen/03-key-algorithm-recovery.md) — 注册码算法还原与 keygen 复现
- [`10-license-keygen/04-signature-chain-pubkey-swap-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/04-signature-chain-pubkey-swap-defense.md) — 签名链信任锚保护与抗公钥替换加固
- [`10-license-keygen/04-signature-chain-pubkey-swap.md`](../../../red/pe-reverse/techniques/10-license-keygen/04-signature-chain-pubkey-swap.md) — 签名链校验与公钥替换攻击
- [`10-license-keygen/05-keygen-frida-verification-loop-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/05-keygen-frida-verification-loop-defense.md) — 进程内 Hook 替换、标志位篡改与本地配置伪造防护
- [`10-license-keygen/05-keygen-frida-verification-loop.md`](../../../red/pe-reverse/techniques/10-license-keygen/05-keygen-frida-verification-loop.md) — keygen 实机验证闭环（Frida 进程内替换）
- [`10-license-keygen/06-cloud-license-frida-hook-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/06-cloud-license-frida-hook-defense.md) — 云端授权查询面防 Hook 与本地状态/试用重置防御
- [`10-license-keygen/06-cloud-license-frida-hook.md`](../../../red/pe-reverse/techniques/10-license-keygen/06-cloud-license-frida-hook.md) — 云端授权识别与 Frida hook 替代路径
- [`10-license-keygen/07-self-referencing-signature-convergence-defense.md`](../../../blue/pe-reverse/techniques/10-license-keygen/07-self-referencing-signature-convergence-defense.md) — 自引用切片漏洞根治与抗迭代收敛签名架构
- [`10-license-keygen/07-self-referencing-signature-convergence.md`](../../../red/pe-reverse/techniques/10-license-keygen/07-self-referencing-signature-convergence.md) — 自引用签名嵌入与单步迭代收敛

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

## 实战写法

每篇文章按“入口信号 → 静态定位 → 动态断点/Hook → dump/patch/IOC → 复验 → Evidence → MCP 工具映射”组织。正文优先给出 DiE、PE header、imports、strings、Ghidra 函数、x64dbg 断点、Procmon 过滤器和 Frida 输出。

记录证据时写哈希、文件偏移、VA/RVA、节区、API、字符串、断点命中、寄存器/栈参数、dump 路径、原始字节/新字节、行为差异。文章结尾要落到下一跳：继续脱壳、还原算法、生成 patch、提取 IOC/YARA/Sigma 或回到 Ghidra 重命名函数。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
Hash/类型/保护 → Ghidra 静态分析 → x64dbg/Frida/Procmon 验证 → IOC/YARA/Sigma → Patch 副本
```
