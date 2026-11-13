# Windows / PE · Blue

本目录收录 17 篇技术文档。

- [Red](../../red/pe-reverse/README.md)
- [共享方法](../../shared/pe-reverse/README.md)
- [防御网](techniques/defense-network.md)

## 技术文档

- [DLL 注入纵深防御与检测](techniques/04-dynamic-analysis/01-dll-injection-defense.md)
- [Trampoline Inline Hook 防护与代码段完整性检测](techniques/04-dynamic-analysis/02-trampoline-detour-defense.md)
- [跨进程内存读写防护与敏感数据混淆](techniques/04-dynamic-analysis/03-external-memory-rw-defense.md)
- [Naked 汇编跳板 Hook 防护与未映射代码检测](techniques/04-dynamic-analysis/04-naked-function-hook-defense.md)
- [反调试机制加固与抗 Frida/ScyllaHide 绕过检测](techniques/04-dynamic-analysis/05-anti-debug-bypass-defense.md)
- [手动映射（Manual Map）无痕注入检测与防护](techniques/04-dynamic-analysis/06-manual-map-injection-defense.md)
- [Direct Syscall 检测与内核态调用链溯源防护](techniques/04-dynamic-analysis/07-direct-syscall-defense.md)
- [行为监控暴露面收敛与持久化检测防御](techniques/04-dynamic-analysis/08-procmon-patterns-defense.md)
- [代码篡改防护与 PE 节区完整性自检](techniques/08-patch/01-code-patching-defense.md)
- [规避与混淆特征静态识别（Shellcode / Syscall / 反沙箱）](techniques/09-av-evasion/01-evasion-indicator-detection.md)
- [商业软件授权架构纵深防御选型](techniques/10-license-keygen/01-license-mechanism-classification-defense.md)
- [授权校验逻辑隐匿与抗静态/动态定位加固](techniques/10-license-keygen/02-validation-function-location-defense.md)
- [注册码算法加固与防 Keygen 密码学设计](techniques/10-license-keygen/03-key-algorithm-recovery-defense.md)
- [签名链信任锚保护与抗公钥替换加固](techniques/10-license-keygen/04-signature-chain-pubkey-swap-defense.md)
- [进程内 Hook 替换、标志位篡改与本地配置伪造防护](techniques/10-license-keygen/05-keygen-frida-verification-loop-defense.md)
- [云端授权查询面防 Hook 与本地状态/试用重置防御](techniques/10-license-keygen/06-cloud-license-frida-hook-defense.md)
- [自引用切片漏洞根治与抗迭代收敛签名架构](techniques/10-license-keygen/07-self-referencing-signature-convergence-defense.md)
