# General · Blue

本目录收录 20 篇技术文档。

- [Red](../../red/general/README.md)
- [共享方法](../../shared/general/README.md)
- [防御网](techniques/defense-network.md)

## 技术文档

- [Linux Page-Cache 原地写入漏洞家族防御（禁用高危零拷贝路径 / Seccomp / 只读根分区）](techniques/01-kernel/01-page-cache-write-family-defense.md)
- [Slab 跨缓存释放防御（禁用非特权 BPF / SLUB 加固 / KFENCE 策略）](techniques/01-kernel/02-slab-cross-cache-defense.md)
- [内核 FD Theft 与 mm-NULL Ptrace 绕过防御（Yama / Seccomp / SUID 收敛）](techniques/01-kernel/03-mm-null-ptrace-bypass-defense.md)
- [CIFSwitch（cifs.spnego 身份混淆与 root NSS 加载）防御](techniques/01-kernel/04-cifswitch-nss-privesc-defense.md)
- [PinTheft（RDS zcopy + io_uring 页缓存污染 LPE）防御](techniques/01-kernel/05-pintheft-io-uring-page-cache-defense.md)
- [间接提示注入防御：内容来源隔离、动作约束与证据复核](techniques/ai-security/01-indirect-prompt-injection-defense.md)
- [MCP 信任边界防御：工具身份、令牌受众与执行授权](techniques/ai-security/02-mcp-trust-boundary-defense.md)
- [RAG 授权与投毒防御：文档权限、撤权缓存与来源追踪](techniques/ai-security/03-rag-authorization-poisoning-defense.md)
- [内存搜索与篡改防御（ObRegisterCallbacks / 数值加密 / IOMMU）](techniques/cheating/01-memory-hacking-defense.md)
- [封包拦截与重放防御（TLS Pinning / 协议双向校验 / 序列号抗重放）](techniques/cheating/02-packet-interception-defense.md)
- [透视与 ESP 渲染防御（视野剔除 / 渲染管线完整性 / 覆盖窗口检测）](techniques/cheating/03-esp-wallhack-rendering-defense.md)
- [反作弊绕过防御（内核回调加固 / 栈回溯 / ETW-Ti 与 HVCI）](techniques/cheating/04-anti-cheat-bypass-defense.md)
- [加速与时间操控防御（多源时钟交叉校验 / 服务端 Tick 预算）](techniques/cheating/05-speedhack-time-manipulation-defense.md)
- [签名验证纵深防御全景（强算法绑定 / 规范化 / 抗重放 / 业务账本闭环）](techniques/signature/00-overview-defense.md)
- [签名算法降级与混淆防御（服务端算法锁定 / 拒绝 alg=none / 密钥类型隔离）](techniques/signature/01-algorithm-defense.md)
- [签名验证实现缺陷防御（恒定时间比对 / 严格类型校验 / Fail-Closed）](techniques/signature/02-implementation-defense.md)
- [签名密钥生命周期防御（CSPRNG 强熵 / KMS 托管 / 客户端隔离与轮换）](techniques/signature/03-key-attacks-defense.md)
- [签名规范化绕过防御（Verify-After-Parse / RFC 8785 JCS / HPP 拦截）](techniques/signature/04-canonicalization-defense.md)
- [哈希长度扩展（HLE）防御（HMAC / KMAC / 非对称签名迁移）](techniques/signature/05-length-extension-defense.md)
- [重放攻击与 Nonce/Timestamp 绕过防御（原子去重 / 严格时间窗 / 上下文绑定）](techniques/signature/06-replay-nonce-defense.md)
