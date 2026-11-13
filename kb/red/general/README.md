# General · Red

本目录收录 20 篇技术文档。

- [Blue](../../blue/general/README.md)
- [共享方法](../../shared/general/README.md)
- [攻击网](techniques/attack-network.md)

## 技术文档

- [Linux 内核 Page-Cache 写入家族：Copy Fail / Dirty Frag / Fragnesia](techniques/01-kernel/01-page-cache-write-family.md)
- [Slab 跨缓存释放：KFENCE 精确大小报告导致 SKB head 释放到错误缓存](techniques/01-kernel/02-slab-cross-cache.md)
- [内核 FD Theft：mm-NULL ptrace check bypass](techniques/01-kernel/03-mm-null-ptrace-bypass.md)
- [CIFSwitch：cifs.spnego 身份混淆 → root 权限 NSS 加载](techniques/01-kernel/04-cifswitch-nss-privesc.md)
- [RDS zcopy double-free + io_uring dangling struct page*：PinTheft 内核 LPE](techniques/01-kernel/05-pintheft-io-uring-page-cache.md)
- [间接提示注入：入口控制与行为证据](techniques/ai-security/01-indirect-prompt-injection.md)
- [MCP 信任边界：工具身份、授权与结果链](techniques/ai-security/02-mcp-trust-boundary.md)
- [RAG 授权与文档投毒：租户、索引和缓存](techniques/ai-security/03-rag-authorization-poisoning.md)
- [内存搜索与修改](techniques/cheating/01-memory-hacking.md)
- [封包拦截与修改](techniques/cheating/02-packet-interception.md)
- [透视/ESP 渲染技术](techniques/cheating/03-esp-wallhack-rendering.md)
- [反作弊系统绕过](techniques/cheating/04-anti-cheat-bypass.md)
- [加速/时间操控](techniques/cheating/05-speedhack-time-manipulation.md)
- [Signature Forgery — 签名伪造与验证绕过全景手册](techniques/signature/00-overview.md)
- [Signature Algorithm Attacks — 签名算法降级/混淆/None 攻击深度手册](techniques/signature/01-algorithm.md)
- [Signature Implementation Bugs — 签名实现缺陷深度手册](techniques/signature/02-implementation.md)
- [Key Attacks — 签名密钥攻击深度技术手册](techniques/signature/03-key-attacks.md)
- [Canonicalization Attacks — 签名规范化绕过](techniques/signature/04-canonicalization.md)
- [Hash Length Extension 攻击 — 深度技术手册](techniques/signature/05-length-extension.md)
- [Replay / Nonce / Timestamp — 重放攻击深度技术手册](techniques/signature/06-replay-nonce.md)
