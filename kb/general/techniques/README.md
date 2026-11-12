# 通用逆向技术库

跨平台逆向技术库。覆盖密码算法、协议、研究型对抗与方法论、Linux 内核漏洞。

## 完整目录（6 类 / 45 篇）

### 01-kernel — Linux 内核漏洞与加固（10）

- [`01-kernel/01-page-cache-write-family-defense.md`](01-kernel/01-page-cache-write-family-defense.md) — Linux Page-Cache 原地写入漏洞家族防御（禁用高危零拷贝路径 / Seccomp / 只读根分区）
- [`01-kernel/01-page-cache-write-family.md`](01-kernel/01-page-cache-write-family.md) — Linux 内核 Page-Cache 写入家族：Copy Fail / Dirty Frag / Fragnesia
- [`01-kernel/02-slab-cross-cache-defense.md`](01-kernel/02-slab-cross-cache-defense.md) — Slab 跨缓存释放防御（禁用非特权 BPF / SLUB 加固 / KFENCE 策略）
- [`01-kernel/02-slab-cross-cache.md`](01-kernel/02-slab-cross-cache.md) — Slab 跨缓存释放：KFENCE 精确大小报告导致 SKB head 释放到错误缓存
- [`01-kernel/03-mm-null-ptrace-bypass-defense.md`](01-kernel/03-mm-null-ptrace-bypass-defense.md) — 内核 FD Theft 与 mm-NULL Ptrace 绕过防御（Yama / Seccomp / SUID 收敛）
- [`01-kernel/03-mm-null-ptrace-bypass.md`](01-kernel/03-mm-null-ptrace-bypass.md) — 内核 FD Theft：mm-NULL ptrace check bypass
- [`01-kernel/04-cifswitch-nss-privesc-defense.md`](01-kernel/04-cifswitch-nss-privesc-defense.md) — CIFSwitch（cifs.spnego 身份混淆与 root NSS 加载）防御
- [`01-kernel/04-cifswitch-nss-privesc.md`](01-kernel/04-cifswitch-nss-privesc.md) — CIFSwitch：cifs.spnego 身份混淆 → root 权限 NSS 加载
- [`01-kernel/05-pintheft-io-uring-page-cache-defense.md`](01-kernel/05-pintheft-io-uring-page-cache-defense.md) — PinTheft（RDS zcopy + io_uring 页缓存污染 LPE）防御
- [`01-kernel/05-pintheft-io-uring-page-cache.md`](01-kernel/05-pintheft-io-uring-page-cache.md) — RDS zcopy double-free + io_uring dangling struct page*：PinTheft 内核 LPE

### cheating — 游戏与对抗研究（10）

- [`cheating/01-memory-hacking-defense.md`](cheating/01-memory-hacking-defense.md) — 内存搜索与篡改防御（ObRegisterCallbacks / 数值加密 / IOMMU）
- [`cheating/01-memory-hacking.md`](cheating/01-memory-hacking.md) — 内存搜索与修改
- [`cheating/02-packet-interception-defense.md`](cheating/02-packet-interception-defense.md) — 封包拦截与重放防御（TLS Pinning / 协议双向校验 / 序列号抗重放）
- [`cheating/02-packet-interception.md`](cheating/02-packet-interception.md) — 封包拦截与修改
- [`cheating/03-esp-wallhack-rendering-defense.md`](cheating/03-esp-wallhack-rendering-defense.md) — 透视与 ESP 渲染防御（视野剔除 / 渲染管线完整性 / 覆盖窗口检测）
- [`cheating/03-esp-wallhack-rendering.md`](cheating/03-esp-wallhack-rendering.md) — 透视/ESP 渲染技术
- [`cheating/04-anti-cheat-bypass-defense.md`](cheating/04-anti-cheat-bypass-defense.md) — 反作弊绕过防御（内核回调加固 / 栈回溯 / ETW-Ti 与 HVCI）
- [`cheating/04-anti-cheat-bypass.md`](cheating/04-anti-cheat-bypass.md) — 反作弊系统绕过
- [`cheating/05-speedhack-time-manipulation-defense.md`](cheating/05-speedhack-time-manipulation-defense.md) — 加速与时间操控防御（多源时钟交叉校验 / 服务端 Tick 预算）
- [`cheating/05-speedhack-time-manipulation.md`](cheating/05-speedhack-time-manipulation.md) — 加速/时间操控

### crypto — 密码算法（5）

- [`crypto/01-algorithm-identification.md`](crypto/01-algorithm-identification.md) — 算法盲识别：从字节特征反推加密/哈希/压缩算法
- [`crypto/02-custom-obfuscation-reverse.md`](crypto/02-custom-obfuscation-reverse.md) — 自定义混淆/加密还原方法论
- [`crypto/03-prng-randomness-cracking.md`](crypto/03-prng-randomness-cracking.md) — 伪随机数生成器(PRNG)破解 — 从输出恢复内部状态与种子
- [`crypto/04-rsa-attack-family.md`](crypto/04-rsa-attack-family.md) — RSA 攻击族 — 按已知量选攻击 + [自检脚本](crypto/04-rsa-attack-family.selftest.py)
- [`crypto/05-web-crypto-abuse.md`](crypto/05-web-crypto-abuse.md) — Web Crypto API 滥用

### methodology — 逆向方法论（2）

- [`methodology/01-reverse-checklist-first-30-min.md`](methodology/01-reverse-checklist-first-30-min.md) — 拿到样本的前30分钟清单
- [`methodology/02-toolchain-decision-tree.md`](methodology/02-toolchain-decision-tree.md) — 按信号选工具决策树

### protocol — 协议逆向（4）

- [`protocol/01-unknown-protocol-reverse.md`](protocol/01-unknown-protocol-reverse.md) — 未知协议逆向方法论
- [`protocol/02-protobuf-flatbuffers-reverse.md`](protocol/02-protobuf-flatbuffers-reverse.md) — Protobuf / FlatBuffers 无 Schema 逆向
- [`protocol/03-grpc-protobuf.md`](protocol/03-grpc-protobuf.md) — gRPC / Protobuf 攻击
- [`protocol/04-js-runtime-reversing.md`](protocol/04-js-runtime-reversing.md) — JS Runtime / Browser Reversing

### signature — 签名验证与防御（14）

- [`signature/00-overview-defense.md`](signature/00-overview-defense.md) — 签名验证纵深防御全景（强算法绑定 / 规范化 / 抗重放 / 业务账本闭环）
- [`signature/00-overview.md`](signature/00-overview.md) — Signature Forgery — 签名伪造与验证绕过全景手册
- [`signature/01-algorithm-defense.md`](signature/01-algorithm-defense.md) — 签名算法降级与混淆防御（服务端算法锁定 / 拒绝 alg=none / 密钥类型隔离）
- [`signature/01-algorithm.md`](signature/01-algorithm.md) — Signature Algorithm Attacks — 签名算法降级/混淆/None 攻击深度手册
- [`signature/02-implementation-defense.md`](signature/02-implementation-defense.md) — 签名验证实现缺陷防御（恒定时间比对 / 严格类型校验 / Fail-Closed）
- [`signature/02-implementation.md`](signature/02-implementation.md) — Signature Implementation Bugs — 签名实现缺陷深度手册
- [`signature/03-key-attacks-defense.md`](signature/03-key-attacks-defense.md) — 签名密钥生命周期防御（CSPRNG 强熵 / KMS 托管 / 客户端隔离与轮换）
- [`signature/03-key-attacks.md`](signature/03-key-attacks.md) — Key Attacks — 签名密钥攻击深度技术手册
- [`signature/04-canonicalization-defense.md`](signature/04-canonicalization-defense.md) — 签名规范化绕过防御（Verify-After-Parse / RFC 8785 JCS / HPP 拦截）
- [`signature/04-canonicalization.md`](signature/04-canonicalization.md) — Canonicalization Attacks — 签名规范化绕过
- [`signature/05-length-extension-defense.md`](signature/05-length-extension-defense.md) — 哈希长度扩展（HLE）防御（HMAC / KMAC / 非对称签名迁移）
- [`signature/05-length-extension.md`](signature/05-length-extension.md) — Hash Length Extension 攻击 — 深度技术手册
- [`signature/06-replay-nonce-defense.md`](signature/06-replay-nonce-defense.md) — 重放攻击与 Nonce/Timestamp 绕过防御（原子去重 / 严格时间窗 / 上下文绑定）
- [`signature/06-replay-nonce.md`](signature/06-replay-nonce.md) — Replay / Nonce / Timestamp — 重放攻击深度技术手册

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
固定输入与哈希 → 建立假设 → 单变量实验 → 独立脚本重放 → 输出 diff/hash → 证据归档
```
