# 通用逆向技术库

跨平台逆向技术库。覆盖密码算法、协议、研究型对抗与方法论。

## 完整目录（4 类 / 12 篇）

### cheating — 游戏与对抗研究（5）

- [`cheating/01-memory-hacking.md`](cheating/01-memory-hacking.md) — 内存搜索与修改
- [`cheating/02-packet-interception.md`](cheating/02-packet-interception.md) — 封包拦截与修改
- [`cheating/03-esp-wallhack-rendering.md`](cheating/03-esp-wallhack-rendering.md) — 透视/ESP 渲染技术
- [`cheating/04-anti-cheat-bypass.md`](cheating/04-anti-cheat-bypass.md) — 反作弊系统绕过
- [`cheating/05-speedhack-time-manipulation.md`](cheating/05-speedhack-time-manipulation.md) — 加速/时间操控

### crypto — 密码算法（3）

- [`crypto/01-algorithm-identification.md`](crypto/01-algorithm-identification.md) — 算法盲识别：从字节特征反推加密/哈希/压缩算法
- [`crypto/02-custom-obfuscation-reverse.md`](crypto/02-custom-obfuscation-reverse.md) — 自定义混淆/加密还原方法论
- [`crypto/03-prng-randomness-cracking.md`](crypto/03-prng-randomness-cracking.md) — 伪随机数生成器(PRNG)破解 — 从输出恢复内部状态与种子

### methodology — 逆向方法论（2）

- [`methodology/01-reverse-checklist-first-30-min.md`](methodology/01-reverse-checklist-first-30-min.md) — 拿到样本的前30分钟清单
- [`methodology/02-toolchain-decision-tree.md`](methodology/02-toolchain-decision-tree.md) — 按信号选工具决策树

### protocol — 协议逆向（2）

- [`protocol/01-unknown-protocol-reverse.md`](protocol/01-unknown-protocol-reverse.md) — 未知协议逆向方法论
- [`protocol/02-protobuf-flatbuffers-reverse.md`](protocol/02-protobuf-flatbuffers-reverse.md) — Protobuf / FlatBuffers 无 Schema 逆向

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

```powershell
python scripts/misc/kb_doc_audit.py
```

## 标准工作流

```text
固定输入与哈希 → 建立假设 → 单变量实验 → 独立脚本重放 → 输出 diff/hash → 证据归档
```
