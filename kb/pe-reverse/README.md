# PE 逆向知识库

Windows PE/二进制逆向技术库，共 **8 类、18 篇正文**。

## 入口

- [完整技术索引](techniques/README.md)
- Board：`boards/windows/README.md`
- 模板：`templates/notes/windows-pe-analysis.md`

## 分析链

```text
样本哈希/类型/保护 → Ghidra 静态分析 → x64dbg/Frida/Procmon 动态验证
→ 脱壳/配置恢复 → IOC → YARA/Sigma → Patch 副本 → 报告
```

`06-ioc-extraction` 与 `07-yara-sigma` 已有正文，不再是待补充分类。原始样本只读保留，动态输出和 patch 必须与原件分离。
