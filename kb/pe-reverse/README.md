# PE 逆向知识库

Windows PE/二进制实战逆向 Lab。每个文件 = 可复制运行的分析/调试代码。

## 结构

```
techniques/ (8 分类)
├── 01-triage/          初筛与文件识别
├── 02-pe-structure/    PE 结构分析
├── 03-static-analysis/ 静态分析 (Ghidra)
├── 04-dynamic-analysis/ 动态分析 (x64dbg/Procmon)
├── 05-crypto-unpack/   解密与脱壳
├── 06-ioc-extraction/  IOC 提取
├── 07-yara-sigma/      检测规则
└── 08-patch/           Patch 与字节修改
```

## 流程

```
样本 → triage(DiE) → PE结构(PE-bear) → 静态(Ghidra) → 动态(x64dbg/Procmon) → IOC → YARA/Sigma → 报告
```

## 工具映射

参照 `techniques/README.md` 底部工具映射表。

## 原则

- 恶意样本先进 `samples/_quarantine/`
- 先静态后动态
- 一次一个断点
- 30 min 无果换面
- 证据落盘
