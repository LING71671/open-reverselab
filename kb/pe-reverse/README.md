# PE 逆向知识库

Windows PE/二进制实战逆向 Lab。每个文件 = 可复制运行的 C++/分析代码。

## 结构

```
techniques/ (9 files, 5 分类)
├── 01-triage/           AOB 特征码扫描
├── 02-pe-structure/     PE 头解析与节区定位
├── 03-static-analysis/  结构体重建 + 反汇编/JIT汇编
├── 04-dynamic-analysis/ DLL注入 + TrampolineHook + 外部内存读写
├── 05-crypto-unpack/    PE 脱壳与内存 Dump
├── 06-ioc-extraction/   待补充
├── 07-yara-sigma/       待补充
└── 08-patch/            Code Patch 与字节修改
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
