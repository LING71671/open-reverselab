# PE 逆向技术库

Windows PE/二进制实战逆向 Lab。每个文件 = 可复制运行的分析/调试代码。

## 分类索引 (8 分类)

### 01-triage — 初筛与文件识别
- 待补充：DiE 使用、hash 计算、编译器/语言识别、壳签名检测

### 02-pe-structure — PE 结构
- 待补充：PE-bear 使用、节区分析、导出表/导入表、重定位、资源解析

### 03-static-analysis — 静态分析 (Ghidra)
- 待补充：Ghidra 项目配置、函数识别、交叉引用、反编译技巧、脚本自动化

### 04-dynamic-analysis — 动态分析
- 待补充：x64dbg 断点策略、Procmon 过滤、内存 dump、反调试绕过

### 05-crypto-unpack — 解密与脱壳
- 待补充：常见加密算法识别、DLL 注入点、内存 dump、壳特征、脱壳脚本

### 06-ioc-extraction — IOC 提取
- 待补充：IP/域名/URL 提取、文件路径、注册表键、互斥体、管道名

### 07-yara-sigma — 检测规则
- 待补充：YARA 规则模板、Sigma 规则模板、基于字符串/导入表/节区特征

### 08-patch — Patch 与修改
- 待补充：字节 patching、NOP 填充、条件跳转修改、常量替换

## 工具映射

```
tools/common/ghidra/           → 反编译器
tools/windows/Cutter/          → 反汇编
tools/windows/PE-bear/         → PE 结构
tools/windows/die/             → 文件识别
tools/windows/HxD/             → 十六进制编辑
tools/windows/ProcessMonitor/  → 进程监控
tools/windows/x64dbg/          → 动态调试
scripts/windows/               → 分析脚本
templates/notes/windows-pe-analysis.md → 笔记模板
```

## 分析链总览

```
样本 → DiE triage → PE-bear 结构 → Ghidra 静态 → x64dbg 动态 → Procmon 行为 → IOC 提取 → YARA/Sigma → 报告
```
