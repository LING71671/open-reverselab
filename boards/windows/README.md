# Windows Board

Windows PE/二进制逆向分析板块。

## 工具链

- `tools/common/` — Ghidra 反编译器（通过 install_tools.ps1 -Common 安装）
- `tools/windows/Cutter/` — Rizin/Cutter 反汇编
- `tools/windows/PE-bear/` — PE 结构分析
- `tools/windows/die/` — Detect It Easy 文件类型识别
- `tools/windows/HxD/` — 十六进制编辑器
- `tools/windows/x64dbg/` — 用户态调试器（手动安装）
- `tools/windows/ProcessMonitor/` — 进程行为监控
- `tools/windows/scylla/` — IAT 修复/dump（手动安装）

## MCP 工具

Windows PE 分析有一整套 MCP 自动化工具链，涵盖初筛、Ghidra 静态分析、调试脚本生成、Procmon 过滤方案、IOC 提取和 YARA/Sigma 规则生成。详见 [AI-USAGE.md](AI-USAGE.md)。

## 知识库

PE 逆向知识库 `kb/pe-reverse/`：9 篇 C++/Frida 可运行技术文件，覆盖 triage、PE 结构、静态分析、动态分析、脱壳/dump、patch。

## 分析流程

1. 样本放入 `samples/windows/`（恶意样本先进 `samples/_quarantine/`）
2. 初始识别：DiE → PE-bear → strings
3. 静态分析：Ghidra 反编译 → 笔记写入 `notes/windows/`
4. 动态分析：x64dbg/Procmon → 脚本放入 `scripts/windows/`
5. Patch → 产物放入 `patches/windows/`
6. IOC/YARA/Sigma → `exports/windows/`
7. 最终报告 → `reports/windows/`

## 参考

- 笔记模板：`templates/notes/windows-pe-analysis.md`
- 通用分析模板：`templates/notes/sample-analysis.md`
- AI 操作指南：[AI-USAGE.md](AI-USAGE.md)
