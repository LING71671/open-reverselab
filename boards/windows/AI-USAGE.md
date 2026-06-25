# Windows AI Usage

分析 Windows PE/二进制时的 AI 工作约定。

## 默认工具路径

- Ghidra: `tools/common/ghidra_*/`
- Cutter: `tools/windows/Cutter/`
- PE-bear: `tools/windows/PE-bear/`
- DiE: `tools/windows/die/`
- HxD: `tools/windows/HxD/`
- x64dbg: `tools/windows/x64dbg/`
- Procmon: `tools/windows/ProcessMonitor/`
- Scylla: `tools/windows/scylla/`

## 分析流程

1. 先做文件识别 (DiE/PE-bear)
2. Ghidra 静态分析，命名函数，标注关键逻辑
3. 需要动态验证时用 x64dbg 或 Frida
4. Procmon 采集行为日志 → `exports/windows/procmon/`
5. IOC 提取 → `exports/windows/iocs/`
6. YARA/Sigma 规则 → `exports/windows/yara/` / `exports/windows/sigma/`

## MCP 工具链（AI 可自动调用）

分析 Windows PE 样本时，优先用 MCP 工具自动完成机械步骤。工具路径和清单以 `tools/skills/mcp/ReverseLabToolsMCP/` 为准。

### 初筛与静态分析

| MCP 工具 | 作用 |
|---|---|
| `triage_pe` | 一键组合 hash/DiE/rz-bin info/sections/imports/strings，生成初筛报告 |
| `hash_file` | 计算 MD5/SHA1/SHA256 |
| `die_scan` | 文件类型/编译器/packer 识别 |
| `rizin_bin_info` / `rizin_sections` / `rizin_imports` / `rizin_strings` | PE 结构/节表/导入表/字符串提取 |
| `ghidra_headless_analyze` | 无头 Ghidra 导入+自动分析，导出 JSON summary |
| `ghidra_summary_functions` / `ghidra_summary_imports` / `ghidra_summary_strings` | 按条件过滤 Ghidra 分析结果 |
| `ghidra_summary_function_detail` | 读取单函数 callers/callees/decompile 证据 |
| `ghidra_summary_call_focus` | 按行为（network/file/crypto/antidebug）推荐函数阅读优先级 |

### 动态分析计划

| MCP 工具 | 作用 |
|---|---|
| `make_x64dbg_breakpoint_script` | 根据 triage/Ghidra summary 自动生成 x64dbg 断点脚本 → `scripts/windows/debug/` |
| `make_pe_crypto_unpack_plan` | 生成 PE 解密/去壳动态分析包（x64dbg 断点 + Frida hook + 函数队列） |
| `make_procmon_filters` | 根据样本导入表生成 Procmon 过滤方案 → `scripts/windows/procmon/` |

### 解包与 Payload 提取

| MCP 工具 | 作用 |
|---|---|
| `carve_payloads_from_dump` | 从 dump/decrypted buffer 自动 carve PE/DEX → `samples/unpacked/` |
| `extract_frida_buffers` | 从 Frida JSON 的 data_hex 落盘二进制 buffer，可选自动 carve |
| `make_crypto_replay_scaffold` | 从 Frida crypto 证据生成 Python 复现脚本 |
| `solve_crypto_from_evidence` | 自动尝试常见解密/hash/HMAC，落盘命中结果 |

### IOC 与检测规则

| MCP 工具 | 作用 |
|---|---|
| `extract_iocs_from_summary` | 从 Ghidra summary/triage/笔记提取 IOC → `exports/windows/iocs/` |
| `refine_ioc_sources` | IOC 按 static_confirmed/mixed/note_only 分层 |
| `make_yara_stub` | 生成 YARA 规则草案 → `exports/windows/yara/` |
| `make_sigma_stub` | 生成 Sigma 规则草案 → `exports/windows/sigma/` |

### 辅助

| MCP 工具 | 作用 |
|---|---|
| `triage_to_notes` | 根据 triage + Ghidra summary 自动生成 13 节分析笔记骨架 |
| `sample_full_workup` | **一键全流程**：triage → Ghidra → 重点函数 → x64dbg/Procmon 计划 → IOC → YARA/Sigma |
| `sample_autopilot_round` | 从 battleplan manifest 规划/执行下一轮逆向动作 |
| `toolbox_list` / `toolbox_launch` | 列出/启动 allowlist 中的 GUI 工具 |
| `procmon_start_capture` / `procmon_stop_capture` / `procmon_export_csv` | Procmon 采集控制 |
| `pe_address_to_offset` | PE file offset / RVA / VA 互转 |

### Patch 与修改

| MCP 工具 | 作用 |
|---|---|
| `patch_bytes` / `patch_pattern` / `patch_pe_bytes` | 按 offset/pattern/RVA 打补丁（自动复制到 patches 目录） |
| `rizin_write_bytes` / `rizin_assemble_patch` | Rizin 方式写字节/汇编→patch |
| `copy_sample_to_patches` | 复制样本到 patches 目录并记 audit log |
| `generate_patch_report` | 从 audit log 生成 Markdown patch report |

### 知识库

PE 逆向知识库位于 `kb/pe-reverse/`，当前覆盖 5 个分类 9 篇技术文件（每篇含可运行 C++/Frida 代码）。详见 `kb/pe-reverse/techniques/README.md`。
