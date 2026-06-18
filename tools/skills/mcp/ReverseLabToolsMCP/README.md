# ReverseLabToolsMCP

逆向实验室通用工具 MCP 服务器。为 AI Agent 提供文件分析、哈希计算、PE/DEX 解析、字符串提取、Procmon 过滤、Ghidra 集成等能力。

## 安装

```bash
cd tools/skills/mcp/ReverseLabToolsMCP
uv sync
# 或 pip install -r requirements.txt
```

或通过 `.mcp.json` 直接启动：
```json
{
  "reverse_lab_tools": {
    "command": "uv",
    "args": ["run", "--project", "tools/skills/mcp/ReverseLabToolsMCP", "python", "tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py"]
  }
}
```

仓库默认 `.mcp.json` 只启用随仓库发布、能够直接安装的
`reverse_lab_tools`。GhidraMCP 和 JSHookLocal 属于可选第三方组件，安装后可从
`.mcp.optional.example.json` 复制相应配置；默认配置不会引用尚不存在的文件。

## 工具列表

| 类别 | 工具 | 说明 |
|---|---|---|
| **样本管理** | `hash_file` | 计算 MD5/SHA1/SHA256 |
| | `sample_status` / `sample_set_status` | 样本生命周期 |
| | `sample_quarantine` | 移入隔离区 |
| | `unpack_intake` | 解包产物入库 |
| **PE 分析** | `pe_info` | PE 结构解析（节表/导入表/入口点） |
| | `die_scan` | Detect It Easy 文件类型识别 |
| | `strings_extract` | 字符串提取 |
| **Ghidra** | `ghidra_headless_analyze` | 后台自动分析 |
| | `ghidra_summary_import` | 导入已有分析摘要 |
| | `ghidra_function_list` | 函数列表 |
| | `ghidra_strings` | 字符串引用 |
| | `ghidra_xrefs` | 交叉引用 |
| | `ghidra_decompile` | 反编译函数 |
| | `ghidra_entry_points` | 入口点分析 |
| | `ghidra_call_graph` | 调用图导出 |
| **Patch** | `mcp_pattern_patch_smoke` | 模式补丁测试 |
| | `mcp_pe_patch_smoke` | PE 补丁测试 |
| | `mcp_rizin_write_smoke` | Rizin 写入测试 |
| | `mcp_mutation_smoke` | 变异测试 |
| **IOC** | `ioc_extract` | 从行为日志提取 IOC |
| | `yara_scan` / `yara_compile` | YARA 规则 |
| | `sigma_stub` | Sigma 规则存根 |
| **Procmon** | `procmon_filter` / `procmon_filter_preset` | 过滤器生成 |
| **工作流** | `triage_sample` | 一键样本 triage |
| | `crypto_unpack` | 加密算法识别和 unpack |
| | `debug_script` | 调试断点脚本生成 |
| | `analysis_note` | 自动生成分析笔记 |
| **Web CTF** | `http_probe` | HTTP 探测（header/body/cookie/指纹） |
| | `kb_router` | 按信号搜索知识库技术文件 |
| | `kb_read_file` | 读取技术文件完整内容 |
| | `kb_catalog` | 列出 KB 全部分类统计 |
| | `ctf_new_challenge` | 创建 CTF 题目 case |
| | `run_ctf_tool` | 运行 sqlmap/dirsearch/jwt_tool/tplmap |
| | `ctf_tool_status` | 检查 CTF 工具安装状态 |
| **工具** | `toolbox_list` | 列出可用二进制工具 |
| | `toolbox_run` | 运行工具 |
| | `mcp_self_update` | 更新自身配置 |
| **项目设置** | `project_skills_status` | 检查 skills/MCP 安装状态 + 推荐安装命令 |

## 路径约定

所有文件操作限制在项目根目录内。工具路径通过 `config.py` 自动发现，不硬编码版本号。

## 环境变量

| 变量 | 说明 |
|---|---|
| `REVERSELAB_HOST_PYTHON` | 宿主机 Python 路径（用于启动 GUI 工具） |
| `ANDROID_SDK_PLATFORM_TOOLS` | Android SDK platform-tools 路径 |
| `MUMU_SERIAL` | MuMu 模拟器 ADB 序列号，默认 `127.0.0.1:16384` |
