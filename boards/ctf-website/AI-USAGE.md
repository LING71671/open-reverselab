# CTF Website AI Usage

做 Web CTF 时的 AI 工作约定。

## 核心原则

1. **先查知识库**：每个信号都先跑 `kb_router.py`，直接用技术文件里的伪代码
2. **多路径**：按 `attack-network.md` 的攻击网同时推进多条链
3. **证据落盘**：每个步骤的请求/响应、工具输出都保存到 `exports/ctf-website/`
4. **CVE 链**：发现版本指纹后联动 `cve_lookup.py` → `cve_graph.py` → `cve_chain_planner.py`

## 工具路径

- 工具安装状态查看：`tools/ctf-website/installed-tools.md`
- 工具 checklist：运行 `python scripts/misc/ai_toolcheck.py` 或 `.\scripts\ctf-website\ctf_toolcheck.ps1`
