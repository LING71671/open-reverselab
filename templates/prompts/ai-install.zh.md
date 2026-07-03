# 给 AI 的安装提示词

把下面整段复制给 Codex / Claude Code / 其他 AI Agent，让它帮你完成 ReverseLab 首次安装和检查。

```text
你是我的 ReverseLab 安装助手。请在我的电脑上完成 open-reverselab 的首次安装、检查和交付，要求如下：

目标：
1. 如果我还没有仓库，请把 https://github.com/LING71671/open-reverselab.git 克隆到一个稳定目录，例如 <workspace>/open-reverselab。
2. 如果我已经有仓库，请直接使用现有的 open-reverselab 文件夹，不要重复克隆。
3. Windows 用户优先运行根目录的 START_HERE.bat；如果你在终端环境里操作，也可以运行：
   python scripts/misc/first_run_check.py --write-report
   uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/misc/start_here.ps1
4. 必须确认 .mcp.json 里存在 mcpServers.reverse_lab_tools。
5. 必须确认 reverse_lab_tools 的入口脚本存在：
   tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py
6. 必须检查 Python、Git、uv 是否可用；缺失时给我明确安装建议，不要假装已经成功。
7. 必须生成或检查 reports/misc/first-run-report.json，并告诉我 overall、warn、fail 数量。
8. 必须生成或检查 reports/misc/mcp-smoke-report.json，并确认 kb_router、kb_read_file、project_skills_status 是 PASS。
9. 最后明确告诉我下一步：
   现在可以用 Codex APP 打开这个文件夹，或在 Claude Code 中 cd 到这里。

安全和公开仓库边界：
1. 不要提交、上传或复制我的私人 cases、samples、logs、exports、reports、截图、真实目标、token、Cookie、账号或本机绝对路径。
2. 不要把运行日志和 first-run-report.json 加入 Git 提交。
3. 如果你需要修改仓库文件，先说明目的；提交前必须运行：
   python scripts/misc/public_release_check.py
   python scripts/misc/lab_healthcheck.py
4. 如果要安装板块工具，先问我需要哪个方向：
   .\scripts\misc\install_tools.ps1 -CTF
   .\scripts\misc\install_tools.ps1 -Android
   .\scripts\misc\install_tools.ps1 -Windows
   .\scripts\misc\install_tools.ps1 -Common

请按步骤执行，并把每一步的结果用简短清单汇报给我。遇到失败时，先给出原因和修复建议，再继续能继续的部分。
```
