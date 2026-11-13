# 给 AI 的安装提示词

把下面整段复制给 Codex / Claude Code / 其他 AI Agent，让它帮你完成 ReverseLab 首次安装和检查。

```text
你是我的 ReverseLab 安装助手。请在我的电脑上完成 open-reverselab 的首次安装、检查和交付，要求如下：

0. 先确认我的操作系统（Windows / macOS / Linux），后续所有安装命令按平台选择执行。

目标：
1. 如果我还没有仓库，请把 https://github.com/LING71671/open-reverselab.git 克隆到一个稳定目录，例如 <workspace>/open-reverselab。
2. 如果我已经有仓库，请直接使用现有的 open-reverselab 文件夹，不要重复克隆。
3. 首次安装检查（按平台）：
   - Windows：优先运行根目录的 START_HERE.bat；如果你在终端环境里操作，也可以运行：
     python scripts/misc/first_run_check.py --write-report
     uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
     powershell -NoProfile -ExecutionPolicy Bypass -File scripts/misc/start_here.ps1
   - macOS / Linux：没有 .bat/.ps1 入口，直接运行（Python/uv 均跨平台）：
     python3 scripts/misc/first_run_check.py --write-report
     uv run --project tools/skills/mcp/ReverseLabToolsMCP python3 scripts/misc/mcp_smoke_check.py --write-report
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
4. 如果要安装板块工具（apktool/jadx/DiE/x64dbg 等），按平台处理：
   - Windows：先问我安装偏好：
       - 一键全装（省事）：.\scripts\misc\install_tools.ps1 -All
       - 按需安装（精准）：告诉我需要哪个方向再执行
           .\scripts\misc\install_tools.ps1 -CTF
           .\scripts\misc\install_tools.ps1 -Android
           .\scripts\misc\install_tools.ps1 -Windows
           .\scripts\misc\install_tools.ps1 -Common
   - macOS / Linux：没有一键安装脚本；按 tools/<board>/README.md 手动安装
     （Ghidra/Cutter/jadx/apktool/DiE 均有 mac/Linux 版，下载解压到 tools/ 对应目录并
     在 tools/bin/ 创建启动脚本或加入 PATH）
5. VMP 专项工具（NoVmp/unidbg/ScyllaHide 等）同样先问我安装偏好，二选一：
   [A] 一键安装：所有 VMP 工具一次装齐（公共库 + PE 组 + Android 组），装完统一验证
   [B] 按需安装：只装当前样本需要的组（按形态判定），最小集
   两种模式共同遵守（先说明用途再装；装完逐项验证；失败明确报告，不假装成功；
   未验证成功的工具标注"未验证"，不要当作已可用）：
   5.0 先查现状，只装缺失项（不要重复安装）：
       - MCP python_re_tool_status 查看已装 Python 库
       - MCP toolbox_list / 检查 tools/ 下已有目录
       - 已装且版本满足的直接跳过
   5.1 工具清单：
       a. 公共 Python 逆向库（优先 MCP python_re_tool_install，或 pip install --user；
          验证：python -c "import angr, unicorn, capstone, frida"）：
          angr、unicorn、capstone、frida
          Triton：未列入 MCP allowlist，且 PyPI 的 triton 包名与 OpenAI GPU 编译器冲突；
          需要时从 https://github.com/JonathanSalwan/Triton 源码构建（依赖 CMake/LLVM），
          或先用 angr 代替 DSE。
       b. PE 组（x64dbg 反调试/静态去虚拟化，按平台）：
          - Windows：
            ScyllaHide（必装）: https://github.com/x64dbg/ScyllaHide/releases
              → 解压到 tools/windows/x64dbg/plugins/；验证：插件菜单出现并启用全部隐藏选项
            NoVmp / NoVmpy: git clone --recursive https://github.com/can1357/NoVmp
              → tools/windows/NoVmp，Visual Studio 2022 构建 Release x64；
              NoVmpy: pip install --user novmpy（PyPI 未发布则 git clone
              https://github.com/wallds/NoVmpy）；
              验证：NoVmp.exe <样本> <函数RVA> 输出 .devirt.exe / .ll
            bochscpu（可选）: https://github.com/x64dbg/bochscpu/releases → plugins/；
              验证：插件菜单出现 bochscpu
          - macOS / Linux（x64dbg 系工具不可用，用替代）：
            动态调试：GDB（Linux）/ LLDB（macOS），或 rizin（跨平台）
            反调试绕过：Frida（跨平台；kb/pe-reverse/techniques/04-dynamic-analysis/
              05-anti-debug-bypass.md 的 Frida 脚本同样适用）
            静态 devirt：优先 NoVmpy（pip install --user novmpy，跨平台）；
              NoVmp 在 Linux 可用 CMake 构建（依赖 vcpkg，较复杂，非必须）
       c. Android 组（so 模拟 trace/脱壳摸底）：
          unidbg（主路线，需 JDK 17+）: git clone --depth 1
            https://github.com/zhkl0228/unidbg → tools/android/unidbg；
            验证：编译并运行 README 的 Utilities64 示例，能输出指令 trace
          BlackDex（必装）: https://github.com/CodingGay/BlackDex/releases
            → 安装 APK 到设备；验证：设备桌面出现图标并可启动
          Youpk / FART（仅抽取壳深度还原，可选）: 需要定制 ROM 或特定设备
            （Youpk 仅 Pixel 1 刷机；FART 有 frida 版），装前先问我是否有对应设备
          frida-server: 用 MCP android_frida_ensure_server 部署，无需手动下载
   [A] 一键安装执行：5.0 查现状 → 安装公共库 + PE 组 + Android 组全部项
       （Youpk/FART 除外，仍需先问设备）→ 逐项验证 → 按下文汇报清单汇报
   [B] 按需安装执行：
       5.2 先判定样本形态（不确定时先读判定条目）：
           - 形态 A：PE 虚拟化（VMP 2.x/3.x x64）→ 只装 PE 组
           - 形态 B：Android 商业 dex2c/VMP 壳 → 只装 Android 组
           - 形态 C：Android 下 VMProtect 保护的 so → PE 组思路（ARM64 适配）+ Android 组
           - 判定依据：kb/shared/pe-reverse/techniques/05-crypto-unpack/02-vmp-virtualization-analysis.md
                       kb/shared/apk-reverse/techniques/07-packer/03-vmp-dex2c-detection.md
       5.3 按形态安装对应组 → 逐项验证 → 按下文汇报清单汇报
   （[A][B] 均适用）安装完成后按清单汇报每一项：工具名 → 安装方式 → 验证命令及输出
   （或失败原因与修复建议），并把版本、安装路径、验证结果记录到 notes/ 供后续分析引用。
   完整分析流程参考知识库条目：
       kb/shared/pe-reverse/techniques/05-crypto-unpack/03-vmp-devirtualization-toolchain.md
       kb/shared/apk-reverse/techniques/07-packer/04-vmp-dump-trace-recovery.md
       kb/shared/apk-reverse/techniques/07-packer/05-vmp-anti-debug-bypass.md

请按步骤执行，并把每一步的结果用简短清单汇报给我。遇到失败时，先给出原因和修复建议，再继续能继续的部分。
```
