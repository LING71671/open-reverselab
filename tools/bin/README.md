# Tool Binaries / Wrappers

工具启动脚本。`tools/bin/` 存放指向仓库内脚本的 wrapper：

- Windows：portable `.bat` wrapper，以及 `install_tools.ps1` 为外部工具生成的快捷方式。
- macOS/Linux：无扩展名的 POSIX shell wrapper；外部 CLI 工具优先从当前 `PATH` 解析。

## 首次 clone

核心 lab 脚本无需下载外部工具，先运行：

```powershell
.\scripts\misc\bootstrap.ps1
```

macOS/Linux：

```sh
./scripts/misc/bootstrap.sh
export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"
```

会生成（或使用已提交的）：

- `ai_context.bat` → `scripts/misc/ai_context.py`
- `ai_tool.bat` → `scripts/misc/ai_tool.py`
- `ai_finding.bat` → `scripts/misc/ai_finding.py`
- `ai_toolcheck.bat` → `scripts/misc/ai_toolcheck.py`

macOS/Linux 同时提供无扩展名 wrapper：

- `ai_context` → `scripts/misc/ai_context.py`
- `ai_tool` → `scripts/misc/ai_tool.py`
- `ai_finding` → `scripts/misc/ai_finding.py`
- `ai_toolcheck` → `scripts/misc/ai_toolcheck.py`

各 board 的外部工具 wrapper 由 `install_tools.ps1` 创建。验证：

```powershell
python scripts/misc/ai_toolcheck.py --board misc
```

## Wrapper 约定

Portable wrapper 使用 `%~dp0` 相对路径，不硬编码机器绝对路径：

```bat
@echo off
python "%~dp0..\..\scripts\misc\ai_context.py" %*
```

POSIX wrapper 使用脚本所在目录推导仓库根目录：

```sh
#!/usr/bin/env sh
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
exec "${PYTHON:-python3}" "$ROOT/scripts/misc/ai_context.py" "$@"
```

外部工具示例：

```bat
@echo off
java -jar "%~dp0..\android\apktool\apktool.jar" %*
```

发布包建议拆分：

- Windows release：包含 `.bat` wrapper、Windows GUI/PE 工具链和 PowerShell 安装脚本。
- macOS/Linux release：包含 shell wrapper、Python/MCP core、Web/Android CLI 工具的 native PATH 探测。
