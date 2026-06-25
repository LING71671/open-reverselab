# Tool Binaries / Wrappers

工具启动脚本。`tools/bin/` 存放指向仓库内脚本的 portable `.bat` wrapper，以及 `install_tools.ps1` 为外部工具生成的快捷方式。

## 首次 clone

核心 lab 脚本无需下载外部工具，先运行：

```powershell
.\scripts\misc\bootstrap.ps1
```

会生成（或使用已提交的）：

- `ai_context.bat` → `scripts/misc/ai_context.py`
- `ai_tool.bat` → `scripts/misc/ai_tool.py`
- `ai_finding.bat` → `scripts/misc/ai_finding.py`
- `ai_toolcheck.bat` → `scripts/misc/ai_toolcheck.py`

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

外部工具示例：

```bat
@echo off
java -jar "%~dp0..\android\apktool\apktool.jar" %*
```
