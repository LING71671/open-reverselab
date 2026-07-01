# CTF Website Tools AI Usage

这里是 Web CTF 工具落地区。AI 使用工具前先把 `tools/ctf-website/bin` 加到当前进程 PATH。

```powershell
$env:Path = "$PWD\tools\ctf-website\bin;$env:Path"
```

## 已验证工具

查看：

- `installed-tools.md`
- `installed-tools.json`
- `reports/ctf-website/toolcheck/version_verify_*.md`

## 工具分工

| 工具 | AI 使用场景 |
|---|---|
| `ffuf`, `gobuster`, `feroxbuster`, `dirsearch` | 路由、目录、参数、扩展名 fuzz |
| `httpx`, `katana` | HTTP 指纹、批量探测、爬取 |
| `nuclei` | 模板化弱点验证；CTF 中需人工复核 |
| `sqlmap` | SQLi 信号确认后自动化枚举 |
| `nmap` | 端口/服务/脚本探测 |
| `jwt_tool` | JWT alg/kid/jku/弱密钥/claim 修改 |
| `tplmap` | SSTI fingerprint 与自动化探测 |
| `searchsploit` | 本地 exploitdb 检索 |
| `Burp Suite` | 复杂认证态/手工 Repeater/Intruder；自动巡检只探测文件，不弹 GUI |

## MCP 接入链

Web/CTF 目标分析时优先走 MCP：

1. `kb_router(query, board="ctf-website")` 查技术文件。
2. `ctf_tool_status()` 检查 sqlmap/Burp wrapper 与本地安装状态。
3. Burp 或浏览器确认请求后，调用 `ctf_save_request(raw_request, case_name, filename)` 保存证据。
4. SQLi 自动化调用 `run_sqlmap_request(request_path, "--batch ...")`；普通工具调用用 `run_ctf_tool("sqlmap", "...")`。
5. `burp_status()` 只做无弹窗探测；需要打开 Burp GUI 时才显式调用 `burp_launch(launch=True)`。

## 证据输出

- 原始扫描输出：`exports/ctf-website/<case>/`
- 筛选后的发现：`notes/ctf-website/<case>/`
- 最终利用链：`reports/ctf-website/<case>/`
