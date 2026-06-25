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

## 证据输出

- 原始扫描输出：`exports/ctf-website/<case>/`
- 筛选后的发现：`notes/ctf-website/<case>/`
- 最终利用链：`reports/ctf-website/<case>/`
