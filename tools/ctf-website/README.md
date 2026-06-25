# CTF Website Tools

Web 安全测试 / CTF 工具集。

## 工具列表

| 工具 | 用途 | 安装说明 |
|---|---|---|
| Burp Suite | HTTP 代理/拦截 | [burp/README.md](burp/README.md) |
| sqlmap | SQL 注入自动化 | [sqlmap/README.md](sqlmap/README.md) |
| dirsearch | Web 目录爆破 | [dirsearch/README.md](dirsearch/README.md) |
| nmap | 端口/服务扫描 | [nmap/README.md](nmap/README.md) |
| jwt_tool | JWT 分析/攻击 | [jwt_tool/README.md](jwt_tool/README.md) |
| tplmap | 模板注入检测 | [tplmap/README.md](tplmap/README.md) |
| exploitdb | 漏洞库本地查询 | [exploitdb/README.md](exploitdb/README.md) |

## 其他工具（Go 生态）

以下工具建议用 `go install` 或下载预编译二进制放到 `bin/`：

| 工具 | 安装命令 |
|---|---|
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` |
| gobuster | `go install github.com/OJ/gobuster/v3@latest` |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |

## 其他工具（Rust 生态）

| 工具 | 安装命令 |
|---|---|
| feroxbuster | `cargo install feroxbuster` 或下载预编译版 |

## 辅助目录

| 目录 | 用途 |
|---|---|
| `payloads/` | 通用 payload 集合 |
| `wordlists/` | 字典文件 |
| `scripts/` | 浏览器 JS 辅助脚本 |
| `_downloads/` | 工具下载缓存 |
