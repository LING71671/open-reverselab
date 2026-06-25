# CTF Website Board

Web CTF / 网站渗透测试分析板块。

## 工具链

- `tools/ctf-website/burp/` — Burp Suite 代理
- `tools/ctf-website/dirsearch/` — 目录爆破
- `tools/ctf-website/sqlmap/` — SQL 注入自动化
- `tools/ctf-website/nmap/` — 端口扫描
- `tools/ctf-website/jwt_tool/` — JWT 分析
- `tools/ctf-website/tplmap/` — 模板注入检测
- `tools/ctf-website/exploitdb/` — 漏洞库本地查询

## 分析流程

1. Recon → HTTP 流量、端口、目录、指纹
2. 按信号查知识库 → `python scripts/ctf-website/kb_router.py "<信号>"`
3. 阅读 `kb/ctf-website/techniques/attack-network.md`
4. 多路径并行探测
5. 工具输出 → `exports/ctf-website/`
6. 最终报告 → `reports/ctf-website/`

## 参考

- 知识库：`kb/ctf-website/`
- Checklist：`kb/ctf-website/checklists/web-ctf-first-30-min.md`
- Case 模板：`templates/cases/ctf-web-challenge.md`
