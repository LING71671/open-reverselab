# CVE 技术库（Web / 内核 / 本地）

## 入口

- Board: `boards/ctf-website/README.md`
- 模板: `templates/notes/ctf-website-writeup.md`

## 完整目录

### 09-cve — CVE 实战（6）

- [`01-browser-sandbox-escape.md`](../../../../red/ctf-website/techniques/09-cve/01-browser-sandbox-escape.md) — Blink UAF → 渲染进程沙箱逃逸（CVE-2026-2441）
- [`02-redis-zipmap-rce.md`](../../../../red/ctf-website/techniques/09-cve/02-redis-zipmap-rce.md) — Redis RESTORE zipmap 长度前缀不一致（CVE-2026-25243）
- [`03-cpanel-caldav-traversal.md`](../../../../red/ctf-website/techniques/09-cve/03-cpanel-caldav-traversal.md) — cPanel CalDAV 预认证路径穿越（CVE-2026-29205）
- [`04-nezha-path-traversal-jwt.md`](../../../../red/ctf-website/techniques/09-cve/04-nezha-path-traversal-jwt.md) — Nezha Monitoring 路径遍历 + JWT 伪造（CVE-2026-53519）
- [`05-litellm-privesc.md`](../../../../red/ctf-website/techniques/09-cve/05-litellm-privesc.md) — LiteLLM API Key 生成 + 角色自提权（CVE-2026-47101）
- [`06-nginx-rewrite-heapoverflow.md`](../../../../red/ctf-website/techniques/09-cve/06-nginx-rewrite-heapoverflow.md) — NGINX rewrite set 缓冲区长度错配堆溢出（CVE-2026-42945）

### 11-dos — 拒绝服务（2）

- [`11-dos/01-valkey-resp-dos.md`](../../../../red/ctf-website/techniques/11-dos/01-valkey-resp-dos.md) — Valkey RESP 协议预认证 DoS（CVE-2026-27623）
- [`02-http2-bomb.md`](../../../../red/ctf-website/techniques/08-infra/http2-attacks.md) — HTTP/2 HPACK 索引引用放大 + 流控停滞（CVE-2026-49975）

## 文档质量基线

每篇正文必须包含：H1 标题、受影响版本、根因分析、技术细节/代码、攻击链、复现、Evidence、MCP 工具映射。

```powershell
python scripts/misc/kb_doc_audit.py
```
