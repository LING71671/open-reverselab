# Claude Code Web CTF Workflows

本目录是 Claude Code / Codex 在该文件夹内运行 Web CTF 的 workflow 层。Python 脚本只负责
manifest/checkpoint/status 这种确定性辅助；攻击执行与长跑调度应优先走 workflow。

## 24h 调度层

| Workflow | 作用 |
|---|---|
| `ctf-24h-round` | 单目标 worker：读取 manifest → autopilot → attack-router → status |
| `ctf-24h-fleet` | 多目标 fleet：按 batch 并行调度多个 `ctf-24h-round` |
| `ctf-full-pipeline` | 一次性全流程：资产 → DoS → 漏洞挖掘 → 验证 → 报告 |

## 攻击 worker 层

| Workflow | 覆盖 KB / 攻击面 |
|---|---|
| `ctf-attack-router` | 根据信号/focus 路由到下面的攻击 worker |
| `ctf-attack-recon` | `01-recon`, `17-api-attacks`, `19-dns-email` |
| `ctf-attack-auth` | JWT, OAuth/OIDC, SAML, Host Header, LDAP, session/cookie |
| `ctf-attack-injection` | SQLi/NoSQLi/SSTI/GraphQL/HPP/CRLF/Prototype Pollution/gRPC |
| `ctf-attack-file_ssrf` | LFI/path traversal/upload/XXE/SSRF/open redirect |
| `ctf-attack-client` | XSS/CORS/CSP/CSRF/postMessage/WebSocket/Web Crypto/admin bot |
| `ctf-attack-api_business` | API discovery/IDOR/BAC/mass assignment/rate limit/payment/signature |
| `ctf-attack-cve_cloud_dos` | CVE graph/cloud/K8s/Lambda/CI/CD/supply-chain/DoS/database |

## 使用

单目标：

```text
/loop /ctf-24h <target-url-or-domain> <case-name>
```

多目标：

```text
/loop /ctf-24h-fleet <target1,target2,...> <fleet-name>
```

每个 target 独立 manifest：

```text
cases/<case>/ai_manifest.json
```

每轮必须输出：

```text
STATUS: CONTINUE|DONE|EXHAUSTED
```
