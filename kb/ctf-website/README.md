# Web CTF 知识库

Web CTF / 授权网站安全技术库，共 **23 类、97 篇正文**。

## 入口

- [完整技术索引](techniques/README.md)
- [Web 攻击网](techniques/attack-network.md)
- [前 30 分钟 Checklist](checklists/web-ctf-first-30-min.md)
- [支付 CTF Playbook](checklists/payment-ctf-playbook.md)

## 流程

```text
Recon → Fingerprint → kb_router → 多路径最小探针 → 服务端副作用/Flag 验证 → 证据落盘
```

```powershell
python scripts/ctf-website/kb_router.py "<发现的信号>"
python scripts/misc/kb_doc_audit.py
```

技术文档要求可运行示例、工作流、证据闭环和 MCP 工具映射；真实 case、凭据和日志不得迁入公共知识库。
