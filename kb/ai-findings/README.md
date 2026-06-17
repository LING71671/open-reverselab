# AI Findings

这里不是命令流水账；只记录实战中可复用的发现、坑点、打法、工具选择经验。

## Record rule

当出现以下情况，AI 必须记录 finding：

- 发现一个可复用攻击路径、分析路径、工具组合或排障方法。
- 某工具在特定环境下失败/弹窗/阻塞，并找到稳定替代或 safe probe。
- 某类目标的指纹能稳定触发某个 CVE/漏洞链/逆向流程。
- 一条路径被证据排除，能避免以后重复踩坑。

## Latest findings

> 以下为示例条目。实战发现通过 `python scripts/misc/ai_finding.py add` 自动追加。

| Time | Board | Kind | Title | Keywords | Confidence |
|---|---|---|---|---|---|
| — | — | — | 暂无记录 | — | — |

## Commands

```powershell
python scripts/misc/ai_finding.py add --board ctf-website --kind tactic --title "..." --trigger "..." --finding "..." --evidence "..." --reuse "..." --keyword k1 --keyword k2
python scripts/misc/ai_finding.py search cve geoserver chain
python scripts/misc/ai_finding.py list --board ctf-website
```
