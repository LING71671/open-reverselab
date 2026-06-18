# APK Reverse AI Findings

APK 逆向实战中可复用的发现、坑点、打法、工具选择经验。

## Record rule

当出现以下情况，AI 必须记录 finding：

- 发现一个可复用的 APK 分析路径、Hook 模式、工具组合或排障方法。
- 某工具在特定 APK/Android 版本下失败/弹窗/阻塞，并找到稳定替代或 safe probe。
- 某类 APK 的指纹能稳定触发某个 crypto/unpack/加固逆向流程。
- 一条路径被证据排除，能避免以后重复踩坑。

## Latest findings

| Time | Kind | Title | Keywords | Confidence |
|---|---|---|---|---|
| — | — | 暂无记录 | — | — |

## Commands

```powershell
python scripts/misc/ai_finding.py add --board apk-reverse --kind tactic --title "..." --trigger "..." --finding "..." --evidence "..." --reuse "..." --keyword k1 --keyword k2
python scripts/misc/ai_finding.py search apk frida hook
python scripts/misc/ai_finding.py list --board apk-reverse
```
