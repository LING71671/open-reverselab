# Windows Scripts

Windows PE/二进制分析与防御脚本，按 `RED` / `BLUE` 双轨分类维护。

## 目录与双轨分类

- `[BLUE]` `detect_evasion_indicators.py` — 静态规避与混淆特征检测器（熵值、伪装表、Direct Syscall 桩、反沙箱 API），对应 `kb/blue/pe-reverse/techniques/09-av-evasion/01-evasion-indicator-detection.md`
- `[RED]` `av-evasion/` — 对抗演练/免杀样本生成参考脚本（仅供受控隔离实验室复现检测规则），对应 `kb/red/pe-reverse/techniques/09-av-evasion/01-ai-powered-evasion.md`
- `[BOTH]` `debug/` — x64dbg 断点配置/调试脚本
- `[BOTH]` `frida/` — Frida hook 脚本
- `[BOTH]` `procmon/` — Procmon 过滤器配置
