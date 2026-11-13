# Windows AV Evasion Reference Scripts [Track: RED]

本目录收录对应攻击面文档 `kb/red/pe-reverse/techniques/09-av-evasion/01-ai-powered-evasion.md` 的 **RED** 轨参考模板，仅供受控隔离实验室用于检测规则校准与对等验证。

- **Track**: `RED`
- **Paired BLUE Detector**: [`../detect_evasion_indicators.py`](../detect_evasion_indicators.py)
- **Paired BLUE KB**: `kb/blue/pe-reverse/techniques/09-av-evasion/01-evasion-indicator-detection.md`

## 文件清单

- `shellcode-patch.py` — 同义指令替换与花指令注入（RED）
- `shellcode-encrypt.py` — XOR / RC4 / S-Box 多层加密（RED）
- `shellcode-obfuscate.py` — UUID / IPv4 / IPv6 / MAC 伪装编码（RED）
- `loader.c` — Direct Syscall / VEH / 反沙箱加载器模板（RED）
- `merge_loader.py` — 加载器模板拼装脚本（RED）
