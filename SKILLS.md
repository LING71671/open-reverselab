# Recommended Skills

本项目推荐安装以下 Claude Code skills，安装后可直接在项目内通过 `/skill-name` 调用。

## 核心 Skills

| Skill | 用途 | 安装 |
|---|---|---|
| **reverse-lab** | 逆向工程全流程：PE/ELF/APK 分析、Ghidra、x64dbg、Frida | `claude plugins install reverse-lab` |
| **ctf** | CTF 竞赛辅助：Web/Binary/Crypto/Misc 全题型 | `claude plugins install ctf` |

## 可选 Skills

| Skill | 用途 | 安装 |
|---|---|---|
| **android-reverse-engineering** | Android APK/DEX 专项逆向 | `claude plugins install android-reverse-engineering-skill` |
| **gdb** | GDB 调试辅助 | `claude plugins install gdb` |

## 验证

```bash
claude plugins list
```

或通过 MCP 检查：

```bash
# 启动 MCP 后让 AI 调用 project_skills_status
```

## 搭配 codex-session-patcher

使用 [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) 配置项目后，AI Agent 会自动路由到对应板块的 `AI-USAGE.md`，skill 提供执行能力，KB 提供知识参考。
