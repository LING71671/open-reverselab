---
description: 24h unattended Web CTF loop runner
argument-hint: <target-url-or-domain> [case-name]
allowed-tools: Bash, Read, Write, Edit, MultiEdit, Glob, Grep, LS, WebFetch, WebSearch
---

# /ctf-24h

在 Claude Code 中对授权 Web/CTF 目标启动 24 小时全流程推进。

这个命令不是单纯提示词。它要求配合 Claude Code 的 `/loop` 使用：

- `/loop` 负责不中断地重复调度。
- `.claude/workflows/ctf-24h-round.js` 负责每次只跑一轮有界动作。
- `cases/<case>/ai_manifest.json` 负责 checkpoint / resume / stop 判断。

审批/权限不在这个提示词里解决；运行 Claude Code 时应启用无人值守/自动审批配置，例如允许本命令声明的工具、Bash、文件读写和网络探测。命令内部不等待人工确认。

如果本地还没配置无人值守 runner，先在仓库根目录执行：

```bash
python3 scripts/misc/setup_unattended_ctf_runner.py --overwrite
```

该命令会生成本地 `.codex/` 配置和 `.claude/settings.local.json`。

## 参数

```
/ctf-24h <target-url-or-domain> [case-name]
```

如果输入包含多个 target（逗号/空白/换行分隔），改用：

```text
/loop /ctf-24h-fleet <target1,target2,...> [fleet-name]
```

如果没有给 `case-name`，用目标 host 生成去标识化 slug。所有真实请求/响应、截图、日志和 flag 只写入本地
`cases/`、`exports/ctf-website/`、`notes/ctf-website/`、`reports/ctf-website/`，不要提交这些私有产物。

## 执行协议

1. 先解析 `$ARGUMENTS` 为：
   - `target`: 第一个参数，URL 或 domain。
   - `caseName`: 第二个参数；缺省时从 target host 生成 slug。
2. 先读：
   - `AI-USAGE.md`
   - `boards/ctf-website/AI-USAGE.md`
   - `kb/ctf-website/techniques/attack-network.md`
3. 初始化 case（如不存在）：
   ```bash
   python3 scripts/ctf-website/ctf_intake.py "$CASE_NAME" --url "$TARGET" --root .
   ```
4. 然后调用单轮 workflow：
   ```text
   workflow: ctf-24h-round
   args:
     target: <target>
     caseName: <caseName>
     maxActions: 4
     execute: true
   ```
5. 每发现一个信号，立即查知识库：
   ```bash
   python3 scripts/ctf-website/kb_router.py "<signal>"
   ```
6. 按攻击网并行推进，不要只走单链：
   - Recon / route discovery / JS endpoint mining
   - Auth/session/JWT
   - Injection: SQLi/NoSQLi/SSTI/HPP/CRLF
   - File/LFI/upload
   - SSRF/internal metadata
   - CVE fingerprint -> graph -> chain
   - Flag path validation
7. 每轮都要写回：
   - `cases/<case>/ai_manifest.json`
   - `notes/ctf-website/<case>/`
   - `reports/ctf-website/<case>/`
   - 必要的 raw request 到 `exports/ctf-website/<case>/requests/`

## `/loop` 使用方式

在 Claude Code 中推荐这样启动：

```text
/loop /ctf-24h <target-url-or-domain> <case-name>
```

如果你的 Claude Code 版本要求先进入 loop，再输入命令，则使用：

```text
/loop
/ctf-24h <target-url-or-domain> <case-name>
```

每轮 workflow 必须输出以下状态之一：

- `CONTINUE`: 还有可执行路径，下一轮继续。
- `DONE`: 已拿到 flag 或完成报告，停止 `/loop`。
- `EXHAUSTED`: 24h 预算耗尽、全部路径耗尽、目标长期不可达或运行器缺少关键能力且无替代路径。

## 停止条件

- 已拿到 flag 并完成复现报告。
- 24 小时预算耗尽。
- 目标不可达且重试/备用路径均有证据。
- 攻击网全部路径都有证据表明不可达/不可利用。

## 输出要求

最终输出中文摘要，包含：

- case 路径
- 已确认攻击链
- flag/关键证据位置
- 失败路径与 dead ends
- 后续可继续的入口
