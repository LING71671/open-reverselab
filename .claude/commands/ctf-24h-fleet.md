---
description: 24h unattended multi-target Web CTF fleet loop runner
argument-hint: <target1,target2,...> [fleet-name]
allowed-tools: Bash, Read, Write, Edit, MultiEdit, Glob, Grep, LS, WebFetch, WebSearch
---

# /ctf-24h-fleet

对多个或单个 Web/CTF 目标启动无人值守 24h fleet workflow。它是 `/ctf-24h`
的上层调度器：每个目标独立 case/manifest，fleet workflow 按 batch 并行调用
`ctf-24h-round`。

## 用法

```text
/loop /ctf-24h-fleet <target1,target2,...> <fleet-name>
```

或在 Claude Code 中先进入 loop：

```text
/loop
/ctf-24h-fleet <target1,target2,...> <fleet-name>
```

## 执行协议

1. 解析 `$ARGUMENTS`：
   - 第一个参数：逗号/空白/换行分隔的 target 列表。
   - 第二个参数：fleetName；缺省时由 targets 派生，可用参数覆盖。
2. 确保无人值守 runner 已配置：
   ```bash
   python3 scripts/misc/setup_unattended_ctf_runner.py --overwrite
   ```
3. 调用 workflow：
   ```text
   workflow: ctf-24h-fleet
   args:
     targets: <target-list>
     fleetName: <fleetName>
     batchSize: 4
     maxActions: 4
     maxWorkflows: 4
     caseRoot: <case-root>
     reportRoot: <report-root>
     workerIds: <optional-worker-list>
     execute: true
   ```
4. 每个 target 使用独立 case：
   - `cases/<fleet>-<target-slug>/ai_manifest.json`
   - `exports/ctf-website/<fleet>-<target-slug>/`
   - `reports/ctf-website/<fleet>-<target-slug>/`
5. fleet 汇总写入：
   - `reports/ctf-website/<fleet>/fleet-round-<timestamp>.md`

## 状态

每轮输出：

- `STATUS: CONTINUE`：至少一个 target 仍有下一轮焦点。
- `STATUS: DONE`：所有目标都已完成。
- `STATUS: EXHAUSTED`：所有目标攻击路径耗尽或目标长期不可达。

不要等待人工确认；无法执行的路径写入目标 manifest 的 `dead_ends` 或
`next_round_focus`，下一轮自动切换路径。
