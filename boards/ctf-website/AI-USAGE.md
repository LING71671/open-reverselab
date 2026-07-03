# CTF Website AI Usage

做 Web CTF 时的 AI 工作约定。

## 核心原则

1. **先查知识库**：每个信号都先跑 `kb_router.py`，直接用技术文件里的伪代码
2. **多路径**：按 `attack-network.md` 的攻击网同时推进多条链
3. **证据落盘**：每个步骤的请求/响应、工具输出都保存到 `exports/ctf-website/`
4. **CVE 链**：发现版本指纹后联动 `cve_lookup.py` → `cve_graph.py` → `cve_chain_planner.py`

## 工具路径

- 工具安装状态查看：`tools/ctf-website/installed-tools.md`
- 工具 checklist：运行 `python scripts/misc/ai_toolcheck.py` 或 `.\scripts\ctf-website\ctf_toolcheck.ps1`

## 自动化入口选择

| 目标 | 入口 | 说明 |
|---|---|---|
| 域名/站点级一次性评估 | `.claude/workflows/ctf-full-pipeline.js` | 资产发现 → DoS 面 → 漏洞挖掘 → 验证 → 综合报告；适合 agent workflow 环境。 |
| Claude Code 单目标 24h 可恢复推进 | `/loop /ctf-24h <target> [case]` | `/loop` 负责不中断调度，`ctf-24h-round` 每轮推进并写 checkpoint。 |
| Claude Code 多目标 24h fleet | `/loop /ctf-24h-fleet <targets> [fleet]` | `ctf-24h-fleet` 按 batch 并行调度多个 `ctf-24h-round`，每个目标独立 manifest。 |
| Codex / 无 workflow runner fallback | `scripts/ctf-website/ctf_intake.py` + `scripts/ctf-website/ctf_autopilot.py` | 先生成 `ai_manifest.json`，再循环单轮动作并由 Agent 继续攻击网判断。 |

### 24h CTF Autopilot

初始化 case：

```bash
python scripts/ctf-website/ctf_intake.py <case-name> --url "<target-url>" --root .
```

单轮规划/检查（默认 dry-run，只写 checkpoint，不执行网络/CVE 扩展动作）：

```bash
python scripts/ctf-website/ctf_autopilot.py cases/<case>/ai_manifest.json --max-actions 4
```

Claude Code 中推荐用 `/loop + workflow`：

```text
/loop /ctf-24h <target-url-or-domain> <case-name>
```

多个目标并行：

```text
/loop /ctf-24h-fleet <target1,target2,...> <fleet-name>
```

无 Claude workflow runner 时可用 Python fallback 做 checkpoint 心跳：

```bash
python scripts/ctf-website/ctf_autopilot.py cases/<case>/ai_manifest.json \
  --loop --interval-seconds 900 --execute
```

规则：

1. 不让单个 workflow 阻塞 24 小时；每轮必须有界执行并返回 `CONTINUE|DONE|EXHAUSTED`。
2. Autopilot 只执行 allowlist 动作：HTTP baseline、fingerprint 模板创建、fingerprint→CVE pipeline、CVE graph/chain 重建。
3. SQLi、XSS、SSRF、认证态等高上下文动作记录为 `agent_required`，由下一轮 Agent 依据 KB 技术文件自动推进。
4. 每轮写回 `ai_manifest.json` 的 `autopilot.rounds[]`、`next_actions` 和 `evidence[]`，中断后可直接再次运行同一命令恢复。
5. 默认 CVE pipeline 使用 `--no-network`；需要实时 NVD enrichment 时增加 `--allow-network-cve`。
