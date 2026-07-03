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
| 单题/靶场 24h 可恢复推进 | `scripts/ctf-website/ctf_intake.py` + `scripts/ctf-website/ctf_autopilot.py` | 先生成 `ai_manifest.json`，再按预算循环执行 allowlist 动作并写回 checkpoint。 |

### 24h CTF Autopilot

初始化 case：

```bash
python scripts/ctf-website/ctf_intake.py <case-name> --url "https://target.example/" --root .
```

单轮规划/检查（默认 dry-run，只写 checkpoint，不执行网络/CVE 扩展动作）：

```bash
python scripts/ctf-website/ctf_autopilot.py cases/<case>/ai_manifest.json --max-actions 4
```

24 小时循环执行：

```bash
python scripts/ctf-website/ctf_autopilot.py cases/<case>/ai_manifest.json \
  --loop --budget-hours 24 --max-rounds 96 --interval-seconds 900 --execute
```

规则：

1. Autopilot 只执行 allowlist 动作：HTTP baseline、fingerprint 模板创建、fingerprint→CVE pipeline、CVE graph/chain 重建。
2. SQLi、XSS、SSRF、认证态等高上下文动作仍记录为 `manual_required`，由 Agent 依据 KB 技术文件继续推进。
3. 每轮写回 `ai_manifest.json` 的 `autopilot.rounds[]`、`next_actions` 和 `evidence[]`，中断后可直接再次运行同一命令恢复。
4. 默认 CVE pipeline 使用 `--no-network`；需要实时 NVD enrichment 时增加 `--allow-network-cve`。
