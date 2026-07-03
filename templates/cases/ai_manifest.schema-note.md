# AI Manifest Schema

Case 目录的 AI 可读索引文件结构说明。Web CTF 当前使用
`reverselab.ctf_website.ai_manifest.v1`，文件名固定为
`ai_manifest.json`。

## ai_manifest.json 格式

```json
{
  "schema": "reverselab.ctf_website.ai_manifest.v1",
  "case": "2026-07-example",
  "board": "ctf-website",
  "target": {
    "url": "https://target.example/"
  },
  "paths": {
    "case": "cases/2026-07-example",
    "exports": "exports/ctf-website/example",
    "notes": "notes/ctf-website/example",
    "reports": "reports/ctf-website/example",
    "scripts": "scripts/ctf-website/example"
  },
  "baseline": {
    "url": "",
    "final_url": "",
    "status": 200,
    "elapsed_ms": 0,
    "headers": {},
    "body_size": 0
  },
  "parsed": {
    "links": [],
    "scripts": [],
    "forms": []
  },
  "hypotheses": [
    {
      "id": "H-001",
      "class": "recon",
      "claim": "Map hidden routes and APIs",
      "status": "pending"
    }
  ],
  "next_actions": [],
  "evidence": [],
  "dead_ends": [],
  "autopilot": {
    "schema": "reverselab.ctf_website.autopilot.v1",
    "started_at": "",
    "updated_at": "",
    "status": "dry_run / running",
    "budget": {
      "budget_seconds": 86400,
      "max_rounds": 96,
      "execute": false
    },
    "last_round_id": "R-YYYYMMDD-HHMMSS",
    "rounds": [
      {
        "round_id": "R-YYYYMMDD-HHMMSS",
        "started_at": "",
        "finished_at": "",
        "execute": false,
        "action_count": 0,
        "actions": []
      }
    ]
  }
}
```

## 状态转换约定

1. `ctf_intake.py` 创建初始 manifest、目录树和 HTTP baseline。
2. `ctf_ai_next.py` 只读 manifest 并生成下一步计划。
3. `ctf_autopilot.py` 读取计划，选择 P0/P1/P2 动作，执行 allowlist 动作或标记
   `manual_required`，然后写回：
   - `autopilot.rounds[]`：每轮计划/执行/checkpoint。
   - `next_actions[]`：下一轮优先动作摘要。
   - `evidence[]`：HTTP baseline、fingerprint 模板、CVE pipeline 等证据。
4. Agent/人工完成非 allowlist 动作后，应补充 `evidence[]` 或 `dead_ends[]`，再跑下一轮 autopilot。

AI 进入 case 目录后应首先读取 `ai_manifest.json` 获取全局视图和最近一轮
`autopilot.last_round_id`。
