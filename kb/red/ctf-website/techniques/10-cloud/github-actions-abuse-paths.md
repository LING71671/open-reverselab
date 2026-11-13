---
id: "ctf-website/10-cloud/github-actions-abuse-paths"
title: "GitHub Actions 滥用路径"
title_en: "GitHub Actions Abuse Paths"
summary: >
  GitHub Actions 攻击面技术卡片，覆盖不可信上下文注入、pull_request_target 误用、GITHUB_TOKEN 权限过大、self-hosted runner 暴露、缓存投毒、artifact 泄露和 OIDC 云角色信任配置，提供 workflow 入口打点、利用分叉和下一跳。
summary_en: >
  GitHub Actions attack-surface card covering untrusted context injection, pull_request_target misuse, over-privileged GITHUB_TOKEN, exposed self-hosted runners, cache poisoning, artifact leaks, and OIDC cloud-role trust configuration, with workflow entry checks, exploitation branches, and next hops.
board: "ctf-website"
category: "10-cloud"
signals: ["GitHub Actions", "pull_request_target", "GITHUB_TOKEN", "self-hosted runner", "workflow injection", "OIDC", "cache poisoning", "artifact leak"]
mcp_tools: ["http_probe", "kb_router", "run_ctf_tool"]
keywords: ["GitHub Actions", "workflow injection", "pull_request_target", "self-hosted runner", "GITHUB_TOKEN", "OIDC", "cache poisoning", "artifact 泄露"]
difficulty: "intermediate"
tags: ["cloud", "ci-cd", "github-actions", "supply-chain", "ctf"]
language: "zh-CN"
last_updated: "2026-07-03"
related_articles: ["ci-cd-pipeline.md", "../11-supply-chain/dependency-confusion.md"]
---
# GitHub Actions 滥用路径

## 场景

项目使用 GitHub Actions 构建、测试、发布镜像或部署云资源。实战优先看三条线：PR 数据能否进 shell，runner 能否接触 secrets，OIDC 能否换云凭证。

## 输入信号

- workflow 中出现 `pull_request_target`
- `run:` 直接拼接 `${{ github.event.pull_request.title }}`
- `permissions: write-all` 或未显式设置 permissions
- `runs-on: self-hosted`
- `id-token: write` 与云角色 trust policy 绑定
- artifact/cache 被 release 或 deploy workflow 消费

## Workflow 入口打点

```python
# gha_workflow_paths.py - 找可打的 workflow 入口
from pathlib import Path
import re

ROOT = Path(".github/workflows")
DANGEROUS_CONTEXT = re.compile(r"\$\{\{\s*github\.event\.(pull_request|issue|comment|head_commit)")

for path in ROOT.glob("*.y*ml"):
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    if "pull_request_target" in text:
        findings.append("pull_request_target")
    if "self-hosted" in text:
        findings.append("self-hosted-runner")
    if "permissions: write-all" in text or "contents: write" in text:
        findings.append("broad-token-permission")
    if "id-token: write" in text:
        findings.append("oidc-token-enabled")
    if DANGEROUS_CONTEXT.search(text) and "run:" in text:
        findings.append("untrusted-context-in-run")
    if findings:
        print(path, findings)
```

## 关键利用分叉

### 不可信上下文进入 shell

```yaml
# PR title/body/branch name 进入 shell
- run: echo "${{ github.event.pull_request.title }}"
```

命中后下一跳：构造 PR title/body/branch，让 shell 解释分隔符、命令替换或换行。

```yaml
# payload 形态示例，按上下文调整引号闭合
title: 'ok"; id; env | sort; #'
```

### pull_request_target 误用

```text
pull_request_target 在 base repo 权限上下文运行。
危险组合: pull_request_target + checkout PR head + secrets/write token。
命中后下一跳: 改 PR 代码或 workflow 输入，让 base repo token/secrets 进入执行路径。
```

### OIDC 云角色信任过宽

```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:ORG/REPO:*"
    }
  }
}
```

命中后下一跳：从非预期 branch/environment 请求 OIDC token，换云临时凭证，再转 IAM 路径。

## 攻击链

```text
PR title injection → workflow shell → GITHUB_TOKEN write → 修改 release artifact
pull_request_target → checkout untrusted head → secrets 暴露 → 云部署接管
self-hosted runner → workspace 残留 → 后续 job 读取 secret/cache
OIDC trust 过宽 → 任意 branch 获取云临时凭证 → Terraform apply
```

## Evidence

记录: workflow 文件路径、触发事件、危险上下文行、token permissions、runner label、OIDC trust 条件、artifact/cache 生产者和消费者、成功命令输出。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| workflow 文件探测 | `http_probe` | 探测公开仓库 workflow/raw 文件 |
| 知识检索 | `kb_router` | 按 GitHub Actions / OIDC / runner 信号搜索 |
| 入口打点脚本 | `run_ctf_tool` | 扫描 workflow 入口、权限和 runner 信号 |
