---
id: "ctf-website/10-cloud/ci-cd-pipeline-defense"
title: "CI/CD Pipeline 防御：上下文注入消除、Runner 隔离与供应链签名"
title_en: "CI/CD Pipeline Defense: Context Injection Elimination, Runner Isolation & Artifact Signing"
summary: >
  针对 CI/CD 流水线攻击面的蓝队防御指南，覆盖 GitHub Actions / GitLab CI 表达式注入消除、Jenkins Script Console 禁用与认证收口、Self-hosted Runner 沙箱化与 fork 隔离、OIDC Trust Policy 精确绑定、构建产物/缓存隔离及 SLSA 溯源签名，并附带 Python Pipeline 安全检查脚本。
summary_en: >
  Blue-team defense guide for CI/CD pipeline threats covering GitHub Actions/GitLab CI expression injection elimination, Jenkins Script Console restriction, ephemeral self-hosted runner isolation against fork triggers, strict OIDC cloud-role trust claims, cache/artifact scoping with SLSA provenance signing, and a Python pipeline lint checker.
board: "ctf-website"
category: "10-cloud"
signals: ["CI/CD defense", "pipeline hardening", "GitHub Actions env indirection", "Jenkins security", "ephemeral runner", "OIDC claims", "artifact provenance"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["CI/CD安全加固", "Pipeline防御", "Workflow注入防护", "Jenkins认证收口", "临时Runner隔离", "OIDC精确绑定", "SLSA产物签名"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "ci-cd", "devsecops", "supply-chain"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/ci-cd-pipeline", "ctf-website/10-cloud/github-actions-abuse-paths-defense", "ctf-website/11-supply-chain/dependency-confusion-defense"]
track: "blue"
defends: "ctf-website/10-cloud/ci-cd-pipeline"
---
# CI/CD Pipeline 防御：上下文注入消除、Runner 隔离与供应链签名

## 1. 威胁模型与流水线风险面

CI/CD 系统连接着源码输入、构建环境 Secrets、云平台 OIDC 角色以及下游发布制品。常见失陷链条包括：
- **不安全上下文插值**：在 `run:` Shell 脚本中直接展开 `${{ github.event.pull_request.title }}` / `body` / `branch` 或 GitLab CI 可控变量，导致命令注入。
- **权限上下文错配**：使用 `pull_request_target` 检出不可信 fork 代码并执行构建脚本，或暴露 `self-hosted` Runner 给公网/fork PR 导致工作区残留 Secrets 与云元数据被窃取。
- **Jenkins 控制面失守**：公网暴露 `/script`（Groovy Script Console）或缺乏细粒度 RBAC 与 CSRF 保护导致直接 RCE。
- **OIDC 信任过宽与产物投毒**：云侧 Trust Policy 未绑定精确分支与 `environment` 审批门禁，或构建 Cache/Artifact 被低权限分支污染并流入部署链。

## 2. 分层防御与加固矩阵

| 环节 | 加固措施 | 关键配置要求 | 阻断目标 |
|---|---|---|---|
| Workflow 上下文安全 | 通过 `env:` 环境变量中转事件字段，禁止 `${{ github.event.* }}` 直接入 `run:` | `env: PR_TITLE: ${{ github.event.pull_request.title }}` + 双引号引用 `"$PR_TITLE"` | 阻断 PR/Commit/Comment Shell 注入 |
| Runner 执行隔离 | 公开仓库禁用持久化 `self-hosted` Runner；私有化采用一次性临时 VM/Pod 并阻断 IMDS | Ephemeral runner + 网络出口白名单 | 消除跨 Job 工作区残留与元数据窃取 |
| Jenkins 加固 | 内网隔离 + 启用 Matrix RBAC + 禁用未认证 `/script` + 启用 Job DSL 沙箱 | 关闭匿名可读、仅管理员可用 Script Console、Agent-to-Controller 隔离 | 阻断 Groovy RCE 与横向凭证窃取 |
| OIDC 最小信任 | 云侧校验 `sub` 含精确 `repo` + `ref:refs/heads/main` 或 `environment:production` | 部署环境开启 Required Reviewers 人工审批 | 防止特性分支或 fork PR 换取生产云角色 |
| 产物与缓存防投毒 | 按分支/信任域隔离 Cache Key，发布制品生成 SBOM 与 Sigstore/SLSA Provenance 校验 | 部署前验证 Artifact 签名与校验和 | 阻断下游部署加载被篡改构件 |

### GitHub Actions 安全上下文中转示例

```yaml
permissions:
  contents: read

jobs:
  validate-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Safely inspect PR title via environment variable
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          printf '%s\n' "$PR_TITLE"
```

### 云侧 OIDC 精确信任条件示例（AWS IAM）

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:example-org/service-repo:environment:production"
    }
  }
}
```

## 防御工作流

1. **流水线暴露面盘点**：枚举所有 `.github/workflows/*.yml`、`.gitlab-ci.yml` 及 Jenkins 实例，标记 `pull_request_target`、`self-hosted`、`/script` 公网暴露及未限制的 OIDC Role。
2. **上下文注入与权限收敛**：全部替换为 `env:` 变量中转写法，顶层显式声明最小 `permissions: contents: read`，仅在需要签发 OIDC 的独立部署 Job 中授予 `id-token: write`。
3. **Runner 与 Jenkins 控制面加固**：迁移为每次构建即毁的 Ephemeral Runner，隔离 Jenkins 管理端口并关闭普通账号 Groovy Console 权限，禁用无凭证 Webhook 触发高权任务。
4. **产物签名与持续门禁**：将下方流水线检查脚本纳入 PR 必过门禁（Branch Protection），并对发布制品启用 SHA256 与 provenance 签名核验。

## 3. Python CI/CD Workflow 危险模式自动化检查脚本

```python
#!/usr/bin/env python3
"""CI/CD Workflow 表达式注入、高危触发器与 Runner 配置检查工具。"""

import re
from pathlib import Path

UNSAFE_INTERP_RE = re.compile(
    r"run\s*:[^\n]*\$\{\{\s*github\.event\.(?:pull_request|issue|comment|head_commit|discussion)",
    re.IGNORECASE,
)
HIGH_RISK_PATTERNS = {
    "pull_request_target": re.compile(r"\bpull_request_target\b"),
    "self_hosted_runner": re.compile(r"\bself-hosted\b"),
    "write_all_perms": re.compile(r"permissions:\s*write-all"),
    "curl_pipe_sh": re.compile(r"curl\s+[^|\n]+\|\s*(?:ba)?sh"),
}


def check_workflow_text(filename: str, content: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if UNSAFE_INTERP_RE.search(content):
        findings.append({"file": filename, "rule": "unsafe-context-in-run", "severity": "HIGH"})
    if "permissions:" not in content:
        findings.append({"file": filename, "rule": "missing-explicit-permissions", "severity": "MEDIUM"})
    for rule, pattern in HIGH_RISK_PATTERNS.items():
        if pattern.search(content):
            findings.append({"file": filename, "rule": rule, "severity": "HIGH"})
    return findings


if __name__ == "__main__":
    bad_yaml = """
on: pull_request_target
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
    safe_yaml = """
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: printf '%s\\n' "$PR_TITLE"
"""
    bad_res = check_workflow_text("bad.yml", bad_yaml)
    safe_res = check_workflow_text("safe.yml", safe_yaml)
    print("bad:", bad_res)
    print("safe:", safe_res)
    assert len(bad_res) >= 3
    assert len(safe_res) == 0
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| Workflow 上下文插值 | 全部通过 `env:` 中转，无 `${{ github.event.* }}` 进入 `run:` | 存在直接拼接 PR title/body/branch 的 `run:` 行 | `check_workflow_text` 全仓检查零 HIGH 告警 |
| Token 与 OIDC 权限 | 显式声明最小 `permissions`，OIDC `sub` 精确绑定 `environment` | 默认 `write-all` 或通配符 `repo:org/repo:*` | 检查 Workflow YAML 与云侧 Trust Policy |
| Jenkins 控制面 | `/script` 仅内网 + 管理员认证可达，开启 CSRF 与沙箱 | 公网匿名可访问 `/script` 或 `/asynchPeople` | `http_probe` 检查 `/script` 返回 `401`/`403` |
| Runner 与制品隔离 | 构建运行在无持久化状态 Ephemeral Runner，产物带签名校验 | 公共分支复用含敏感凭据的 `self-hosted` Runner | 核查 Runner 生命周期与部署验签步骤 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索流水线加固方案 | `kb_router` | 按 `CI/CD` / `GitHub Actions` / `OIDC` 检索配套指南 |
| 核对攻击链条 | `kb_read_file` | 读取 `ctf-website/10-cloud/ci-cd-pipeline` 对照各注入面 |
| Jenkins 端点核验 | `http_probe` | 验证 `/script` 控制面已返回未授权拒绝状态码 |
