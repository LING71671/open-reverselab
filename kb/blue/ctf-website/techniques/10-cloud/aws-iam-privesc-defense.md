---
id: "ctf-website/10-cloud/aws-iam-privesc-defense"
title: "AWS IAM 最小权限与提权路径防御"
title_en: "AWS IAM Least Privilege and Privilege Escalation Defense"
summary: >
  针对 AWS IAM 权限枚举与提权路径的蓝队防御指南，覆盖元数据服务（IMDSv2 + hop-limit=1）加固、iam:PassRole 资源条件限制、sts:AssumeRole Trust Policy 与 ExternalId/MFA 约束、Permission Boundaries 与 SCP 护栏，以及 Python 离线 IAM 策略危险边检查脚本。
summary_en: >
  Blue-team defense guide against AWS IAM enumeration and privilege escalation paths. Covers IMDSv2 enforcement with hop-limit=1, iam:PassRole service and resource condition scoping, strict sts:AssumeRole trust policies, IAM Permission Boundaries and AWS Organizations SCP guardrails, and an offline Python IAM policy escalation-edge checker.
board: "ctf-website"
category: "10-cloud"
signals: ["AWS IAM defense", "IMDSv2", "PassRole condition", "Permission Boundary", "SCP guardrail", "AssumeRole trust policy", "least privilege"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["AWS IAM防御", "IMDSv2加固", "PassRole条件限制", "Permission Boundary", "SCP护栏", "Trust Policy收敛", "云凭证防护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "aws", "iam", "least-privilege"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/aws-iam-privesc", "ctf-website/10-cloud/serverless-lambda-defense", "ctf-website/10-cloud/ci-cd-pipeline-defense"]
track: "blue"
defends: "ctf-website/10-cloud/aws-iam-privesc"
---
# AWS IAM 最小权限与提权路径防御

## 1. 威胁模型与常见提权链路

当攻击者通过 SSRF 窃取实例元数据、从 Lambda/CI 环境变量泄露临时凭证，或利用 K8s IRSA 获取 STS Token 后，通常会利用 `sts:GetCallerIdentity` 定位身份并沿着以下高危权限边横向提权：
- `iam:PassRole` 配合 `lambda:CreateFunction` / `lambda:UpdateFunctionCode` / `ecs:RunTask` / `cloudformation:CreateStack`，以高权限角色代为执行代码。
- 宽松的 `sts:AssumeRole` Trust Policy（缺少 `Condition` 或允许过宽 `Principal`）导致跨角色或跨账号跃迁。
- 长期静态 Access Key 泄露或缺乏 Permission Boundary，使单点凭证直接读取 S3、Secrets Manager、SSM Parameter Store 或 DynamoDB 全量数据。

## 2. 核心加固策略与控制矩阵

| 攻击面 | 蓝队控制措施 | 关键条件 / 配置项 | 防御效果 |
|---|---|---|---|
| 凭证源头（EC2/ECS） | 强制 IMDSv2 并设置 `HttpPutResponseHopLimit=1` | `HttpTokens=required`、`HttpPutResponseHopLimit=1` | 阻断 SSRF 及容器层跨跳窃取实例角色临时凭证 |
| `iam:PassRole` 提权边 | 限制目标角色 ARN 前缀并强制 `iam:PassedToService` | `Condition.StringEquals["iam:PassedToService"]` | 防止低权限主体将高权限 Role 绑定到新建 Lambda/ECS |
| `sts:AssumeRole` 跃迁 | 收敛 Trust Policy `Principal`，要求 `aws:SourceAccount` / `ExternalId` / Tag 匹配 | 禁止 `Principal: "*"` 或无条件跨账号信任 | 阻断未授权主体换取高权限 Session |
| 权限上限护栏 | 统一挂载 IAM Permission Boundary 与 Organizations SCP | 显式 `Deny` 修改自身策略/Boundary 操作 | 即使存在策略疏漏也无法突破边界上限 |
| 凭证生命周期 | 禁用长期 IAM User Access Key，改用 OIDC/IRSA 短时凭证并按环境隔离 | STS TTL `<= 1h`，IRSA 绑定精确 `namespace:sa` | 压缩凭证泄露后的有效利用窗口 |

### 安全的 `iam:PassRole` 与 Permission Boundary 策略模板

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopedPassRoleToLambdaOnly",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/app-worker-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DenyBoundaryRemoval",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteRolePermissionsBoundary",
        "iam:PutRolePermissionsBoundary",
        "iam:CreatePolicyVersion",
        "iam:AttachRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

### EC2 / EKS 节点 IMDSv2 强制策略（SCP 或启动模板）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireIMDSv2OnLaunch",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
```

## 防御工作流

1. **凭证源头收敛**：全量检查 EC2、ECS 与 EKS 节点实例元数据配置，强制 `HttpTokens=required` 与 `HttpPutResponseHopLimit=1`，并排查代码库/CI 变量中的静态 IAM Key。
2. **高危提权边扫描**：导出账号内所有 IAM Policy 与 Role Trust Policy，识别 `iam:PassRole`（`Resource: "*"` 或无 `PassedToService`）、`lambda:UpdateFunctionCode`、`cloudformation:CreateStack`、`sts:AssumeRole` 等危险组合。
3. **护栏与边界挂载**：为所有开发人员及自动化部署 Role 强制附加 Permission Boundary，在组织层通过 SCP 禁止越权修改 Boundary 或关闭 CloudTrail。
4. **CloudTrail 异常行为检测**：对 `GetCallerIdentity` 高频枚举、`SimulatePrincipalPolicy` 异常调用、`PassRole` 跨服务绑定以及非预期来源 IP 的 `AssumeRole` 建立实时告警。

## 3. Python IAM Policy 危险提权边离线检测脚本

```python
#!/usr/bin/env python3
"""AWS IAM Policy 危险提权边（PassRole / AssumeRole / Lambda / Wildcard）离线检查脚本。"""

import json

ESCALATION_ACTIONS = {
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
    "cloudformation:CreateStack",
    "ssm:SendCommand",
}


def inspect_policy_document(doc: dict) -> list[str]:
    findings: list[str] = []
    for idx, stmt in enumerate(doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        condition = stmt.get("Condition", {})

        if "*" in actions and "*" in resources:
            findings.append(f"stmt[{idx}]: full admin wildcard (* on *)")
        if "iam:PassRole" in actions:
            passed_to = condition.get("StringEquals", {}).get("iam:PassedToService")
            if "*" in resources or not passed_to:
                findings.append(f"stmt[{idx}]: unrestricted iam:PassRole without resource scope or PassedToService")
        risky_hits = sorted(set(actions) & ESCALATION_ACTIONS)
        if risky_hits and "*" in resources and not condition:
            findings.append(f"stmt[{idx}]: unconditional wildcard resource on {risky_hits}")
    return findings


if __name__ == "__main__":
    risky_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"}
        ],
    }
    safe_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/app-worker-role",
                "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
            }
        ],
    }
    bad_findings = inspect_policy_document(risky_policy)
    good_findings = inspect_policy_document(safe_policy)
    print("risky:", bad_findings)
    print("safe:", good_findings)
    assert len(bad_findings) >= 2
    assert len(good_findings) == 0
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| IMDS 元数据版本 | 所有实例强制 IMDSv2 且 `HttpPutResponseHopLimit == 1` | 允许 IMDSv1 或容器可直接请求 `169.254.169.254` | AWS CLI `describe-instances` 检查 `MetadataOptions` |
| `iam:PassRole` 范围 | 限定具体角色 ARN 前缀并带有 `iam:PassedToService` 条件 | `Resource: "*"` 且无 `Condition` | 运行 `inspect_policy_document` 零告警 |
| Trust Policy 与 Boundary | 关键 Role 均配置 Permission Boundary，无 `Principal: "*"` | 存在未受限跨账号信任或无 Boundary 的自动化 Role | IAM Access Analyzer + 策略检查 |
| 静态长期凭据 | 生产工作负载零长期 `AK` 静态密钥，均走短期 STS/OIDC | 存在长期有效且未轮换的 IAM User Access Key | IAM Credential Report 核查 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索云 IAM 加固文档 | `kb_router` | 按 `AWS IAM` / `PassRole` / `IMDSv2` 搜索相关蓝队方案 |
| 核对攻击路径详情 | `kb_read_file` | 读取 `ctf-website/10-cloud/aws-iam-privesc` 对照提权边 |
| 查看云安全体系条目 | `kb_catalog` | 浏览 `10-cloud` 下 Lambda、K8s 与 CI/CD 联动防护文档 |
