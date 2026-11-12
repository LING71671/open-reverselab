---
id: "ctf-website/10-cloud/serverless-lambda-defense"
title: "Serverless / Lambda 防御：最小角色、事件源校验与执行隔离"
title_en: "Serverless / Lambda Defense: Least-Privilege Execution Role, Event Validation & Isolation"
summary: >
  针对 Serverless / AWS Lambda 攻击面的蓝队防御指南。覆盖一函数一最小 IAM Execution Role、敏感参数迁移出环境变量至 KMS 加密的 Secrets Manager、Event Injection 结构与来源账户校验（S3/SQS/API Gateway）、消除 /tmp 热启动跨请求状态污染、Layer/Extension 完整性签名以及 VPC Egress 控制，并附带 Python 事件校验与环境变量检查脚本。
summary_en: >
  Blue-team defense guide for Serverless/Lambda security covering per-function least-privilege IAM roles, migrating secrets out of plaintext environment variables into KMS-encrypted Secrets Manager, strict event-source schema and account validation, eliminating /tmp warm-start state confusion, Layer/Extension code signing, VPC egress filtering, and a Python Lambda defense check script.
board: "ctf-website"
category: "10-cloud"
signals: ["Serverless defense", "Lambda hardening", "event validation", "per-function IAM role", "warm start /tmp isolation", "Lambda code signing"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Serverless防御", "Lambda加固", "最小执行角色", "Event Injection防护", "冷启动tmp隔离", "Secrets Manager", "Lambda代码签名"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "serverless", "aws", "lambda"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/serverless-lambda", "ctf-website/10-cloud/aws-iam-privesc-defense", "ctf-website/10-cloud/ci-cd-pipeline-defense"]
track: "blue"
defends: "ctf-website/10-cloud/serverless-lambda"
---
# Serverless / Lambda 防御：最小角色、事件源校验与执行隔离

## 1. 威胁模型与 Serverless 核心风险面

Lambda 等 Serverless 函数具有“事件驱动、短时凭证注入环境变量、同一执行环境跨调用复用 `/tmp` 与内存”的特性，常见攻击链路包括：
1. **Runtime API 与环境变量窃取**：函数存在 RCE 或 SSRF 时，攻击者读取 `AWS_ACCESS_KEY_ID` / `AWS_SESSION_TOKEN` 或明文环境变量中的 DB 密码，或劫持 `127.0.0.1:9001`（Runtime API `invocation/next`）窃取后续用户请求事件。
2. **Event Injection（事件源投毒）**：函数直接信任 `event` 中的 `bucket`、`key`、`rawPath` 或 SQS `body`，未校验事件源归属或路径白名单，导致读取任意 S3 对象、SSRF 或订单状态错位。
3. **跨调用状态混用（`/tmp` 污染）**：热启动（warm execution environment）保留上一次调用写入 `/tmp` 的文件或全局内存对象，导致跨租户数据泄露或状态篡改。
4. **IAM 宽权限与 Layer 供应链**：多个函数共用宽权限 Role（含 `ssm:GetParameter *`、`lambda:UpdateFunctionCode`、`iam:PassRole`），或引入未签名第三方 Layer/Extension。

## 2. 分层防御与架构加固矩阵

| 防御面 | 控制措施 | 配置与开发要求 | 阻断效果 |
|---|---|---|---|
| IAM 一函数一角色 | 每个 Lambda 独立 Execution Role，权限精确到单个 Bucket 前缀/表/Secret ARN | 严禁 `Resource: "*"` 或共享通用角色；禁用 `lambda:UpdateFunctionCode`、`iam:PassRole` | 压缩单函数失陷后的爆炸半径 |
| 敏感配置隔离 | 密钥不以明文存入函数环境变量，改在运行时按需从 KMS 加密的 Secrets Manager 获取并限制最小缓存范围 | 配置 KMS Key Policy 仅允许对应函数 Role 解密 | 防止任意环境变量读取直接泄露核心密钥 |
| 事件输入校验 | 使用 Pydantic / JSON Schema 严格校验事件格式、允许的 S3 Bucket 白名单及字符集 | S3/SQS Resource Policy 限制 `aws:SourceAccount` 与 `aws:SourceArn` | 阻断伪造事件源与参数污染 |
| 执行环境与 `/tmp` 隔离 | 禁止把 `/tmp` 用于跨调用持久化业务状态；按 `aws_request_id` 创建子目录并在 `finally` 中清理 | 仅在只读静态缓存场景复用内存；敏感临时文件使用后立即删除 | 消除热启动跨租户状态混淆 |
| 网络与签名控制 | 无需公网的内部函数放入无 NAT 私有子网（VPC Egress 白名单）；启用 AWS Signer 代码签名 | 配置 `CodeSigningConfig`（`Enforce` 模式）校验函数包与 Layer | 阻断外带信道与非授权 Layer/Extension 注入 |

### Lambda 事件强校验与 `/tmp` 请求级清理模式

```python
import json
import os
import re
import shutil
from pathlib import Path

ALLOWED_BUCKETS = frozenset(os.environ.get("ALLOWED_S3_BUCKETS", "prod-ingest-bucket").split(","))
SAFE_KEY_RE = re.compile(r"^uploads/[a-zA-Z0-9._-]{1,128}\.json$")


def validate_s3_event(event: dict) -> list[tuple[str, str]]:
    validated: list[tuple[str, str]] = []
    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:s3":
            raise ValueError("unexpected eventSource")
        s3_info = record.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name", "")
        key = s3_info.get("object", {}).get("key", "")
        if bucket not in ALLOWED_BUCKETS:
            raise PermissionError(f"disallowed bucket: {bucket}")
        if not SAFE_KEY_RE.match(key):
            raise ValueError(f"invalid object key: {key}")
        validated.append((bucket, key))
    return validated


def isolated_handler(event: dict, request_id: str) -> dict:
    """每次调用使用独立 request_id 临时目录并在结束时强制清理。"""
    workdir = Path("/tmp") / f"req-{request_id}"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        items = validate_s3_event(event)
        return {"accepted": len(items), "workdir_isolated": True}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
```

## 防御工作流

1. **函数配置与角色梳理**：盘点所有 Lambda 函数的 Execution Role、环境变量名及 Layer 来源，标记共用高权 Role、含 `SECRET`/`PASSWORD` 明文环境变量以及开放公网 Function URL 的函数。
2. **输入校验与状态清理改造**：在 Handler 入口增加严格事件 Schema 与 Bucket/Queue 白名单校验，并审计代码对 `/tmp` 的读写，确保所有临时目录按 `context.aws_request_id` 隔离并在 `finally` 块销毁。
3. **触发器与代码签名收口**：为 S3/SQS/SNS 触发策略添加 `aws:SourceAccount` 与 `aws:SourceArn` 条件；为生产部署启用 Lambda Code Signing，确保只有经过 CI 签名的函数包与 Layer 允许发布。
4. **监控与基线回归**：监控 CloudWatch Logs 中非常规 `sts:AssumeRole` / `secretsmanager` 访问频次以及 Lambda 异常超时行为，并通过校验脚本回归验证非法事件被拒绝。

## 3. Python Lambda 安全基线自检脚本

```python
#!/usr/bin/env python3
"""Lambda 函数配置、环境变量及事件校验规则合规检测脚本。"""

SENSITIVE_ENV_KEYWORDS = ("SECRET", "PASSWORD", "PRIVATE_KEY", "DB_PASS", "API_TOKEN")


def check_lambda_config(fn_cfg: dict) -> list[str]:
    issues: list[str] = []
    role_count = fn_cfg.get("shared_role_functions", 1)
    if role_count > 1:
        issues.append(f"HIGH: IAM role shared across {role_count} functions (violates per-function role)")
    if not fn_cfg.get("code_signing_enforced", False):
        issues.append("MEDIUM: AWS Signer code signing not enforced")
    if fn_cfg.get("function_url_auth") == "NONE":
        issues.append("HIGH: Function URL uses AuthType NONE without upstream WAF/auth")
    for env_key in fn_cfg.get("env_keys", []):
        upper = env_key.upper()
        if upper.endswith(("_ARN", "_ID", "_NAME")):
            continue
        if any(marker in upper for marker in SENSITIVE_ENV_KEYWORDS):
            issues.append(f"HIGH: plaintext secret suspected in env var {env_key} (use Secrets Manager)")
    return issues


if __name__ == "__main__":
    risky_fn = {
        "shared_role_functions": 4,
        "code_signing_enforced": False,
        "function_url_auth": "NONE",
        "env_keys": ["LOG_LEVEL", "DB_PASSWORD", "JWT_SECRET"],
    }
    clean_fn = {
        "shared_role_functions": 1,
        "code_signing_enforced": True,
        "function_url_auth": "AWS_IAM",
        "env_keys": ["LOG_LEVEL", "SECRET_ARN"],
    }
    bad_hits = check_lambda_config(risky_fn)
    good_hits = check_lambda_config(clean_fn)
    print("risky:", bad_hits)
    print("clean:", good_hits)
    assert len(bad_hits) == 5
    assert len(good_hits) == 0
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| IAM Role 隔离度 | 一函数一专用 Role，仅包含业务最小资源 ARN 权限 | 多函数共用宽权 Role 或含 `*` 资源权限 | `check_lambda_config` 与 IAM Access Analyzer |
| 敏感配置存储 | 环境变量仅放 ARN/配置名，密钥托管于 KMS + Secrets Manager | 明文密码/API Token 存在于 Lambda 环境变量 | `get-function-configuration` 核查环境变量键名 |
| Event Injection 防护 | 非白名单 `bucket` / 非法 `key` 在进入 SDK 调用前抛出拒绝异常 | 可控事件参数直接进入 `s3.get_object` 或下游请求 | 单元测试传入非白名单事件验证抛出异常 |
| `/tmp` 热启动隔离 | 连续调用同一 warm container 不残留前序请求文件 | 第二次调用可读取前一次写入 `/tmp` 的状态数据 | 连续两次调用测试验证隔离与清理 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 Serverless 防护知识 | `kb_router` | 按 `Lambda` / `Serverless` / `event injection` 搜索 |
| 核对攻击链路细节 | `kb_read_file` | 读取 `ctf-website/10-cloud/serverless-lambda` 核对触发源与分叉 |
| 关联 IAM 与 CI/CD 加固 | `kb_catalog` | 协同查看 `aws-iam-privesc-defense` 与 `ci-cd-pipeline-defense` |
