---
id: "ctf-website/10-cloud/terraform-state-secrets"
title: "Terraform State 与 IaC 凭证泄露"
title_en: "Terraform State and IaC Secret Exposure"
summary: >
  Terraform State 与 IaC 攻击面技术卡片，覆盖 tfstate 泄露来源、远端后端配置、state 中的敏感输出、云资源拓扑还原、CI artifact 泄露、Plan 文件审计，以及从 IaC 元数据到云凭证和资源访问的证据闭环。
summary_en: >
  Terraform State and IaC exposure card covering tfstate leak sources, remote backend configuration, sensitive outputs in state, cloud topology reconstruction, CI artifact leaks, plan-file parsing, and evidence closure from IaC metadata to cloud credentials and resource access.
board: "ctf-website"
category: "10-cloud"
signals: ["Terraform", "tfstate", "IaC", "backend", "state file", "terraform plan", "cloud secret", "S3 backend", "CI artifact"]
mcp_tools: ["http_probe", "kb_router", "run_ctf_tool"]
keywords: ["Terraform state", "tfstate 泄露", "IaC", "backend config", "sensitive outputs", "CI artifact", "S3 backend", "secret exposure"]
difficulty: "intermediate"
tags: ["cloud", "iac", "terraform", "secrets", "ctf"]
language: "zh-CN"
last_updated: "2026-07-03"
related_articles: ["ci-cd-pipeline.md", "aws-iam-privesc.md"]
---
# Terraform State 与 IaC 凭证泄露

## 场景

目标暴露了 `.tfstate`、`terraform.tfvars`、`.terraform/`、CI artifact 或 plan 输出。Terraform state 常保存资源 ID、连接串、明文 output、随机密码结果和云资源依赖关系，是从源码泄露走向云资源访问的重要桥。

## 输入信号

- Web 目录或 artifact 中出现 `terraform.tfstate`
- Git 仓库包含 `backend "s3"`、`backend "azurerm"`、`backend "gcs"`
- CI 日志包含 `terraform plan` / `terraform output`
- `*.tfvars`、`.terraform.lock.hcl`、`crash.log` 暴露
- state JSON 中出现 `sensitive_values` 或 provider credential

## 泄露文件探测

```python
# terraform_leak_probe.py - 只探测公开路径，不爆破
import requests

COMMON = [
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    "/terraform.tfvars",
    "/prod.tfvars",
    "/crash.log",
]

def probe(base):
    for path in COMMON:
        url = base.rstrip("/") + path
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and ("terraform" in r.text.lower() or "resources" in r.text[:500]):
            print("[hit]", url, len(r.text))

probe("https://target.example")
```

## State 快速拆解

```python
# tfstate_paths.py - 拆 state，找下一跳资源和敏感字段
import json
from pathlib import Path

SENSITIVE_KEYS = ("password", "secret", "token", "key", "credential", "connection_string")

state = json.loads(Path("terraform.tfstate").read_text(encoding="utf-8"))
for res in state.get("resources", []):
    rtype = res.get("type")
    name = res.get("name")
    for inst in res.get("instances", []):
        attrs = inst.get("attributes", {})
        hits = [k for k in attrs if any(s in k.lower() for s in SENSITIVE_KEYS)]
        if hits:
            print(f"[sensitive-field] {rtype}.{name}: {hits}")
        if rtype in ("aws_iam_role", "aws_lambda_function", "aws_s3_bucket", "kubernetes_secret"):
            print(f"[resource] {rtype}.{name}")
```

## 后端配置分析

```hcl
terraform {
  backend "s3" {
    bucket = "example-tfstate"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}
```

后端配置本身不一定是凭证，但它给出云账号、bucket、路径和环境命名。结合泄露 IAM 凭证时，可快速定位 state 存储位置。

## 攻击链

```text
Git leak → backend config → S3 tfstate → output password → DB/Flag
CI artifact → terraform plan → resource topology → API Gateway/Lambda/S3 目标定位
tfstate → aws_iam_role / policy → PassRole 边 → IAM 提权
tfvars leak → provider credential → sts:GetCallerIdentity → 云资源枚举
```

## Evidence

记录: 泄露文件路径、state serial/lineage、资源类型统计、敏感字段名、output 名称、backend 位置、可直接访问的云资源。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 公开路径探测 | `http_probe` | 探测 tfstate/tfvars/artifact 是否暴露 |
| 知识检索 | `kb_router` | 按 Terraform / tfstate / IaC 信号搜索 |
| State 拆解脚本 | `run_ctf_tool` | 对 state 做敏感字段和资源拓扑统计 |
