---
id: "ctf-website/10-cloud/k8s-rbac-attack-paths"
title: "Kubernetes RBAC 攻击路径"
title_en: "Kubernetes RBAC Attack Paths"
summary: >
  Kubernetes RBAC 攻击路径技术卡片，覆盖 Pod 内身份确认、SelfSubjectAccessReview 权限枚举、RoleBinding/ClusterRoleBinding 关系分析、pods/exec、pods/create、secrets/get、serviceaccounts/token 等高价值权限，以及从最小权限到集群控制的证据闭环。
summary_en: >
  Kubernetes RBAC attack-path card covering in-pod identity discovery, SelfSubjectAccessReview enumeration, RoleBinding/ClusterRoleBinding relationship analysis, high-value permissions such as pods/exec, pods/create, secrets/get, serviceaccounts/token, and evidence closure from low-privilege identity to cluster control.
board: "ctf-website"
category: "10-cloud"
signals: ["Kubernetes", "RBAC", "SelfSubjectAccessReview", "RoleBinding", "ClusterRoleBinding", "pods/exec", "secrets/get", "serviceaccounts/token"]
mcp_tools: ["http_probe", "kb_router", "run_ctf_tool"]
keywords: ["Kubernetes RBAC", "权限枚举", "pods exec", "secrets get", "service account token", "RoleBinding", "ClusterRoleBinding", "kubectl auth can-i"]
difficulty: "advanced"
tags: ["cloud", "kubernetes", "rbac", "privilege-escalation", "ctf"]
language: "zh-CN"
last_updated: "2026-07-03"
related_articles: ["kubernetes-container.md", "aws-iam-privesc.md"]
---
# Kubernetes RBAC 攻击路径

## 场景

已经获得 Pod 内命令执行、泄露的 kubeconfig，或 SSRF 能访问 Kubernetes API。目标是判断当前身份在 namespace 和 cluster 维度能做什么，并找出从低权限到读 secret、exec、创建 workload 或云凭证访问的最短路径。

## 输入信号

- `/var/run/secrets/kubernetes.io/serviceaccount/token` 存在
- 环境变量中有 `KUBERNETES_SERVICE_HOST`
- kubeconfig 泄露，包含 `client-certificate-data` 或 bearer token
- API 返回 `Forbidden` 但暴露了当前 user/group
- `kubectl auth can-i` 对部分 verbs 返回 yes

## Pod 内身份确认

```bash
TOKEN=/var/run/secrets/kubernetes.io/serviceaccount/token
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://kubernetes.default.svc

curl --cacert "$CA" -H "Authorization: Bearer $(cat $TOKEN)" \
  "$API/api"
```

如果能访问 API，继续做 `SelfSubjectRulesReview` 或逐项 `SelfSubjectAccessReview`。

## 权限探针

```python
# k8s_rbac_probe.py - RBAC 可打权限矩阵
import json
import os
import requests

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"

CHECKS = [
    ("", "pods", "list"),
    ("", "pods", "create"),
    ("", "pods/exec", "create"),
    ("", "secrets", "get"),
    ("", "configmaps", "list"),
    ("", "serviceaccounts/token", "create"),
    ("apps", "deployments", "patch"),
    ("rbac.authorization.k8s.io", "rolebindings", "create"),
    ("rbac.authorization.k8s.io", "clusterrolebindings", "create"),
]

def can_i(group, resource, verb, namespace="default"):
    token = open(TOKEN_PATH, encoding="utf-8").read().strip()
    body = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": {"resourceAttributes": {
            "namespace": namespace,
            "group": group,
            "resource": resource,
            "verb": verb,
        }},
    }
    r = requests.post(
        f"{API}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
        verify=CA_PATH,
        timeout=5,
    )
    status = r.json().get("status", {})
    print(f"{verb:8s} {group or 'core':30s} {resource:28s} allowed={status.get('allowed')}")

for item in CHECKS:
    can_i(*item)
```

## 高价值权限解释

| 权限 | 攻击意义 | 验证方式 |
|---|---|---|
| `secrets/get` | 读取凭证、token、数据库密码 | 下一跳打 DB、云凭证或镜像仓库 |
| `pods/exec create` | 进入其他 Pod，横向读取业务环境变量 | 下一跳挑高权限 Pod 或业务后端 |
| `pods/create` | 创建自控 Pod、挂载 SA、尝试 hostPath | 下一跳 privileged/hostPath/IRSA |
| `serviceaccounts/token create` | 为其他 SA 签发 token | 下一跳切换身份重跑权限矩阵 |
| `rolebindings/create` | 在 namespace 内扩大权限 | 下一跳绑定 edit/admin |
| `clusterrolebindings/create` | 集群级接管 | 下一跳绑定 cluster-admin |

## 攻击链

```text
Pod RCE → SA token → can-i secrets/get → 读业务 secret → DB/Flag
Pod RCE → can-i pods/exec → exec 到高权限 Pod → 读云凭证
Pod RCE → can-i pods/create → 创建挂载高权限 SA 的 Pod → secrets/list
Leaked kubeconfig → rolebinding create → 绑定 edit/admin → namespace 接管
K8s service account → IRSA → AWS AssumeRoleWithWebIdentity → 云资源访问
```

## Evidence

记录: 当前 namespace、service account 名、`can-i` 检查矩阵、允许的高价值权限、下一跳 pod/secret/rolebinding、成功返回码。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| API 可达性探测 | `http_probe` | 验证 Kubernetes API/kubelet 是否可达 |
| 知识检索 | `kb_router` | 按 RBAC / can-i / service account 信号搜索 |
| 权限矩阵脚本 | `run_ctf_tool` | 执行 RBAC 可打权限矩阵 |
