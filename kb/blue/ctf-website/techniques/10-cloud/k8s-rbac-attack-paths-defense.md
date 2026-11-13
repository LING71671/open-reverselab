---
id: "ctf-website/10-cloud/k8s-rbac-attack-paths-defense"
title: "Kubernetes RBAC 最小权限防御与高危权限边阻断"
title_en: "Kubernetes RBAC Least Privilege Defense and High-Risk Edge Blocking"
summary: >
  针对 Kubernetes RBAC 攻击路径的蓝队防御指南，覆盖禁止 Pod 自动挂载默认 ServiceAccount Token（automountServiceAccountToken: false）、禁用 default SA 授权、消除 secrets/get、pods/exec、pods/create、serviceaccounts/token 与 escalate/bind 权限边，以及 Python RBAC Role/ClusterRole 危险权限组合检查脚本。
summary_en: >
  Blue-team defense guide against Kubernetes RBAC attack paths. Covers disabling default ServiceAccount token automounting, zero-permission default SAs, removing high-risk verbs such as secrets/get, pods/exec, pods/create, serviceaccounts/token, and bind/escalate, plus a Python RBAC Role/ClusterRole escalation checker.
board: "ctf-website"
category: "10-cloud"
signals: ["Kubernetes RBAC defense", "automountServiceAccountToken", "least privilege RBAC", "secrets isolation", "pods/exec restriction", "ClusterRoleBinding"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Kubernetes RBAC防御", "K8s最小权限", "ServiceAccount Token禁用挂载", "pods exec限制", "ClusterRoleBinding检查", "RBAC防提权"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "kubernetes", "rbac", "least-privilege"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/k8s-rbac-attack-paths", "ctf-website/10-cloud/kubernetes-container-defense", "ctf-website/10-cloud/aws-iam-privesc-defense"]
track: "blue"
defends: "ctf-website/10-cloud/k8s-rbac-attack-paths"
---
# Kubernetes RBAC 最小权限防御与高危权限边阻断

## 1. 威胁模型与高价值 RBAC 权限边

当攻击者取得 Pod 执行权或泄露 kubeconfig 后，往往通过 `SelfSubjectAccessReview` 枚举当前身份可用动作。以下 RBAC 权限组合最容易导致直接提权或横向接管：
- **凭据读取**：`secrets` 资源的 `get`/`list`/`watch` 或 `serviceaccounts/token` 的 `create`（可替其他高权 SA 签发 Token）。
- **横向与容器逃逸**：`pods/exec`、`pods/attach`、`pods/portforward`，或 `pods/create`、`deployments/patch`（可创建挂载高权 SA、开启 `privileged`/`hostPath` 的新 Pod）。
- **权限自我放大**：`rolebindings/create`、`clusterrolebindings/create`，以及 `roles`/`clusterroles` 上的 `bind`、`escalate`、`impersonate` 动词。
- **默认暴露放大**：业务 Pod 未关闭 `automountServiceAccountToken`，共享 `default` ServiceAccount 并在不经意间被绑定宽权限。

## 2. 分层加固策略与最小权限设计

| 防御面 | 控制措施 | 落地配置要求 | 阻断效果 |
|---|---|---|---|
| Token 挂载收敛 | 无需访问 K8s API 的工作负载禁用自动挂载 | SA 与 Pod 均设 `automountServiceAccountToken: false` | 即使 Pod 被 RCE 也不存在可用 API Token |
| 专用 ServiceAccount | 每个微服务使用独立 SA，严禁给 `default` SA 绑定 Role | 一服务一 SA，Token 使用有界投影卷（`expirationSeconds`） | 消除同 Namespace 跨应用权限串联 |
| 禁止通配符与高危动词 | 禁止 `verbs: ["*"]` / `resources: ["*"]`；业务 SA 禁用 `pods/exec`、`pods/create`、`secrets` 全库读 | 使用 `resourceNames` 精确限定单个 Secret/ConfigMap | 防止通过单点权限横向读取全命名空间机密 |
| 提权动词控制 | 严禁非平台管理员拥有 `bind`、`escalate`、`impersonate` 及 `rolebindings` 写权限 | 仅 GitOps/控制面具备受控绑定权限 | 阻断自建绑定成为 `cluster-admin` |
| KMS 静态加密与审计日志 | 启用 etcd EncryptionConfiguration 并记录 `RequestResponse` 级敏感 API 审计事件 | 监控非运维主体调用 `pods/exec` 与 `SelfSubjectAccessReview` | 及时发现权限枚举与异常读取 |

### 安全的 Pod 与 ServiceAccount 最小化配置示例

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-worker-sa
  namespace: prod-payments
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-config-reader
  namespace: prod-payments
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["payment-public-config"]
    verbs: ["get"]
```

## 防御工作流

1. **ServiceAccount 与挂载梳理**：统计所有 Namespace 下未设置 `automountServiceAccountToken: false` 的工作负载，以及绑定到 `default` SA 或 `system:authenticated` / `system:unauthenticated` 的 RoleBinding。
2. **RBAC 危险规则清理**：运行下方检查脚本扫描全部 `Role`/`ClusterRole`/`Binding`，清除通配符规则、多余 `secrets/list`、`pods/exec`、`serviceaccounts/token` 及 `bind`/`escalate` 权限。
3. **准入策略拦截**：配合 Pod Security Admission（`restricted`）禁止普通 SA 创建特权或 `hostPath` Pod，确保即便持有受限调度权限也无法完成节点逃逸。
4. **API 异常行为监控**：在 kube-apiserver 日志对 `selfsubjectaccessreviews` 高频试探、非白名单来源 `pods/exec` 及 `serviceaccounts/token` 签发建立告警。

## 3. Python Kubernetes RBAC 危险权限边检测脚本

```python
#!/usr/bin/env python3
"""Kubernetes RBAC Role/ClusterRole 高危权限边离线检查工具。"""

HIGH_RISK_RULES = {
    ("", "secrets", "get"),
    ("", "secrets", "list"),
    ("", "pods", "create"),
    ("", "pods/exec", "create"),
    ("apps", "deployments", "patch"),
    ("authentication.k8s.io", "serviceaccounts/token", "create"),
    ("rbac.authorization.k8s.io", "rolebindings", "create"),
    ("rbac.authorization.k8s.io", "clusterrolebindings", "create"),
}
ESCALATION_VERBS = {"*", "bind", "escalate", "impersonate"}


def check_rbac_manifest(manifest: dict) -> list[str]:
    issues: list[str] = []
    kind = manifest.get("kind", "")
    name = manifest.get("metadata", {}).get("name", "unknown")

    if kind in ("ServiceAccount", "Pod"):
        automount = manifest.get("automountServiceAccountToken")
        if automount is not False:
            issues.append(f"{kind}/{name}: automountServiceAccountToken should be false by default")
        return issues

    for idx, rule in enumerate(manifest.get("rules", [])):
        groups = rule.get("apiGroups", [])
        resources = rule.get("resources", [])
        verbs = set(rule.get("verbs", []))
        res_names = rule.get("resourceNames", [])

        if "*" in resources or "*" in verbs:
            issues.append(f"{kind}/{name} rule[{idx}]: wildcard resources or verbs forbidden")
        if verbs & ESCALATION_VERBS:
            issues.append(f"{kind}/{name} rule[{idx}]: escalation verb(s) {sorted(verbs & ESCALATION_VERBS)}")
        for g in groups:
            for r in resources:
                for v in verbs:
                    if (g, r, v) in HIGH_RISK_RULES and not res_names:
                        issues.append(f"{kind}/{name} rule[{idx}]: unscoped high-risk ({g or 'core'}, {r}, {v})")
    return issues


if __name__ == "__main__":
    risky_role = {
        "kind": "Role",
        "metadata": {"name": "over-privileged"},
        "rules": [
            {"apiGroups": [""], "resources": ["secrets", "pods/exec"], "verbs": ["get", "list", "create"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"], "verbs": ["create"]},
        ],
    }
    safe_role = {
        "kind": "Role",
        "metadata": {"name": "scoped-reader"},
        "rules": [
            {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["app-db-url"], "verbs": ["get"]},
        ],
    }
    bad = check_rbac_manifest(risky_role)
    good = check_rbac_manifest(safe_role)
    print("risky:", bad)
    print("safe:", good)
    assert len(bad) >= 4
    assert len(good) == 0
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| 默认 SA 与 Token 挂载 | 无需 API 的 Pod 均设 `automountServiceAccountToken: false`，`default` SA 无任何绑定 | Pod 默认挂载高权 Token 或 `system:authenticated` 存在宽权限 | `kubectl get sa,rolebinding -A` 核查 |
| 高危权限边收敛 | 业务 SA 对 `secrets`/`pods/exec`/`pods/create`/`rolebindings` 返回 `no` | `kubectl auth can-i` 对上述任意一项返回 `yes` | 使用目标 SA 执行 `kubectl auth can-i --as=...` |
| 通配符与 `resourceNames` | 零 `*` 规则，敏感 Secret 访问均绑定 `resourceNames` | 存在 `verbs: ["*"]` 或全量 `secrets` 读取权 | 运行 `check_rbac_manifest` 零告警 |
| API 审计可观测性 | 已开启 `SelfSubjectAccessReview`、`pods/exec`、`token` 签发告警 | 集群未留存 API 审计日志 | 核查 apiserver `--audit-policy-file` |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 K8s RBAC 防护条目 | `kb_router` | 按 `Kubernetes` / `RBAC` / `least privilege` 搜索 |
| 对照高价值权限边 | `kb_read_file` | 读取 `ctf-website/10-cloud/k8s-rbac-attack-paths` 核对权限矩阵 |
| 关联集群与容器防护 | `kb_catalog` | 协同查看 `kubernetes-container-defense` 与 `container-runtime-escape-defense` |
