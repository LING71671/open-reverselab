---
id: "ctf-website/10-cloud/kubernetes-container-defense"
title: "Kubernetes 与容器逃逸纵深防御：Pod Security、控制面隔离与网络策略"
title_en: "Kubernetes & Container Escape Defense-in-Depth: Pod Security, Control-Plane Isolation & NetworkPolicy"
summary: >
  针对 Kubernetes 与容器逃逸全链路的蓝队纵深防御指南。覆盖 Pod Security Admission（restricted 基线）、kubelet 10250/10255 匿名关闭与 Webhook 认证、etcd 2379 mTLS 与 NetworkPolicy 隔离、Cloud Metadata（IMDSv2 hop-limit=1）阻断、runc 补丁基线，以及 Python 集群控制面暴露与 Pod 基线检查脚本。
summary_en: >
  Blue-team defense-in-depth guide for Kubernetes and container escape chains. Covers Pod Security Admission (restricted profile), kubelet 10250/10255 anonymous auth disablement and webhook auth, etcd 2379 mTLS and NetworkPolicy isolation, cloud metadata IMDSv2 hop-limit=1 enforcement, runc patching, and a Python K8s cluster hardening verification script.
board: "ctf-website"
category: "10-cloud"
signals: ["Kubernetes defense", "Pod Security Admission", "kubelet 10250 hardening", "etcd mTLS", "NetworkPolicy", "IMDSv2 hop-limit", "runc CVE-2024-21626 defense"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["Kubernetes加固", "Pod Security restricted", "kubelet认证", "etcd隔离", "NetworkPolicy阻断", "容器逃逸防御", "runc补丁"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "kubernetes", "container-security", "network-policy"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/kubernetes-container", "ctf-website/10-cloud/k8s-rbac-attack-paths-defense", "ctf-website/10-cloud/container-runtime-escape-defense"]
track: "blue"
defends: "ctf-website/10-cloud/kubernetes-container"
---
# Kubernetes 与容器逃逸纵深防御：Pod Security、控制面隔离与网络策略

## 1. 威胁模型与集群横向/逃逸路径

当攻击者在业务 Pod 中获得 RCE 后，会同时探测控制面、运行时与云元数据多条并行通路：
1. **Pod/Runtime 层**：读取自动挂载的 SA Token、探测 `/var/run/docker.sock`、检查 `privileged`/`hostPath`/`hostPID` 或利用 `runc` fd leak（CVE-2024-21626）访问宿主机文件。
2. **节点控制面（Kubelet）**：访问节点 `10250`（未关闭匿名或授权模式为 `AlwaysAllow`）或只读端口 `10255`，执行 `/run/...` 读取 `admin.conf` 或其他高权 Pod Token。
3. **集群存储（etcd）**：Pod 网络未隔离时直连 `2379` 端口读取 `/registry/secrets` 全量明文机密。
4. **云元数据接口**：从 Pod 访问 `169.254.169.254` 获取节点实例 IAM Role 凭证。

## 2. 纵深防御架构与基线配置

| 防御层级 | 控制措施 | 关键配置项 | 阻断路径 |
|---|---|---|---|
| Namespace 准入基线 | 全局业务命名空间强制 Pod Security Admission `restricted` | `pod-security.kubernetes.io/enforce: restricted` | 拒绝 `privileged`、`hostPath`、`hostPID`、`CAP_SYS_ADMIN`、Root 容器 |
| Kubelet 安全配置 | 彻底禁用 `10255` 只读端口，关闭匿名访问并强制 Webhook 鉴权 | `--anonymous-auth=false`、`--authorization-mode=Webhook`、`--read-only-port=0` | 阻断 Pod 横向调用 Kubelet `/pods` 与 `/run` |
| etcd 与加密隔离 | 启用 `client-cert-auth: true`（双向 mTLS），启用 KMS Secret 静态加密，NetworkPolicy 禁 Pod 访问控制面 | 仅允许 `kube-apiserver` 访问 `2379` | 阻断 Pod 直连 etcd 导出 `/registry/secrets` |
| Pod 网络微隔离 | 默认拒绝 Egress 到元数据 IP、节点内网段及控制面端口 | `NetworkPolicy` deny `169.254.169.254/32` 与节点 `10250`/`2379` | 阻断 SSRF / Pod RCE 触达 IMDS 与节点端口 |
| 节点元数据与 Runtime | 节点开启 IMDSv2 + `HttpPutResponseHopLimit=1`；升级 `runc >= 1.1.12` | `HttpTokens=required`、`hop-limit=1` | 阻断跨网络命名空间获取节点 IAM Role 与 fd leak 逃逸 |

### Pod Security Admission 与默认 Egress 隔离示例

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prod-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-and-control-plane
  namespace: prod-app
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
      ports:
        - protocol: TCP
          port: 443
```

### Kubelet 安全配置片段（`/var/lib/kubelet/config.yaml`）

```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
```

## 防御工作流

1. **控制面端口与认证收口**：在所有工作节点检查 Kubelet 配置，关闭 `10255` 与匿名认证，确认 etcd 仅监听控制面私有网络并强制双向 TLS。
2. **准入与 Pod 安全基线落地**：为业务命名空间添加 PSA `restricted` 标签，并启用 Kyverno/Gatekeeper 阻断非合规 Pod 调度。
3. **Egress 微隔离与 IMDSv2 加固**：通过 CNI（Cilium/Calico）下发禁止业务 Pod 访问 `169.254.169.254`、节点 `10250` 和 etcd `2379` 的全局策略，同时将云节点 metadata hop-limit 设为 `1`。
4. **节点运行时升级与定期巡检**：统一升级节点 `runc` 与 `containerd` 至修复 CVE-2024-21626 的版本，并结合下方脚本周期性检查集群配置基线。

## 3. Python K8s 节点配置与 Pod 安全上下文核查脚本

```python
#!/usr/bin/env python3
"""Kubernetes Kubelet/Namespace/Pod 纵深安全基线检查工具。"""


def check_kubelet_config(cfg: dict) -> list[str]:
    issues = []
    if cfg.get("authentication", {}).get("anonymous", {}).get("enabled", True):
        issues.append("CRITICAL: kubelet anonymous auth must be false")
    if cfg.get("authorization", {}).get("mode") != "Webhook":
        issues.append("CRITICAL: kubelet authorization.mode must be Webhook")
    if cfg.get("readOnlyPort", 10255) != 0:
        issues.append("HIGH: kubelet readOnlyPort must be 0")
    return issues


def check_pod_restricted(pod_spec: dict, ns_labels: dict) -> list[str]:
    issues = []
    if ns_labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        issues.append("HIGH: namespace missing PSA enforce=restricted label")
    if pod_spec.get("automountServiceAccountToken", True):
        issues.append("MEDIUM: disable automountServiceAccountToken unless required")
    if pod_spec.get("hostPID") or pod_spec.get("hostNetwork"):
        issues.append("CRITICAL: hostPID/hostNetwork forbidden")
    for c in pod_spec.get("containers", []):
        sc = c.get("securityContext", {})
        if sc.get("privileged"):
            issues.append(f"CRITICAL: container {c.get('name')} is privileged")
        if sc.get("allowPrivilegeEscalation", True) is not False:
            issues.append(f"HIGH: container {c.get('name')} allowPrivilegeEscalation must be false")
        if "ALL" not in sc.get("capabilities", {}).get("drop", []):
            issues.append(f"HIGH: container {c.get('name')} must drop ALL capabilities")
    return issues


if __name__ == "__main__":
    good_kubelet = {"authentication": {"anonymous": {"enabled": False}}, "authorization": {"mode": "Webhook"}, "readOnlyPort": 0}
    good_pod = {
        "automountServiceAccountToken": False,
        "hostPID": False,
        "hostNetwork": False,
        "containers": [{
            "name": "web",
            "securityContext": {"privileged": False, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        }],
    }
    good_ns = {"pod-security.kubernetes.io/enforce": "restricted"}
    assert check_kubelet_config(good_kubelet) == []
    assert check_pod_restricted(good_pod, good_ns) == []

    bad_kubelet = {"authentication": {"anonymous": {"enabled": True}}, "authorization": {"mode": "AlwaysAllow"}, "readOnlyPort": 10255}
    print("bad kubelet issues:", check_kubelet_config(bad_kubelet))
    assert len(check_kubelet_config(bad_kubelet)) == 3
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| Kubelet 端口与鉴权 | `10255` 关闭，未认证访问 `10250` 返回 `401`/`403` | 可匿名列出 `/pods` 或触发 `/run` | `http_probe` 对节点 `10250`/`10255` 验证拒绝 |
| etcd 网络与 mTLS | Pod 内无法连通 `2379`，无客户端证书握手失败 | Pod 可直连 etcd 读取 `/registry/secrets` | 集群 NetworkPolicy 与 etcd TLS 配置核查 |
| Pod Security & Metadata | 业务 NS 强制 `restricted`，Pod 内请求 `169.254.169.254` 超时或被 IMDSv2 hop=1 拒绝 | 可从业务 Pod 获取节点 IAM Role 凭证或调度 `privileged` Pod | 在测试 Pod 验证 metadata 不可达与拒绝特权调度 |
| 节点运行时补丁 | 全节点 `runc >= 1.1.12` | 存在未修补 CVE-2024-21626 的 `runc` 节点 | 节点软件版本清单核查 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 K8s 纵深防护方案 | `kb_router` | 按 `Kubernetes` / `kubelet` / `etcd` 搜索防御指南 |
| 对照逃逸攻击链 | `kb_read_file` | 读取 `ctf-website/10-cloud/kubernetes-container` 核对三向分叉 |
| 端点暴露核验 | `http_probe` | 验证节点 Kubelet `10250`/`10255` 与 metadata 阻断状态 |
