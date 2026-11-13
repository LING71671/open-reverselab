---
id: "ctf-website/22-dos/11-cloud-container-dos-defense"
title: "云原生、Kubernetes 与 Serverless 拒绝服务防御"
title_en: "Cloud-Native, Kubernetes, and Serverless DoS Defense"
summary: >
  针对云原生基础设施拒绝服务与经济消耗（Denial of Wallet）的系统防御指南：涵盖 Kubernetes ResourceQuota 与优先级抢占隔离、HPA 扩缩容速率与上限封顶、Serverless 预留并发与计费熔断、IMDSv2 跳数限制与 NetworkPolicy 阻断元数据耗尽，以及容器 PID/共享内存/临时存储隔离。提供 K8s YAML 加固清单及 Python 策略校验脚本。
summary_en: >
  Defense guide for cloud-native DoS and Denial-of-Wallet: Kubernetes ResourceQuota and PriorityClass isolation, HPA maxReplicas and scaleUp rate capping, Serverless reserved concurrency and billing circuit breakers, IMDSv2 hop-limit and NetworkPolicy metadata isolation, and container PID/shm/ephemeral-storage boundaries. Includes K8s YAML configs and runnable Python manifest checker.
board: "ctf-website"
category: "22-dos"
signals:
  - "ResourceQuota 按优先级作用域隔离"
  - "HPA maxReplicas 与 scaleUp 步长上限"
  - "Serverless 预留并发与预算告警"
  - "IMDSv2 HttpPutResponseHopLimit=1"
  - "NetworkPolicy 阻断 169.254.169.254"
  - "容器 PID 上限与非特权只读根文件系统"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "Kubernetes DoS 防御"
  - "ResourceQuota 隔离"
  - "HPA 限流"
  - "Denial of Wallet 防护"
  - "IMDSv2 加固"
  - "容器 PID 限制"
  - "NetworkPolicy"
  - "cloud container dos defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "kubernetes"
  - "cloud-native"
  - "serverless"
  - "containers"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/11-cloud-container-dos"
track: "blue"
defends: "ctf-website/22-dos/11-cloud-container-dos"
---
# 云原生、Kubernetes 与 Serverless 拒绝服务防御

## 防御目标与对抗矩阵

云原生 DoS（对应攻击向量见 [11-cloud-container-dos.md](../../../../red/ctf-website/techniques/22-dos/11-cloud-container-dos.md)）不仅会瘫痪业务 Pod，还会利用弹性扩缩容与按量计费制造经济灾难（Denial of Wallet）或借容器压力拖垮宿主机。防御核心是**多租户配额硬隔离、弹性扩展速率封顶、元数据访问收敛以及内核级容器资源边界**。

| 攻击向量 | 影响面 | 核心防御措施 | 关键配置 / 策略 |
|---|---|---|---|
| ResourceQuota 耗尽与 PriorityClass 抢占 | 业务 Pod `Pending` 或被高优先级恶意 Pod 驱逐 | 分租户 Namespace 配额 + `scopeSelector` 限制高优先级配额为 0 + LimitRange + PDB | `NotTerminating` / `PriorityClass` 作用域隔离 + OPA/Kyverno 禁特权优先级 |
| HPA 无限扩容耗尽集群 | 节点耗尽资源 `NotReady`、账单暴涨 | 设置硬性 `maxReplicas` + `behavior.scaleUp` 步长与冷却窗 + 前置边缘 WAF 限流 | `maxReplicas <= 20`、`stabilizationWindowSeconds: 60` |
| Serverless 计费爆炸与冷启动放大 | Lambda/Cloud Run 巨额账单（Denial of Wallet） | 设置单函数 `ReservedConcurrentExecutions` 硬上限、边缘缓存/认证拦截无效请求、缩短超时与预算自动告警 | 预留并发封顶 + API Gateway Usage Plan + 异常计费熔断 |
| IMDS 元数据与云 API 限频 | 同节点业务无法获取 IAM 凭证或云接口报错 | 强制 IMDSv2 且设置 `HttpPutResponseHopLimit: 1` 阻断容器内跨跳访问，或 NetworkPolicy 封禁 `169.254.169.254/32` | 改用 Pod Identity / IRSA，严禁容器直连 IMDS；云 API 加本地缓存与指数退避 |
| 容器内资源压力波及宿主机 | 全局 PID 耗尽、共享卷 inode 耗尽、`/dev/shm` 爆满 | 启用容器运行时的 `PodPidsLimit`、限制 `ephemeral-storage` 与 `emptyDir.sizeLimit`、只读根文件系统 | `--pids-limit=256`、`readOnlyRootFilesystem: true`、`drop: ["ALL"]` |

---

## 防御工作流

### 阶段一：Kubernetes 配额、优先级与 HPA 封顶加固

1. **禁止普通租户使用系统级 PriorityClass**：通过 Kyverno/OPA Gatekeeper 策略或 `ResourceQuota` 作用域，阻止非系统命名空间声明 `system-cluster-critical` / `system-node-critical` 抢占核心组件；同时为关键服务配置 `PodDisruptionBudget`。
2. **HPA 扩容速率与上限双约束**：除设定绝对 `maxReplicas` 外，在 `autoscaling/v2` 中显式配置 `behavior.scaleUp`，防止恶意突发负载瞬间拉满整个节点池。

```yaml
# k8s-dos-hardening.yaml — 配额隔离、LimitRange 与受控 HPA
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-compute-quota
  namespace: app-prod
spec:
  hard:
    pods: "40"
    requests.cpu: "16"
    requests.memory: "32Gi"
    limits.cpu: "32"
    limits.memory: "64Gi"
    requests.ephemeral-storage: "20Gi"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: block-critical-priority-abuse
  namespace: app-prod
spec:
  hard:
    pods: "0"
  scopeSelector:
    matchExpressions:
      - operator: In
        scopeName: PriorityClass
        values: ["system-cluster-critical", "system-node-critical"]
---
apiVersion: v1
kind: LimitRange
metadata:
  name: default-container-bounds
  namespace: app-prod
spec:
  limits:
    - type: Container
      defaultRequest: { cpu: "100m", memory: "128Mi", ephemeral-storage: "128Mi" }
      default:        { cpu: "500m", memory: "512Mi", ephemeral-storage: "512Mi" }
      max:            { cpu: "2",    memory: "2Gi",   ephemeral-storage: "2Gi" }
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-api-hpa
  namespace: app-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-api
  minReplicas: 2
  maxReplicas: 15
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: { type: Utilization, averageUtilization: 65 }
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
```

### 阶段二：容器运行时防宿主机资源逃逸与元数据封禁

1. **kubelet 开启 `podPidsLimit: 256`**：防止容器内 Fork Bomb 消耗宿主机全局 `kernel.pid_max`；禁止使用 `hostPID`、`privileged: true` 与可写宿主机 `/proc`/`/sys`。
2. **锁定 `emptyDir.sizeLimit` 与 `/dev/shm` 尺寸**：为所有内存/磁盘临时卷显式声明 `sizeLimit`，防止写满节点根分区导致 `DiskPressure` 驱逐。
3. **NetworkPolicy 阻断容器直连 IMDS (`169.254.169.254`)**：结合 AWS `HttpPutResponseHopLimit=1` 与 IRSA（IAM Roles for Service Accounts），既消除凭证窃取又阻止容器内 IMDS 令牌洪泛影响同节点其它服务。

```yaml
# k8s-imds-egress-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cloud-metadata-egress
  namespace: app-prod
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

### 阶段三：Serverless 计费爆炸（Denial of Wallet）硬边界

1. **并发与超时双封顶**：为非核心函数设置 `ReservedConcurrentExecutions`（如 `50`）防止无限制冷启动与账号级并发池被吃空；将单次调用超时从默认 15 分钟收紧至业务实需（如 `5–15s`），并禁用无效输入下的盲目自动重试。
2. **边缘认证与缓存前置**：将静态/低变响应前置至 CDN 或 API Gateway Cache，未携带合法签名/Token 的请求在 API Gateway 层即返回 `401/429`，绝不唤醒后端函数计费实例。

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本对 Kubernetes 工作负载/HPA 字典清单与 Serverless 函数配置进行自动化合规校验：确保存在 CPU/Memory/Ephemeral-Storage 限制、只读根文件系统、禁用特权与 `hostPID`、HPA 设置合理 `maxReplicas`，以及 Serverless 预留并发与超时不超标。

```python
#!/usr/bin/env python3
"""Cloud-native DoS defense verifier: K8s Pod/HPA/NetworkPolicy & Serverless budget checks."""

from typing import Any


def validate_k8s_container_spec(container: dict[str, Any], pod_spec: dict[str, Any]) -> list[str]:
    """Validate Pod and Container resource & security boundaries against host resource DoS."""
    issues: list[str] = []
    if pod_spec.get("hostPID") or pod_spec.get("hostNetwork"):
        issues.append("forbidden_host_namespace")

    sc = container.get("securityContext", {})
    if sc.get("privileged"):
        issues.append("privileged_container_forbidden")
    if not sc.get("readOnlyRootFilesystem", False):
        issues.append("missing_readOnlyRootFilesystem")
    if not sc.get("runAsNonRoot", False):
        issues.append("missing_runAsNonRoot")

    limits = container.get("resources", {}).get("limits", {})
    for res in ("cpu", "memory", "ephemeral-storage"):
        if res not in limits:
            issues.append(f"missing_limit:{res}")

    for vol in pod_spec.get("volumes", []):
        if "emptyDir" in vol and "sizeLimit" not in vol["emptyDir"]:
            issues.append(f"unbounded_emptyDir:{vol.get('name')}")
    return issues


def validate_hpa_spec(hpa_spec: dict[str, Any], max_allowed_replicas: int = 50) -> list[str]:
    """Ensure HPA has bounded maxReplicas and scaleUp rate policies."""
    issues: list[str] = []
    max_rep = hpa_spec.get("maxReplicas")
    if not isinstance(max_rep, int) or max_rep <= 0 or max_rep > max_allowed_replicas:
        issues.append(f"invalid_maxReplicas:{max_rep}")
    scale_up = hpa_spec.get("behavior", {}).get("scaleUp", {})
    if not scale_up.get("policies"):
        issues.append("missing_scaleUp_rate_policy")
    return issues


def validate_serverless_config(fn_cfg: dict[str, Any], max_timeout_sec: int = 15, max_concurrency: int = 200) -> list[str]:
    """Verify Serverless function concurrency cap, timeout cap, and IMDS isolation."""
    issues: list[str] = []
    conc = fn_cfg.get("reserved_concurrency")
    if not isinstance(conc, int) or conc <= 0 or conc > max_concurrency:
        issues.append(f"unbounded_concurrency:{conc}")
    timeout = fn_cfg.get("timeout_sec", 900)
    if timeout > max_timeout_sec:
        issues.append(f"excessive_timeout:{timeout}s")
    if not fn_cfg.get("api_gateway_rate_limit"):
        issues.append("missing_edge_rate_limit")
    return issues


def run_self_checks() -> None:
    good_pod = {
        "hostPID": False,
        "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}}],
    }
    good_container = {
        "securityContext": {"privileged": False, "readOnlyRootFilesystem": True, "runAsNonRoot": True},
        "resources": {"limits": {"cpu": "500m", "memory": "512Mi", "ephemeral-storage": "512Mi"}},
    }
    assert validate_k8s_container_spec(good_container, good_pod) == []

    bad_pod = {"hostPID": True, "volumes": [{"name": "tmp", "emptyDir": {}}]}
    bad_container = {"securityContext": {"privileged": True}, "resources": {"limits": {"cpu": "1"}}}
    assert len(validate_k8s_container_spec(bad_container, bad_pod)) >= 5

    good_hpa = {"maxReplicas": 15, "behavior": {"scaleUp": {"policies": [{"type": "Pods", "value": 2}]}}}
    assert validate_hpa_spec(good_hpa) == []
    assert "invalid_maxReplicas:500" in validate_hpa_spec({"maxReplicas": 500})

    good_fn = {"reserved_concurrency": 50, "timeout_sec": 10, "api_gateway_rate_limit": True}
    assert validate_serverless_config(good_fn) == []
    assert len(validate_serverless_config({"timeout_sec": 900})) == 3
    print("[PASS] All cloud-native & container DoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| K8s 配额与优先级隔离 | 普通业务 Namespace 无法创建 `system-cluster-critical` Pod 且总容量受 `ResourceQuota` 硬控 | 越权 Pod 创建立即被 Admission 拒绝 |
| HPA 可控弹性 | 持续高 CPU 压力下扩容受 `stabilizationWindow` 节流且止步于 `maxReplicas` | 节点资源保留安全缓冲 `>= 20%`，零 `NotReady` |
| 容器边界与 IMDS 隔离 | 容器内无法访问 `169.254.169.254` 且 Fork 测试在 `256` 进程处被截断 | 宿主机负载与 PID 数量保持平稳 |
| Serverless 成本封顶 | 突发洪泛在 API Gateway 返回 `429` 或在预留并发上限处限流，未产生无界账单 | 单日调用费用处于预算告警阈值内 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 云原生边缘端点核验 | `http_probe` | 验证 API Gateway / Ingress 限流与 429 降级行为 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 搜索 `kubernetes` / `serverless` / `imds` 防御文档 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/11-cloud-container-dos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下所有云原生防御指南 |
