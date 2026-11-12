---
id: "ctf-website/10-cloud/container-runtime-escape-defense"
title: "容器运行时逃逸防御：Docker Socket 隔离、Capabilities 收敛与 LSM 加固"
title_en: "Container Runtime Escape Defense: Docker Socket Isolation, Capabilities Drop & LSM Hardening"
summary: >
  针对容器运行时逃逸打点与利用链的蓝队防御指南。覆盖禁止挂载 docker.sock/containerd.sock、消除 privileged/hostPath/hostPID 配置、Capabilities 全量 Drop 与 Seccomp/AppArmor 强制基线、runc/containerd 补丁版本核查（含 CVE-2024-21626 防护），以及 Python 容器安全基线合规检测脚本。
summary_en: >
  Blue-team defense guide against container runtime escape paths. Covers prohibiting docker.sock/containerd.sock mounts, eliminating privileged/hostPath/hostPID specs, dropping all Linux capabilities with mandatory Seccomp/AppArmor profiles, runc/containerd patch verification (including CVE-2024-21626), and a Python container runtime spec compliance checker.
board: "ctf-website"
category: "10-cloud"
signals: ["container escape defense", "docker.sock isolation", "drop capabilities", "seccomp", "AppArmor", "non-root container", "runc patch"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["容器逃逸防御", "Docker socket禁止挂载", "Capabilities收敛", "Seccomp基线", "AppArmor配置", "runc升级", "无特权容器"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "container", "docker", "runtime-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/10-cloud/container-runtime-escape", "ctf-website/10-cloud/kubernetes-container-defense"]
track: "blue"
defends: "ctf-website/10-cloud/container-runtime-escape"
---
# 容器运行时逃逸防御：Docker Socket 隔离、Capabilities 收敛与 LSM 加固

## 1. 威胁模型与逃逸前提

容器内的命令执行本身不等于宿主机失陷，真正促成容器逃逸的通常是以下四类运行时配置与组件缺陷：
1. **宿主机控制面 Socket 挂载**：将 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 挂载进业务容器或 CI 容器，等效于直接授予宿主机 Root 级容器编排权限。
2. **特权模式与宿主命名空间共享**：开启 `privileged=true`、`hostPID=true`、`hostNetwork=true` 或挂载 `/`、`/host`、`/var/lib/kubelet` 等 `hostPath`。
3. **能力集与系统调用过滤缺失**：未执行 `cap-drop=ALL`，或关闭 Seccomp（`Seccomp: 0`）与 AppArmor/SELinux，使容器保留 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE` 等高危系统调用能力。
4. **运行时本身漏洞**：如旧版 `runc` 内部文件描述符泄漏（CVE-2024-21626）或 `containerd` 漏洞。

## 2. 核心加固策略与运行时基线

| 防线维度 | 加固要求 | 推荐配置 | 阻断效果 |
|---|---|---|---|
| 控制面 Socket | 严禁挂载 `docker.sock` / `containerd.sock` | 构建类场景改用 Rootless BuildKit / Kaniko / Buildah | 阻断经 Docker API 挂载宿主根目录逃逸 |
| Linux Capabilities | 先全量丢弃再按需精确加回 | `--cap-drop=ALL`，默认零额外 Capability | 消除 `CAP_SYS_ADMIN` / `CAP_SYS_PTRACE` 滥用面 |
| 特权与宿主挂载 | 禁止 `privileged`、`hostPID`、`hostIPC` 与敏感 `hostPath` | `allowPrivilegeEscalation: false`、`readOnlyRootFilesystem: true` | 阻断 `nsenter`、设备挂载与宿主文件系统篡改 |
| Seccomp 与 LSM | 强制启用 `RuntimeDefault` Seccomp 与 AppArmor/SELinux | `seccompProfile.type: RuntimeDefault`、非 `unconfined` | 拦截 `bpf`、`mount`、`ptrace`、`keyctl` 等危险系统调用 |
| 身份与命名空间 | 非 Root 运行 + User Namespace 映射 / Rootless Runtime | `USER 65532:65532`、开启 `userns-remap` | 即使发生文件挂载穿透也无法映射宿主机 UID 0 |
| 运行时补丁 | 升级 `runc >= 1.1.12` / `containerd >= 1.7.13` 并定期巡检 | 启用底层内核 cgroup v2 与只读 `/proc` 遮罩 | 消除已知 fd leak 等运行时逃逸 CVE |

### Docker Compose / Pod 安全基线配置模板

```yaml
services:
  app:
    image: registry.example.com/app:1.4.2
    user: "65532:65532"
    read_only: true
    privileged: false
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      - seccomp:default
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
```

## 防御工作流

1. **运行环境基线摸底**：检查宿主机 `runc`/`containerd` 版本、`/proc/sys/kernel` 安全参数以及 Docker daemon 是否启用 `no-new-privileges` 与 `userns-remap`。
2. **容器定义与编排拦截**：在 CI 阶段及集群准入控制器（OPA Gatekeeper / Kyverno）扫描并拒绝任何含 `privileged: true`、`docker.sock`、`hostPID: true` 或缺失 `cap_drop: ALL` 的配置。
3. **替换高风险构建模式**：将依赖 Docker-in-Docker 或 `docker.sock` 的 CI 构建器迁移至无特权 Rootless BuildKit 或独立临时构建 VM。
4. **运行时行为监测**：部署 Falco / eBPF 运行时检测规则，告警容器内打开 `/proc/self/fd/*` 指向宿主机路径、执行 `nsenter`、`mount` 或访问云元数据端点的行为。

## 3. Python 容器配置基线与运行时逃逸风险自检脚本

```python
#!/usr/bin/env python3
"""容器部署配置（Docker/Pod Spec）运行时逃逸防线合规检查脚本。"""

SENSITIVE_HOST_PATHS = ("/", "/etc", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/kubelet")
DANGEROUS_CAPS = {"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_DAC_READ_SEARCH", "ALL"}


def audit_container_spec(spec: dict) -> list[str]:
    issues: list[str] = []
    if spec.get("privileged") is True:
        issues.append("CRITICAL: privileged=true is forbidden")
    if spec.get("hostPID") or spec.get("hostIPC") or spec.get("hostNetwork"):
        issues.append("HIGH: host namespace sharing (hostPID/hostIPC/hostNetwork) enabled")

    cap_drop = {c.upper() for c in spec.get("cap_drop", [])}
    cap_add = {c.upper() for c in spec.get("cap_add", [])}
    if "ALL" not in cap_drop:
        issues.append("HIGH: cap_drop must include ALL")
    if cap_add & DANGEROUS_CAPS:
        issues.append(f"CRITICAL: dangerous capabilities added: {sorted(cap_add & DANGEROUS_CAPS)}")

    if not spec.get("no_new_privileges", False):
        issues.append("MEDIUM: no-new-privileges must be true")
    if spec.get("seccomp_profile") in (None, "unconfined"):
        issues.append("HIGH: seccomp profile must not be unconfined")
    if str(spec.get("user", "0")).startswith("0"):
        issues.append("MEDIUM: container should run as non-root UID")

    for mount in spec.get("mounts", []):
        src = str(mount.get("source", ""))
        if src in SENSITIVE_HOST_PATHS or src.startswith("/var/run/docker.sock"):
            issues.append(f"CRITICAL: sensitive host mount {src}")
    return issues


if __name__ == "__main__":
    bad_spec = {
        "privileged": False,
        "hostPID": True,
        "cap_drop": [],
        "cap_add": ["CAP_SYS_ADMIN"],
        "seccomp_profile": "unconfined",
        "user": "0:0",
        "mounts": [{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}],
    }
    good_spec = {
        "privileged": False,
        "hostPID": False,
        "cap_drop": ["ALL"],
        "cap_add": [],
        "no_new_privileges": True,
        "seccomp_profile": "RuntimeDefault",
        "user": "65532:65532",
        "mounts": [{"source": "/var/app/data", "target": "/data"}],
    }
    bad_issues = audit_container_spec(bad_spec)
    good_issues = audit_container_spec(good_spec)
    print("bad:", bad_issues)
    print("good:", good_issues)
    assert len(bad_issues) >= 5
    assert len(good_issues) == 0
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| 控制面 Socket 与宿主路径 | 容器内不存在 `/var/run/docker.sock`、`/run/containerd/containerd.sock` 与敏感 `hostPath` | 存在任意宿主机控制面 Socket 挂载 | `mountinfo` 核查与配置基线检查零 CRITICAL |
| Capabilities 与 Seccomp | `/proc/self/status` 中 `CapEff: 0000000000000000` 且 `Seccomp: 2` | `CapEff` 含高危位或 `Seccomp: 0` | 容器内基线校验脚本复核 |
| 身份与根文件系统 | 非 UID 0 运行、`no-new-privileges` 开启、根文件系统只读 | 以 root 运行且可写根文件系统及提权位有效 | `id` 核查与 `inspect` 配置检查 |
| 运行时版本 | `runc >= 1.1.12`、`containerd >= 1.7.13`（含 CVE-2024-21626 修复） | 运行低于修复基线的 runtime 版本 | `runc --version` 与 `containerd --version` |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索容器加固方案 | `kb_router` | 按 `container` / `seccomp` / `docker.sock` 搜索蓝队基线 |
| 核对逃逸打点清单 | `kb_read_file` | 读取 `ctf-website/10-cloud/container-runtime-escape` 对照检查面 |
| 关联 K8s 集群防护 | `kb_catalog` | 查找 `10-cloud` 下的 Kubernetes 与 RBAC 防护条目 |
