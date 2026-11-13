---
id: "ctf-website/10-cloud/container-runtime-escape"
title: "容器运行时逃逸打点"
title_en: "Container Runtime Escape Field Checks"
summary: >
  容器运行时逃逸技术卡片，覆盖容器内环境识别、capabilities/seccomp/AppArmor 检查、Docker socket 暴露、privileged/hostPID/hostPath、runc/containerd 版本命中，以及从容器 shell 到宿主机路径的实战打点流程。
summary_en: >
  Container runtime escape field-check card covering in-container environment detection, capabilities/seccomp/AppArmor checks, exposed Docker socket, privileged/hostPID/hostPath, runc/containerd version hits, and a practical path from container shell to host reachability.
board: "ctf-website"
category: "10-cloud"
signals: ["container", "Docker", "containerd", "runc", "privileged", "hostPath", "docker.sock", "capabilities", "seccomp", "AppArmor"]
mcp_tools: ["http_probe", "kb_router", "run_ctf_tool"]
keywords: ["容器逃逸", "Docker socket", "privileged container", "hostPath", "capabilities", "seccomp", "AppArmor", "runc", "containerd"]
difficulty: "advanced"
tags: ["cloud", "container", "docker", "runtime", "escape", "ctf"]
language: "zh-CN"
last_updated: "2026-07-03"
related_articles: ["kubernetes-container.md", "k8s-rbac-attack-paths.md"]
---
# 容器运行时逃逸打点

## 场景

拿到容器内 shell 后，先判断它是普通 Docker、Kubernetes Pod、CI runner 容器，还是已经挂了宿主机资源。核心不是背 CVE，而是快速回答三件事：有没有宿主机控制面、有没有危险 capability、有没有 host mount。

## 输入信号

- `/proc/1/cgroup` 出现 `docker`、`kubepods`、`containerd`
- `/var/run/docker.sock` 可读写
- `CapEff` 包含 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`
- `/host`、`/mnt/host` 或 `/var/lib/kubelet` 被挂载
- `securityContext.privileged=true` 或 `hostPID=true`

## 容器环境基线

```bash
echo "[cgroup]"
cat /proc/1/cgroup 2>/dev/null

echo "[capabilities]"
grep -E 'Cap(Prm|Eff|Bnd)|Seccomp' /proc/self/status

echo "[mounts]"
grep -E 'docker|containerd|kubelet|/host|/var/run/docker.sock' /proc/self/mountinfo

echo "[profile]"
cat /proc/self/attr/current 2>/dev/null || true
ls -l /var/run/docker.sock 2>/dev/null || true
```

## 快速打点脚本

```python
# container_escape_paths.py - 容器逃逸入口打点
from pathlib import Path

def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""

signals = []
status = read("/proc/self/status")
mounts = read("/proc/self/mountinfo")
cgroup = read("/proc/1/cgroup")

if "docker" in cgroup or "kubepods" in cgroup or "containerd" in cgroup:
    signals.append("running-inside-container")
if "0000003fffffffff" in status or "CapEff:\t0000003fffffffff" in status:
    signals.append("broad-capabilities")
if "Seccomp:\t0" in status:
    signals.append("seccomp-disabled")
if "/var/run/docker.sock" in mounts or Path("/var/run/docker.sock").exists():
    signals.append("docker-socket-mounted")
if "/var/lib/kubelet" in mounts or "/host" in mounts:
    signals.append("host-path-mounted")

print({"signals": signals, "next": "docker.sock/hostPath/capability" if len(signals) >= 3 else "version-and-mount-check"})
```

## 关键入口

### Docker Socket

```bash
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

如果 socket 可写，等价于拿到 Docker API。下一跳看能否创建容器、挂载 `/`、读写宿主机路径。

### Privileged / hostPath / hostPID

```text
privileged=true → capabilities 广、设备访问多
hostPath=/ → 宿主机文件系统直接暴露
hostPID=true → 可观察宿主机进程，结合 nsenter 风险更高
CAP_SYS_ADMIN → mount/ns/cgroup 相关逃逸面显著扩大
```

### runc/containerd CVE 判定

```bash
runc --version 2>/dev/null || true
containerd --version 2>/dev/null || true
crictl version 2>/dev/null || true
```

版本命中只是线索，真正决定路径的是启动参数、runtime 配置、内核、LSM 和可达文件描述符。

## 攻击链

```text
Container shell → docker.sock mounted → Docker API → host filesystem access → Flag
Container shell → privileged + hostPath → chroot/nsenter 验证 → host proof
K8s Pod → hostPID + CAP_SYS_PTRACE → 观察宿主进程 → 凭证线索
CI container → mounted workspace + cloud env → CI secret → cloud IAM
```

## Evidence

记录: `/proc/1/cgroup`、capability 摘要、seccomp/AppArmor 状态、挂载点摘要、Docker API 响应、runtime 版本、可达宿主机路径。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 本地 HTTP/socket 探测 | `http_probe` | 探测 Docker API、kubelet、metadata |
| 知识检索 | `kb_router` | 按 docker.sock / privileged / runc 信号搜索 |
| 路径脚本运行 | `run_ctf_tool` | 执行容器逃逸入口打点 |
