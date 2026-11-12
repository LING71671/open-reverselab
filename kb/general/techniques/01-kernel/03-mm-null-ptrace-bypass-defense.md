---
id: "general/01-kernel/03-mm-null-ptrace-bypass-defense"
title: "内核 FD Theft 与 mm-NULL Ptrace 绕过防御（Yama / Seccomp / SUID 收敛）"
title_en: "Defense Against Kernel FD Theft and mm-NULL ptrace Bypass"
summary: >
  防御 CVE-2026-46333（do_exit mm-NULL 窗口导致 pidfd_getfd 绕过 dumpable 检查）：升级至包含提交 31e62c2ebbfd 的内核、通过 Seccomp 阻断非特权容器调用 pidfd_getfd、启用 Yama ptrace_scope 与清理高风险 SUID 暴露面。
summary_en: >
  Defense against CVE-2026-46333 (mm-NULL window in do_exit allowing pidfd_getfd to bypass dumpable checks): upgrade to kernel with commit 31e62c2ebbfd, block pidfd_getfd via seccomp, enforce Yama ptrace_scope, and minimize SUID binaries.
board: "general"
category: "01-kernel"
signals:
  - "pidfd_getfd block"
  - "yama ptrace_scope"
  - "SUID reduction"
  - "CVE-2026-46333"
  - "dumpable hardening"
  - "seccomp"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "FD theft defense"
  - "pidfd_getfd"
  - "Yama ptrace_scope"
  - "SUID hardening"
  - "CVE-2026-46333"
difficulty: "intermediate"
tags:
  - "kernel-defense"
  - "ptrace-defense"
  - "seccomp"
  - "SUID-hardening"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/01-kernel/03-mm-null-ptrace-bypass"
  - "general/01-kernel/04-cifswitch-nss-privesc-defense"
track: "blue"
defends: "general/01-kernel/03-mm-null-ptrace-bypass"
---
# 内核 FD Theft 与 mm-NULL Ptrace 绕过防御（Yama / Seccomp / SUID 收敛）

## 防御目标

防止非特权进程利用内核 `do_exit()` 中 `exit_mm()` 与 `exit_files()` 之间的 `mm-NULL` 竞态窗口（CVE-2026-46333），通过 `pidfd_open(434)` + `pidfd_getfd(438)` 复制已退出的 SUID 进程打开的 `/etc/shadow` 或 SSH 主机私钥句柄。

## 分层防御矩阵

| 防御层 | 控制点 | 实施细节 | 效果 |
|---|---|---|---|
| 内核修复 | 合入提交 `31e62c2ebbfd`（2026-05-14 之后稳定版内核） | `__ptrace_may_access()` / `pidfd_getfd()` 在 `mm == NULL` 时强制失败或严格校验 `PF_EXITING`/dumpable | 从内核根因封堵 `mm-NULL` 窗口 |
| Seccomp 过滤 | 禁用 `pidfd_getfd`（x86_64 syscall 438） | 在容器运行时、systemd 服务单元（`SystemCallFilter=~pidfd_getfd`）和沙箱中拦截 `pidfd_getfd` | 截断跨进程 FD 复制原语 |
| Ptrace 与 Dumpable 收敛 | `kernel.yama.ptrace_scope >= 1`、`fs.suid_dumpable = 0` | 限制进程间 `ptrace` 附着关系并禁止 SUID 进程生成核心转储 | 缩小可附着与转储暴露面 |
| SUID 暴露面最小化 | 清理/替换 SUID 二进制（`ssh-keysign`、`chage` 等） | 移除非必要 SUID 位；无需 Host-Based Auth 时禁用 `ssh-keysign` 的 SUID 位并配置 `HostbasedAuthentication no` | 消除“以 root 打开敏感文件后降权退出”的攻击靶标 |
| 凭证隔离与密码哈希强度 | 使用 `yescrypt` / `Argon2id` 并限制 `ssh_host_*_key` 访问策略 | 即便发生历史泄露也提升离线破解门槛，并触发 SSH 主机密钥告警 | 降低二次横向风险 |

## 防御实现与校验示例

### 1. systemd 服务沙箱与 sysctl 加固配置

```ini
# /etc/sysctl.d/99-ptrace-hardening.conf
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
```

```ini
# systemd unit 片段：阻断服务及子进程使用 pidfd_getfd
[Service]
SystemCallFilter=~pidfd_getfd
NoNewPrivileges=yes
```

### 2. 系统 SUID 暴露面与 sysctl 基线检查脚本（Python）

```python
from pathlib import Path

SENSITIVE_SUID_TARGETS = {
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/bin/chage",
}

def evaluate_fd_theft_posture(suid_paths: list[str], yama_scope: int, seccomp_blocks_pidfd_getfd: bool) -> dict:
    risky_suid = [p for p in suid_paths if p in SENSITIVE_SUID_TARGETS]
    findings = []
    if yama_scope < 1:
        findings.append("weak_yama_ptrace_scope")
    if not seccomp_blocks_pidfd_getfd:
        findings.append("pidfd_getfd_not_filtered_in_sandbox")
    if risky_suid:
        findings.append(f"suid_targets_present:{','.join(risky_suid)}")
    return {
        "hardened": len(findings) == 0,
        "findings": findings,
    }

if __name__ == "__main__":
    assert evaluate_fd_theft_posture([], 2, True)["hardened"] is True
    res = evaluate_fd_theft_posture(["/usr/bin/chage"], 0, False)
    assert not res["hardened"] and len(res["findings"]) == 3
    print("mm_null_fd_theft_defense: PASS")
```

## 防御工作流

```text
1. 核对内核补丁：确认运行内核已包含修复提交 31e62c2ebbfd（或发行版对应 CVE-2026-46333 安全更新）
2. 启用 Yama 与转储禁用：设置 kernel.yama.ptrace_scope >= 1（服务器推荐 2）及 fs.suid_dumpable = 0
3. 清理高危 SUID：若业务未启用 SSH HostbasedAuthentication，剥离 ssh-keysign SUID 权限（chmod u-s）
4. Seccomp 拦截：在容器与隔离服务配置中禁止 pidfd_getfd 系统调用
5. 运行时检测：对高频 fork + pidfd_open + pidfd_getfd 的异常进程行为生成告警
```

## 验证与判定标准

- **系统调用拦截**：在配置了 `SystemCallFilter=~pidfd_getfd` 的服务或容器内调用 `pidfd_getfd` 返回 `EPERM`
- **内核补丁校验**：在已修复内核上运行 `pidfd_getfd` 访问正在退出的子进程句柄返回 `EACCES` / `EPERM` / `ESRCH`，无法读取 `/etc/shadow` 或 `ssh_host_*_key`
- **SUID 与 sysctl 合规**：`sysctl kernel.yama.ptrace_scope` >= 1、`sysctl fs.suid_dumpable` == 0，且非必需 SUID 列表已清空

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 同类内核逃逸路径查询 | `kb_router` | 检索 ptrace/namespace 相关防御卡 |
| 加固配置文件生成 | `workspace_write_text` | 输出 sysctl 与 systemd seccomp 加固片段 |
| 异常行为检测规则 | `make_sigma_stub` | 生成高频 `pidfd_open`/`pidfd_getfd` 窃取行为检测规则 |
