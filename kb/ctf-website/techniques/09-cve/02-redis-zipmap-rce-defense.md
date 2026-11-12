---
id: "ctf-website/09-cve/02-redis-zipmap-rce-defense"
title: "Redis/Valkey RESTORE 防御：zipmap 规范编码校验与 ACL 隔离（CVE-2026-25243）"
title_en: "Redis/Valkey RESTORE Defense: zipmap Canonical Validation & ACL Isolation (CVE-2026-25243)"
summary: >
  针对 CVE-2026-25243（Redis/Valkey RESTORE 命令处理 RDB type 9 zipmap 时，zipmapValidateIntegrity 与 zipmapNext 对 overlong 长度前缀步长理解不一致引发堆越界读）的蓝队防御方案。包含 canonical 长度检查补丁原理、ACL 禁用 RESTORE/DEBUG 临时缓解、网络暴露收口、以及 Python 离线 RDB/zipmap 畸形负载检测脚本。
summary_en: >
  Blue-team defense guide for CVE-2026-25243 (Redis/Valkey RESTORE command zipmap overlong length prefix step mismatch causing heap out-of-bounds read). Covers canonical length validation patch semantics, ACL restrictions on RESTORE/DEBUG commands, network exposure hardening, and a Python offline RDB/zipmap malformed payload detector.
board: "ctf-website"
category: "09-cve"
signals: ["CVE-2026-25243", "Redis defense", "Valkey defense", "zipmap canonical check", "RESTORE ACL", "RDB_TYPE_HASH_ZIPMAP", "heap overflow mitigation"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["CVE-2026-25243防御", "Redis RESTORE加固", "Valkey补丁", "zipmap长度校验", "ACL禁用RESTORE", "RDB type 9", "内存越界防护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cve", "redis", "valkey", "memory-safety"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/09-cve/02-redis-zipmap-rce", "ctf-website/11-dos/01-valkey-resp-dos-defense"]
track: "blue"
defends: "ctf-website/09-cve/02-redis-zipmap-rce"
---
# Redis/Valkey RESTORE 防御：zipmap 规范编码校验与 ACL 隔离（CVE-2026-25243）

## 1. 威胁模型与漏洞根因回顾

CVE-2026-25243 影响 Redis 与 Valkey 对 `RESTORE` 命令中 RDB type 9（`RDB_TYPE_HASH_ZIPMAP`）载荷的解析。即使现代实例默认采用 listpack/hashtable 存储 Hash，仍保留了对历史 RDB type 9 的反序列化分支。漏洞根因在于：
- `zipmapValidateIntegrity` 依据首字节 `0xFE` 判定长度前缀为 5 字节（overlong 编码，如 `fe 03 00 00 00`）。
- `zipmapNext` 随后通过 `zipmapRawKeyLength` -> `zipmapEncodeLength(NULL, l)` 计算前缀步长，当 `l = 3 < 254` 时仅前进 1 字节而非 5 字节。
- 4 字节步长差导致第二次迭代指针落入字符串内部，把普通 ASCII 字符（如 `'a'` = `0x61` = 97）当成长度送入 `sdstrynewlen`，触发堆越界读及潜在内存破坏。

## 2. 分层防御与缓解措施

| 防线层级 | 控制措施 | 适用场景 | 效果 |
|---|---|---|---|
| 官方补丁升级 | 升级至包含 Valkey commit `fea0b4064`（PR #3619）或对应 Redis GHSA 修复的版本 | 所有生产 Redis/Valkey 节点 | 在 `zipmapValidateIntegrity` 中拒绝非规范（overlong）长度编码 |
| ACL 最小权限 | 除专用迁移账号外，对业务账号禁用 `RESTORE`、`MIGRATE`、`DEBUG` 命令 | 尚未完成二进制升级的集群 | 阻断未授权或低权限客户端注入自定义 RDB payload |
| 网络与认证边界 | 强制 `requirepass` / ACL 用户口令、TLS、关闭公网监听并启用 `protected-mode yes` | 全部部署环境 | 防止未认证侧直接投递恶意 RDB 流 |
| 运行时监控 | 监控 `RESTORE` 调用频次、异常 `Bad data format` 报错及服务重启事件 | SOC / 数据库安全监测 | 及时捕获利用尝试 |

### 源码层面补丁原理（Canonical Check）

```c
// zipmap.c: zipmapValidateIntegrity 中强制要求长度前缀采用最小规范编码
unsigned int s = zipmapGetEncodedLengthSize(p);
if (s == 0) return 0;
unsigned int l = zipmapDecodeLength(p);
if (l < ZIPMAP_BIGLEN && s != 1) {
    // 长度小于 254 时必须使用 1 字节短编码，禁止 0xFE + uint32 的 overlong 形式
    return 0;
}
```

### ACL 与配置加固基线

```conf
# valkey.conf / redis.conf 最小权限加固示例
protected-mode yes
bind 127.0.0.1 10.0.10.20
enable-debug-command no

# 默认业务用户禁止危险序列化与管理命令
user default off
user app_rw on >StrongRandomCredentialPlaceholder ~app:* &* +@read +@write -@dangerous -RESTORE -MIGRATE -DEBUG -SLAVEOF -REPLICAOF
```

若使用在线 ACL 命令临时收口：

```bash
valkey-cli ACL SETUSER default -RESTORE -MIGRATE -DEBUG
valkey-cli ACL SAVE
```

## 防御工作流

1. **版本与补丁基线核查**：盘点全量 Redis/Valkey 实例版本与二进制构建 commit，确认是否已合入 `zipmapValidateIntegrity` canonical 校验。
2. **ACL 命令面收敛**：检查 `ACL LIST` 中所有业务角色，移除 `+RESTORE`、`+@dangerous`、`+DEBUG` 等非必要权限；仅迁移窗口期对专有白名单账号按需放行。
3. **实例配置与网络核验**：确认 `protected-mode yes`、`enable-debug-command no` 已启用，且 6379/TLS 端口仅对受信任应用网段开放。
4. **离线载荷校验与回归检查**：在升级前后使用校验脚本对历史 RDB dump 片段与模拟畸形 zipmap 样本做规范性检测，确认非规范编码被拒绝。

## 3. Python 离线 zipmap 规范编码检测与 ACL 策略检查脚本

```python
#!/usr/bin/env python3
"""CVE-2026-25243 离线 zipmap canonical 编码校验与 Redis ACL 基线检查。"""

import struct

ZIPMAP_BIGLEN = 254
ZIPMAP_END = 255


def validate_zipmap_canonical(blob: bytes) -> tuple[bool, str]:
    """复现补丁后的 zipmap canonical 长度校验逻辑。"""
    if len(blob) < 2:
        return False, "zipmap too short"
    pos = 1  # 跳过 zmlen 首字节
    while pos < len(blob):
        first = blob[pos]
        if first == ZIPMAP_END:
            return True, "valid canonical zipmap"
        if first < ZIPMAP_BIGLEN:
            key_len = first
            pos += 1
        elif first == ZIPMAP_BIGLEN:
            if pos + 5 > len(blob):
                return False, "truncated 5-byte key length"
            (key_len,) = struct.unpack_from("<I", blob, pos + 1)
            if key_len < ZIPMAP_BIGLEN:
                return False, f"overlong key length prefix: 0xFE for len={key_len}"
            pos += 5
        else:
            return False, "unexpected end marker"

        if pos + key_len >= len(blob):
            return False, "key exceeds zipmap bounds"
        pos += key_len

        # 解析 value 长度与 free 字节
        vfirst = blob[pos]
        if vfirst < ZIPMAP_BIGLEN:
            val_len = vfirst
            pos += 1
        elif vfirst == ZIPMAP_BIGLEN:
            if pos + 5 > len(blob):
                return False, "truncated 5-byte value length"
            (val_len,) = struct.unpack_from("<I", blob, pos + 1)
            if val_len < ZIPMAP_BIGLEN:
                return False, f"overlong value length prefix: 0xFE for len={val_len}"
            pos += 5
        else:
            return False, "invalid value length prefix"

        if pos + 1 > len(blob):
            return False, "missing free byte"
        free_len = blob[pos]
        pos += 1 + val_len + free_len
    return False, "missing ZIPMAP_END (0xFF)"


def check_acl_line(acl_rule: str) -> tuple[bool, list[str]]:
    tokens = acl_rule.split()
    issues = []
    if "+@all" in tokens and "-RESTORE" not in tokens and "-@dangerous" not in tokens:
        issues.append("RESTORE permitted via +@all")
    if "+RESTORE" in tokens:
        issues.append("RESTORE explicitly enabled")
    if "nopass" in tokens:
        issues.append("nopass enabled")
    return len(issues) == 0, issues


if __name__ == "__main__":
    # CVE-2026-25243 畸形 zipmap 内部片段（zmlen=0x02, overlong key len=3）
    malformed = bytes.fromhex("02fe0300000061626303006465660367686903006a6b6cff")
    canonical = bytes.fromhex("020361626303006465660367686903006a6b6cff")

    ok_bad, msg_bad = validate_zipmap_canonical(malformed)
    ok_good, msg_good = validate_zipmap_canonical(canonical)
    print("malformed:", ok_bad, msg_bad)
    print("canonical:", ok_good, msg_good)
    assert not ok_bad and "overlong" in msg_bad
    assert ok_good

    acl_ok, acl_issues = check_acl_line("user app on >hash +@read +@write -@dangerous -RESTORE")
    assert acl_ok and not acl_issues
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| 二进制补丁状态 | Valkey 已包含 `fea0b4064` 或 Redis 已升至官方修复版 | 运行未修补版本且未隔离网络/ACL | `INFO server` 核对版本与构建提交 |
| 畸形 `RESTORE` 响应 | 提交 overlong zipmap 时返回 `-ERR Bad data format` 且无 ASan/crash | 服务崩溃、重启或成功写入异常 key | 离线校验脚本 + 隔离测试实例回归 |
| ACL 命令策略 | 业务账号均含 `-RESTORE`、`-DEBUG`、`-@dangerous` 且禁用 `nopass` | 业务账号或 `default` 允许 `+RESTORE` | `ACL LIST` 输出核查 |
| 调试开关与网络 | `enable-debug-command no`、`protected-mode yes`、非公网暴露 | 允许未认证访问或开启公网 `bind 0.0.0.0` | `CONFIG GET` 与端口可达性检查 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索关联防御策略 | `kb_router` | 按 `CVE-2026-25243` / `Valkey` / `RESTORE` 搜索攻防条目 |
| 核对攻击载荷结构 | `kb_read_file` | 读取 `ctf-website/09-cve/02-redis-zipmap-rce` 验证构造细节 |
| 核查同目录防护体系 | `kb_catalog` | 浏览 `09-cve` 与 `11-dos` 下的数据库与缓存加固指南 |
