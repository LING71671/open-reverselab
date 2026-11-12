---
id: "ctf-website/03-injection/sqli-nosqli-defense"
title: "SQLi 与 NoSQLi 纵深防御及账本隔离"
title_en: "SQLi and NoSQLi Defense and Ledger Isolation"
summary: >
  针对高阶 SQL 注入（WAF 绕过、盲注、二阶注入、OOB 外带、堆叠查询、WAFFLED Content-Type 走私）与 NoSQL 注入（MongoDB $ne/$regex/$where 与嵌套对象注入）的纵深防御指南，包含编码层归一化、最小数据库权限矩阵、支付账本数据隔离及可运行 Python 参数化与输入校验器。
summary_en: >
  Defense-in-depth guide against advanced SQL injection (WAF bypasses, blind, second-order, OOB exfiltration, stacked queries, WAFFLED Content-Type smuggling) and NoSQL injection (MongoDB operators, $where JS execution, nested objects). Covers encoding normalization, least-privilege DB matrix, payment ledger isolation, and runnable Python parameterization/validation code.
board: "ctf-website"
category: "03-injection"
signals: ["SQLi防御", "NoSQLi防御", "参数化查询", "预编译语句", "宽字节防御", "MongoDB注入防护", "最小权限DB", "Content-Type严格校验"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["SQL注入防御", "NoSQL注入防御", "Prepared Statement", "MongoDB安全", "二阶注入防护", "OOB阻断", "支付账本隔离", "WAFFLED防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "injection", "sqli", "nosqli", "database-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/03-injection/sqli-nosqli", "ctf-website/24-database/01-sqli-fundamentals", "ctf-website/24-database/02-sqli-advanced", "ctf-website/24-database/03-nosql-injection", "ctf-website/12-payment/payment-logic"]
track: "blue"
defends: "ctf-website/03-injection/sqli-nosqli"
---

# SQLi 与 NoSQLi 纵深防御及账本隔离

黑名单关键字过滤（如拦截 `UNION`、`SELECT`、空格、`=`）极易被双写、内联注释 `/*!50000*/`、替代函数、`Content-Type` 走私（WAFFLED）和分片请求（Session Splicing）绕过。数据库注入的唯一根本防线是**结构与数据分离（参数化预编译 / 强类型查询构造）**，并辅以严格编码一致性、最低数据库账户权限与业务账本边界隔离。

## 防御工作流

```text
网关与框架层强制 Content-Type 唯一匹配（阻断 WAFFLED 与宽字节编码差异）
  → 全部 SQL 查询强制 Prepared Statements，动态标识符采用白名单映射
  → 二阶落库字段在后续对账、导出、搜索路径同样参数化绑定
  → NoSQL 入口强制标量类型校验并剥离 $ 操作符与禁用 $where
  → 数据库账户收紧文件读写/命令执行/外连权限，核心支付密钥移出业务库
```

## 1. SQL 注入根治与编码/协议一致性

1. **强制参数化预编译（Prepared Statements）**：
   - 使用真正服务端预编译（如 MySQL `prepared=True`、PostgreSQL `psycopg` 参数占位 `%s`、ORM 参数绑定），避免仅在客户端模拟转义拼接。
   - **无法参数化的位置（表名、列名、`ORDER BY`、`ASC/DESC`）**：绝不接受自由文本，必须通过服务端枚举白名单字典映射（例如 `SORT_MAP = {"created": "created_at", "price": "amount"}`）。
2. **消除宽字节注入与编码分裂**：
   - 数据库、连接驱动与客户端统一使用 `utf8mb4`，禁用 `GBK`/`GB2312` 连接集与过时的 `addslashes()`，防止 `%df%5c%27` 吞噬反斜线。
3. **阻断多语句与二阶注入**：
   - 驱动连接显式关闭多语句执行（如 MySQL `CLIENT.MULTI_STATEMENTS` 置 `False`，SQLite 禁止 `executescript()` 处理业务数据）。
   - 订单备注、发票抬头、个人简介等入库后，在后台搜索、对账导出、异步回调处理中一律按不可信参数重新走预编译绑定，杜绝二阶拼接。
4. **阻断 Content-Type 走私（WAFFLED）**：
   - API 路由严格限定可接受的 `Content-Type`（例如仅允许 `application/json; charset=utf-8`），拒绝 `text/plain`、`application/xml` 或非预期 `multipart/form-data` 进入 JSON 解析器，确保 WAF 与后端对同一请求使用同一解析路径。

## 2. 数据库最小权限与 OOB 外带阻断

即使出现局部逻辑缺陷，通过裁剪数据库运行账户权限也可彻底切断读文件、写 Webshell、OOB 外带与提权链：

| 数据库 | 高危功能/函数 | 加固措施 |
|---|---|---|
| MySQL / MariaDB | `LOAD_FILE()`, `INTO OUTFILE`, `LOAD DATA LOCAL INFILE` | 业务账号收回 `FILE` 权限；配置 `secure_file_priv=/dev/null`；禁用 `local_infile=0` |
| PostgreSQL | `COPY ... FROM PROGRAM`, `dblink_connect`, `lo_import` | 业务账号不得具备 `SUPERUSER`、`pg_execute_server_program` 或 `pg_read_server_files` 角色；关闭非必要 `dblink` 扩展 |
| MSSQL | `xp_cmdshell`, `xp_dirtree`, `sp_OACreate` | 禁用 `xp_cmdshell` 与 OLE Automation；收紧扩展存储过程权限；阻断数据库主机出网 SMB/DNS |
| SQLite / Oracle | `ATTACH DATABASE`, `UTL_HTTP`, `UTL_INADDR` | SQLite 以只读或无写权限目录隔离运行；Oracle 收回普通用户的 `UTL_HTTP`/`UTL_INADDR` 网络 ACL |

## 3. 支付与订单账本专项防护

针对支付/订单库成为高价值注入目标的问题，实施纵深分层：

- **凭据分离**：`pay_secret`、`webhook_secret`、`jwt_secret` 禁止存放在业务可读的 `settings/config` 数据表中，改由环境变量或专用 KMS 服务下发，只读权限与业务库隔离。
- **查询行级隔离**：订单、支付流水、权益表查询强制携带服务端会话绑定的 `AND user_id = ?` 条件，不依赖前端传入的 `user_id` 或仅用单字段 `out_trade_no` 查询。
- **错误抑制**：统一拦截 SQL/ORM 异常并记录内部日志，对外仅返回标准错误码，杜绝表名、列名或时间/布尔异常差异。

## 4. NoSQL 注入（MongoDB）彻底防护

1. **强制标量类型校验**：登录与筛选接口（`username`、`password`、`token`）使用 Schema（Pydantic / Zod / Joi）声明字段必须为 `string`，拒绝任何 `dict` / `list` 对象传入，从源头阻断 `{"$ne": "guest"}` 与 `{"$gt": ""}`。
2. **清除操作符键与点号路径**：递归检查嵌套对象，拒绝所有以 `$` 开头的键名及含 `.` 的深层路径键（如防御 `{"user": {"$gt": ""}}`）。
3. **禁用服务端 JS 执行与正则全匹配**：MongoDB 配置关闭 `security.javascriptEnabled: false`，严禁 `$where`、`$function`、`$accumulator`；用户输入用于模糊搜索时，必须先经正则字符转义（`re.escape()`）并限制最大长度，避免 `$regex` 逐字节盲注或引发 ReDoS。

## 5. 可运行参数化校验与 NoSQL 清洗器

以下 Python 代码展示安全的 SQL 标识符白名单与参数化查询构建、严格 `Content-Type` 校验以及 MongoDB/NoSQL 查询对象递归消毒与类型强校验：

```python
#!/usr/bin/env python3
"""SQLi 参数化标识符白名单、Content-Type 校验与 NoSQL 输入防御校验器。"""
import re
import sqlite3
from typing import Any

ALLOWED_SORT_COLUMNS = {
    "id": "id",
    "created": "created_at",
    "amount": "amount",
}
ALLOWED_SORT_DIRS = {"asc": "ASC", "desc": "DESC"}


class DefensePolicyError(ValueError):
    pass


def enforce_json_content_type(content_type: str) -> None:
    """严格匹配 JSON Content-Type，防止 WAFFLED 走私绕过前后端解析差异。"""
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime != "application/json":
        raise DefensePolicyError(f"unsupported Content-Type for JSON endpoint: {content_type!r}")


def build_safe_order_query(conn: sqlite3.Connection, user_id: int, sort_key: str, sort_dir: str) -> list[tuple]:
    """数据值走参数占位符，列名/排序方向走不可变白名单映射。"""
    col = ALLOWED_SORT_COLUMNS.get(sort_key)
    direction = ALLOWED_SORT_DIRS.get(sort_dir.lower())
    if not col or not direction:
        raise DefensePolicyError("invalid sort parameter")
    # col 与 direction 均来自服务端受控常量字典，不含有任何用户输入字符
    sql = f"SELECT id, out_trade_no, amount, status FROM orders WHERE user_id = ? ORDER BY {col} {direction}"
    return conn.execute(sql, (user_id,)).fetchall()


def sanitize_nosql_scalar(field_name: str, value: Any, max_len: int = 128) -> str:
    """强制字段必须为纯字符串，彻底阻断 MongoDB $ne/$gt/$regex 对象注入。"""
    if not isinstance(value, str):
        raise DefensePolicyError(f"field {field_name!r} must be scalar string, got {type(value).__name__}")
    if len(value) > max_len:
        raise DefensePolicyError(f"field {field_name!r} exceeds max length {max_len}")
    return value


def sanitize_nosql_filter_tree(obj: Any) -> Any:
    """递归拒绝所有以 $ 开头的操作符键及含 . 的原型/嵌套路径键。"""
    if isinstance(obj, dict):
        clean: dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str) or k.startswith("$") or "." in k:
                raise DefensePolicyError(f"forbidden NoSQL operator or dotted key: {k!r}")
            clean[k] = sanitize_nosql_filter_tree(v)
        return clean
    if isinstance(obj, list):
        return [sanitize_nosql_filter_tree(item) for item in obj]
    return obj


def safe_regex_literal(term: str) -> str:
    """搜索输入必须先做字面量转义，防止 $regex 盲注探测或元字符注入。"""
    text = sanitize_nosql_scalar("search", term, max_len=64)
    return re.escape(text)


if __name__ == "__main__":
    # 1. SQLi 参数化与白名单测试（含二阶注入载荷入库后安全查询）
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE orders (id INT, user_id INT, out_trade_no TEXT, amount REAL, status TEXT, created_at TEXT)")
    evil_remark = "x' OR 1=1 --"
    db.execute("INSERT INTO orders VALUES (1, 100, ?, 9.9, 'paid', '2026-11-12')", (evil_remark,))
    db.execute("INSERT INTO orders VALUES (2, 200, 'ORD-200', 99.0, 'paid', '2026-11-12')")

    rows = build_safe_order_query(db, user_id=100, sort_key="amount", sort_dir="desc")
    assert len(rows) == 1 and rows[0][1] == evil_remark

    for bad_sort in ("amount; DROP TABLE orders--", "1=1"):
        try:
            build_safe_order_query(db, 100, bad_sort, "asc")
            raise AssertionError("expected sort rejection")
        except DefensePolicyError:
            pass

    # 2. WAFFLED Content-Type 校验
    enforce_json_content_type("application/json; charset=utf-8")
    for bad_ct in ("text/plain; charset=utf-8", "application/x-www-form-urlencoded"):
        try:
            enforce_json_content_type(bad_ct)
            raise AssertionError("expected Content-Type rejection")
        except DefensePolicyError:
            pass

    # 3. NoSQLi 拦截测试
    for bad_nosql in ({"$ne": "guest"}, {"$regex": "^f"}, {"user": {"$gt": ""}}, {"$where": "1==1"}):
        try:
            sanitize_nosql_filter_tree(bad_nosql)
            raise AssertionError(f"expected NoSQL rejection for {bad_nosql}")
        except DefensePolicyError:
            pass

    try:
        sanitize_nosql_scalar("password", {"$gt": ""})
        raise AssertionError("expected scalar type rejection")
    except DefensePolicyError:
        pass

    assert safe_regex_literal("^admin.*") == r"\^admin\.\*"
    print("[PASS] SQLi parameterization, WAFFLED Content-Type, and NoSQLi guards passed")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| 绕过变体与多语句 | `UNIunionON`、`/**/`、`%df%5c%27`、堆叠 `;DROP` 全部作为字面量处理或参数校验拒绝 | 布尔真假/延时出现显著响应差分或报错回显 |
| 二阶注入与排序字段 | 入库含引号载荷在搜索/导出路径不触发语法错误；非法 `sort`/`orderBy` 返回 `400` | 二次触发接口产生延时或数据库报错 |
| Content-Type 走私 | 非 `application/json` 的 JSON 请求返回 `415`/`400` | `text/plain` 载体绕过边界进入后端解析 |
| 数据库 OOB 与特权 | 数据库用户调用 `LOAD_FILE`/`COPY PROGRAM`/`UTL_HTTP` 均被权限拒绝 | DNS/HTTP 监听器收到数据库出网外带请求 |
| NoSQL 登录与正则 | 传入 `{"$ne": ""}` 或 `{"$regex": "^a"}` 被强类型拒绝返回 `400` | 非标量对象进入 Mongo 查询导致登录绕过或逐字节盲注 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `sqli`、`nosqli`、`parameterized`、`database-security` 搜索相关条目 |
| 读取攻击细节 | `kb_read_file` | 对照 `ctf-website/03-injection/sqli-nosqli` 与 `24-database/*` 排查变体 |
| 浏览目录索引 | `kb_catalog` | 列出 `03-injection` 与 `24-database` 防御关联条目 |
| 响应与报错核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后核验 SQL/NoSQL 边界输入是否返回标准 `400` |
