---
id: "ctf-website/22-dos/02-resource-exhaustion-defense"
title: "资源耗尽与算法复杂度攻击防御"
title_en: "Resource Exhaustion and Algorithm Complexity Defense"
summary: >
  针对 HashDoS 哈希碰撞（CVE-2011-4885/CVE-2022-30115）、XML Bomb（Billion Laughs 与二次膨胀）、Zip Bomb 递归解压炸弹、文件描述符耗尽、连接池/线程池饥饿、JSON 深层解析炸弹与 Fork Bomb 的纵深防御手册。提供语言/框架加固配置、系统 cgroups/ulimit 隔离及 Python 弹性校验代码。
summary_en: >
  Defense-in-depth playbook against HashDoS collision attacks (CVE-2011-4885/CVE-2022-30115), XML Bomb entity expansion, Zip Bomb decompression bombs, file descriptor exhaustion, DB connection/thread pool starvation, JSON parser bombs, and Fork Bombs. Provides runtime/framework limits, OS cgroups/ulimit isolation, and runnable Python verification checks.
board: "ctf-website"
category: "22-dos"
signals:
  - "HashDoS 参数数量上限拦截"
  - "XML DTD 与外部实体禁用"
  - "Zip 解压比与总字节硬限制"
  - "ulimit RLIMIT_NOFILE 与 TasksMax"
  - "PgBouncer 池化与 statement_timeout"
  - "JSON 深度与键数量守卫"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "HashDoS 防御"
  - "defusedxml"
  - "Zip Bomb 检测"
  - "文件描述符限制"
  - "线程池隔离"
  - "JSON 解析深度限制"
  - "Fork Bomb 防护"
  - "resource exhaustion defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "resource-exhaustion"
  - "xml-bomb"
  - "zip-bomb"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/02-resource-exhaustion"
track: "blue"
defends: "ctf-website/22-dos/02-resource-exhaustion"
---
# 资源耗尽与算法复杂度攻击防御

## 防御目标与对抗矩阵

资源耗尽与算法复杂度攻击（对应攻击方法见 [02-resource-exhaustion.md](../../../../red/ctf-website/techniques/22-dos/02-resource-exhaustion.md)）利用解析器、哈希表或操作系统默认无界配置，以数 KB 输入触发 OOM 或 CPU 100%。防御的核心原则是**禁止无界解析、强制随机化哈希种子、严格限制资源配额与异步隔离**。

| 攻击向量 | 失效点 | 核心防御措施 | 推荐硬边界 |
|---|---|---|---|
| HashDoS (CVE-2011-4885 / CVE-2022-30115) | 哈希碰撞导致 `O(n^2)` 退化 | 升级随机化哈希运行时并限制单请求键数 | PHP `max_input_vars=1000`、Tomcat `maxParameterCount=1000`、body `< 1MB` |
| XML Bomb (Billion Laughs / 二次膨胀) | 默认 XML 解析器展开 DTD 实体 | 彻底禁用 DTD 与外部实体解析（`defusedxml`） | `disallow-doctype-decl=true`、禁止 `EXTERNAL_GENERAL_ENTITIES` |
| Zip / Gzip Bomb (42.zip) | 无上限递归解压触发内存/磁盘耗尽 | 流式读取并强制解压总字节、嵌套层数与压缩比 | 单文件 `<= 50MB`、压缩比 `<= 100:1`、禁止嵌套归档或层数 `<= 2` |
| 文件描述符 (FD) 耗尽 | 连接/管道泄漏耗尽 `RLIMIT_NOFILE` | 合理提升进程 FD 上限配合连接空闲回收 | `LimitNOFILE=65535` + 上下文管理器强制 `close()` |
| 数据库连接池耗尽 | 慢查询/`pg_sleep`/行锁占满池槽位 | 事务级连接池 + 硬执行超时 + 锁等待超时 | PgBouncer `transaction` + `statement_timeout=5s` |
| 线程池饥饿 (Sync-over-Async) | 异步事件循环内调用同步阻塞 I/O | 消除同步阻塞调用，隔离独立有界执行器并设超时 | 禁止在协程内调用同步网络/睡眠；阻塞任务隔离到有界队列 |
| JSON / Unicode 解析炸弹 | 深度递归栈溢出或超大数组/重复键 OOM | 流式/有界 JSON 解析，限制最大深度、键数和数组长度 | `max_depth <= 32`、禁用重复键覆盖、body `< 2MB` |
| Fork Bomb 进程表耗尽 | 容器/用户无进程数上限 | 强制 cgroups `pids.max` 与 PAM `nproc` | `TasksMax=256`、`--pids-limit=256` |

---

## 防御工作流

### 阶段一：解析器边界加固（HashDoS / XML / JSON / Zip）

1. **HashDoS 防护**：
   - 确认运行环境已启用加密级随机哈希种子：Python `>= 3.4`（SipHash，且不在多实例间硬编码 `PYTHONHASHSEED`）、PHP `>= 7.4`、.NET `>= 6.0.18 / 7.0.5`；
   - 在 Web 容器和框架层设置表单/查询参数数量上限，从入口处阻断包含数万键的载荷：

```ini
; /etc/php/8.2/fpm/php.ini — 阻断参数级 HashDoS 与资源爆炸
max_input_vars = 1000
max_input_nesting_level = 32
post_max_size = 8M
upload_max_filesize = 8M
max_execution_time = 15
memory_limit = 256M
```

```javascript
// Express.js body-parser 严格参数与体限制
const express = require('express');
app.use(express.urlencoded({ extended: false, parameterLimit: 500, limit: '256kb' }));
app.use(express.json({ limit: '512kb', strict: true }));
```

2. **XML Bomb 防护**：
   - Python 一律使用 `defusedxml` 替代标准库 `xml.etree.ElementTree` / `lxml` 默认配置；
   - Java `DocumentBuilderFactory` / `SAXParserFactory` 显式开启安全特性禁用 DTD：

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

3. **Zip / Gzip Bomb 防护**：
   - 严禁依赖 `ZipInfo.file_size` 头部声明作为唯一依据（恶意归档可伪造头信息或使用重叠记录）；必须采用**流式分块解压计数**，一旦累计解压字节、单文件字节、文件数量或实时压缩比超过阈值立即中止并清理临时目录。

### 阶段二：数据库与异步线程池隔离（Pool / Thread Starvation）

1. **数据库连接池防御**：部署 PgBouncer（`pool_mode = transaction`）或严格有界的 HikariCP，并为连接配置服务端强超时（`statement_timeout`、`idle_in_transaction_session_timeout`、`lock_timeout`），避免 `pg_sleep` 或未提交事务长占连接。
2. **异步事件循环防饥饿**：
   - 禁止在 FastAPI/aiohttp/Node.js 主事件循环中调用 `requests.get`、`time.sleep` 或 CPU 密集型同步运算；
   - 若必须调用遗留同步库，必须通过有界队列的独立线程池隔离，并设定 `asyncio.wait_for(..., timeout=5.0)`，超出队列容量快速返回 `503 Service Unavailable` 实现负载脱落（Load Shedding）。

### 阶段三：操作系统级文件描述符与进程配额隔离（FD / Fork Bomb）

在 systemd 服务单元与容器运行时中硬性限定 `LimitNOFILE` 与 `TasksMax`，防止单个受影响进程拖垮整机进程表与全局句柄池：

```ini
# /etc/systemd/system/web-api.service.d/limits.conf
[Service]
LimitNOFILE=65535
LimitNPROC=256
TasksMax=256
MemoryMax=2G
MemoryHigh=1536M
```

```yaml
# Kubernetes Pod 级 PID 与临时存储隔离
spec:
  containers:
    - name: api
      resources:
        limits:
          cpu: "1000m"
          memory: "1Gi"
          ephemeral-storage: "512Mi"
```

---

## 弹性校验代码（可运行 Python 自检）

以下代码演示如何在内存中进行无文件落地的防 Zip Bomb 流式解压、XML DTD 拦截、有界 JSON 深度与键数量校验（避免递归栈溢出），并内含断言测试：

```python
#!/usr/bin/env python3
"""Resource exhaustion defense verifier: Zip bomb, XML DTD, and JSON depth/key guards."""

import io
import json
import re
import zipfile
from xml.etree import ElementTree as ET


class ResourceGuardError(ValueError):
    """Raised when an input exceeds safe complexity or expansion limits."""


def safe_extract_zip_bytes(
    raw_zip: bytes,
    max_uncompressed_bytes: int = 5 * 1024 * 1024,
    max_entries: int = 100,
    max_ratio: float = 50.0,
) -> dict[str, bytes]:
    """Stream-verify ZIP payload against overlapping headers and decompression bombs."""
    compressed_size = max(len(raw_zip), 1)
    total_read = 0
    files: dict[str, bytes] = {}

    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise ResourceGuardError(f"entry count {len(infos)} > {max_entries}")

        for info in infos:
            if info.is_dir():
                continue
            if info.filename.lower().endswith((".zip", ".gz", ".bz2", ".xz")):
                raise ResourceGuardError(f"nested archive rejected: {info.filename}")

            chunks: list[bytes] = []
            with zf.open(info, "r") as member:
                while True:
                    chunk = member.read(65536)
                    if not chunk:
                        break
                    total_read += len(chunk)
                    if total_read > max_uncompressed_bytes:
                        raise ResourceGuardError("total uncompressed limit exceeded")
                    if total_read / compressed_size > max_ratio and total_read > 1024 * 1024:
                        raise ResourceGuardError("compression ratio bomb detected")
                    chunks.append(chunk)
            files[info.filename] = b"".join(chunks)
    return files


def safe_parse_xml(xml_text: str, max_bytes: int = 262144) -> ET.Element:
    """Reject DOCTYPE/ENTITY declarations before XML parsing to prevent Billion Laughs."""
    if len(xml_text.encode("utf-8")) > max_bytes:
        raise ResourceGuardError("XML payload exceeds max_bytes")
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", xml_text, flags=re.IGNORECASE):
        raise ResourceGuardError("DOCTYPE/ENTITY declarations are forbidden")
    return ET.fromstring(xml_text)


def safe_parse_json(raw_json: str, max_depth: int = 20, max_keys: int = 500, max_items: int = 5000) -> object:
    """Iterative JSON structure check blocking deep nesting, duplicate keys, and huge arrays."""
    # Pre-check bracket nesting depth in O(n) without recursion risk
    depth = 0
    in_str = False
    escaped = False
    for ch in raw_json:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_str:
            escaped = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if not in_str:
            if ch in "{[":
                depth += 1
                if depth > max_depth:
                    raise ResourceGuardError(f"JSON nesting depth > {max_depth}")
            elif ch in "}]":
                depth -= 1

    key_count = 0
    item_count = 0

    def reject_duplicates_and_count(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal key_count
        obj: dict[str, object] = {}
        for k, v in pairs:
            if k in obj:
                raise ResourceGuardError(f"duplicate JSON key rejected: {k}")
            key_count += 1
            if key_count > max_keys:
                raise ResourceGuardError(f"JSON key count > {max_keys}")
            obj[k] = v
        return obj

    def check_array_or_obj(node: object) -> None:
        nonlocal item_count
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, list):
                item_count += len(cur)
                if item_count > max_items:
                    raise ResourceGuardError(f"JSON array items > {max_items}")
                stack.extend(cur)
            elif isinstance(cur, dict):
                stack.extend(cur.values())

    parsed = json.loads(raw_json, object_pairs_hook=reject_duplicates_and_count)
    check_array_or_obj(parsed)
    return parsed


def run_self_checks() -> None:
    # 1. Zip bomb 校验：高压缩比零字节负载被阻断
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"A" * (6 * 1024 * 1024))
    try:
        safe_extract_zip_bytes(buf.getvalue())
        raise AssertionError("Zip bomb was not blocked")
    except ResourceGuardError:
        pass

    # 2. XML Billion Laughs 拦截校验
    xml_bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><root>&lol;</root>'
    try:
        safe_parse_xml(xml_bomb)
        raise AssertionError("XML bomb was not blocked")
    except ResourceGuardError:
        pass

    # 3. JSON 深度嵌套与重复键拦截校验
    deep_json = '{"a":' * 30 + "1" + "}" * 30
    try:
        safe_parse_json(deep_json, max_depth=20)
        raise AssertionError("Deep JSON was not blocked")
    except ResourceGuardError:
        pass

    try:
        safe_parse_json('{"k":1,"k":2}')
        raise AssertionError("Duplicate JSON key was not blocked")
    except ResourceGuardError:
        pass

    assert safe_parse_json('{"ok": [1, 2, 3]}') == {"ok": [1, 2, 3]}
    print("[PASS] All resource exhaustion defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| HashDoS 键数量限制 | 发送超过 `1000` 个表单键或超限 JSON 键时在解析前返回 `400/413` | 单请求 CPU 耗时 `< 20ms`，无秒级阻塞 |
| XML Bomb 拦截 | 含 `<!DOCTYPE` 或 `<!ENTITY` 的请求被立即拒绝 | 内存 RSS 无波动，解析耗时 `< 5ms` |
| Zip Bomb 流式阻断 | 超过 `50MB` 解压量或压缩比超限即终止解压并清理临时流 | 磁盘与内存占用保持平稳，无 OOMKilled |
| JSON 深度与数组限流 | 深度 `> 20` 或重复键在 `json.loads` 前/中抛出异常并返回 `400` | 无 `RecursionError` 或 `500` 崩溃 |
| 系统句柄与进程配额 | `LimitNOFILE` 与 `TasksMax` 生效，单服务异常不扩散至宿主机 | `/proc/sys/fs/file-nr` 远低于 `file-max`，宿主机 SSH/监控正常 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 上传与解析端点校验 | `http_probe` | 验证超大 JSON/XML/表单载荷是否返回预期 400/413 且无超时 |
| 蓝队技术检索 | `kb_router` | 以 `track="blue"` 检索资源耗尽、连接池及解析器防护方案 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/02-resource-exhaustion` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下所有资源防护指南 |
