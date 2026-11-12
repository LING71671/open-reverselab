---
id: "general/crypto/04-rsa-attack-family"
title: "RSA 攻击族 — 按已知量选攻击"
title_en: "The RSA Attack Family: Choosing by What You Are Given"
summary: >
  以「手里有哪些量」为唯一分叉依据组织 RSA 攻击选型：小指数整数开根、共模攻击、模数为素数、
  Franklin-Reiter 相关消息攻击（含闭式推导）、Håstad 广播攻击与 CRT、Fermat 分解、共享素数批量
  gcd、Wiener 连分数。全部为纯标准库实现，附可运行自检与断言闭环。
summary_en: >
  RSA attack selection organized by what you are given: small-exponent integer root,
  common modulus, prime modulus, Franklin-Reiter related messages (with closed-form derivation),
  Hastad broadcast with CRT, Fermat factorization, shared-prime batch gcd, and Wiener continued
  fractions. Pure standard library, with a runnable self-test and assertion-based closure.
board: "general"
category: "crypto"
signals:
  - "e = 3"
  - "small exponent"
  - "same n different e"
  - "common modulus"
  - "n = getPrime()"
  - "m2 = m1 + delta"
  - "related messages"
  - "same message multiple moduli"
  - "CRT"
  - "broadcast attack"
  - "Fermat factorization"
  - "shared prime"
  - "Wiener"
  - "RSA CTF"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
  - "solve_crypto_from_evidence"
  - "make_crypto_replay_scaffold"
  - "python_re_tool_install"
keywords:
  - "RSA"
  - "Franklin-Reiter"
  - "common modulus"
  - "Hastad broadcast"
  - "CRT"
  - "Coppersmith"
  - "Wiener"
  - "Fermat factorization"
  - "batch gcd"
difficulty: "intermediate"
tags:
  - "cryptography"
  - "RSA"
  - "number-theory"
  - "CTF"
language: "zh-CN"
last_updated: "2026-09-17"
related_articles:
  - "general/crypto/03-prng-randomness-cracking"
  - "general/crypto/01-algorithm-identification"
---
# RSA 攻击族 — 按已知量选攻击

> RSA 题几乎从不需要"破解 RSA"。出题人总是**故意少给或故意多给**某个量，攻击点就藏在
> 「给了什么、没给什么」里。本文按这个维度组织选型，不按攻击名字的字母顺序。
>
> 核心原则：**先把题目给的全部量抄下来，标出哪些是"按理不该给"的**——那就是入口。

## 0. 选型决策树

```text
手里有 (n, e, c) 单组
├─ e 很小 (3 / 5 / 17) 且 m^e < n  ──────► 直接整数开根 (§1)
└─ 否则
   ├─ n 能被判定为素数 ────────────────► φ(n) = n-1 (§3)
   ├─ n 很长但 p、q 很近 ──────────────► Fermat 分解 (§6)
   └─ 有多个 (n_i, e_i) 三元组
      ├─ 同一个 n，两个互素 e ────────► 共模攻击 (§2)
      ├─ 同一个 e，多组 n 且 Πn > m^e ─► Håstad 广播 + CRT (§5)
      └─ 两个 n 共享素因子 ───────────► 批量 gcd (§7)

手里有 (n, e, c) 且 e 特别大 ──────────► Wiener 连分数 (§8)

手里有多组同类明文
└─ 同 n、同 e、明文线性相关 m2 = a*m1 + b ► Franklin-Reiter (§4)

拿到了 p 或 q ─────────────────────────► 直接 d = e^-1 mod (p-1)(q-1)，无攻击
```

**先做的一件小事**：把每个数都 `bit_length()` 打印出来。`n` 的位数告诉你 flag 大概多长；
`c` 的位数和 `n` 差很多，往往意味着 `m^e < n`（可以直接开根）。

```python
def triage(n, e, c):
    print(f"n: {n.bit_length()} bit")
    print(f"e: {e}")
    print(f"c: {c.bit_length()} bit   c < n: {c < n}")
    # e 很小时，若 m^e < n 则 c 恰好是 m^e，位数会明显小于 n
    if e <= 17 and c.bit_length() * 1.0 < n.bit_length() * e:
        print("  => 可疑：m^e 可能小于 n，先试整数开根")
```

## 1. 小指数 + 整数开根

`c = m^e mod n`。如果明文比 `n` 短很多，就有 `m^e < n`，取模这一步**根本没发生**，
`c` 就是 `m^e` 本身，直接开 `e` 次整数根即可。

```python
def iroot(x: int, k: int) -> int:
    """整数 k 次根，向下取整。纯整数运算，避免浮点精度问题。"""
    if x < 0:
        raise ValueError("x must be >= 0")
    if x in (0, 1) or k == 1:
        return x
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def small_e_integer_root(e: int, c: int):
    """返回 (m, True) 表示精确开根成功；否则 (None, False)。"""
    r = iroot(c, e)
    if r ** e == c:
        return r, True
    return None, False
```

**判据必须用 `r ** e == c` 断言，不能用 `abs(r - float(c)**(1/e)) < 1` 之类的浮点近似。**
根附近的浮点误差会让错误结果看起来"差不多"。

### 1.1 开根不成立时的三条后路

`m^e > n` 时开根失败，但小指数仍然危险：

| 情形 | 出路 |
|---|---|
| 同一 `m` 在多个互素 `n` 下加密（同一个 `e`） | §5 Håstad 广播攻击 |
| 同一 `n`，`m` 与另一明文线性相关 | §4 Franklin-Reiter |
| 单一方程，无额外信息 | 需要 Coppersmith partial-key / stereotyped message（本文不展开，需 lattice） |

## 2. 共模攻击（同一 n，两个互素 e）

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
gcd(e1, e2) = 1
```

由扩展欧几里得求 `a*e1 + b*e2 = 1`，其中 `a`、`b` 必有一负。负指数用模逆处理：

```python
def egcd(a: int, b: int):
    """返回 (g, x, y) 使 a*x + b*y = g。"""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> int:
    g, a, b = egcd(e1, e2)
    assert g == 1, f"gcd(e1,e2)={g} != 1，本攻击不适用"
    # 负指数转模逆
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

**注意**：`pow(c, -1, n)` 需要 `gcd(c, n) = 1`。若报 `ValueError`，说明 `c` 与 `n` 不互素
——那本身就是**免费的因式分解**：`gcd(c, n)` 直接给出 `p`。

## 3. 模数本身就是素数

附件写 `n = getPrime(1024)` 而不是 `n = p * q`，是最常见的"送分错"。

```python
def prime_modulus_decrypt(n: int, e: int, c: int) -> int:
    phi = n - 1                    # n 是素数 => φ(n) = n-1
    d = pow(e, -1, phi)
    return pow(c, d, n)
```

识别信号：`sympy.isprime(n)` 为真，或 `n.bit_length()` 与 `p.bit_length()*2` 不匹配。

```python
def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin，纯标准库。"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    import random
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True
```

## 4. Franklin-Reiter 相关消息攻击

### 4.1 适用条件

同一 `(n, e)`，两条明文满足**已知的线性关系** `m2 = a*m1 + b`（`a`、`b` 已知），
且 `e` 足够小。

```text
c1 = m1^e     mod n
c2 = (a*m1 + b)^e mod n
```

`x = m1` 同时是两个多项式的根：

```text
f(x) = x^e - c1
g(x) = (a*x + b)^e - c2        (mod n)
```

在 `Z_n[x]` 上求 `gcd(f, g)`。这两个多项式共享根 `m1 mod n`，且
`deg f = deg g = e`，正规情况下 gcd 恰好降为一次式 `x - m1`。

```python
def poly_trim(p: list) -> list:
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_mod(a: list, b: list, n: int) -> list:
    """a mod b over Z_n[x]，系数低位在前。"""
    a, b = poly_trim(a[:]), poly_trim(b[:])
    if len(b) == 1:
        return [0]
    inv = pow(b[-1], -1, n)          # 若抛 ValueError，说明 n 可被分解
    while len(a) >= len(b):
        shift = len(a) - len(b)
        coeff = a[-1] * inv % n
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coeff * b[i]) % n
        a = poly_trim(a)
        if len(a) == 1 and a[0] == 0:
            break
    return a


def poly_gcd(a: list, b: list, n: int) -> list:
    a, b = poly_trim(a[:]), poly_trim(b[:])
    while not (len(b) == 1 and b[0] == 0):
        a, b = b, poly_mod(a, b, n)
    inv = pow(a[-1], -1, n)
    return [c * inv % n for c in a]


def poly_eval(p: list, x: int, n: int) -> int:
    acc = 0
    for c in reversed(p):
        acc = (acc * x + c) % n
    return acc


def franklin_reiter(n: int, e: int, c1: int, c2: int, a: int = 1, b: int = 1):
    """m2 = a*m1 + b。返回 m1。"""
    f = [(-c1) % n] + [0] * (e - 1) + [1]                  # x^e - c1
    # (a*x + b)^e 的二项式展开，系数低位在前
    from math import comb
    g = [0] * (e + 1)
    for i in range(e + 1):
        g[i] = (comb(e, i) * pow(a, i) * pow(b, e - i)) % n
    g[0] = (g[0] - c2) % n
    h = poly_gcd(f, g, n)
    assert len(h) == 2, f"gcd 次数={len(h) - 1}，期望 1；可能需改用格方法"
    m1 = (-h[0] * pow(h[1], -1, n)) % n
    assert poly_eval(f, m1, n) == 0 and poly_eval(g, m1, n) == 0
    return m1
```

### 4.2 `b = 1` 时的闭式解（免多项式 gcd）

`e = 3`、`b = 1` 这一类可以纯代数消元，比 gcd 更快也更不容易踩实现的坑：

```text
c2 - c1 ≡ (m1+1)^3 - m1^3 = 3*m1^2 + 3*m1 + 1        (mod n)   ... (1)
设 d = (c2 - c1) mod n，则  3*m1^2 + 3*m1 + 1 - d ≡ 0

(1) 两边乘 m1：3*m1^3 + 3*m1^2 + m1 - d*m1 ≡ 0
代入 m1^3 ≡ c1 并替换 3*m1^2 ≡ d - 3*m1 - 1：
    3*c1 + (d - 3*m1 - 1) + m1 - d*m1 ≡ 0
    3*c1 + d - 1 - 2*m1 - d*m1 ≡ 0
=>  m1 * (d + 2) ≡ 3*c1 + d - 1                       (mod n)
=>  m1 ≡ (3*c1 + d - 1) * (d + 2)^(-1)                (mod n)
```

```python
def fr_e3_delta1_closed_form(n: int, c1: int, c2: int) -> int:
    """e=3, m2=m1+1 的闭式解。"""
    d = (c2 - c1) % n
    den = (d + 2) % n
    from math import gcd
    g = gcd(den, n)
    if g != 1:
        raise ValueError(f"gcd(d+2, n) = {g} — n 可被分解，直接拿这个因子")
    m = ((3 * c1 + d - 1) % n) * pow(den, -1, n) % n
    assert pow(m, 3, n) == c1 and pow(m + 1, 3, n) == c2
    return m
```

**同一条推导可推广**：对任意 `delta`，`(m+delta)^e - m^e` 是 `e-1` 次多项式；
逐次乘 `m` 并代入 `m^e = c1` 就能把次数往下压，`e` 很小时总能压到线性。
这是"手算版 Franklin-Reiter"，理解它比记住 gcd 写法更有用。

### 4.3 实现注意点

- **多项式 gcd over `Z_n[x]` 需要可逆的首项系数。** 若 `pow(b[-1], -1, n)` 抛
  `ValueError`，别慌——`gcd(b[-1], n)` 就是一个因子，直接拿到 `p`。
- **先试闭式（§4.2），失败再上 gcd。** 两条路互证：闭式解出的 `m` 代回
  两个多项式都应得 0。
- `m1 mod n` 恢复出来是**模 `n` 的剩余**。flag 比 `n` 短时它等于原值；
  `long_to_bytes` 之前先确认位数合理，过长说明推错了。

## 5. Håstad 广播攻击 + CRT

同一个明文 `m`、同一个**小**指数 `e`，在 `e` 个（或更多）互素的模数下分别加密：

```text
c_i = m^e mod n_i,   i = 1..k
```

只要 `Π n_i > m^e`，用 CRT 恢复 `C = m^e mod Πn_i`，而 `C` 恰好等于 `m^e`（没有取模），
再开 `e` 次整数根。

```python
def crt(residues: list, moduli: list):
    """中国剩余定理。返回 (x mod M, M)。要求 moduli 两两互素。"""
    from math import gcd
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"模数不互素: gcd(n{i+1}, n{j+1}) != 1")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x = (x + r * Mi * pow(Mi, -1, m)) % M
    return x % M, M


def hastad_broadcast(e: int, ns: list, cs: list) -> int:
    """模数个数需满足 Πn_i > m^e。

    注意：不是"必须凑够 e 组"。e 组只是常见经验值 —— 当单个 n 的位数远大于 m 时，
    少于 e 组也可能已经覆盖 m^e。真正的判据只有乘积。
    这里从少到多逐个尝试，并用全部已知 (n, c) 回验。
    """
    assert len(ns) == len(cs) >= 1, "模数与密文数量必须一致且非空"
    for k in range(1, len(ns) + 1):
        C, M = crt(cs[:k], ns[:k])
        m, ok = small_e_integer_root(e, C)
        if ok and all(pow(m, e, n) == c for n, c in zip(ns, cs)):
            return m
    raise ValueError("Πn_i 不足以覆盖 m^e：需要更多模数，或改用格方法（Coppersmith）")
```

**这里有个容易写错的判据**：很多资料说"至少需要 `e` 个模数"，那是假设每个 `n_i` 与
`m` 同量级时的结论。实际判据只有一个：

```text
Π n_i  >  m^e
```

`n_i` 足够大时，两个模数就能解 `e = 3` 的题；反过来 `n_i` 很小时，`e` 组也可能不够。
**不要写成 `assert len(ns) >= e`** —— 那会把本来可解的题误判为不可解。

上面实现还多了一层保护：开根成功后用**全部**已知 `(n, c)` 回验，而不是只用参与 CRT 的
那几组，避免"CRT 恰好得到某个完全幂但它不是答案"的误判。

**另一种形态**：题目给的就是 `m mod m_i = r_i`（连加密都没有），那只是纯 CRT，
`M = Π m_i > m` 即可唯一恢复。

```python
def crt_direct(residues: list, moduli: list) -> int:
    x, M = crt(residues, moduli)
    assert x < M
    for r, m in zip(residues, moduli):
        assert x % m == r
    return x
```

**区分两个很像的题面**：

| 题面 | 攻击 |
|---|---|
| 给了 `e` 和 `c_i = m^e mod n_i` | Håstad 广播：CRT 后**开根** |
| 给了 `r_i = m mod m_i` | 纯 CRT：CRT 后**就是 m** |

## 6. Fermat 分解（p 与 q 很近）

`p`、`q` 接近时 `n = p*q` 靠近一个完全平方数。令 `a = ceil(sqrt(n))`，
逐个试 `b2 = a^2 - n` 是否为完全平方数：

```python
def isqrt_exact(x: int):
    if x < 0:
        return None
    r = iroot(x, 2)
    return r if r * r == x else None


def fermat_factor(n: int, max_iter: int = 1 << 20):
    a = iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt_exact(b2)
        if b is not None:
            return a - b, a + b
        a += 1
    return None
```

`p` 与 `q` 的差小于 `n^(1/4)` 量级时收敛很快。对大数先用
`a*a - n` 的开方是否"接近整数"做一次嗅探，能省掉很多无效循环。

## 7. 共享素数：批量 gcd

同一批题目、多个模数里有两个共享一个素因子时，两两 `gcd` 直接分解：

```python
from math import gcd


def batch_gcd(moduli: list):
    """返回 {index: (p, q)}，只列出被成功分解的。"""
    out = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                out[i] = (g, moduli[i] // g)
                out[j] = (g, moduli[j] // g)
    return out
```

即使只有一组 `(n, e, c)`，也先做一次 `gcd(c, n)`：`c` 与 `n` 不互素时同样直接分解。
这一步成本极低，应该固化成习惯。

## 8. Wiener 攻击（e 过大）

`d` 很小时 `e/d` 是 `φ(n)/n` 的连分数逼近。连分数展开 `e/n`，逐个收敛项当候选 `k/d`
去验 `φ`：

```python
def continued_fraction(num: int, den: int) -> list:
    cf = []
    while den:
        cf.append(num // den)
        num, den = den, num % den
    return cf


def convergents(cf: list):
    for i in range(len(cf)):
        h, k = 1, 0
        for a in reversed(cf[:i + 1]):
            h, k = a * h + k, h
        yield h, k


def wiener_attack(e: int, n: int):
    from math import isqrt
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        # p, q 是 x^2 - (n - phi + 1)x + n = 0 的根
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = isqrt(disc)
        if s * s == disc and (b + s) % 2 == 0:
            return (b + s) // 2, (b - s) // 2, d
    return None
```

信号：`e` 和 `n` 位数相当（甚至更长）。正常 RSA 的 `e` 通常是 65537。

## 9. 验证闭环（必做）

**每一条解出来的东西都要用原式回验，不能只看解码结果像不像 flag。**

```python
def verify_all(n, e, c, m, extra_checks=()) -> None:
    """把恢复出的 m 代回原始关系式。任一断言失败即结论无效。"""
    assert pow(m, e, n) == c, "基础关系 c = m^e mod n 不成立"
    for name, fn in extra_checks:
        assert fn(m), f"附加关系 {name} 不成立"
    print(f"[ok] m = {m}")


def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")
```

推荐的回验清单：

| 攻击 | 至少要验的 |
|---|---|
| 小指数开根 | `m**e == c`（整数相等，非模） |
| 共模 | `pow(m, e1, n) == c1` 且 `pow(m, e2, n) == c2` |
| 模数为素数 | `pow(m, e, n) == c` 且 `is_probable_prime(n)` |
| Franklin-Reiter | `f(m) == 0` 且 `g(m) == 0`，或 `m^e==c1` 且 `(m+1)^e==c2` |
| Håstad | `pow(m, e, n_i) == c_i` 对**每个** `i` |
| CRT | `x % m_i == r_i` 对**每个** `i` |
| Fermat | `p * q == n` |
| Wiener | `p * q == n` 且 `pow(pow(m, e, n), d, n) == m` |

额外一眼判据：`long_to_bytes(m)` 应该只含可打印 ASCII，且长度与 `n` 的位数相称。
出现大量 `\x00` 或超长，说明 `m` 是模 `n` 的剩余而非原值，或者推错了。

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| RSA 题面知识检索 | `kb_router` | 按 `n/e/c` 的形态特征搜索 |
| 技术文件阅读 | `kb_read_file` | 读取本文件与相关文章 |
| 直接求解 | `solve_crypto_from_evidence` | 从已知量自动选择攻击并求解 |
| 复现脚手架 | `make_crypto_replay_scaffold` | 生成可重放的解密脚本骨架 |
| 依赖安装 | `python_re_tool_install` | 安装 sympy / pycryptodome / z3 |
| 结果哈希 | `hash_file` | 对解出的明文做哈希留证 |

## 工作流

```text
抄下全部已知量 → bit_length 分诊 → 按决策树选攻击 → 写最小脚本 →
原式回验（断言）→ long_to_bytes → 可打印性检查 → 记录参数与哈希
```

## 证据与验证闭环

- **先固定输入**：把题目给的每个大整数原样保存（含位数），不要中途"整理格式"。
  复制时漏一位数字会表现为"攻击不适用"，而不是报错。
- **每个结论绑定一条等式**：`pow(m, e, n) == c` 这类断言是唯一可接受的证据。
  "解出来是 `Flag{...}` 所以对了"不是证据——flag 格式可以被猜中。
- **失败的模式要记录**：`gcd 次数 = 2` 而不是 1、`gcd(lead, n) != 1`、开根余数不为 0，
  这些都指向不同的后续路线（换攻击 / 已拿到因子 / 需要格方法），不要笼统记成"没解出来"。
- **多路线互证**：Franklin-Reiter 的闭式解与多项式 gcd 应当给出同一个 `m`；
  只走一条路而没交叉验证时，留意"恰好命中"的可能。
- 题目附件与解题脚本进入 `exports/general/`，脚本与手算过程分离保存。

## 自检

本文所有代码片段都已抽出成可回归脚本，共 39 项断言（含反例：非法参数必须抛错）：

```bash
python kb/general/techniques/crypto/04-rsa-attack-family.selftest.py
```

覆盖：整数开根的边界（`x=0`、`k=1`、非完全幂）、共模攻击在 `gcd(e1,e2)!=1` 时拒绝、
Miller-Rabin 对 1/2/合数的判定、Franklin-Reiter 在 `e ∈ {3,5,7}` × 三组 `(a,b)` 下全部命中、
闭式解与多项式 gcd 结果一致、CRT 对非互素模数拒绝、Håstad 在模数不足时报错、
Fermat / 批量 gcd / Wiener 的正例与反例、以及回验函数能拦住错误解。

写这篇时就是被它抓到一个真错误：`hastad_broadcast` 原本断言"模数个数 ≥ e"，
在 `n` 很大时会把两模数可解的题误判为不可解。**示例代码必须跑，不能只写。**

