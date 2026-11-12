#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对 kb/general/techniques/crypto/04-rsa-attack-family.md 中的示例做自检。

用小素数构造可控样例，逐个攻击跑通并断言。
"""
from __future__ import annotations

import random
from math import comb, gcd, isqrt


# --------------------------------------------------------- 文中函数（原样抄录）
def iroot(x: int, k: int) -> int:
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
    r = iroot(c, e)
    if r ** e == c:
        return r, True
    return None, False


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> int:
    g, a, b = egcd(e1, e2)
    assert g == 1
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
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


def prime_modulus_decrypt(n: int, e: int, c: int) -> int:
    phi = n - 1
    d = pow(e, -1, phi)
    return pow(c, d, n)


def poly_trim(p: list) -> list:
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_mod(a: list, b: list, n: int) -> list:
    a, b = poly_trim(a[:]), poly_trim(b[:])
    if len(b) == 1:
        return [0]
    inv = pow(b[-1], -1, n)
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
    f = [(-c1) % n] + [0] * (e - 1) + [1]
    g = [0] * (e + 1)
    for i in range(e + 1):
        g[i] = (comb(e, i) * pow(a, i) * pow(b, e - i)) % n
    g[0] = (g[0] - c2) % n
    h = poly_gcd(f, g, n)
    assert len(h) == 2, f"gcd 次数={len(h) - 1}"
    m1 = (-h[0] * pow(h[1], -1, n)) % n
    assert poly_eval(f, m1, n) == 0 and poly_eval(g, m1, n) == 0
    return m1


def fr_e3_delta1_closed_form(n: int, c1: int, c2: int) -> int:
    d = (c2 - c1) % n
    den = (d + 2) % n
    g = gcd(den, n)
    if g != 1:
        raise ValueError(f"gcd(d+2, n) = {g}")
    m = ((3 * c1 + d - 1) % n) * pow(den, -1, n) % n
    assert pow(m, 3, n) == c1 and pow(m + 1, 3, n) == c2
    return m


def crt(residues: list, moduli: list):
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"模数不互素: gcd(n{i + 1}, n{j + 1}) != 1")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x = (x + r * Mi * pow(Mi, -1, m)) % M
    return x % M, M


def hastad_broadcast(e: int, ns: list, cs: list) -> int:
    assert len(ns) == len(cs) >= 1, "模数与密文数量必须一致且非空"
    for k in range(1, len(ns) + 1):
        C, M = crt(cs[:k], ns[:k])
        m, ok = small_e_integer_root(e, C)
        if ok and all(pow(m, e, n) == c for n, c in zip(ns, cs)):
            return m
    raise ValueError("Πn_i 不足以覆盖 m^e")


def crt_direct(residues: list, moduli: list) -> int:
    x, M = crt(residues, moduli)
    assert x < M
    for r, m in zip(residues, moduli):
        assert x % m == r
    return x


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


def batch_gcd(moduli: list):
    out = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                out[i] = (g, moduli[i] // g)
                out[j] = (g, moduli[j] // g)
    return out


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
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = isqrt(disc)
        if s * s == disc and (b + s) % 2 == 0:
            return (b + s) // 2, (b - s) // 2, d
    return None


def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def verify_all(n, e, c, m, extra_checks=()) -> None:
    assert pow(m, e, n) == c, "基础关系 c = m^e mod n 不成立"
    for name, fn in extra_checks:
        assert fn(m), f"附加关系 {name} 不成立"
    print(f"[ok] m = {m}")


# --------------------------------------------------------- 自检
def gen_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p


def main() -> int:
    random.seed(20260917)
    f = 0
    fail = 0

    def check(name, cond, detail=""):
        nonlocal f, fail
        if cond:
            f += 1
            print(f"  [PASS] {name} {detail}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {detail}")

    def raises(name, fn, exc=Exception):
        nonlocal f, fail
        try:
            fn()
        except exc:
            f += 1
            print(f"  [PASS] {name} 如期抛错")
            return
        fail += 1
        print(f"  [FAIL] {name} 未抛错")

    msg = int.from_bytes(b"Flag{selftest_rsa_family}", "big")
    print(f"明文 m = {msg}  ({msg.bit_length()} bit)\n")

    print("§1 小指数整数开根")
    c = msg ** 3
    m, ok = small_e_integer_root(3, c)
    check("iroot 精确命中", ok and m == msg)
    check("iroot 非完全立方数返回 False", small_e_integer_root(3, c + 1)[1] is False)
    check("iroot(x,1)==x", iroot(12345, 1) == 12345)
    check("iroot(2**200, 2)", iroot(2 ** 200, 2) == 2 ** 100)
    check("iroot(0)", iroot(0, 3) == 0)

    print("\n§2 共模攻击")
    n = gen_prime(256) * gen_prime(256)
    e1, e2 = 17, 19
    mm = msg % n
    c1, c2 = pow(mm, e1, n), pow(mm, e2, n)
    rec = common_modulus(n, e1, c1, e2, c2)
    check("共模恢复", rec == mm, f"(期望 {mm})")
    verify_all(n, e1, c1, rec)
    raises("gcd(e1,e2)!=1 时拒绝", lambda: common_modulus(n, 17, c1, 17, c1), AssertionError)

    print("\n§3 模数为素数")
    p_only = gen_prime(512)
    c3 = pow(msg, 65537, p_only)
    check("Miller-Rabin 判定素数", is_probable_prime(p_only))
    check("Miller-Rabin 判定合数", not is_probable_prime(gen_prime(128) * gen_prime(128)))
    check("素模数解密", prime_modulus_decrypt(p_only, 65537, c3) == msg)
    check("Miller-Rabin(1)=False", not is_probable_prime(1))
    check("Miller-Rabin(2)=True", is_probable_prime(2))

    print("\n§4 Franklin-Reiter")
    n2 = gen_prime(512) * gen_prime(512)
    m1 = msg % n2
    for e in (3, 5, 7):
        for a, b in ((1, 1), (1, 3), (7, 2)):
            c1 = pow(m1, e, n2)
            c2 = pow(a * m1 + b, e, n2)
            got = franklin_reiter(n2, e, c1, c2, a, b)
            check(f"FR e={e} a={a} b={b}", got == m1)
    cf = fr_e3_delta1_closed_form(n2, pow(m1, 3, n2), pow(m1 + 1, 3, n2))
    check("FR e=3 delta=1 闭式", cf == m1)
    gcd_rec = franklin_reiter(n2, 3, pow(m1, 3, n2), pow(m1 + 1, 3, n2))
    check("闭式与 gcd 互证", cf == gcd_rec)
    raises("闭式在非适用参数下不静默出错",
           lambda: fr_e3_delta1_closed_form(n2, pow(m1, 3, n2), pow(m1 + 5, 3, n2)))

    print("\n§5 Håstad 广播 + CRT")
    e = 3
    ns, cs = [], []
    while True:
        nn = gen_prime(160) * gen_prime(160)
        cc = pow(msg, e, nn)
        ns.append(nn)
        cs.append(cc)
        M = 1
        for x in ns:
            M *= x
        if M > msg ** e:
            break
    got = hastad_broadcast(e, ns, cs)
    check(f"Håstad 用 {len(ns)} 组模数恢复", got == msg)
    check("CRT 直解", crt_direct([msg % x for x in ns], ns) == msg)
    raises("模数不互素时 CRT 拒绝",
           lambda: crt([1, 1], [gen_prime(64) * 2, gen_prime(64) * 2]))
    raises("模数不足时 Håstad 报错",
           lambda: hastad_broadcast(e, ns[:1], cs[:1]), ValueError)
    check("isqrt_exact 非平方返回 None", isqrt_exact(15) is None)

    print("\n§6 Fermat 分解（p 与 q 很近）")
    q = gen_prime(256)
    p = q + 2                      # q 是奇素数，q+1 是偶数，必须从 q+2 起走奇数步
    while not is_probable_prime(p):
        p += 2
    nf = p * q
    res = fermat_factor(nf)
    check("Fermat 分解近距离素数", res is not None and res[0] * res[1] == nf,
          f"(p-q={p - q})")

    print("\n§7 批量 gcd（共享素数）")
    sh = gen_prime(256)
    na, nb = sh * gen_prime(256), sh * gen_prime(256)
    out = batch_gcd([na, nb, gen_prime(256) * gen_prime(256)])
    check("定位共享素因子", 0 in out and 1 in out and out[0][0] == sh)
    check("不误报无关模数", 2 not in out)

    print("\n§8 Wiener（d 过小）")
    pw, qw = gen_prime(256), gen_prime(256)
    nw = pw * qw
    phi_w = (pw - 1) * (qw - 1)
    dw = gen_prime(64)
    while gcd(dw, phi_w) != 1:
        dw = gen_prime(64)
    ew = pow(dw, -1, phi_w)
    rw = wiener_attack(ew, nw)
    check("Wiener 恢复 d", rw is not None and rw[2] == dw)
    if rw:
        check("Wiener 分解 n", rw[0] * rw[1] == nw)
    check("正常 e=65537 不触发 Wiener",
          wiener_attack(65537, gen_prime(256) * gen_prime(256)) is None)

    print("\n§9 回验与解码")
    raw = long_to_bytes(msg)
    check("long_to_bytes 往返", int.from_bytes(raw, "big") == msg)
    check("long_to_bytes(0)", long_to_bytes(0) == b"\x00")
    check("明文可打印", raw.decode().startswith("Flag{"))
    try:
        verify_all(n, e1, c1, mm + 1)
        fail += 1
        print("  [FAIL] verify_all 未拦住错误 m")
    except AssertionError:
        f += 1
        print("  [PASS] verify_all 拦住错误 m")

    print(f"\n{'=' * 60}")
    print(f"通过 {f} / 失败 {fail}")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
