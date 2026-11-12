---
id: "ctf-website/12-payment/payment-php-defense"
title: "PHP 支付系统纵深防御 — 严格类型比较、反序列化禁用与 BCMath 计价"
title_en: "PHP Payment Defense — Strict Comparisons, Safe Deserialization & BCMath Precision"
summary: >
  针对 PHP 支付场景特有的 Type Juggling（== 与 magic hash、in_array/switch 隐式转换、strcmp 数组返回 NULL）、
  危险函数（extract/parse_str/unserialize）、Session 状态劫持与浮点精度截断，提供全等校验、JSON 替代反序列化与 BCMath/整数分币加固规范。
summary_en: >
  Hardens PHP payment systems against type juggling (loose ==, magic hashes, in_array/switch coercion, strcmp array
  null bypass), dangerous functions (extract/parse_str/unserialize), session state hijacking, and float truncation
  using strict comparisons, JSON-only serialization, and BCMath/integer-cent accounting.
board: "ctf-website"
category: "12-payment"
signals: ["PHP防御", "strict_types", "hash_equals", "in_array严格模式", "禁用unserialize", "BCMath", "Laravel Cashier", "WooCommerce"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["PHP payment hardening", "type juggling defense", "hash_equals", "declare strict_types", "bcmath", "safe deserialization"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "php", "payment", "type-juggling", "deserialization"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-php", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/15-mass-assignment/01-mass-assignment-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-php"
---
# PHP 支付系统纵深防御 — 严格类型比较、反序列化禁用与 BCMath 计价

> 配对攻击手册：[payment-php.md](./payment-php.md)。PHP 支付漏洞的绝大多数根因源自弱类型隐式转换（`==`、`switch`、`in_array` 非严格模式）、原生 `unserialize()` 注入以及 `float`/`intval` 精度失真。

## 威胁模型与控制映射

| 攻击向量 | 脆弱代码模式 | 加固控制措施 |
|---|---|---|
| Type Juggling 与 Magic Hash | `$sign == $expected`、`$amount == $paid`、`switch ($status)` | 签名比较强制使用 `hash_equals((string)$expected, (string)$sign)`；所有业务比较用 `===`；文件顶部启用 `declare(strict_types=1);` |
| `in_array()` 与 `strcmp()` 绕过 | `in_array($role, ['paid','admin'])`、`strcmp($_POST['sig'], $secret) == 0` | 强制 `in_array($role, $allowed, true)` 第三参数为 `true`；前置 `is_string()` 检查拒绝数组输入 |
| `extract()` / `parse_str()` 变量覆盖 | `extract($_POST)` 覆盖 `$is_paid` 或 `$price` | 严禁对用户输入调用 `extract()`；`parse_str($str, $out)` 必须提供第二参数且显式抽取白名单键 |
| PHP 反序列化对象注入 | `unserialize(base64_decode($_COOKIE['cart']))` | 彻底替换为 `json_decode($raw, true, 16, JSON_THROW_ON_ERROR)` 并做 HMAC 完整性校验（或直接仅在 Session 存 ID，数据放服务端 Redis/DB） |
| 浮点与 `intval()` 截断 | `$total = (float)$qty * (float)$price` 或 `intval("1e5")` | 金额全程使用整数分（`int`）或 `bcmath`（`bcmul`/`bcadd`/`bccomp`），入参先用正则 `/^\d+$/` 校验后再转换 |
| Session 支付状态篡改与框架缺陷 | 把 `$_SESSION['order_paid'] = true` 当发货依据；Laravel/WooCommerce Webhook 未验签 | 仅信任数据库持久化的网关实付记录；升级框架、配置 Laravel `WebhookSignature` 中间件与严格 `$fillable` 白名单 |

## 核心加固实现

### 1. PHP 8.x 支付核验加固范式

```php
<?php
declare(strict_types=1);

final class SecurePhpPaymentVerifier
{
    public static function verifyHmacSignature(array $payload, string $secret): bool
    {
        if (!isset($payload['sign']) || !is_string($payload['sign'])) {
            return false; // 拒绝数组或缺失签名导致的 strcmp/hash_equals 类型异常
        }
        $provided = $payload['sign'];
        unset($payload['sign'], $payload['sign_type']);
        ksort($payload, SORT_STRING);

        $canonical = http_build_query($payload, '', '&', PHP_QUERY_RFC3986);
        $expected = hash_hmac('sha256', $canonical, $secret);
        return hash_equals($expected, $provided);
    }

    public static function parseStrictPositiveCents(mixed $raw): int
    {
        if (is_int($raw)) {
            if ($raw <= 0) {
                throw new InvalidArgumentException('amount must be positive');
            }
            return $raw;
        }
        if (is_string($raw) && preg_match('/^[1-9]\d{0,9}$/', $raw) === 1) {
            return (int) $raw;
        }
        throw new InvalidArgumentException('invalid integer cents input');
    }

    public static function isAllowedStatus(mixed $status): bool
    {
        $allowed = ['PAID', 'FULFILLED'];
        return is_string($status) && in_array($status, $allowed, true);
    }
}
```

### 2. Python 静态模式巡检器（定位 PHP 支付危险原语）

```python
# php_payment_pattern_scanner.py — 检测 PHP 支付代码中的弱比较、反序列化与危险变量覆盖
import re
from dataclasses import dataclass

RULES = [
    ("PHP_LOOSE_COMPARE_SIGN", re.compile(r"\$(?:sign|sig|hmac|hash|token)\s*==\s*")),
    ("PHP_IN_ARRAY_NON_STRICT", re.compile(r"in_array\s*\((?:(?!,\s*true\s*\))[^;])+\)")),
    ("PHP_UNSERIALIZE_CALL", re.compile(r"\bunserialize\s*\(")),
    ("PHP_EXTRACT_USER_INPUT", re.compile(r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)")),
    ("PHP_STRCMP_LOOSE", re.compile(r"strcmp\s*\([^)]+\)\s*==\s*0")),
    ("PHP_FLOAT_MONEY_CAST", re.compile(r"\((?:float|double)\)\s*\$(?:price|amount|total)")),
]

@dataclass
class Finding:
    rule_id: str
    line: int
    snippet: str

def scan_php_source(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for idx, line in enumerate(source.splitlines(), start=1):
        for rule_id, pattern in RULES:
            if pattern.search(line):
                findings.append(Finding(rule_id=rule_id, line=idx, snippet=line.strip()))
    return findings

if __name__ == "__main__":
    vuln_sample = """
    extract($_POST);
    if ($sign == $calc_sign) { deliver(); }
    if (in_array($role, ['paid', 'admin'])) { grant(); }
    $cart = unserialize($_COOKIE['cart']);
    """
    hits = scan_php_source(vuln_sample)
    hit_ids = {h.rule_id for h in hits}
    assert {"PHP_EXTRACT_USER_INPUT", "PHP_LOOSE_COMPARE_SIGN", "PHP_IN_ARRAY_NON_STRICT", "PHP_UNSERIALIZE_CALL"} <= hit_ids

    safe_sample = """
    if (hash_equals($calc_sign, (string)$sign)) { deliver(); }
    if (in_array($role, ['paid', 'admin'], true)) { grant(); }
    $cart = json_decode($_COOKIE['cart'], true, 16, JSON_THROW_ON_ERROR);
    """
    assert scan_php_source(safe_sample) == []
    print("payment-php-defense self-check passed")
```

## 防御工作流

```text
1. 静态门禁：在 CI 中运行 php_payment_pattern_scanner 与 PHPStan (level >= 8)，清零 `==`、`unserialize()`、`extract()` 与非严格 `in_array()`。
2. 签名与输入强类型：所有支付文件首行添加 `declare(strict_types=1);`，签名比对统一改用 `hash_equals()` 并先校验 `is_string()`。
3. 金额定点数化：将 `float`/`double` 金额运算全部替换为最小货币单位 `int` 或 `bcmath` 扩展函数。
4. 反序列化清退：购物车与支付凭据改用 JSON + 服务端 Session 存储，禁止向客户端透传序列化对象。
5. 框架配置核查：确认 Laravel Cashier Webhook 验签中间件开启、WooCommerce 回调秘钥非空且禁用调试日志明文落盘。
```

## 验证与判定标准

- **弱类型载荷零绕过**：向 PHP 支付回调提交 `"0e12345"`、`sign[]=1`、`amount="100abc"` 或 `role=0` 时，均被严格类型守卫拒绝返回 `400/403`。
- **反序列化面清零**：代码库支付模块静态扫描命中 `PHP_UNSERIALIZE_CALL` 与 `PHP_EXTRACT_USER_INPUT` 数量为 `0`。
- **精度零误差**：高小数位商品数量乘以单价后，与 `bcmath` 基准结果偏差为 `0`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| PHP 支付路由边界核查 | `http_probe` | 验证数组参数 `sign[]`、magic hash 与异常类型输入的拒绝状态码 |
| 批量赋值与参数加固关联 | `kb_router` | 检索 Mass Assignment 与支付通用防御文档 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-php` 核查全部 PHP 绕过面 |
| 知识库防御索引 | `kb_catalog` | 列出所有 PHP 与支付相关防御条目 |
