# 13-signature — 签名伪造与验证绕过

> 签名 = 信任的数学表达。打破它 = 伪造信任。

## 快速查找

| 你发现了 | 去看 |
|---|---|
| `sign_type=MD5` / `alg=none` / 空签名 | [01-algorithm.md](01-algorithm.md) |
| `strcmp` / `==` vs `===` / magic hash / PHP type juggling | [02-implementation.md](02-implementation.md) |
| 弱密钥 / 硬编码密钥 / 密钥在 JS 里 / .env 泄露 | [03-key-attacks.md](03-key-attacks.md) |
| 参数顺序不同签名不同 / XML parse差异 / URL编码差异 | [04-canonicalization.md](04-canonicalization.md) |
| MD5/SHA1/SHA2 签名 / 知道 `sign = hash(secret + data)` | [05-length-extension.md](05-length-extension.md) |
| 重放 / nonce 复用 / timestamp 过期绕过 | [06-replay-nonce.md](06-replay-nonce.md) |
| 不确定是哪类 / 想做全覆盖 | [00-overview.md](00-overview.md) |

## 跨文件引用

- JWT 签名: [02-auth/jwt/](../02-auth/jwt/)
- OAuth state/signature: [02-auth/oauth-sso.md](../02-auth/oauth-sso.md)
- SAML XML Signature: [02-auth/saml-attacks.md](../02-auth/saml-attacks.md)
- 支付回调签名: [12-payment/payment-callback-async.md](../12-payment/payment-callback-async.md)
- PHP 签名绕过: [12-payment/payment-php.md](../12-payment/payment-php.md)
