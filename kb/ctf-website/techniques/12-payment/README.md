# 12-payment — 支付、订单与票务业务逻辑

| 信号 | Technique |
|---|---|
| 通用订单/金额/状态机 | [payment-logic.md](payment-logic.md) |
| 参数篡改、类型混淆、零元购 | [payment-bypass.md](payment-bypass.md) |
| 回调、异步、幂等与竞态 | [payment-callback-async.md](payment-callback-async.md) |
| 余额/quota 共享行写入、Lost Update、乐观锁冲突 | [payment-race-lost-update.md](payment-race-lost-update.md) |
| 订单邮件退信、游客查询与卡密 IDOR | [payment-email-bounce-idor.md](payment-email-bounce-idor.md) |
| 支付平台/CMS/网关指纹 | [platform-fingerprints.md](platform-fingerprints.md) |
| PHP 支付实现 | [payment-php.md](payment-php.md) |
| 订阅与续费 | [payment-subscription.md](payment-subscription.md) |
| 数字商品/IAP | [payment-digital-goods.md](payment-digital-goods.md) |
| 抢票、project/screen/SKU、prepare/create、ptoken/ctoken | [ticket-rush-api-reversing.md](ticket-rush-api-reversing.md) |

白盒参考源码固定在 `../../sources/`，Technique 只保留可复用模型和验证步骤。
