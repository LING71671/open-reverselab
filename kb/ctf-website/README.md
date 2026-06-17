# Web CTF 知识库

AI 实战 Lab。每个文件 = 可复制运行的攻击代码。每个文件有攻击链。

## 结构

```
techniques/ (33 files)
├── 01-recon/ (2)
├── 02-auth/  (13: jwt×11 + oauth + host-header)
├── 03-injection/ (5: sqli + ssti + pp + graphql + hpp-crlf)
├── 04-ssrf/  (2: ssrf + open-redirect)
├── 05-deserialization/ (1)
├── 06-file-attacks/ (1)
├── 07-client/ (4: xss + js + ws + cors-csrf)
├── 08-infra/ (1)
└── 09-cve/   (3)
```

## 核心文件

| 文件 | 说明 |
|------|------|
| `techniques/attack-network.md` | **攻击网** — 全网图(Mermaid)、6条典型路径、枢纽节点、决策驱动 |
| `techniques/README.md` | 技术索引 — 所有文件清单、工具映射 |
| `checklists/web-ctf-first-30-min.md` | 前30分钟行动计划 |

## 流程

```
Recon → Fingerprint → 查攻击网 → 选入口 → 多条路径并行 → Flag
```
攻击网 > 单条攻击链: 网状思考，多线并进，选最短路径。

## 工具映射

参照 `techniques/README.md` 底部工具映射表。

## 原则

- 伪代码直接跑
- 先 min probe，再深入
- 一次一个变量
- 30 min 无果换面
- 证据落盘

## 支付类题目

- Technique: ./kb\ctf-website\techniques\12-payment\payment-logic.md`n- 关键词：订单、金额、支付状态、回调签名、幂等并发、订单 IDOR、优惠/余额/退款/权益错配。

