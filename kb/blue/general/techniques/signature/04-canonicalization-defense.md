---
id: "general/signature/04-canonicalization-defense"
title: "签名规范化绕过防御（Verify-After-Parse / RFC 8785 JCS / HPP 拦截）"
title_en: "Defense Against Signature Canonicalization Bypass"
summary: >
  防御参数排序缺陷、URL 编码差异、JSON 重复键/Unicode 解析不一致、XML 规范化（XSW）与 HTTP 参数污染（HPP）：推行单一解析树与“先解析校验唯一性、再规范化验签、后直接使用已验签 AST”的架构标准。
summary_en: >
  Defense against parameter sorting bugs, URL encoding differentials, JSON duplicate keys, XML Signature Wrapping (XSW), and HPP: enforce single-parser verify-after-parse architecture, RFC 8785 JCS, duplicate parameter rejection, and strict XML element binding.
board: "general"
category: "signature"
signals:
  - "RFC 8785 JCS"
  - "HPP rejection"
  - "single AST"
  - "XML XSW defense"
  - "verify after parse"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "canonicalization defense"
  - "RFC 8785"
  - "HPP"
  - "JSON duplicate keys"
  - "XSW defense"
difficulty: "advanced"
tags:
  - "signature-defense"
  - "canonicalization"
  - "HPP-defense"
  - "XML-security"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/signature/04-canonicalization"
  - "general/signature/00-overview-defense"
track: "blue"
defends: "general/signature/04-canonicalization"
---
# 签名规范化绕过防御（Verify-After-Parse / RFC 8785 JCS / HPP 拦截）

## 防御目标

消除“验签层看到的报文”与“业务层读取的报文”之间的解析差异，阻断参数排序截断、URL 二次解码差异、JSON 重复 key 覆盖、HTTP 参数污染（HPP）以及 XML 签名包裹攻击（XSW）。

## 规范化差异与防御标准对照

| 绕过维度 | 解析差异根源 | 强制防御标准 |
|---|---|---|
| HTTP 参数污染（HPP） | 验签取首值/全拼接，业务层取末值（`amount=0.01&amount=100`） | 解析 Query/Form 时**严禁静默覆盖重复键**，发现任意重复参数名直接返回 `400 Bad Request` |
| `sign` 字段混入排序与截断 | `sign` 字段自身参与排序或拼装字符串未按定界符转义 | 仅对净业务字段集合签名；字段名与值之间用不可伪造长度前缀或 RFC 8785 JSON 序列化 |
| URL 编解码差异 | 一端对 `+`/`%20`/`%2F` 解码后再签名，另一端按原文验签 | 统一规定按解码后规范键值对排序，或直接对原始字节流（如 Webhook `raw_body`）做 HMAC |
| JSON 键冲突与数字格式 | JSON `{"amount":100,"amount":0.01}` 或 `1e2` vs `100` 导致差异 | 反序列化时使用 `object_pairs_hook` 拒绝重复键，并采用 RFC 8785（JCS）确定性序列化或直接验签原始 `raw_body` |
| XML 签名包裹（XSW） | 仅验证 `Reference URI` 指向的签名节点，而业务 XPath 读取了未签名位置节点 | 先校验 `SignedInfo` 内 `URI` 唯一性及与业务根节点位置关系（只信任已验签子树本身，不再重新全局 XPath 搜索） |

## 防御实现与校验示例

### 1. 拒绝重复键的表单/JSON 统一规范化验签器（Python）

确保验证层与业务层消费完全一致的数据对象，在解析阶段即拦截 HPP 与 JSON 重复键：

```python
import hmac
import hashlib
import json
from urllib.parse import parse_qsl

def parse_strict_query(raw_query: str) -> dict[str, str]:
    pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=False)
    result: dict[str, str] = {}
    for k, v in pairs:
        if k in result:
            raise ValueError(f"duplicate_query_param:{k}")
        result[k] = v
    return result

def parse_strict_json(raw_json: bytes) -> dict:
    def no_duplicates_hook(ordered_pairs: list[tuple[str, object]]) -> dict:
        obj = {}
        for k, v in ordered_pairs:
            if k in obj:
                raise ValueError(f"duplicate_json_key:{k}")
            obj[k] = v
        return obj
    data = json.loads(raw_json.decode("utf-8"), object_pairs_hook=no_duplicates_hook)
    if not isinstance(data, dict):
        raise ValueError("json_root_must_be_object")
    return data

def verify_and_extract_query(secret: bytes, raw_query: str, sig_param: str = "sign") -> dict[str, str]:
    params = parse_strict_query(raw_query)
    if sig_param not in params or not params[sig_param]:
        raise ValueError("missing_signature")
    client_sig = params.pop(sig_param)
    # 明确排除 sign 字段后，按 UTF-8 字典序序列化净键值对
    canonical = "&".join(f"{k}={params[k]}" for k in sorted(params))
    expected = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(client_sig.lower(), expected):
        raise ValueError("invalid_signature")
    # 下游业务只能使用这里返回的已验签 params，严禁重读 raw_query
    return params

if __name__ == "__main__":
    key = b"K" * 32
    base_canon = "amount=100&order_id=A1"
    good_sig = hmac.new(key, base_canon.encode(), hashlib.sha256).hexdigest()
    verified = verify_and_extract_query(key, f"order_id=A1&amount=100&sign={good_sig}")
    assert verified == {"order_id": "A1", "amount": "100"}
    try:
        verify_and_extract_query(key, f"order_id=A1&amount=100&amount=0.01&sign={good_sig}")
        assert False, "HPP should have failed"
    except ValueError as e:
        assert "duplicate_query_param" in str(e)
    try:
        parse_strict_json(b'{"amount":100,"amount":0.01}')
        assert False, "Duplicate JSON key should have failed"
    except ValueError as e:
        assert "duplicate_json_key" in str(e)
    print("canonicalization_defense_check: PASS")
```

## 防御工作流

```text
1. 单一解析器原则：在网关或中间件层仅解析一次请求，拒绝任何重复键或编码歧义
2. 原始体签名优先：对 Webhook/API POST 场景优先直接对 HTTP raw_body 字节流计算 HMAC，避免 JSON 重序列化漂移
3. 剔除签名字段后序列化：确保 sign 字段本身绝不进入待签字符串参与排序或拼接
4. 传值不传原文：验签函数返回已验证的强类型对象给下游业务，禁止业务代码二次读取原始 request 字符串
5. XML 安全加固：禁用外部实体（XXE），并使业务层直接读取 Signature 验证通过后返回的已绑定 DOM 子树
```

## 验证与判定标准

- **HPP 阻断**：请求包含重复键（如 `amount=100&amount=0.01`）或重复 JSON 键时，解析层 100% 抛出拒绝错误
- **值绑定一致**：修改空值、空格、`+`/`%20` 或键顺序，服务端规范化结果唯一且不产生与业务层读取值的偏差
- **XSW 防护**：在 SAML/XML 报文插入未签名克隆节点时，业务层仅读取经签名引用确认的节点内容

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 关联重放与实现防御 | `kb_router` | 检索签名实现与算法锁定方案 |
| 严格解析中间件落盘 | `workspace_write_text` | 输出 `parse_strict_query` 与 `parse_strict_json` 工具模块 |
| 参数污染监控规则 | `make_sigma_stub` | 生成检测请求中包含重复关键参数（HPP）的 WAF/日志规则 |
