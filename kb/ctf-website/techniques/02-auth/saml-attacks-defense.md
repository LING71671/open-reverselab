---
id: "ctf-website/02-auth/saml-attacks-defense"
title: "SAML 2.0 XML 签名包装与解析器差异防御"
title_en: "SAML 2.0 XSW, Void Canonicalization, and Replay Defense"
summary: >
  针对 SAML 2.0 单点登录中的 XML Signature Wrapping (XSW1-XSW8)、Void Canonicalization 空摘要绕过、XML 序列化 Round-Trip 解析器差异、Assertion 属性与 NameID 注入以及 SAMLResponse 重放攻击，提供严格单解析器 DOM 验签、唯一 Assertion 与 Reference URI 强制绑定、Schema/Namespace 白名单校验、NotOnOrAfter/Audience/Recipient/InResponseTo 验证及 Assertion ID 防重放缓存方案。
summary_en: >
  Defensive guide for SAML 2.0 SSO covering XML Signature Wrapping (XSW1-XSW8), Void Canonicalization bypass, Round-Trip XML parser differentials, Assertion attribute injection, and SAMLResponse replay. Enforces single-parser DOM verification, strict single-Assertion and Reference-URI binding, absolute namespace validation, and Assertion ID replay cache.
board: "ctf-website"
category: "02-auth"
signals: ["SAML", "XML Signature Wrapping", "XSW", "Void Canonicalization", "Round-Trip", "Assertion", "InResponseTo", "Replay"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["SAML防御", "XSW防御", "XML签名验证", "Void Canonicalization修复", "SAML防重放", "SAML Schema校验"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "saml", "xml-security", "sso"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/saml-attacks", "ctf-website/02-auth/oauth-sso-defense", "ctf-website/02-auth/host-header-defense"]
track: "blue"
defends: "ctf-website/02-auth/saml-attacks"
---

# SAML 2.0 XML 签名包装与解析器差异防御

SAML 2.0 攻击的核心规律是**“验签库看到的 XML 节点”与“业务逻辑提取身份的 XML 节点”不是同一个节点**，或是底层 XML 规范化库在异常命名空间/注释/CDATA 面前返回空摘要或出现序列化偏差。稳健的 SP 必须强制使用**同一解析器实例**先验签再从**已签名节点对象本身**读取 `NameID` 与 `Attribute`。

## 威胁面与防御映射

| 攻击向量 | 漏洞根因 | 强制防御措施 |
|---|---|---|
| XSW1–XSW8 签名包装 | 验签库按 `Reference URI="#legit"` 验证某个节点，业务代码却用 XPath 取第一个 `<Assertion>` | 强制整份 `<Response>` 至多存在**唯一** `<Assertion>`；业务只从通过验签的 DOM 子树引用读取字段，禁止再次全局 XPath |
| `ID` vs `Id` 属性歧义 | 解析器对大小写敏感度不同或存在重复 `ID` | 校验全文档 `ID` 唯一性，拒绝任何重复或非标准大小写 `Id`/`id` 属性 |
| Void Canonicalization | 相对命名空间 URI（如 `xmlns:ns="1"`）导致 `libxml2` c14n 返回空字符串并匹配空摘要 | 预扫描所有 `nsmap`，拒绝任何非绝对 URI 命名空间；升级修复后的 `xmlsec`/`libxml2` 并禁止空摘要或弱算法（禁用 SHA-1） |
| Round-Trip 解析器差异 | 验签前或验签后二次序列化 XML（REXML/Nokogiri 等处理 CDATA、注释、前缀不一致） | 禁止跨解析器二次序列化；解析时剥离非必要注释前先校验完整字节流，拒绝多段混合 CDATA 与结构异常元素 |
| SAML Replay / 属性注入 | 未验证 `NotOnOrAfter`、`AudienceRestriction`、`Recipient`、`InResponseTo` 与消费记录 | 校验时间窗口（允许 <= 60s 时钟漂移）、精确匹配 SP `entityID` 与 ACS URL、绑定 `InResponseTo`，并将 `(AssertionID, NotOnOrAfter)` 写入防重放缓存 |

## 防御工作流

```text
1. 传输解码与实体防护
   └─ 按绑定方式解码（HTTP-POST Base64 / HTTP-Redirect DEFLATE），解析时禁用 DTD 与外部实体（防 XXE）
2. 结构与命名空间预检（Schema & Namespace Guard）
   └─ 校验 XSD 结构 -> 检查所有 xmlns 是否为绝对 URI（阻断 Void C14n）-> 检查全文档 ID 唯一性
3. 单节点签名验证（Single-DOM Verification）
   └─ 验证 SignedInfo 仅引用唯一合法 Reference URI，且签名覆盖完整 Assertion 或根 Response（禁止多 Assertion 并存）
4. 上下文与重放核验（Context & Replay Check）
   └─ 验证 NotBefore / NotOnOrAfter、Audience == SP_ENTITY_ID、Recipient == ACS_URL、InResponseTo，并将 AssertionID 写入 Redis 防重放
5. 安全提取身份属性
   └─ 直接从第 3 步返回的已验签 Assertion 对象句柄读取 NameID 与 Attribute，禁止二次字符串解析
```

### Python SAML XML 结构预检与上下文硬校验实现

```python
from datetime import datetime, timezone
from urllib.parse import urlsplit
from lxml import etree

ALLOWED_DIGEST_ALGS = {"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512"}
ALLOWED_SIG_ALGS = {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"}


def parse_safe_saml_xml(xml_bytes: bytes) -> etree._Element:
    """禁用 DTD 与实体解析，防止 XXE 与解析歧义。"""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
    return etree.fromstring(xml_bytes, parser=parser)


def preflight_saml_guards(root: etree._Element) -> etree._Element:
    """拦截 Void Canonicalization、XSW 多断言包装与弱算法。"""
    # 1. 拒绝相对 namespace URI（阻断 libxml2 Void Canonicalization）
    for elem in root.iter():
        for prefix, uri in (elem.nsmap or {}).items():
            parsed = urlsplit(uri)
            if not parsed.scheme or not (parsed.netloc or parsed.path):
                raise ValueError(f"relative or malformed namespace URI rejected: {prefix}={uri}")

    # 2. 拒绝任何注释节点与多 Assertion 结构（阻断 XSW1-XSW8 与注释混淆）
    if root.xpath("//comment()"):
        raise ValueError("XML comments are disallowed in SAML responses")
    assertions = root.xpath("//*[local-name()='Assertion']")
    if len(assertions) != 1:
        raise ValueError(f"expected exactly 1 Assertion, got {len(assertions)}")
    assertion = assertions[0]

    # 3. 校验 ID 唯一性且禁止非标准 Id/id 混淆属性
    if root.xpath("//*[@Id or @id]"):
        raise ValueError("non-standard Id/id attributes disallowed")
    ids = root.xpath("//@ID")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate ID attributes detected")

    # 4. 检查 Signature Reference URI 必须精确指向唯一 Assertion 或 Response
    refs = root.xpath("//*[local-name()='Signature']//*[local-name()='Reference']/@URI")
    valid_targets = {f"#{assertion.get('ID')}", f"#{root.get('ID')}"} - {"#None"}
    if len(refs) != 1 or refs[0] not in valid_targets:
        raise ValueError(f"untrusted Signature Reference URI: {refs}")

    # 5. 强制安全摘要与签名算法
    digest_algs = root.xpath("//*[local-name()='DigestMethod']/@Algorithm")
    sig_algs = root.xpath("//*[local-name()='SignatureMethod']/@Algorithm")
    if not digest_algs or any(a not in ALLOWED_DIGEST_ALGS for a in digest_algs):
        raise ValueError("disallowed digest algorithm")
    if not sig_algs or any(a not in ALLOWED_SIG_ALGS for a in sig_algs):
        raise ValueError("disallowed signature algorithm")

    return assertion


def validate_assertion_conditions(
    assertion: etree._Element,
    expected_audience: str,
    expected_recipient: str,
    expected_in_response_to: str,
    replay_cache: set[str],
    now: datetime | None = None,
) -> str:
    """在签名验证通过后，强制校验时间窗口、受众、接收端点、请求绑定与防重放。"""
    now = now or datetime.now(timezone.utc)
    aid = assertion.get("ID")
    if not aid or aid in replay_cache:
        raise PermissionError("missing or replayed Assertion ID")

    # Audience 校验
    audiences = assertion.xpath("./*[local-name()='Conditions']//*[local-name()='Audience']/text()")
    if expected_audience not in audiences:
        raise PermissionError("AudienceRestriction mismatch")

    # Recipient 与 InResponseTo 校验
    sc_data = assertion.xpath("./*[local-name()='Subject']/*[local-name()='SubjectConfirmation']/*[local-name()='SubjectConfirmationData']")
    if not sc_data:
        raise PermissionError("missing SubjectConfirmationData")
    node = sc_data[0]
    if node.get("Recipient") != expected_recipient:
        raise PermissionError("Recipient ACS URL mismatch")
    if expected_in_response_to and node.get("InResponseTo") != expected_in_response_to:
        raise PermissionError("InResponseTo mismatch")

    not_after_raw = node.get("NotOnOrAfter")
    if not not_after_raw:
        raise PermissionError("missing NotOnOrAfter")
    not_after = datetime.fromisoformat(not_after_raw.replace("Z", "+00:00"))
    if now >= not_after:
        raise PermissionError("SAML assertion expired")

    replay_cache.add(aid)
    nameids = assertion.xpath("./*[local-name()='Subject']/*[local-name()='NameID']/text()")
    if len(nameids) != 1:
        raise PermissionError("ambiguous NameID")
    return nameids[0].strip()
```

## 验证与判定标准

运行以下自检验证 [saml-attacks.md](saml-attacks.md) 中的 XSW1、Void Canonicalization 及重放攻击均被拦截：

```python
def run_saml_hardening_checks() -> None:
    xsw1_xml = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp1">
      <saml:Assertion ID="evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>
      <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#legit"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo></ds:Signature>
      <saml:Assertion ID="legit"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject></saml:Assertion>
    </samlp:Response>"""

    void_c14n_xml = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ns="1" ID="resp1">
      <saml:Assertion ID="evil"><saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject></saml:Assertion>
      <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#evil"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo></ds:Signature>
    </samlp:Response>"""

    for sample in (xsw1_xml, void_c14n_xml):
        try:
            preflight_saml_guards(parse_safe_saml_xml(sample))
        except ValueError:
            pass
        else:
            raise AssertionError("SAML attack sample bypassed preflight")

    valid_xml = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp1">
      <saml:Assertion ID="legit1">
        <saml:Subject>
          <saml:NameID>alice@example.com</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://sp.example.com/acs" InResponseTo="req-42"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>
      </saml:Assertion>
      <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#legit1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo></ds:Signature>
    </samlp:Response>"""

    cache: set[str] = set()
    assertion = preflight_saml_guards(parse_safe_saml_xml(valid_xml))
    assert validate_assertion_conditions(assertion, "https://sp.example.com", "https://sp.example.com/acs", "req-42", cache) == "alice@example.com"
    try:
        validate_assertion_conditions(assertion, "https://sp.example.com", "https://sp.example.com/acs", "req-42", cache)
    except PermissionError:
        pass
    else:
        raise AssertionError("replayed Assertion ID was not blocked")

    print("PASS: all SAML hardening checks passed")


if __name__ == "__main__":
    run_saml_hardening_checks()
```

判定标准：
1. **单断言与单解析器**：提交含两个 `<Assertion>` 或注释节点、重复 `ID`、`Id`/`id` 混用的 SAMLResponse 时直接拒绝。
2. **相对命名空间零放行**：含 `xmlns:ns="1"` 等非绝对 URI 命名空间在 c14n 之前被预检拦截。
3. **重放与跨站阻断**：同一 `Assertion ID` 第二次提交返回拒绝，变更 `Recipient`、`Audience` 或移除 `InResponseTo` 均失败。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `SAML`、`XSW`、`canonicalization` 检索对应防御规程 |
| 规程读取 | `kb_read_file` | 读取 `saml-attacks-defense` 与 `oauth-sso-defense` |
| 知识目录核查 | `kb_catalog` | 列出 `02-auth` 板块内所有身份协议加固文档 |
