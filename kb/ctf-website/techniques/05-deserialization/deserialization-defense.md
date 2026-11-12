---
id: "ctf-website/05-deserialization/deserialization-defense"
title: "多语言反序列化安全防御与类型约束"
title_en: "Polyglot Deserialization Hardening & Type Allowlisting"
summary: >
  针对 PHP unserialize、Python pickle、Java ObjectInputStream、Node node-serialize、.NET BinaryFormatter/ViewState 与多态 YAML/Jackson/Hessian 反序列化漏洞，提供数据格式替代（JSON/Protobuf）、严格白名单过滤器（ObjectInputFilter/RestrictedUnpickler/allowed_classes）、HMAC 完整性签名及危险依赖清理方案。
summary_en: >
  Defense against unsafe deserialization across PHP, Python pickle, Java ObjectInputStream, Node, .NET BinaryFormatter/ViewState, and polymorphic YAML/Jackson/Hessian. Covers switching to schema-driven formats (JSON/Protobuf), strict class allowlisting, HMAC envelope verification, and gadget library removal.
board: "ctf-website"
category: "05-deserialization"
signals: ["deserialization", "pickle", "ObjectInputStream", "PHP unserialize", "YAML", "ViewState", "反序列化防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["反序列化防御", "安全反序列化", "ObjectInputFilter", "RestrictedUnpickler", "allowed_classes", "safe_load", "HMAC签名", "blue-team"]
difficulty: "advanced"
tags: ["defense", "blue-team", "deserialization", "java", "python", "php", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/05-deserialization/deserialization", "ctf-website/03-injection/prototype-pollution-defense"]
track: "blue"
defends: "ctf-website/05-deserialization/deserialization"
---
# 多语言反序列化安全防御与类型约束

## 防御目标与威胁面

不安全反序列化的本质是**将不可信字节流直接映射为可执行代码对象图**。当数据通道（Cookie、JSON 字段、上传文件、消息队列、Session 存储）接受客户端可控序列化数据时，攻击者可利用魔术方法（`__destruct`/`__wakeup`/`__reduce__`/`readObject`）或公共依赖库中的 Gadget Chain 实现 RCE、SSRF 或文件写入。

重点高危格式特征：
- **Java 原生二进制**：`AC ED 00 05`（Base64 前缀 `rO0AB`）及 `Hessian`、`Kryo`、Jackson `enableDefaultTyping`。
- **PHP 对象序列化**：`O:<len>:"Class":...` 及借助 `phar://` 包装器隐式触发的元数据反序列化。
- **Python Pickle / PyYAML**：`gAS` / `\x80\x04` / `\x80\x05` 及未安全化的 `yaml.load(..., Loader=Loader)`。
- **Node / .NET**：`node-serialize` 的 `_$$ND_FUNC$$_`、`.NET BinaryFormatter` (`AAEAAAD`) 及缺少 MAC 校验或静态密钥的 `__VIEWSTATE`。

## 核心防御架构

| 语言/框架 | 根本替代方案 | 过渡期硬约束（不能立即替换时） |
|---|---|---|
| 跨语言通用 | 全面迁移至无多态代码执行能力的 `JSON` 或 `Protobuf`（强 Schema） | 对必须在客户端流转的不透明状态采用 **HMAC-SHA256 / AES-GCM 服务端签名验真**，先验签后解析 |
| Java | 禁用原生 `ObjectInputStream` 与 Jackson `enableDefaultTyping` | 启用 JEP 290 `ObjectInputFilter` 严格白名单（仅允许基本类型及明确 DTO，末尾 `;!*` 拒绝其余所有类） |
| PHP | 使用 `json_decode` 替代 `unserialize`；禁用 `phar://` 流包装 | 若必须反序列化，强制 `unserialize($data, ['allowed_classes' => false])` 并禁止用户路径触及文件操作函数 |
| Python | 改用 `json` 或 `yaml.safe_load` | 若必须读已有 pickle，继承 `pickle.Unpickler` 重写 `find_class` 仅放行极窄白名单，严禁 `builtins`/`os`/`subprocess` |
| .NET / Node | 废弃 `BinaryFormatter`（微软已标记永久不安全）与 `node-serialize`，迁移 `System.Text.Json` | ViewState 强制启用 `EnableViewStateMac=true`、`ViewStateEncryptionMode=Always` 并轮换高熵独立 `machineKey` |

## 加固代码与离线核查示例

以下 Python 示例展示了**安全外封 HMAC 验签 + 受限 `RestrictedUnpickler` 白名单 + 入口前置 Magic Bytes 阻断**的纵深防护及测试验证：

```python
import base64
import hashlib
import hmac
import io
import json
import pickle
from typing import Any, Set, Tuple

MAGIC_BLACKLIST = (
    b"\xac\xed\x00\x05",  # Java ObjectStream
    b"rO0AB",             # Java Base64
    b"_$$ND_FUNC$$_",     # node-serialize
    b"AAEAAAD",           # .NET BinaryFormatter
)


class RestrictedUnpickler(pickle.Unpickler):
    """仅允许极窄只读数据类，拒绝所有 builtins/os/subprocess/动态模块。"""

    ALLOWED: Set[Tuple[str, str]] = {
        ("collections", "OrderedDict"),
    }

    def find_class(self, module: str, name: str) -> Any:
        if (module, name) not in self.ALLOWED:
            raise pickle.UnpicklingError(f"Blocked unsafe class: {module}.{name}")
        return super().find_class(module, name)


def verify_and_load_json_envelope(token: str, secret: bytes) -> dict:
    """推荐模式：先恒定时间验签，再以纯 JSON 解析（零对象实例化）。"""
    if "." not in token:
        raise ValueError("malformed_envelope")
    b64_payload, sig_hex = token.rsplit(".", 1)
    raw = base64.urlsafe_b64decode(b64_payload + "=" * (-len(b64_payload) % 4))
    for magic in MAGIC_BLACKLIST:
        if raw.startswith(magic) or magic in raw[:64]:
            raise ValueError("forbidden_serialized_magic")
    expected_sig = hmac.new(secret, b64_payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig_hex):
        raise ValueError("invalid_signature")
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("unexpected_root_type")
    return obj


if __name__ == "__main__":
    secret = b"ephemeral-test-hmac-key-32bytes!"
    # 1. 构造含 __reduce__ 恶意载荷并验证 RestrictedUnpickler 拦截
    class Evil:
        def __reduce__(self):
            return (eval, ("1+1",))

    malicious_pickle = pickle.dumps(Evil())
    blocked = False
    try:
        RestrictedUnpickler(io.BytesIO(malicious_pickle)).load()
    except pickle.UnpicklingError:
        blocked = True
    assert blocked is True

    # 2. 验证合法签名 JSON 信封通过，篡改或含 Java magic 被拒
    payload = base64.urlsafe_b64encode(b'{"uid":42,"role":"user"}').decode()
    sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    assert verify_and_load_json_envelope(f"{payload}.{sig}", secret) == {"uid": 42, "role": "user"}

    bad_payload = base64.urlsafe_b64encode(b"\xac\xed\x00\x05sr\x00").decode()
    bad_sig = hmac.new(secret, bad_payload.encode(), hashlib.sha256).hexdigest()
    try:
        verify_and_load_json_envelope(f"{bad_payload}.{bad_sig}", secret)
        assert False
    except ValueError as e:
        assert str(e) == "forbidden_serialized_magic"
    print("Deserialization defense self-check passed.")
```

Java JEP 290 全局与局部反序列化过滤器参考配置（JVM 启动参数）：

```text
-Djdk.serialFilter=maxdepth=5;maxrefs=500;maxbytes=65536;java.lang.String;java.lang.Number;com.example.dto.*;!*
```

## 防御工作流

```text
1. 入口盘点：梳理所有接收 Cookie、文件、RPC 消息、缓存与表单字段中的序列化反解码调用点
2. 格式迁移：优先将 pickle/unserialize/ObjectInputStream/BinaryFormatter/yaml.load 替换为 JSON 或 Protobuf
3. 不可替接口加固：若受历史协议制约无法立即替换，先实施 HMAC-SHA256 服务端验签，再施加类白名单过滤器
4. 包装器与多态关闭：PHP 禁用 phar:// 及允许类实例化；Jackson 禁用 enableDefaultTyping()；Python 使用 yaml.safe_load
5. 依赖清理：移除类路径或运行环境中不必要的 Gadget 危险库（如老版本 CommonsCollections/Groovy）并升级框架补丁
```

## 验证与判定标准

- **静态危险调用清零**：代码库中不存在未配 `allowed_classes=false` 的 `unserialize`、未过滤的 `pickle.loads`、`yaml.load`（无 SafeLoader）或 `BinaryFormatter`。
- **恶意载荷零触发**：向接口提交 URLDNS/Pickle Marker/PHP 对象/`_$$ND_FUNC$$_` 负载时，必须在解析前或白名单过滤器层立即抛错拒绝，无任何外连 DNS/HTTP 回调或类实例化。
- **签名防篡改有效**：修改序列化信封任意 1 字节后验签失败直接返回 `400/403`，根本不会进入反序列化函数。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索反序列化防御指南 | `kb_router` | 搜索 `deserialization`、`ObjectInputFilter`、`safe_load`、`allowed_classes` |
| 对照格式指纹与入口变体 | `kb_read_file` | 读取 [deserialization.md](deserialization.md) 核查各类魔术字与入口点 |
| 关联原型链与服务端请求防御 | `kb_catalog` | 协同查阅 `prototype-pollution-defense` 与 `ssrf-defense` |
