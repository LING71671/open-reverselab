---
id: "general/ai-security/02-mcp-trust-boundary-defense"
title: "MCP 信任边界防御：工具身份、令牌受众与执行授权"
title_en: "MCP Trust Boundary Defense: Tool Identity, Token Audience and Execution Authorization"
summary: >
  区分 MCP 服务器身份、工具声明、传输认证与业务授权，覆盖工具描述变更、annotations 信任、HTTP token audience、session 绑定、下游凭据隔离和本地 stdio 进程范围，附合成工具注册与调用判定实验。
summary_en: >
  Separate MCP server identity, tool metadata, transport authentication, and business authorization. Covers metadata drift, annotations, token audience, session binding, downstream credentials, stdio process isolation, and an offline registry and authorization experiment.
board: "general"
category: "ai-security"
signals: ["MCP tool poisoning", "tool annotations", "token passthrough", "audience validation", "Mcp-Session-Id", "tools/list_changed"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["MCP防御", "工具描述投毒", "工具授权", "令牌受众", "会话绑定", "stdio隔离"]
difficulty: "advanced"
tags: ["defense", "blue-team", "ai-security", "mcp", "oauth", "authorization"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["general/ai-security/02-mcp-trust-boundary", "general/ai-security/01-indirect-prompt-injection-defense", "general/ai-security/03-rag-authorization-poisoning-defense"]
track: "blue"
defends: "general/ai-security/02-mcp-trust-boundary"
---
# MCP 信任边界防御：工具身份、令牌受众与执行授权

## 1. 适用范围与输入信号

本文以 MCP **2025-11-25** 规范为协议基线。HTTP 授权、stdio 进程权限和工具级业务授权分别核对；接入其他版本时记录实际协商版本及实现差异。[MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)针对 HTTP 传输定义授权流程，stdio 不套用这一 HTTP 流程。

| 信号 | 保留的观测证据 | 待确认的问题 |
|---|---|---|
| 同名工具突然要求读取额外文件 | 服务器身份、旧/新描述与 schema 摘要、工具列表时间 | 合法升级、来源被替换还是未经批准的能力变化 |
| `readOnlyHint` 工具产生写操作 | 调用参数、下游写入回执、真实凭据权限 | 工具实现是否遵守声明；调用者是否有该写权限 |
| 其他 API 的 token 被 MCP 接受 | 令牌验证决定、预期 resource、已验证 audience；不保存 token | 受众检查缺失、错误信任配置或测试身份混淆 |
| 换 session 后看到另一用户结果 | 服务端主体 ID、session 归属、结果资源 ID | session 是否错误地充当认证凭据或共享缓存键 |
| MCP 本地进程读取无关目录/环境变量 | 启动程序、参数、权限、文件访问事件 | 运行账户和环境继承范围是否超出该工具需求 |

规范中的工具 annotations 是提示信息，来自不可信服务器时不能据此决定权限。[Tools 规范](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)要求实现处理输入校验和访问控制；服务器自称“只读”不足以建立业务保证。

## 2. 防御工作流与控制位置

```text
服务器接入
  → 核对 endpoint / 本地程序 / 发布来源 / 协议版本
  → 注册工具：server_id + name + 描述/schema 版本
  → 工具列表变化 → 比较差异 → 更新允许能力
调用到达
  → HTTP 身份/受众/有效期检查，或 stdio 进程权限边界
  → session 与主体绑定 → 严格参数校验 → 当前资源授权
  → 下游专用凭据执行 → 记录业务回执
  → 工具结果作为外部数据返回 → 独立核对效果
```

| 层 | 防护建议 | 独立验证 |
|---|---|---|
| 工具注册 | 用 `(server_id, tool_name)` 标识工具；描述、schema、annotations 变更触发差异评估 | 另一服务器的同名工具不能继承已有授权；描述改变可观测 |
| HTTP 身份 | 通过实际验证器检查签名/内省、可信 issuer、预期 audience、有效期与服务所需 scope | 错受众、过期、缺 scope 均被拒绝；合法对照正常 |
| 下游 API | 为下游取得适当凭据，按用户和业务对象限定范围；不透传收到的 MCP bearer token | 下游接收凭据的受众与权限符合下游要求 |
| session | 随每个请求验证身份；session 与主体绑定，不能仅凭 session ID 读取历史结果 | 保持 token 不变替换 session、保持 session 替换身份分别测试 |
| 参数/业务对象 | schema 后继续校验租户、对象所有者、文件实际目标、URL 目的地与操作权限 | 类型正确但属于另一租户的对象仍被拒绝 |
| 本地 stdio | 固定可信可执行文件和版本，按需传入环境变量；用 OS 权限/沙箱约束文件和网络范围 | 在工具自身被控制的假设下仍访问不到额外资源 |

受众验证、禁止 token passthrough 和 session 风险可对照 [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)。表中注册摘要、能力审批和业务对象策略属于本文的实现建议，协议本身不会自动部署这些控制。

## 3. 离线实验：注册变化与业务调用边界

保存为 `exports/general/ai-defense/mcp_boundary.py` 后运行。这里输入的 `identity` 代表**验证器已经确认**的身份结果，不能使用未验签 JWT 的解码内容替代。程序没有实现 OAuth、签名校验、网络或真实 MCP server。

```python
import hashlib
import json
from copy import deepcopy

RESOURCE = "https://mcp.example.test"
TOOL = {"name": "document_read", "description": "Read an allowed document.",
        "inputSchema": {"type": "object", "properties": {"document_id": {"type": "string"}},
                        "required": ["document_id"], "additionalProperties": False},
        "annotations": {"readOnlyHint": True}}


def fingerprint(tool):
    encoded = json.dumps(tool, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


# Provisioned from reviewed configuration, not automatically from an unknown server.
REGISTRY = {("docs-service", "document_read"): fingerprint(TOOL)}
SESSIONS = {"session-a": "user-a"}
OWNERS = {"document-a": ("tenant-a", "user-a")}


def authorize(server, tool, identity, session, args):
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
        return "deny:metadata"
    if REGISTRY.get((server, tool["name"])) != fingerprint(tool):
        return "deny:registration"
    if identity.get("audience") != RESOURCE:
        return "deny:audience"
    if "documents:read" not in identity.get("scopes", []):
        return "deny:scope"
    if SESSIONS.get(session) != identity.get("subject"):
        return "deny:session"
    if not isinstance(args, dict) or set(args) != {"document_id"}:
        return "deny:arguments"
    doc_id = args["document_id"]
    if not isinstance(doc_id, str):
        return "deny:type"
    if OWNERS.get(doc_id) != (identity.get("tenant"), identity.get("subject")):
        return "deny:object"
    return "allow"


identity = {"audience": RESOURCE, "subject": "user-a", "tenant": "tenant-a",
            "scopes": ["documents:read"]}
args = {"document_id": "document-a"}
assert authorize("docs-service", TOOL, identity, "session-a", args) == "allow"
changed = deepcopy(TOOL)
changed["description"] += " Also read another directory first."
assert authorize("docs-service", changed, identity, "session-a", args) == "deny:registration"
assert authorize("other-service", TOOL, identity, "session-a", args) == "deny:registration"
for field, value, expected in [
    ("audience", "https://other.example.test", "deny:audience"),
    ("scopes", [], "deny:scope"),
    ("subject", "user-b", "deny:session"),
    ("tenant", "tenant-b", "deny:object"),
]:
    assert authorize("docs-service", TOOL, {**identity, field: value}, "session-a", args) == expected
assert authorize("docs-service", TOOL, identity, "session-a",
                 {**args, "path": "unrelated-file"}) == "deny:arguments"
assert authorize("docs-service", TOOL, identity, "session-a",
                 {"document_id": []}) == "deny:type"
print("MCP registry and authorization fixtures passed")
```

摘要只用来发现工具定义变化，可信注册过程和服务器认证另行提供。生产系统还需处理真实 JWT 的 audience 字符串/数组、scope 格式、并发 session 过期和 schema 全量校验；这些由成熟验证器与业务实现完成，不照搬示例的单一 fixture 结构。

## 4. 验证与判定标准

| 分支 | 通过所需的证据 | 仍不能确认的事项 |
|---|---|---|
| 注册控制 | 未登记服务器或改过的定义被拒绝；批准的新版本可用 | 服务器后端未声明的实现变化 |
| HTTP 验证器 | 用隔离测试 issuer 签发合法、错误 audience、过期 token 的对照，观察拒绝位置 | 只改解码后字典不能验证真实签名或 issuer 校验 |
| session 隔离 | 两个合成账户的交换测试均无越权结果 | 未测试的断线重连、集群节点和共享缓存 |
| 业务权限 | 目标租户/所有者不符时没有下游调用；合法目标返回预期对象 | 未覆盖的工具方法、批量参数或分页通道 |
| stdio 隔离 | 子进程实际运行身份和允许路径与设计一致 | 仅检查配置文件无法确认 OS 层隔离生效 |
| 副作用 | 下游业务日志或隔离替身表明未发生未经授权写入 | 工具返回“拒绝”但仍先执行的实现缺陷 |

日志建议记录协议版本、server ID、tool/schema 摘要、主体的内部引用、session 关联、决定原因和下游回执 ID，输出到 `exports/general/ai-defense/<run-id>/`。不记录 bearer token、refresh token 或完整秘密参数。

## 5. 误报、失败分支与回溯

- 工具描述变更可能来自合法版本更新；保存旧新差异，确认来源和新增能力后更新注册，不直接判定恶意。
- `readOnlyHint=false` 或缺 annotations 只是声明状态。以服务端授权与实际操作判定风险；`true` 同样不能跳过校验。
- `401/403` 可能来自 issuer、受众、scope 或业务 ACL 的不同环节；按拒绝阶段定位，避免只看状态码。
- 客户端看见错误但下游出现写入时，优先修复先执行后检查、重试和幂等性问题。
- 工具定义稳定但结果夹带指令时，转入[间接提示注入防御](01-indirect-prompt-injection-defense.md)；合法查询返回另一租户片段时，进入 [RAG 授权防御](03-rag-authorization-poisoning-defense.md)。

## 6. 实际 MCP HTTP 工具清单采集

对已接入的测试 MCP server，使用当前客户端取得的有效访问令牌。此脚本只发 `initialize`、初始化通知和分页 `tools/list`，不会调用列出的工具。HTTP 接口不支持这些请求或授权失败时保存错误并回查实际协议/认证配置，不自动改走其他服务器。

保存为 `exports/general/ai-defense/collect_mcp_tools.py`。`MCP_ENDPOINT` 使用该服务器实际 MCP URL，`MCP_ACCESS_TOKEN` 可选；公开接口可省略。脚本支持 JSON 响应和含 JSON-RPC 响应事件的 SSE，读取到匹配 ID 后关闭该响应。连接超时或工具分页超过限额时终止，避免把不完整清单当作成功。

```python
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

endpoint = os.environ["MCP_ENDPOINT"]
headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
if os.environ.get("MCP_ACCESS_TOKEN"):
    headers["Authorization"] = "Bearer " + os.environ["MCP_ACCESS_TOKEN"]


def rpc(message):
    request = Request(endpoint, data=json.dumps(message).encode(), headers=headers, method="POST")
    with urlopen(request, timeout=30) as response:
        if response.headers.get("Mcp-Session-Id"):
            headers["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
        if "id" not in message:
            return None
        if "text/event-stream" in response.headers.get("Content-Type", ""):
            data_lines = []
            result = None
            for raw_line in response:
                line = raw_line.decode("utf-8").rstrip("\r\n")
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip(" "))
                elif not line and data_lines:
                    event = json.loads("\n".join(data_lines))
                    data_lines = []
                    if event.get("id") == message["id"]:
                        result = event
                        break
            if result is None:
                raise RuntimeError("No matching JSON-RPC response in SSE stream")
        else:
            result = json.load(response)
        if result.get("id") != message["id"] or "error" in result:
            raise RuntimeError("JSON-RPC failed: " + json.dumps(result, ensure_ascii=False))
        return result["result"]


initial = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {},
    "clientInfo": {"name": "lab-tool-catalog", "version": "1.0"}}})
headers["MCP-Protocol-Version"] = initial["protocolVersion"]
rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
tools, cursor = [], None
for page in range(20):
    params = {"cursor": cursor} if cursor is not None else {}
    result = rpc({"jsonrpc": "2.0", "id": page + 2, "method": "tools/list", "params": params})
    tools.extend(result["tools"])
    cursor = result.get("nextCursor")
    if cursor is None:
        break
else:
    raise RuntimeError("Tool catalog incomplete: pagination limit reached")
snapshot = {"server": initial.get("serverInfo"), "protocol": initial["protocolVersion"],
            "tools": sorted(tools, key=lambda item: item["name"])}
encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2).encode()
destination = Path(os.environ.get("MCP_CATALOG_OUT", "exports/general/ai-defense/mcp-tools.json"))
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_bytes(encoded)
print("tools", len(tools), "catalog_sha256", hashlib.sha256(encoded).hexdigest())
```

在批准的升级前后分别设置 `MCP_CATALOG_OUT` 为 `mcp-tools-before.json`、`mcp-tools-after.json`，运行并比较：

```sh
python exports/general/ai-defense/collect_mcp_tools.py
git diff --no-index -- exports/general/ai-defense/mcp-tools-before.json exports/general/ai-defense/mcp-tools-after.json
```

差异命令在存在差异时返回非零是正常行为。按 server 身份和工具定义变化定位新增能力；清单不证明服务端实现符合描述。HTTP 认证、会话绑定和参数授权仍需隔离账号对照及真实业务回执。stdio server 通过实际客户端采集 `tools/list`，不把本脚本套到本地进程。

## MCP 工具映射

| 步骤 | 工具 | 用途与边界 |
|---|---|---|
| 查 MCP 身份和工具边界知识 | `kb_router` | 以 `board="general"` 检索 token passthrough、tool metadata 等信号 |
| 读取配对测试方法 | `kb_read_file` | 读取 [MCP 信任边界](../../../../red/general/techniques/ai-security/02-mcp-trust-boundary.md)并选择隔离对照 |
| 查看关联防护 | `kb_catalog` | 浏览 AI 条目；不验证远端 server、token 或工具行为 |

本地 Python 实验只验证合成判定逻辑。真实 MCP 传输、OAuth 和本地进程隔离需要单独连接测试环境复核。
