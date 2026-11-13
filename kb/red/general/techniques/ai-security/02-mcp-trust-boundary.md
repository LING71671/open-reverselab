---
id: "general/ai-security/02-mcp-trust-boundary"
title: "MCP 信任边界：工具身份、授权与结果链"
title_en: "MCP Trust Boundaries: Tool Identity, Authorization, and Result Chains"
summary: >
  分析 MCP 工具目录、描述、参数、结果、HTTP 身份与下游凭据之间的信任边界，覆盖工具更新、同名服务、审批参数变化、audience 混淆、会话复用与元数据发现，并提供离线授权差分试件。
summary_en: >
  Analyze MCP catalog, description, argument, result, transport identity, and downstream credential boundaries. Covers catalog changes, name collisions, approval drift, audience confusion, session reuse, and discovery with an offline authorization matrix.
board: "general"
category: "ai-security"
signals: ["MCP", "tools/list", "tools/call", "tool poisoning", "token passthrough", "Mcp-Session-Id", "audience", "工具投毒"]
mcp_tools: ["kb_router", "kb_read_file"]
keywords: ["MCP信任边界", "tool poisoning", "工具授权", "confused deputy", "token passthrough", "工具描述", "资源指示符"]
difficulty: "advanced"
tags: ["ai-security", "mcp", "oauth", "authorization", "red-team"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["general/ai-security/02-mcp-trust-boundary-defense", "general/ai-security/01-indirect-prompt-injection", "general/ai-security/03-rag-authorization-poisoning", "ctf-website/02-auth/oauth-sso"]
track: "red"
---
# MCP 信任边界：工具身份、授权与结果链

## 1. 场景与协议基准

Agent 连接多个 MCP server，读取工具目录后选择工具，工具再访问文件、业务 API 或检索系统。检查对象包括客户端的工具选择和执行控制、server 的用户授权、下游 API 的权限映射。模型、客户端、MCP server 与下游服务各自拥有不同的信任边界。

本文协议事实固定参考 **2025-11-25** 版；目标协商到其他版本时，保存 `initialize` 结果并对照该版本。工具名在单个 server 内唯一，`tools/list` 支持分页；工具 annotations 来自非可信 server 时必须按不可信数据处理。这些属性由 [MCP Tools 规范](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) 定义。完整身份应在实验记录中写成 server 身份与工具名的组合。

HTTP 授权检查和 stdio 本地启动是两条路径。HTTP 授权规范要求 access token 面向目标 MCP server，客户端在授权及 token 请求中提供 `resource`；禁止把收到的 token 直接透传给下游 API。stdio 的凭据接入不按同一 HTTP OAuth 流程处理。参见 [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)。

## 2. 输入信号与边界地图

| 输入信号 | 控制方 | 需要核验的边界 |
|---|---|---|
| 描述、参数说明或结果声称“调用前必须读取另一文件” | server 或其数据源 | 内容能否增加工具权限 |
| 同名工具来自两个 server | 两个独立连接 | UI、缓存与执行路由是否保留 server 身份 |
| 目录更新后描述、schema 或目的地改变 | 可更新 server | 旧的信任决定是否被应用到新能力 |
| 工具 annotation 声称只读，但调用会写入 | server 元数据 | 执行权限是否依赖未经验证的提示字段 |
| HTTP token 只检查签名，不检查目标资源 | 授权服务与 MCP server | 服务 A 的凭据是否能用于服务 B |
| 请求只有 `Mcp-Session-Id` 或跨用户复用它 | 客户端/代理 | session 是否错误地替代身份检查 |
| 发现元数据包含可变 URL 或重定向 | 远端 server | 自动请求的网络目的地是否受约束 |
| 本地 server 的启动命令、工作目录、环境可被项目修改 | 本地配置/包 | 一次连接是否导致额外进程或凭据暴露 |

## 3. 工作流与并行分支

```text
记录 initialize 协商版本 / transport / server 实例
  → 完整读取工具目录（包含分页）与资源来源
  → 记录任务授权、工具选择、最终参数、执行结果
    ├─ 描述或结果引导调用 → 间接提示注入
    ├─ 名称相同、server 不同 → 工具身份混淆
    ├─ 审批后参数或目录变化 → 授权与执行脱节
    ├─ HTTP 凭据跨资源可用 → audience / 代理授权
    ├─ session 跨用户可用 → 身份与会话绑定
    └─ discovery / 本地启动越界 → 网络或进程边界
```

一次只替换一个维度。正常工具调用必须先成功；随后换 server、参数、工具版本、主体或 audience，并保持其他状态不变。每个负例都有正常对照，避免把 schema 错误、过期凭据或初始化失败误作授权控制。

### 3.1 工具选择与审批绑定

在合成 server 中暴露 `canary.record`，它只向实验内存记录标记。将注入放在工具描述、schema 字段描述、工具结果三处，分别测试。记录模型选择工具前实际看到的目录版本。

对同一工具准备两版目录，第二版改变一个参数的语义或目标位置。正常完成目录刷新后，观察客户端是否重新建立相应信任决定。目录改变本身是协议能力；问题发生在旧批准被用于不同 server、不同参数或不同操作时。

审批界面展示什么、执行器收到什么、server 实际做什么，需要用同一个 `call_id` 对齐。审批了对象 A，却向对象 B 执行动作，才是该分支的具体越界证据。若产品按策略自动授权，则比较策略允许的操作集合与实际操作，无须假设每次调用都有弹窗。

### 3.2 HTTP 授权、代理与会话

准备同一实验授权服务签发的两组有效凭据，分别面向 MCP-A 与 MCP-B；不在日志里输出 token 正文。先确认各自在自身服务成功，再交叉使用。若 token 不透明，应从授权服务的验证或 introspection 结果取得 audience 证据，不能假设所有 token 都是 JWT。

分别测试“用户 A 的有效凭据 + A 会话”“用户 B 的有效凭据 + A 会话”“无凭据 + A 会话”。记录每个请求的验证主体、server 绑定主体和数据归属。HTTP 授权不能只在初次建立逻辑会话时检查；规范要求每个客户端 HTTP 请求携带授权信息，参见前述 Authorization 规范。

代理模式还需核验 MCP client 的同意记录与下游 OAuth client 身份。静态下游 client ID、动态注册、已存在的同意 cookie，以及缺失逐 client 同意控制共同形成 confused deputy 风险；仅观察到其中一项时保留为条件缺口。[官方安全实践](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) 描述了这些前置条件及 token passthrough 风险。

### 3.3 网络与本地启动

对于 Streamable HTTP，分别记录合法 Origin、非法 Origin、无 Origin 的结果。规范要求校验 Origin，存在且非法时返回 403；绑定 localhost 是本地服务的建议。无 Origin 的本地客户端请求与浏览器跨源请求应分开分析。[MCP Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

元数据发现实验使用本地模拟授权服务和固定 canary 端点，逐层记录 `resource_metadata`、授权服务元数据、重定向与最终请求目的地。stdio 则记录固定启动配置、实际可执行文件、参数、环境变量名称和子进程；不要把 HTTP Origin 测试结果套到 stdio。

### 3.4 直接连接实验 HTTP MCP server

从客户端的连接配置取得 MCP endpoint，从已完成的实验 OAuth 登录取得面向该 server 的 access token。不要把业务 API 的 token 随手替换成 MCP token。记录 endpoint 对应的 server 实例、授权主体和协议版本，随后设置 `LAB_MCP_URL`、`LAB_MCP_AUTH`（完整 Authorization 值）及可选的 `LAB_MCP_ORIGIN`。

下面保存为 `mcp_http_capture.py`，执行 initialize、initialized notification、目录分页或一次 tools/call，并保存每条请求与响应。它面向普通 Streamable HTTP 调用，不提供 OAuth 登录、sampling、elicitation 或 task 轮询；遇到这些交互时，使用目标已有 MCP 客户端并导出同样的消息记录。

```python
import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decode_messages(raw, content_type):
    if not raw:
        return []
    text = raw.decode("utf-8")
    if "text/event-stream" not in content_type:
        return [json.loads(text)]
    events, lines = [], []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            lines.append(line[5:].lstrip(" "))
        elif not line and lines:
            events.append(json.loads("\n".join(lines)))
            lines = []
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--tool")
    ap.add_argument("--arguments", help="JSON file for an observed tool schema")
    args = ap.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(NoRedirect)
    state = {"session": "", "version": "", "sequence": 0}

    def post(message, label):
        state["sequence"] += 1
        prefix = output / f"{state['sequence']:02d}-{label}"
        payload = json.dumps(message).encode()
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        for env, key in (("LAB_MCP_AUTH", "Authorization"), ("LAB_MCP_ORIGIN", "Origin")):
            if os.environ.get(env):
                headers[key] = os.environ[env]
        if state["session"]:
            headers["Mcp-Session-Id"] = state["session"]
        if state["version"]:
            headers["MCP-Protocol-Version"] = state["version"]
        request = urllib.request.Request(os.environ["LAB_MCP_URL"], data=payload,
                                         headers=headers, method="POST")
        try:
            response = opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")
            if response.headers.get("Mcp-Session-Id"):
                state["session"] = response.headers["Mcp-Session-Id"]
            prefix.with_suffix(".request.json").write_bytes(payload)
            prefix.with_suffix(".response.bin").write_bytes(raw)
            prefix.with_suffix(".meta.json").write_text(json.dumps({
                "status": response.status, "content_type": content_type,
                "session_present": bool(state["session"])}), encoding="utf-8")
            if response.status >= 300:
                raise RuntimeError(f"{label}: HTTP {response.status}; see captured response")
        messages = decode_messages(raw, content_type)
        if "id" not in message:
            return None
        matches = [m for m in messages if m.get("id") == message["id"]
                   and ("result" in m or "error" in m)]
        if len(matches) != 1 or "error" in matches[0]:
            raise RuntimeError(f"{label}: expected one JSON-RPC result; inspect messages")
        return matches[0]["result"]

    init = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "reverselab-capture", "version": "1.0"}}}, "initialize")
    state["version"] = init["protocolVersion"]
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, "initialized")
    (output / "session.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    if args.tool:
        arguments = json.loads(Path(args.arguments).read_text(encoding="utf-8")) if args.arguments else {}
        result = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": args.tool, "arguments": arguments}}, "call")
    else:
        catalog, cursor, seen = [], None, set()
        while True:
            params = {"cursor": cursor} if cursor else {}
            page = post({"jsonrpc": "2.0", "id": state["sequence"] + 1,
                         "method": "tools/list", "params": params}, "list")
            catalog.extend(page["tools"])
            cursor = page.get("nextCursor")
            if not cursor:
                break
            if cursor in seen:
                raise RuntimeError("repeated pagination cursor")
            seen.add(cursor)
        result = {"tools": catalog}
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"protocol_version": state["version"], "output": str(output)}))


if __name__ == "__main__":
    main()
```

```powershell
python mcp_http_capture.py --output exports/general/demo-mcp/catalog-a
# 根据 catalog-a/result.json 中真实存在的工具名/schema 创建 arguments.json。
python mcp_http_capture.py --tool $observedToolName --arguments arguments.json --output exports/general/demo-mcp/call-a
```

不要把文中的 `canary.record` 假定为远端已安装工具。真实写操作用实验 server 提供的 canary 或产品专用测试对象；先读取目录确认名字、输入 schema 与副作用。server 若返回其他协议版本，记录实际值并确认客户端流程兼容后继续；不以脚本请求的版本冒充协商结果。

将 A/B 身份、正常/错误 audience、正常/变化后的工具参数分别放到独立 output 目录。比较请求正文、JSON-RPC `error`、工具 `isError` 和业务状态。HTTP 401 需先恢复该身份的正常调用对照；目录缺少工具时检查 server 能力与分页，不开始猜测调用名。`session.json` 含实验 session ID，只保存于本地案件目录。

## 4. 离线授权差分试件

保存为 `mcp_boundary_matrix.py`，运行 `python mcp_boundary_matrix.py`。此脚本使用已经验证过身份的**合成记录**，演示将批准绑定到用户、server、目录版本、工具和精确参数后的差分结果；它不执行 OAuth 验签、不启动 MCP server，也不是生产授权库。

```python
from copy import deepcopy
import hashlib
import json


def argument_hash(arguments):
    # 本试件只使用无浮点数的简单 JSON，不作为跨语言规范化算法。
    raw = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def decision(call, grant):
    checks = {
        "principal": call["verified_subject"] == grant["subject"],
        "audience": call["verified_audience"] == grant["server"],
        "server": call["server"] == grant["server"],
        "tool": call["tool"] == grant["tool"],
        "catalog": call["catalog_revision"] == grant["catalog_revision"],
        "arguments": argument_hash(call["arguments"]) == grant["arguments_hash"],
    }
    failed = [name for name, ok in checks.items() if not ok]
    return {"allow": not failed, "failed": failed}


def main():
    server = "https://mcp.example.test/lab"
    args = {"marker": "SYNTHETIC_MCP_CANARY", "object": "demo-a"}
    grant = {"subject": "user-a", "server": server, "tool": "canary.record",
             "catalog_revision": "r1", "arguments_hash": argument_hash(args)}
    baseline = {"verified_subject": "user-a", "verified_audience": server,
                "server": server, "tool": "canary.record",
                "catalog_revision": "r1", "arguments": args}
    cases = [("baseline", baseline, True)]
    replacements = {
        "subject": {"verified_subject": "user-b"},
        "audience": {"verified_audience": "https://api.example.test/other"},
        "server": {"server": "https://other.example.test/lab"},
        "catalog": {"catalog_revision": "r2"},
        "arguments": {"arguments": {**args, "object": "demo-b"}},
    }
    for name, patch in replacements.items():
        changed = deepcopy(baseline)
        changed.update(patch)
        cases.append((name, changed, False))
    output = []
    effects = []
    for name, call, expected in cases:
        result = decision(call, grant)
        assert result["allow"] == expected, name
        if result["allow"]:
            effects.append(call["arguments"]["object"])
        output.append({"case": name, **result})
    assert effects == ["demo-a"]
    print(json.dumps({"kind": "offline-model", "decisions": output,
                      "effects": effects}, indent=2))


if __name__ == "__main__":
    main()
```

对实际目标复用这些变量，而不是把脚本的判定当成目标结果。若目标允许某些参数范围，应把允许集合明确写入实验前提；精确参数绑定只是本合成试件的策略。目录指纹只能检测变化，不能证明 server 实现与描述一致。

## 5. 证据、判定与失败分支

| 结果 | 证据要求 | 继续方向 |
|---|---|---|
| 只出现异常工具建议 | 原始描述/结果与模型调用记录 | 选择层注入，转间接提示注入篇 |
| 错误 server 收到同名工具调用 | 连接身份、路由记录、server 接收日志 | 检查名称缓存和显示层 |
| 参数改变后仍沿用旧批准 | 批准对象、最终参数、调用关联 ID | 定位批准与执行之间的变化点 |
| 跨 audience 凭据被接受 | 有效 token 元数据、验证日志、资源返回 | 定位 audience 校验或代理映射 |
| session 被拒绝 | 主体和会话绑定日志、正常对照 | 记录该分支阻断，不推断其他权限正确 |
| HTTP 200 但 JSON-RPC 错误或 `isError` | 完整响应类型与工具业务状态 | 按协议错误、工具错误、业务拒绝分层 |
| 工具返回成功但无副作用记录 | 调用 ID 与接收端状态 | 标为执行结果待确认 |

输出目录使用 `exports/general/<case>/mcp-boundary/`，保存协议版本、工具目录、server 标识、参数差分、身份验证结果摘要、授权决定、响应和 canary 事件。

## 6. MCP 工具映射

| 步骤 | 工具 | 能力边界 |
|---|---|---|
| 路由 MCP 信号 | `kb_router(query="MCP token passthrough", board="general", track="red")` | 检索技术文档 |
| 读取 OAuth 或关联篇 | `kb_read_file` | 按指定 board 和相对技术路径读取 |
| 检验目录、调用与授权 | 目标 MCP 客户端/SDK 的测试入口 | 必须完成目标协议的初始化、分页及响应处理；通用 GET 探测不能替代该流程 |
| 本篇离线试件 | 本地 Python | 只验证合成策略矩阵，没有对真实 MCP 服务作出结论 |

蓝队关联：[MCP 信任边界防御](../../../../blue/general/techniques/ai-security/02-mcp-trust-boundary-defense.md)。
