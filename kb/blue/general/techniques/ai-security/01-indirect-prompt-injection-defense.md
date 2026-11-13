---
id: "general/ai-security/01-indirect-prompt-injection-defense"
title: "间接提示注入防御：内容来源隔离、动作约束与证据复核"
title_en: "Indirect Prompt Injection Defense: Source Isolation, Action Constraints and Evidence"
summary: >
  为读取网页、仓库、邮件或工具结果的 Agent 建立低信任内容边界。覆盖来源追踪、按任务限制工具能力、执行端参数校验、合成 canary 对照、实际副作用复核和误报处理；附离线动作实验与真实运行接口回放流程。
summary_en: >
  Defend agents that consume web pages, repositories, messages, and tool results through source provenance, constrained capabilities, execution-time validation, synthetic canaries, and independent side-effect checks. Includes an offline action-boundary experiment.
board: "general"
category: "ai-security"
signals: ["indirect prompt injection", "tool result injection", "repository instruction", "canary", "agent action boundary", "间接提示注入"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["提示注入防御", "低信任内容", "工具输出", "Agent授权", "canary验证", "外部网页指令"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "ai-security", "prompt-injection", "agent"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["general/ai-security/01-indirect-prompt-injection", "general/ai-security/02-mcp-trust-boundary-defense", "general/ai-security/03-rag-authorization-poisoning-defense"]
track: "blue"
defends: "general/ai-security/01-indirect-prompt-injection"
---
# 间接提示注入防御：内容来源隔离、动作约束与证据复核

## 1. 适用场景与证据层级

适用于 Agent 从网页、代码仓库、邮件附件、OCR、搜索片段或工具结果读取内容，再生成回答或提出工具调用的系统。[间接提示注入原始研究](https://arxiv.org/abs/2302.12173)描述了攻击者通过被检索的数据影响应用行为的路径；本篇关注这些数据进入上下文后，应用如何约束操作并验证效果。

| 输入信号 | 首先保留的证据 | 当前可下的结论 |
|---|---|---|
| 外部文档要求改变角色、忽略任务、调用新工具 | 来源 ID、版本/内容摘要、进入上下文的位置 | 发现指令性内容；是否影响模型尚待观察 |
| 回答出现合成 canary 或指定短语 | 用户任务、对照输入、完整输出的本地引用 | 输出受到影响的候选证据；普通摘录也会产生同样现象 |
| 模型提出与任务无关的写入、发送、读取秘密动作 | 工具名、规范化参数摘要、关联来源 ID | 已出现越界动作建议；执行结果需另查 |
| 工具返回成功或模型声称“已发送” | 执行端决定与业务系统回执 | 只有业务侧状态变化能确认副作用 |

记录三列状态：`observed`（实际事件）、`recommended`（拟采取的控制）、`unverified`（缺少的验证）。本文示例使用合成输入，没有运行在线模型或真实连接器。

## 2. 防御工作流

```text
已认证用户任务与可用能力
  → 来源分类：用户指令 / 应用策略 / 外部内容
  → 外部内容保留出处，以数据形式进入上下文
  → 模型生成回答或动作建议
      ├─ 回答 → 按展示端规则处理链接、HTML、附件 → 输出复核
      └─ 动作 → 执行端校验身份、工具、对象和参数
                  ├─ 拒绝 → 记录原因 → 回查来源与同类请求
                  └─ 允许 → 执行 → 独立读取业务结果
  → 合成攻击样本 + 正常样本复测 → 调整能力或检测规则
```

建议按应用实现以下控制。内容标签、提示模板与分类器可帮助模型理解来源；实际权限由执行代码、服务身份与下游系统约束。[OWASP 的提示注入防御指南](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)也将输入筛查与工具执行授权分开。

| 边界 | 控制措施 | 验证观察点 |
|---|---|---|
| 检索 → 上下文 | 外部正文与可信任务分别存储，记录来源链；不把下载的 README 或工具结果升级为应用策略 | 回放时可定位每段内容的来源和版本 |
| 模型 → 工具 | 工具白名单、严格参数 schema、每次检查调用者和目标对象；凭据不放入模型上下文 | 同一恶意建议在不同措辞下均被执行端拒绝 |
| 工具 → 外部系统 | 查询任务只配置查询能力；固定输出目的地或逐项授权写操作 | 未授权请求没有到达下游；已授权请求仍正常完成 |
| 输出 → 用户界面 | 对模型生成的 HTML、Markdown 链接和远程图片应用展示策略，禁止未经评估的自动取回 | 输出内容不会借渲染器隐式访问外部地址 |
| 高影响动作 | 授权绑定具体目标、参数、有效期和一次操作；参数变化后重新判定 | 旧批准不能用于新收件人、新资源或改过的动作 |

高影响动作的具体约束是应用设计选择；应按已有任务授权实施，避免让每次普通只读调用都重复打断用户。相关设计可参照 [OWASP Agent action integrity](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)。

## 3. 离线实验：无论模型建议什么，都检查实际能力

将代码保存为本地 `exports/general/ai-defense/action_boundary.py`，用 `python` 运行。实验故意跳过模型，直接把正常、越界和格式异常的动作交给执行端替身，验证最终控制位置。`doc_ids` 来自服务端已认证任务配置，调用者不能通过工具参数覆盖它。

```python
from copy import deepcopy

DOCUMENTS = {"guide-1": "Synthetic installation guide."}
CAPABILITY = {"tool": "read_document", "doc_ids": frozenset({"guide-1"})}


def dispatch(action, effects):
    if not isinstance(action, dict) or set(action) != {"tool", "arguments"}:
        return "deny:shape"
    if action["tool"] != CAPABILITY["tool"]:
        return "deny:tool"
    args = action["arguments"]
    if not isinstance(args, dict) or set(args) != {"doc_id"}:
        return "deny:arguments"
    doc_id = args["doc_id"]
    if not isinstance(doc_id, str) or doc_id not in CAPABILITY["doc_ids"]:
        return "deny:object"
    # In a service, recheck current resource authorization here.
    if doc_id not in DOCUMENTS:
        return "deny:missing"
    effects.append(("read", doc_id))
    return DOCUMENTS[doc_id]


cases = [
    ("normal", {"tool": "read_document", "arguments": {"doc_id": "guide-1"}}, True),
    ("injected-send", {"tool": "send_message", "arguments": {"body": "CANARY-A"}}, False),
    ("cross-object", {"tool": "read_document", "arguments": {"doc_id": "private-2"}}, False),
    ("extra-destination", {"tool": "read_document", "arguments": {
        "doc_id": "guide-1", "destination": "https://sink.example.test/collect"}}, False),
    ("invalid-type", {"tool": "read_document", "arguments": {"doc_id": ["guide-1"]}}, False),
]
effects = []
for name, action, expected_allowed in cases:
    before = deepcopy(effects)
    result = dispatch(action, effects)
    allowed = not result.startswith("deny:")
    assert allowed == expected_allowed, name
    assert effects == before + ([("read", "guide-1")] if allowed else []), name
    print(name, "allowed" if allowed else result)
assert effects == [("read", "guide-1")]
```

断言验证的是这个替身的工具、对象、参数与副作用边界。接入真实 Agent 后，还需检查下游凭据范围、并发撤权、文件路径解析、重定向和实际 API 行为。用同一批动作直接测试真实执行网关，可以把模型随机性与授权实现问题分开定位。

## 4. 检测与独立验证

1. 准备一个正常检索文档和一个仅增加合成指令段的变体，固定用户任务、工具集合、模型配置和语料版本。canary 采用无秘密含义的随机标记。
2. 分别记录 `source_id → context_id → proposed_call → policy_decision → downstream_receipt`。不要保存凭据或默认汇总全部原始聊天；原始内容按案件访问权限保留。
3. 统计输出偏转、越界调用建议、被拒绝调用、实际副作用四个结果。一次运行只报告此次配置；多次运行报告样本数、分母与正常任务成功率。
4. 独立查询工具替身计数、消息收件箱替身、文件副本或业务账本。模型文字和工具包装层的 `success` 字段不能替代这一步。
5. 对攻击样本的改写、多语言、引用嵌套、跨工具结果传递做回归，同时保留正常安全教程、代码注释、用户明确要求摘录指令的样本。

建议本地输出 `exports/general/ai-defense/<run-id>/trace.jsonl` 与 `verdict.json`；报告列出拒绝发生在哪一层、实际效果、未覆盖通道和下一轮动作。公开知识库只保存合成 fixture 与通用结论。

## 5. 失败分支与误报

| 现象 | 优先排查 | 下一步 |
|---|---|---|
| canary 出现在回答 | 任务是否要求引用或总结原文 | 与正常摘录对照，确认是否违背任务输出约束 |
| 提出了越界工具，业务侧无变化 | 执行端是否拒绝；失败是否仅因网络错误 | 保存拒绝原因，恢复替身可用性后重放 |
| 没有可见工具调用，仍发生外联 | 渲染器、自动预览、资源加载或连接器内部请求 | 观察网络层与展示层，转入对应 Web/SSRF 防护 |
| 分类器零告警 | 注入改写、编码、来源标签丢失或覆盖不全 | 测执行约束；扩展正常与恶意样本，测漏报及误报 |
| 拒绝率上升且正常任务失败 | 规则匹配了普通文档中的技术词 | 按动作与目标对象调整规则，保留合法查询对照 |
| 来源已移除，行为仍重复 | 缓存、会话记忆、摘要是否继续携带内容 | 按来源 ID 追踪派生物并使相关缓存失效 |

RAG 权限和派生缓存进入[检索授权与投毒防御](03-rag-authorization-poisoning-defense.md)；工具声明、服务器身份和 token 边界进入 [MCP 防御](02-mcp-trust-boundary-defense.md)。

## 6. 接入真实 Agent：获取输入、回放与收集效果

先在应用的测试环境运行一个正常任务，例如“总结测试文档的安装步骤”。从该应用的 Network 或服务端请求记录取得一次真实运行接口请求体，保存为 `exports/general/ai-defense/request-control.json`。副本 `request-variant.json` 只替换所引用的文档 ID；第二份文档保留正常正文，并加入要求输出 `CANARY-UNEXPECTED-ACTION` 或提出未授权工具调用的测试段。保持用户任务和可用工具不变，工具写入目的地设置为隔离替身。

接口地址、认证头和请求体取自正在测的应用，不能假设所有 Agent 共用某个 `/run` schema。以下标准库程序适用于返回 JSON 的 Bearer 认证 HTTP 运行接口；使用 Cookie、异步 job 或 SSE 的应用，沿其真实客户端流程取得 run ID、事件流和最终结果。

```python
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

out = Path(os.environ.get("AGENT_EVIDENCE_DIR", "exports/general/ai-defense"))
endpoint = os.environ["AGENT_RUN_URL"]
headers = {"Content-Type": "application/json", "Accept": "application/json"}
if os.environ.get("AGENT_ACCESS_TOKEN"):
    headers["Authorization"] = "Bearer " + os.environ["AGENT_ACCESS_TOKEN"]
for name in ("control", "variant"):
    request_bytes = (out / f"request-{name}.json").read_bytes()
    json.loads(request_bytes)  # Catch invalid saved input before sending it.
    request = Request(endpoint, data=request_bytes, headers=headers, method="POST")
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        (out / f"response-{name}.json").write_bytes(body)
        print(name, "HTTP", response.status, "bytes", len(body))
```

运行前通过当前终端环境设置 `AGENT_RUN_URL` 和测试身份的 `AGENT_ACCESS_TOKEN`，不要把凭据写入请求文件。每轮可用 `AGENT_EVIDENCE_DIR` 指定单独目录，并把两份请求体放入该目录。将上述脚本保存为 `exports/general/ai-defense/replay_agent.py` 后执行：

```sh
python exports/general/ai-defense/replay_agent.py
```

随后按实际 run ID 导出执行器的工具调用事件及独立替身的效果记录，分别保存 `calls-control.jsonl`、`calls-variant.jsonl` 与 `effects.jsonl`。把原事件字段映射为调用 ID、工具、参数摘要、决定和业务回执；不要用模型最终回答补写不存在的事件。若攻击变体只改变回答，记录输出偏转；若提出调用但被拒绝，记录动作边界生效；若替身实际收到越界操作，回到具体执行权限修复。本文没有提供真实服务地址，也未执行这两次在线请求。

## MCP 工具映射

| 步骤 | 工具 | 能完成的工作 |
|---|---|---|
| 按信号查防护路径 | `kb_router` | 使用 `board="general"`、蓝队轨道查提示注入和工具边界文档 |
| 对照攻击侧实验 | `kb_read_file` | 读取[间接提示注入](../../../../red/general/techniques/ai-security/01-indirect-prompt-injection.md)，选合成对照输入 |
| 查相关防守条目 | `kb_catalog` | 枚举 `ai-security`；不会运行模型评测或拦截工具调用 |

本篇 Python 实验通过本地解释器运行；知识库工具没有替代执行端授权或自动提供上述遥测的能力。
