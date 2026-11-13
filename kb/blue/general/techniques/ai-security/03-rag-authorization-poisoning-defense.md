---
id: "general/ai-security/03-rag-authorization-poisoning-defense"
title: "RAG 授权与投毒防御：文档权限、撤权缓存与来源追踪"
title_en: "RAG Authorization and Poisoning Defense: Document ACLs, Revocation and Provenance"
summary: >
  覆盖 RAG 入库身份、文档与 chunk 权限传播、向量/关键词/混合检索授权、重排与缓存的泄露边界、撤权和删除后的派生内容失效，以及知识投毒的来源复核。附双租户、撤权、隔离与缓存回归的离线合成实验。
summary_en: >
  Cover ingestion identity, document and chunk permissions, authorization across retrieval paths, reranker and cache boundaries, revocation, derivative invalidation, and poisoning provenance. Includes an offline two-tenant and cache regression experiment.
board: "general"
category: "ai-security"
signals: ["RAG authorization", "cross-tenant retrieval", "document ACL", "stale cache", "knowledge poisoning", "vector filter"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["RAG防御", "文档权限", "跨租户检索", "检索投毒", "撤权缓存", "来源追踪", "chunk ACL"]
difficulty: "advanced"
tags: ["defense", "blue-team", "ai-security", "rag", "authorization", "data-poisoning"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["general/ai-security/03-rag-authorization-poisoning", "general/ai-security/01-indirect-prompt-injection-defense", "general/ai-security/02-mcp-trust-boundary-defense"]
track: "blue"
defends: "general/ai-security/03-rag-authorization-poisoning"
---
# RAG 授权与投毒防御：文档权限、撤权缓存与来源追踪

## 1. 两类风险与证据入口

检索权限负责决定谁能看到哪些材料；来源复核负责判断被允许的材料是否可信。业务允许读取某份文档后，该文档仍可能包含错误知识或间接指令。[PoisonedRAG 原始论文](https://arxiv.org/abs/2402.07867)在其评估设置中展示了少量污染文档影响目标问题答案的可能性；具体成功率不能直接套到其他语料、模型和检索器。

| 观察信号 | 首轮取证 | 应进入的分支 |
|---|---|---|
| 用户 A 的上下文或引用出现 B 的私有 canary | 用户/租户、文档/chunk ID、检索分支、授权决定 | 文档权限或缓存隔离 |
| 源文档已撤权，旧回答或摘要仍可获取 | ACL 版本、撤权时间、索引/缓存/记忆版本 | 撤权传播与派生物失效 |
| 某新文档反复占据高排名并改变答案 | 上传主体、来源版本、内容摘要、排名、引用链 | 入库权限、知识投毒与来源复核 |
| 同一问题在向量与关键词入口权限不同 | 路由、过滤参数、候选集和返回 chunk | 检索路径授权不一致 |
| 回答正确但重排服务已收到私有片段 | 重排请求记录、外发对象范围 | 数据在生成前已越过允许边界 |

“出现敏感内容”“看见可疑新文档”“产生错误答案”分别记录。用实际检索/上下文证据确认权限问题，用独立可信资料和对照实验确认内容污染。

## 2. 防御工作流

```text
已认证上传者 → 入库授权 → 来源/版本/tenant/ACL → chunk 继承权限
  → 合格语料进入索引；未知来源进入隔离队列
查询身份 → 服务端构造授权约束
  → 向量 / 关键词 / 混合检索各分支执行相同边界
  → 授权材料才进入外部重排、模型、日志与回答缓存
  → 引用与派生摘要携带来源版本
撤权 / 删除 / 确认投毒
  → 更新源状态 → 索引和缓存失效 → 旧引用再次读取时复核
  → 双租户对照 + 正常召回回归 → 记录仍未覆盖的入口
```

### 2.1 文档与身份绑定

把 `tenant_id`、文档 ACL、来源版本、发布状态和 chunk 的父文档 ID 作为受控元数据。上传请求中的“我是哪个租户”“该文档是公开的”必须由入库服务按当前身份确认；模型和待索引正文不能修改这些字段。

安全过滤可用用户/组字段限制结果，但字符串过滤本身不完成身份认证。应用需要先认证用户，再从可信身份构造过滤条件；具体实现参照 [Azure AI Search security filter pattern](https://learn.microsoft.com/en-us/azure/search/search-security-trimming-for-azure-search)。

### 2.2 检索、重排与缓存

| 位置 | 防护措施 | 验证点 |
|---|---|---|
| 文档/chunk | 所有 chunk、附件、OCR、摘要继承父对象权限；缺少权限元数据时拒绝返回 | 不会因拆块或重建索引变成公开对象 |
| 查询分支 | 向量、关键词、混合、推荐、引用直读、导出均按当前身份授权 | 同一不可见文档在所有入口均不进入允许返回集合 |
| 排名与重排 | 授权在内容进入外部重排器/模型前完成，明确哪些服务可处理哪些租户数据 | 模型输入和重排请求均不含禁止对象 |
| 缓存/会话 | 键包含身份权限范围、语料/ACL 版本和生成配置；命中后重新核对来源当前权限 | 跨用户复用、撤权后重放和旧会话均被正确处理 |
| 入库内容 | 检查来源、发布者、差异和外部引用；对关键结论保留可核对的原文位置 | 合法入库权限不会自动变成事实可信度 |

向量检索过滤的执行阶段还影响召回。Azure 的 `postFilter` 在小 `k` 或高选择性过滤下可能漏掉合法结果；应测试召回量与权限边界两个维度。[官方 vector filters 文档](https://learn.microsoft.com/en-us/azure/search/vector-search-filters)说明了这一取舍。不要将召回减少直接判为越权，也不要为了召回回退到未授权检索。

## 3. 离线实验：双租户、撤权和缓存

保存为 `exports/general/ai-defense/rag_boundary.py`。这段标准库实验以固定排名代替向量服务，以合成身份代替身份提供者，检查资料进入上下文之前的授权和缓存重检；没有调用模型，也不测模型抗投毒效果。

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str


docs = {
    "a-1": {"tenant": "a", "readers": {"alice"}, "revision": 1,
            "status": "published", "text": "CANARY-TENANT-A"},
    "b-1": {"tenant": "b", "readers": {"bob"}, "revision": 1,
            "status": "published", "text": "CANARY-TENANT-B"},
    "a-review": {"tenant": "a", "readers": {"alice"}, "revision": 1,
                 "status": "quarantine", "text": "Synthetic unreviewed claim."},
}
cache = {}
acl_epoch = 1
corpus_version = 1


def permitted(principal, doc_id):
    doc = docs.get(doc_id)
    return bool(doc and doc["status"] == "published"
                and doc["tenant"] == principal.tenant
                and principal.subject in doc["readers"])


def context(principal, query, candidates):
    key = (principal.tenant, principal.subject, acl_epoch,
           corpus_version, "template-v1", query)
    if key in cache:
        saved = cache[key]
        if all(permitted(principal, doc_id) and docs[doc_id]["revision"] == revision
               for doc_id, revision in saved):
            return [docs[doc_id]["text"] for doc_id, _ in saved]
        del cache[key]
    # Preserve ranking, but only permitted IDs can reach the context builder.
    selected = [doc_id for doc_id in candidates if permitted(principal, doc_id)]
    cache[key] = [(doc_id, docs[doc_id]["revision"]) for doc_id in selected]
    return [docs[doc_id]["text"] for doc_id in selected]


alice, bob = Principal("alice", "a"), Principal("bob", "b")
ranking = ["b-1", "a-review", "a-1", "missing"]
assert context(alice, "guide", ranking) == ["CANARY-TENANT-A"]
assert context(bob, "guide", ranking) == ["CANARY-TENANT-B"]
# Simulate a missed invalidation event: current ACL still prevents stale cache use.
docs["a-1"]["readers"].clear()
assert context(alice, "guide", ranking) == []
acl_epoch += 1
docs["a-1"]["readers"].add("alice")
assert context(alice, "guide", ranking) == ["CANARY-TENANT-A"]
docs["a-1"]["revision"] += 1
docs["a-1"]["text"] = "Synthetic updated guide."
assert context(alice, "guide", ranking) == ["Synthetic updated guide."]
docs["a-1"]["status"] = "quarantine"
assert context(alice, "guide", ranking) == []
print("RAG tenant, revocation, revision and quarantine fixtures passed")
```

在真实系统中，ACL 更新、缓存读取和生成执行可能并发，需要明确撤权生效语义并测试竞态。示例将状态放在单进程字典，无法验证分布式一致性；它也没有判断已发布文档中的事实真伪。组成员变更、公开文档例外、跨租户共享必须作为显式策略扩展并配套正常/拒绝对照。

## 4. 检测、独立验证与 Evidence

1. 为两个合成租户建立互不可见文档、显式共享文档、隔离文档和正常公开文档。每份材料使用独立 canary；登录身份由测试认证服务创建。
2. 经向量、关键词、混合、引用直读、缓存命中、历史会话和导出分别查询。检查返回 ID、模型上下文与外部重排请求；仅检查最终回答会漏掉中间泄露。
3. 撤销单用户/组权限并删除一份材料，记录写入完成与索引/缓存传播时间。立即、传播后和新会话各测一次，报告实际窗口。
4. 将合成错误事实作为合法可读但待复核文档加入，比较入库前后引用来源和答案变化。用独立维护的事实表判定内容，避免让同一模型同时生成和裁定答案。
5. 隔离已确认的污染文档，按来源 ID 清理其 chunk、摘要、缓存和记忆派生物；保留受限证据副本，验证正常材料召回与答案仍可用。

本地输出建议为 `exports/general/ai-defense/<run-id>/retrieval.jsonl` 和 `verdict.json`。记录字段：身份引用、tenant、ACL/语料版本、检索路由、候选/允许/进入上下文的 chunk ID、来源版本、缓存命中及复核结果、独立事实判定。原始私有文本只留受控案件目录。

## 5. 误报与失败分支

| 现象 | 可替代解释 | 下一跳 |
|---|---|---|
| 同一资料在两个租户出现 | 可能是明确允许的共享文档 | 对照服务端共享策略，记录来源与实际 ACL |
| 撤权后还可见 | 缓存、索引、会话摘要或 ACL 复制滞后 | 找到仍返回旧版本的组件，测传播时间与读取前校验 |
| 新材料排名上升 | 正常更新、重复内容、检索器变更 | 对照内容差异、发布者和固定检索配置 |
| 答案错误但没有污染文档 | 生成错误、检索遗漏或可信来源已过时 | 检查实际引用和独立资料，分别记录根因 |
| 所有私有查询都无结果 | 身份映射、组同步或过滤配置失效 | 用有权限的正常对照查可用性，避免把全拒绝当成完整通过 |
| 资料有权限且可信，仍要求新动作 | 文档包含指令或工具建议 | 转入[间接提示注入防御](01-indirect-prompt-injection-defense.md)和 [MCP 工具授权](02-mcp-trust-boundary-defense.md) |

## 6. 真实检索接口的双身份回放

在测试知识库分别以租户 A、B 的正常入库流程添加文档，正文写入各自独有的合成标记 `RAG-PRIVATE-A-731`、`RAG-PRIVATE-B-852`，保留源文档 ID、chunk ID 与实际 ACL。用应用的正常检索页面发起一个能召回这两份主题的查询，从 Network 取得真实请求体，存为 `exports/general/ai-defense/retrieval-request.json`。不要在正文里伪造 ACL 元数据。

下面脚本将相同请求分别作为两个测试用户发送到实际查询接口，保存完整响应，并检查另一租户的 canary。它不假设返回 JSON 的字段名。前提是该接口使用 Bearer 身份；其他认证机制按真实客户端修改。`RAG_QUERY_URL` 是实际检索 API，不是模型供应商通用聊天接口。

```python
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

out = Path(os.environ.get("RAG_EVIDENCE_DIR", "exports/general/ai-defense"))
payload = (out / "retrieval-request.json").read_bytes()
canaries = {"A": "RAG-PRIVATE-A-731", "B": "RAG-PRIVATE-B-852"}
for user in ("A", "B"):
    request = Request(os.environ["RAG_QUERY_URL"], data=payload, method="POST", headers={
        "Authorization": "Bearer " + os.environ[f"RAG_TEST_TOKEN_{user}"],
        "Content-Type": "application/json", "Accept": "application/json"})
    try:
        response = urlopen(request, timeout=60)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        (out / f"retrieval-{user}.json").write_bytes(body)
        text = body.decode("utf-8", errors="replace")
        other = "B" if user == "A" else "A"
        print(user, "HTTP", response.status,
              "own_canary", canaries[user] in text,
              "foreign_canary", canaries[other] in text)
        if canaries[other] in text:
            raise SystemExit("Cross-tenant marker observed; preserve request and response evidence")
```

保存为 `exports/general/ai-defense/replay_retrieval.py` 并运行。设置变量时使用两个真实测试账号的 token，不使用管理员 token 冒充普通用户。若请求体含 tenant 或用户 ID，按应用契约保留并测试服务端是否重新授权，不能把改这些字段当成身份认证。

```sh
python exports/general/ai-defense/replay_retrieval.py
```

第一次正常返回后撤销 A 对其文档的权限，用同一查询测试缓存命中，再用新会话测试；每轮用 `RAG_EVIDENCE_DIR` 指定不同目录，并将真实查询请求体复制进去，避免覆盖前一轮证据。响应未出现外租户 canary 只说明此次响应没有该标记：同步从真实检索日志取候选/允许的 chunk ID，从重排和生成请求记录取实际上下文，按第 4 节确认中间路径。`own_canary=false` 时先排查召回、过滤和响应是否省略正文，不能记成权限验证通过。本文未访问任何真实向量库或业务接口。

## MCP 工具映射

| 步骤 | 工具 | 用途与边界 |
|---|---|---|
| 按 RAG 信号定位 | `kb_router` | 在 `board="general"` 检索跨租户、撤权、投毒等词 |
| 对照攻击输入与证据 | `kb_read_file` | 读取 [RAG 授权与投毒分析](../../../../red/general/techniques/ai-security/03-rag-authorization-poisoning.md) |
| 查相邻防护路径 | `kb_catalog` | 连接提示注入与工具信任边界；不读取真实向量库 ACL |

这些工具提供知识路由，不会自动修复向量数据库权限、验证模型回答或清理业务缓存。离线示例通过本地 Python 运行，真实集成结果另行记录。
