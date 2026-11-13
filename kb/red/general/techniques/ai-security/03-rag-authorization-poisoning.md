---
id: "general/ai-security/03-rag-authorization-poisoning"
title: "RAG 授权与文档投毒：租户、索引和缓存"
title_en: "RAG Authorization and Document Poisoning: Tenants, Indexes, and Caches"
summary: >
  检查 RAG 摄取、检索、重排、模型上下文、引用下载与缓存的授权传递，区分跨租户读取、事实投毒和指令注入，覆盖权限撤销、文档版本与来源完整性，并提供双租户离线检索试件。
summary_en: >
  Trace authorization through RAG ingestion, retrieval, reranking, context, citations, and caches. Distinguish cross-tenant reads, factual poisoning, and instruction injection; test revocation, versions, and provenance with a two-tenant offline fixture.
board: "general"
category: "ai-security"
signals: ["RAG", "document poisoning", "RAG 投毒", "tenant ACL", "security trimming", "vector filter", "引用越权", "retrieval cache"]
mcp_tools: ["kb_router", "kb_read_file"]
keywords: ["RAG授权", "文档投毒", "知识库投毒", "跨租户检索", "ACL撤销", "缓存隔离", "chunk", "reranker"]
difficulty: "advanced"
tags: ["ai-security", "rag", "authorization", "data-poisoning", "red-team"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["general/ai-security/03-rag-authorization-poisoning-defense", "general/ai-security/01-indirect-prompt-injection", "general/ai-security/02-mcp-trust-boundary", "ctf-website/14-idor/01-idor-enumeration"]
track: "red"
---
# RAG 授权与文档投毒：租户、索引和缓存

## 1. 场景与三种不同结果

应用将文档拆成 chunk、索引并检索，再把片段交给模型生成答案。这里需要分别建立三个假设：用户能检索到无权读取的文档；用户可读但来源不可信的文档污染答案；文档中的指令改变 Agent 行为。

外部知识库可以成为答案污染入口，攻击者插入的内容可能影响检索结果与生成答案；[PoisonedRAG 原始论文](https://arxiv.org/abs/2402.07867)研究了这一攻击面。本文的合成排序与 canary 试件用于定位阶段，不复现论文算法，也不引用其成功率作为目标系统的预期。

| 观察结果 | 分类 | 必需证据 |
|---|---|---|
| 用户 A 的上下文含 B 的私有 canary 文档 | 授权越界 | 已认证主体、文档 ACL、实际模型输入 |
| 文档合法可读，但错误事实被采用 | 知识投毒 | 正确基准、被改来源、检索与答案差分 |
| 文档要求调用工具，Agent 随后提出该调用 | 间接提示注入 | 来源指令、工具调用、执行决定 |
| A 看不到正文，却能打开 B 的引用下载链接 | 引用/下载越权 | 引用 ID、下载身份、源对象归属 |

## 2. 输入信号与工作流

输入信号包括向量数据库、`tenant_id` 或 `group_ids` 过滤器、上传知识库、混合检索、reranker、共享检索缓存、按文档 ID 打开的引用以及权限变更后的索引同步。

```text
两个实验租户，各自拥有公开/私有 canary 文档
  → 摄取时记录原文件身份、ACL、版本、chunk 映射
  → 同一查询从 A / B / 未登录主体发起
  → 观察候选、重排、模型上下文、回答、引用下载
    ├─ 跨租户候选进入不该接收的外部重排/模型 → 权限传递缺口
    ├─ 返回允许文档中的错误事实 → 来源投毒
    ├─ 文档指令变成动作 → 间接提示注入
    ├─ A 的缓存结果被 B 复用 → 缓存键/权限复核
    └─ 撤权后仍可读取 → 索引、缓存、会话的撤销传播
```

先看应用真正如何取得身份。若客户端传来的 `tenant_id` 被当作可信身份，应使用 A 的有效会话只替换该字段；若网关从已验证会话派生租户，则转向索引 ACL、引用和缓存路径。

身份字符串过滤不自带认证能力；它依赖应用提供可信主体。[Azure AI Search security filter pattern](https://learn.microsoft.com/en-us/azure/search/search-security-trimming-for-azure-search) 明确区分了过滤字符串与身份认证。可借此核对目标是否把任意请求参数直接拼入权限过滤器。

## 3. 分阶段实验矩阵

| 阶段 | 单变量变化 | 观察点与下一跳 |
|---|---|---|
| 摄取 | 改文件名中的租户、重复 `source_id`、同名不同来源 | server 是否覆盖了其他主体的文档；chunk 是否继承真实 ACL |
| 检索 | A 会话下替换 `tenant_id`、省略过滤字段 | 过滤器由谁生成；返回 doc/chunk ID 与真实归属 |
| 混合查询 | 保留同一身份，切换关键词/向量/重写查询路径 | 每条分支是否同样带有权限限制 |
| 重排 | 固定候选集合，仅切换重排开关 | 未授权正文是否被发送给外部重排器 |
| 缓存 | A 先查询，B 再问完全相同的问题 | 缓存键、命中主体、返回 chunk、引用与答案 |
| 引用 | A 请求 B 的合成 citation/doc ID | 下载路由是否重新确认文档权限 |
| 撤权 | 源 ACL 从允许改成拒绝，保持查询不变 | 源系统、索引、缓存各自版本与失效时间 |
| 投毒 | 同一来源仅替换事实，随后恢复 | 检索排名、模型输入、答案是否随来源恢复 |

向量查询的过滤时机也影响召回。Azure 的 `postFilter`/`strictPostFilter` 在高选择性或小 `k` 时可能漏掉允许文档；零结果不能直接判成权限正确或被绕过。该机制参见 [Vector query filters](https://learn.microsoft.com/en-us/azure/search/vector-search-filters)。对于目标系统，仍要看实际结果是否跨越其声明的授权边界。

### 3.1 从真实应用取得查询与身份输入

分别以实验用户 A/B 登录应用，走实际上传入口建立两份带不同 canary 的私有文档。保存上传返回的 source/document ID；等待应用显示索引完成，再从检索 trace 取得 chunk ID、当前 ACL 及内容版本。若应用只有对话入口，用同一问题触发检索并保存返回的 task/run ID。

从浏览器 Network 导出 A/B 的检索或对话 POST body。身份由两个独立会话提供，不能仅修改 body 中的 `user_id` 就当作切换用户。使用[间接提示注入篇的 HTTP 重放脚本](01-indirect-prompt-injection.md)重放实际请求：

```powershell
# 每次设置对应实验身份的 LAB_AGENT_AUTH 或 LAB_AGENT_COOKIE。
python agent_http_replay.py --body exports/general/demo-rag/query-a.json --output exports/general/demo-rag/a-first
python agent_http_replay.py --body exports/general/demo-rag/query-b.json --output exports/general/demo-rag/b-same-question
```

A 先查询、B 再问相同问题用于检查缓存分支；另做 B 首先查询的对照。保存响应中的引用 ID，沿界面实际使用的下载接口以 B 身份请求 A 的实验引用。引用接口与检索接口的拒绝结果分开记录。

没有后端 tracing 权限时，可以确认最终返回或下载的越权结果，但不能声称已知道候选集、重排器或模型上下文在哪一步泄露。下一步取得对应组件日志，按同一个 run ID 对齐。

### 3.2 Azure AI Search：读取真实 schema 并重放检索

以下适用于实验系统确实使用 Azure AI Search 且已有该测试索引的管理/查询凭据。环境变量分别来自该实验服务配置：`LAB_SEARCH_ENDPOINT`、`LAB_SEARCH_INDEX`、`LAB_SEARCH_API_VERSION`、`LAB_SEARCH_API_KEY`。API version 沿用应用当前版本，不在脚本里猜测服务支持范围。

```powershell
$ragRoot = 'exports/general/demo-rag/search'
New-Item -ItemType Directory -Path $ragRoot -Force | Out-Null
$ragIndexUrl = "$(( $env:LAB_SEARCH_ENDPOINT ).TrimEnd('/'))/indexes/$($env:LAB_SEARCH_INDEX)"
$ragHeaders = @{ 'api-key' = $env:LAB_SEARCH_API_KEY }
$ragSchema = Invoke-RestMethod -Method Get -Uri "$($ragIndexUrl)?api-version=$($env:LAB_SEARCH_API_VERSION)" -Headers $ragHeaders
$ragSchema | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath "$ragRoot/index-schema.json"
$ragSchema.fields | Select-Object name,type,filterable,retrievable,searchable
```

确认租户、读者集合、文档 ID、正文、向量字段的**实际名称与类型**。以下 body 约定测试索引中存在 `tenant_id` 字符串、`reader_ids` 字符串集合、`id`、`content`；如果名称不同，先按 schema 修改，不能把不存在的字段错误当成授权拒绝。

```powershell
$ragBody = @{
  search = 'SYNTHETIC_RETENTION_CANARY'
  filter = "tenant_id eq 'a' and reader_ids/any(r: search.in(r, 'alice'))"
  select = 'id,content,tenant_id'
  top = 5
}
$ragResponse = Invoke-RestMethod -Method Post -Uri "$ragIndexUrl/docs/search?api-version=$($env:LAB_SEARCH_API_VERSION)" -Headers $ragHeaders -ContentType 'application/json' -Body ($ragBody | ConvertTo-Json -Depth 20)
$ragResponse | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath "$ragRoot/query-a.json"
```

在混合检索分支，从真实应用 trace 取得该查询的向量数组，保存为 `query-vector.json`；不要用随机数组代替同一查询的 embedding。按 schema 中真实向量字段名加入：

```powershell
$ragVector = Get-Content -LiteralPath "$ragRoot/query-vector.json" -Raw | ConvertFrom-Json
$ragBody.vectorQueries = @(@{ kind = 'vector'; vector = $ragVector; fields = $env:LAB_SEARCH_VECTOR_FIELD; k = 5 })
$ragBody.vectorFilterMode = 'preFilter'
$ragHybrid = Invoke-RestMethod -Method Post -Uri "$ragIndexUrl/docs/search?api-version=$($env:LAB_SEARCH_API_VERSION)" -Headers $ragHeaders -ContentType 'application/json' -Body ($ragBody | ConvertTo-Json -Depth 30)
$ragHybrid | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath "$ragRoot/hybrid-a.json"
```

这些直连请求检查 schema 和过滤行为；使用后端 API key 的请求不代表终端用户拥有同样权限。判定应用授权时仍以 3.1 的真实用户入口为准，并检查应用实际发送的过滤器是否一致。

### 3.3 撤权和投毒沿原有入库链推进

在原文档系统撤销 A 对一份实验文档的权限，记录该操作返回时间和源 ACL 版本。随后重复同一应用查询，分别检查已有会话、新会话、缓存命中、直接引用下载；保存首个不再返回该文档的时间。若源文档仍可读而索引暂时失效，只能确认索引状态，不能把它当作源权限已经撤销。

事实投毒通过原上传/更新接口提交两份版本：`Demo retention: 7 days` 与 `Demo retention: 700 days`。保持同一问题和检索配置，保存每次命中的文档版本、排名、引用和答案。更改正文后还未重新索引时，应先等待对应版本进入索引，再运行对照。移除投毒版本后重跑同一流程，沿 source ID 继续查看派生摘要与旧缓存。

## 4. 可运行的双租户离线试件

保存为 `rag_boundary_fixture.py`，运行 `python rag_boundary_fixture.py`。脚本演示漏掉租户过滤、只按查询缓存以及撤权后复用旧缓存的差异。`score` 为人为排序分值，未调用 embedding、向量数据库或 LLM；输出只说明这组数据和函数的行为。

```python
from copy import deepcopy
import json

DOCS = [
    {"id": "a-private", "tenant": "a", "readers": ["alice"],
     "version": 1, "score": 8, "text": "SYNTHETIC_A_CANARY"},
    {"id": "b-private", "tenant": "b", "readers": ["bob"],
     "version": 1, "score": 10, "text": "SYNTHETIC_B_CANARY"},
    {"id": "a-public", "tenant": "a", "readers": ["*"],
     "version": 1, "score": 6, "text": "Demo retention: 7 days."},
]
ALICE = {"subject": "alice", "tenant": "a", "acl_epoch": 1}
BOB = {"subject": "bob", "tenant": "b", "acl_epoch": 1}


def allowed(doc, identity):
    return (doc.get("tenant") == identity["tenant"]
            and ("*" in doc.get("readers", [])
                 or identity["subject"] in doc.get("readers", [])))


def retrieve(docs, identity, enforce_acl=True):
    candidates = [d for d in docs if not enforce_acl or allowed(d, identity)]
    return sorted(candidates, key=lambda d: d["score"], reverse=True)[:2]


def cache_key(query, identity, index_revision):
    return (query, identity["tenant"], identity["subject"],
            identity["acl_epoch"], index_revision)


def main():
    docs = deepcopy(DOCS)
    normal = retrieve(docs, ALICE)
    unfiltered = retrieve(docs, ALICE, enforce_acl=False)
    assert all(allowed(d, ALICE) for d in normal)
    assert any(d["id"] == "b-private" for d in unfiltered)
    query = "What is the demo retention policy?"
    bad_cache = {query: normal}
    leaked_to_bob = bad_cache[query]
    assert any(not allowed(d, BOB) for d in leaked_to_bob)
    good_cache = {cache_key(query, ALICE, "index-r1"): normal}
    assert cache_key(query, BOB, "index-r1") not in good_cache

    # 源权限变更后，旧上下文仍然存在，直到缓存失效或重新授权。
    docs[0]["readers"] = []
    after_revoke = {**ALICE, "acl_epoch": 2}
    assert cache_key(query, after_revoke, "index-r2") not in good_cache
    current_by_id = {d["id"]: d for d in docs}
    replayed = [current_by_id[d["id"]] for d in normal
                if allowed(current_by_id[d["id"]], after_revoke)]
    assert [d["id"] for d in replayed] == ["a-public"]
    assert not allowed({"id": "missing-acl", "tenant": "a"}, ALICE)
    print(json.dumps({"kind": "offline-model",
                      "normal_ids": [d["id"] for d in normal],
                      "unfiltered_ids": [d["id"] for d in unfiltered],
                      "bad_cache_ids_for_bob": [d["id"] for d in leaked_to_bob],
                      "revalidated_ids": [d["id"] for d in replayed]}, indent=2))


if __name__ == "__main__":
    main()
```

真实系统可能使用组权限、分享范围或显式拒绝规则，应依据其权限模型扩充主体集合；不能直接复制这个简化的 `readers` 规则。`acl_epoch` 仅是试件中的缓存版本机制，实际版本必须由服务端维护，不能来自未经验证的请求字段。

### 文档投毒的对照操作

在 A 可读的合成资料中固定事实“Demo retention: 7 days”，保存该正确基准。新增一份由实验低信任来源提供的文档，仅声称“Demo retention: 700 days”，不加入任何助手指令。依次观察它是否入库、命中、被重排、进入模型输入和被最终答案采用。移除该文档并等待索引更新后重跑同一问题，检查是否恢复。

这种实验测的是来源完整性与答案采用。若新增文档未被检索到，只能记录摄取或检索失败；若答案仍为 7，需区分模型使用了其他证据、拒绝低信任来源，还是根本没收到变体。需要测试指令执行时再使用 [间接提示注入试件](01-indirect-prompt-injection.md)。

## 5. 证据闭环与失败分支

保存 `run_id → authenticated principal → source_id/version → chunk_id/ACL → query/filter → candidates → reranker input → model context → answer/citations → download result`。权限撤销实验再附源 ACL 变化时间、索引刷新时间和缓存失效时间。已公开且双方可读的文档不作为跨租户泄露 canary。

结果写入 `exports/general/<case>/rag-boundary/`，分析笔记写入 `notes/general/<case>_analysis.md`。每个结论说明最早出现越界的阶段；若无候选或模型上下文记录，只能缩小到可观察的接口边界。

- **源系统已拒绝、索引仍允许**：检查同步延迟与产品声明的撤销时限；超出该时限后再判定持续缺口。
- **B 文档只在受信任检索后端内部参与排序**：结合系统的数据处理边界判断；进一步确认是否被返回或送往不应接收它的组件。
- **回答无 canary，但上下文有 B 私文**：模型的最终拒答不能消除已经发生的上下文暴露。
- **回答含通用事实但没有私有标记**：无法确定来自 B 的私文；使用独有合成数据和引用关联。
- **缓存命中但结果重新检查了当前 ACL**：记录被排除的文档和调用轨迹，说明该复核环节有效。
- **投毒与检索版本同时变化**：分离变更重新运行，避免把新 embedding 或 chunk 参数影响归于投毒。

## 6. MCP 工具映射

| 步骤 | 工具 | 能力边界 |
|---|---|---|
| 路由 RAG/ACL 信号 | `kb_router(query="RAG tenant ACL", board="general", track="red")` | 检索相关方法 |
| 读取跨域授权篇 | `kb_read_file` | 可继续读取 Web IDOR 与 MCP 边界文档 |
| 获取检索阶段轨迹 | 目标应用/检索服务的测试日志 | 仓库通用 HTTP 探针无法看到内部候选与模型输入 |
| 运行离线矩阵 | 本地 Python | 只覆盖合成租户、缓存与撤权语义 |

蓝队关联：[RAG 授权与文档投毒防御](../../../../blue/general/techniques/ai-security/03-rag-authorization-poisoning-defense.md)。
