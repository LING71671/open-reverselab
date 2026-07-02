---
id: "ctf-website/24-database/07-data-cleaning"
title: "Database Dump Cleaning — 泄露数据清洗方法论"
title_en: "Database Dump Cleaning — Leaked Data Cleaning Methodology"
summary: >
  从非结构化泄露数据中提取有效信息的系统方法：源数据结构识别（HTML/JSON/纯文本/混合格式）、特征维度提取（长度分布/字符集/前缀聚类/计数器归一化）、锚点映射从可信样本扩展到全量数据、品牌名称关联（拼音/缩写），以及置信度分级和去噪验证。
summary_en: >
  Systematic methodology for extracting actionable information from unstructured leaked data: source structure identification (HTML/JSON/plaintext/hybrid), feature extraction (length distribution, charset, prefix clustering, counter normalization), anchor mapping from ground-truth samples to full datasets, brand/name association (pinyin/abbreviations), and confidence grading with noise removal.
board: "ctf-website"
category: "24-database"
signals:
  - "HTML 堆叠 多段 body"
  - "JSON 响应 泄露数据"
  - "前缀聚类 2-3 字符"
  - "计数器归一化 十六进制"
  - "锚点映射 ground truth"
  - "置信度分级 确认 高 中 低"
  - "假数据 占位符 asd123"
  - "数据行 分隔符行 标记行"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
keywords:
  - "数据清洗"
  - "泄露数据"
  - "格式分类"
  - "前缀聚类"
  - "特征提取"
  - "锚点映射"
  - "置信度分级"
  - "data dump cleaning"
  - "data classification"
  - "泄露数据库"
difficulty: "beginner"
tags:
  - "database"
  - "data-cleaning"
  - "forensics"
  - "methodology"
  - "data-analysis"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Database Dump Cleaning — 泄露数据清洗方法论

> 从非结构化或半结构化泄露数据中提取、分类、关联有效信息，建立源数据到业务实体的映射。

## 关键词

`数据清洗` `泄露数据` `格式分类` `特征提取` `锚点映射` `置信度分级` `数据去噪` `前缀聚类` `计数器归一化`

## 0. 流程全景

```
原始数据 → 结构识别 → 有效载荷提取 → 特征聚类 → 锚点关联 → 去噪验证 → 结构化输出
  │           │            │            │          │          │           │
HTML/JSON  定位数据块   去除标记行   长度/字符集  样本→实体   假数据剔除   CSV/DB
纯文本/CSV  识别分隔符   去重        前缀聚类     格式→名称   不可用过滤   索引
```

## 1. 源数据结构识别

### 1.1 原始格式判定

| 格式 | 特征 | 提取策略 |
|------|------|---------|
| HTML 堆叠 | 多段 `<body>`、多个 `<textarea>`/`<table>` | 定位目标标签，提取 textContent |
| JSON 响应 | `{...}` 或 `[...]` 结构 | 解析后遍历字段路径 |
| 纯文本列表 | 每行一条记录 | 按行处理，识别行类型 |
| 混合格式 | 数字行+文本行+标记行交错 | 逐行分类，建立行类型状态机 |

### 1.2 行类型分类

- **数据行**：符合预期格式（长度/字符集/前缀）
- **分隔符行**：短数字（如 `1`）、空行
- **标记行**：含特定关键词（状态/标签）
- **Header行**：文件开头几行的元数据
- **冗余行**：与其他行完全重复

### 1.3 数据块定位

有效数据常被包裹在噪声中——错误页输出、标签行穿插、重复 header。策略：**状态机扫描**，定义进入/退出条件，仅提取数据块内的行。

## 2. 特征维度

### 2.1 基础维度

| 维度 | 用途 |
|------|------|
| 长度分布 | 聚类第一特征，同格式往往等长 |
| 字符集 | `[A-Z0-9]` vs `[a-f0-9]` vs 含特殊字符 |
| 前缀（2-4 字符） | 最强区分特征 |
| 结构模式 | 固定段+分隔符+可变段 |

### 2.2 前缀聚类

先取 2 字符分组，高频分组再细化到 3 字符。对计数器变体做归一化合并。

### 2.3 计数器归一化

前缀第三位是十六进制计数器（如 `TK0`-`TKF`）的，合并为同一类型。识别模式：固定前缀 + `[0-9A-F]` + 固定结构段。

## 3. 可独立使用资产识别

### 3.1 直接可用

| 类型 | 判定方式 |
|------|---------|
| URL/下载链接 | `https?://` 正则匹配 |
| 邮箱+密码 | `@` + `----` 分隔符结构 |
| 手机号+API | 国际区号 + 固定长度 + URL |
| 联系方式 | 特定前缀 + 可识别 ID |

### 3.2 需上下文

短激活码（6-12 字符）、UUID 格式码——不知道对应哪个产品/平台就无法使用。

### 3.3 假数据特征

重复模式（`123456`、`111111`）、明显占位符（`asd123`、`dasdasd`）、不符合任何已知业务格式的行。

## 4. 锚点映射

### 4.1 原理

从有限的 ground truth 样本出发，通过格式一致性将映射关系扩展到同格式的全部数据。

```
样本:  { prefix_A → Entity_X }  (来源: 订单/API 等可信数据)
扩展:  所有 prefix_A 的记录 → Entity_X
```

### 4.2 锚点来源与可信度

| 来源 | 可信度 | 获取难度 |
|------|--------|---------|
| 订单/交易记录 | 最高 | 需要 API 访问 |
| 商品描述直接匹配 | 高 | 需要商品目录 |
| 品牌名拼音推断 | 中 | 需要目录+拼音映射 |
| 格式结构推测 | 低 | 仅需泄露数据本身 |

### 4.3 扩展验证

- 同一前缀下的数据格式是否完全一致
- 同一商品下不同锚点返回的前缀是否一致
- 块大小与商品库存量是否在同一数量级

## 5. 品牌/名称关联

### 5.1 直接匹配

前缀出现在商品名称的显著位置（如被 `【】` 包裹的品牌名）。

### 5.2 拼音首字母

中文品牌名逐字取首字母，匹配前缀。需处理多音字和生僻字。

### 5.3 英文缩写

游戏/平台英文名缩写匹配（`PUBG`→`GU`、`Minecraft`→`MC`）。

### 5.4 收敛策略

无法匹配的前缀：数量<阈值归入"未分类"；结构可识别标记格式类型；无特征标记"未知"。

## 6. 置信度分级

| 级别 | 标准 |
|------|------|
| **确认** | 有订单/API 直接证据 |
| **高** | 品牌名直接匹配 + 格式一致 |
| **中** | 拼音/缩写匹配 |
| **低** | 纯格式推断 |

## 7. 去噪

- 重复值聚类——异常高频的同一内容
- 模式匹配——连续数字、键盘序列、占位符
- 业务验证——有效凭证/账号格式校验

## 8. 输出规范

每条记录应包含：原始行号、数据内容、分类标签、关联实体 ID、关联实体名称、置信度。输出格式：CSV（全量）、SQLite（查询）、HTML（浏览）。

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 database dump、data cleaning、leak triage 搜索 |
| 文件哈希 | `hash_file` | 记录原始 dump、清洗后 CSV/SQLite 的完整性 |
| 模式搜索 | `search_pattern` | 扫描邮箱、手机号、卡密、token、订单号等模式 |
| 脚本执行 | `run_ctf_tool` | 调用清洗、去重、聚类、格式转换脚本 |
| 证据记录 | `workspace_write_text` | 保存字段字典、脱敏样例、置信度规则和输出索引 |

## 9. 关联技术

- [[00-overview]] — 数据库攻击全景
- [[01-sqli-fundamentals]] — SQL 注入
- [[04-config-exposure]] — 配置泄露
