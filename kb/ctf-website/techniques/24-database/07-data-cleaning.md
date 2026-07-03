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
difficulty: "advanced"
tags:
  - "database"
  - "data-cleaning"
  - "forensics"
  - "methodology"
  - "data-analysis"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/24-database/00-overview", "ctf-website/24-database/05-backup-log-leak", "ctf-website/24-database/06-card-platform", "ctf-website/12-payment/payment-digital-goods", "ctf-website/12-payment/payment-email-bounce-idor"]
---
# Database Dump Cleaning — 泄露数据清洗方法论

> 从非结构化或半结构化泄露数据中提取、分类、关联有效信息，建立源数据到业务实体的映射。

## 关键词

`数据清洗` `泄露数据` `格式分类` `特征提取` `锚点映射` `置信度分级` `数据去噪` `前缀聚类` `计数器归一化`

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| HTML/JSON/日志里混入卡密、订单号、账号、下载链接 | 先抽字段路径和原始行号 | 同一字段下值格式稳定，能聚出高频前缀 | 每行都是模板文案、错误页或分页噪声 |
| dump 中有商品名、SKU、订单 ID、CDK 同时出现 | 建立 `record -> entity -> order` 三表 | 同一 SKU 下 CDK 前缀、长度、字符集一致 | SKU 与 CDK 无稳定关系，只是后台操作日志 |
| 文件里只有一堆短码/长 token | 做长度、字符集、前缀、校验位聚类 | 聚类结果能反推出库存批次或权益类型 | 分布均匀且没有任何可复查锚点 |
| 邮件/短信/回调日志泄露 | 用订单号、手机号后四位、邮箱域名做弱锚点 | 订单状态、支付金额、发货字段能连成链 | 只有通知模板，无订单实体字段 |
| 备份 SQL / CSV / XLSX | 先解析 schema，再抽高价值字段 | 字段名指向 `card/pass/secret/key/url/license` | 只有测试表、空表或迁移结构 |

## 0. 流程全景

```
原始数据 → 结构识别 → 有效载荷提取 → 特征聚类 → 锚点关联 → 去噪验证 → 结构化输出
  │           │            │            │          │          │           │
HTML/JSON  定位数据块   去除标记行   长度/字符集  样本→实体   假数据剔除   CSV/DB
纯文本/CSV  识别分隔符   去重        前缀聚类     格式→名称   不可用过滤   索引
```

## 1. 源数据结构识别

### 1.0 路由矩阵

| 输入形态 | 第一刀 | 第二刀 | 证据字段 |
|---|---|---|---|
| HTML 多段 body/table/textarea | `BeautifulSoup.get_text()` 与表格列名双轨 | 保留 DOM 路径、行号和邻近标题 | `source_path`, `dom_hint`, `line_no` |
| JSON API 响应 | 递归遍历所有标量字段 | 字段路径聚类，优先含 `card/token/order/url` 的路径 | `json_path`, `value`, `siblings` |
| SQL dump | 解析 `CREATE TABLE` 与 `INSERT` | 字段名评分，按表输出 CSV | `table`, `column`, `row_id` |
| 混合日志 | 正则提取 key-value、URL query、JSON 片段 | 按 request id/order id/session id 归并 | `ts`, `request_id`, `entity_id` |
| 无结构短码列表 | 行分类 + 长度/字符集/前缀聚类 | 找计数器、校验位、批次前缀 | `cluster`, `pattern`, `sample` |

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

```python
#!/usr/bin/env python3
import argparse
import csv
import json
import re
from html.parser import HTMLParser
from pathlib import Path

TOKEN_RE = re.compile(r"(?i)(https?://\S+|[A-Z0-9][A-Z0-9._-]{5,80}|[\w.+-]+@[\w.-]+\.[a-z]{2,})")
NOISE_RE = re.compile(r"(?i)^(null|none|undefined|test|demo|asd+|123456|[-_=]{3,})$")

class TextSink(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
    def handle_data(self, data):
        if data.strip():
            self.parts.append(data.strip())

def html_text(raw):
    sink = TextSink()
    sink.feed(raw)
    return "\n".join(sink.parts)

def flatten_json(obj, prefix="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten_json(v, f"{prefix}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from flatten_json(v, f"{prefix}[{i}]")
    else:
        yield prefix, "" if obj is None else str(obj)

def iter_candidates(path):
    raw = Path(path).read_text(encoding="utf-8", errors="ignore")
    rows = []
    try:
        obj = json.loads(raw)
        for jp, value in flatten_json(obj):
            rows.append((jp, value))
    except json.JSONDecodeError:
        text = html_text(raw) if "<html" in raw.lower() or "<body" in raw.lower() else raw
        for idx, line in enumerate(text.splitlines(), 1):
            rows.append((f"line:{idx}", line.strip()))
    for source, text in rows:
        for m in TOKEN_RE.finditer(text):
            value = m.group(1).strip(" ,;\"'")
            if not NOISE_RE.match(value):
                yield {"source": source, "value": value, "length": len(value)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("-o", "--output", default="clean-candidates.csv")
    args = ap.parse_args()
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "value", "length"])
        writer.writeheader()
        writer.writerows(iter_candidates(args.dump))
    print(args.output)

if __name__ == "__main__":
    main()
```

成功样本：输出 CSV 里同一字段路径出现稳定 token/CDK/URL；失败样本：候选集中大多是模板词、CSS 类名、前端 bundle hash，需要回到源格式重新定界。

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

```python
#!/usr/bin/env python3
import argparse
import csv
import re
from collections import Counter, defaultdict

HEX_COUNTER = re.compile(r"^([A-Z]{2})[0-9A-F]([A-Z0-9._-]{3,})$", re.I)

def charset_of(v):
    if re.fullmatch(r"[0-9]+", v):
        return "digits"
    if re.fullmatch(r"[a-f0-9]+", v):
        return "hex-lower"
    if re.fullmatch(r"[A-F0-9]+", v):
        return "hex-upper"
    if re.fullmatch(r"[A-Z0-9]+", v):
        return "upper-num"
    if v.startswith("http"):
        return "url"
    return "mixed"

def normalize_prefix(v, n=3):
    up = v.upper()
    m = HEX_COUNTER.match(up)
    if m:
        return f"{m.group(1)}*:{len(v)}:{charset_of(v)}"
    return f"{up[:n]}:{len(v)}:{charset_of(v)}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file")
    ap.add_argument("--value-column", default="value")
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()
    buckets = defaultdict(list)
    with open(args.csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            v = row[args.value_column].strip()
            if v:
                buckets[normalize_prefix(v)].append(v)
    ranked = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:args.top]
    for key, values in ranked:
        lens = Counter(map(len, values))
        print(f"{key}\tcount={len(values)}\tlens={dict(lens)}\tsample={values[:3]}")

if __name__ == "__main__":
    main()
```

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

```python
#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict

def load_map(path, key, value):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out[row[key].strip().upper()] = row[value].strip()
    return out

def prefix(v):
    up = v.strip().upper()
    return up[:3] if len(up) >= 3 else up

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidates")
    ap.add_argument("anchors", help="CSV: prefix,entity")
    ap.add_argument("-o", "--output", default="classified.csv")
    args = ap.parse_args()
    anchors = load_map(args.anchors, "prefix", "entity")
    stats = defaultdict(int)
    with open(args.candidates, newline="", encoding="utf-8") as src, open(args.output, "w", newline="", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        fieldnames = reader.fieldnames + ["prefix", "entity", "confidence"]
        writer = csv.DictWriter(dst, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            p = prefix(row["value"])
            entity = anchors.get(p, "")
            row.update({"prefix": p, "entity": entity, "confidence": "confirmed" if entity else "format-only"})
            stats[(p, entity or "UNKNOWN")] += 1
            writer.writerow(row)
    for (p, entity), count in sorted(stats.items(), key=lambda x: -x[1])[:40]:
        print(f"{p}\t{entity}\t{count}")

if __name__ == "__main__":
    main()
```

锚点 CSV 最小格式：

```csv
prefix,entity
VIP,monthly_vip
CDK,game_card
TK*,ticket_batch
```

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

```python
#!/usr/bin/env python3
import argparse
import csv
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS records(
  id INTEGER PRIMARY KEY,
  source TEXT,
  value TEXT,
  length INTEGER,
  prefix TEXT,
  entity TEXT,
  confidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_records_prefix ON records(prefix);
CREATE INDEX IF NOT EXISTS idx_records_entity ON records(entity);
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("classified_csv")
    ap.add_argument("-o", "--output", default="classified.sqlite")
    args = ap.parse_args()
    db = sqlite3.connect(args.output)
    db.executescript(SCHEMA)
    with open(args.classified_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    db.executemany(
        "INSERT INTO records(source,value,length,prefix,entity,confidence) VALUES(:source,:value,:length,:prefix,:entity,:confidence)",
        rows,
    )
    db.commit()
    for row in db.execute("SELECT prefix, entity, confidence, COUNT(*) FROM records GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 30"):
        print(row)
    db.close()

if __name__ == "__main__":
    main()
```

### 8.1 支付/卡密字段字典

整理 dump 时优先给字段打业务标签，后续才能直接接订单、发货和回调链。

| 标签 | 字段/值信号 | 输出列 |
|---|---|---|
| `order_id` | `order`, `trade`, `out_trade_no`, 长数字订单号 | `entity_id`, `order_hint` |
| `payment` | `amount`, `money`, `paid`, `status`, `transaction_id` | `amount`, `pay_state` |
| `card_secret` | `card`, `kami`, `cdk`, `license`, `secret`, 短码/长码 | `value`, `secret_type` |
| `delivery` | `download_url`, `delivered_at`, `result`, `kminfo` | `delivery_hint` |
| `callback` | `notify`, `sign`, `raw`, `xml`, `json` | `callback_seed` |
| `identity` | email、手机号、uid、session、cookie | `owner_hint` |

```python
# dump_business_tagger.py — 给泄露记录打业务标签
import re

RULES = {
    "order_id": re.compile(r"(out_trade_no|order[_-]?id|trade[_-]?no)|\b\d{10,20}\b", re.I),
    "payment": re.compile(r"(amount|money|total_fee|paid|pay_status|transaction_id)", re.I),
    "card_secret": re.compile(r"(card|kami|cdk|license|secret|key)|[A-Z0-9]{8,40}", re.I),
    "delivery": re.compile(r"(download_url|delivered_at|kminfo|result)", re.I),
    "callback": re.compile(r"(notify|sign_type|sign=|<xml>|callback|webhook)", re.I),
    "identity": re.compile(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b1[3-9]\d{9}\b|PHPSESSID|session", re.I),
}

def tag_record(text):
    return [name for name, rx in RULES.items() if rx.search(text)]
```

### 8.2 输出到下一跳

| 输出文件 | 用途 |
|---|---|
| `classified_records.csv` | 全量字段、行号、标签、置信度 |
| `entity_index.sqlite` | 按订单/商品/用户/卡密查询 |
| `callback_replay_seed.jsonl` | 给签名/回调文档复放 |
| `card_inventory_candidates.csv` | 给数字商品/发卡平台核对 |
| `noise_rules.json` | 记录被剔除的模板、占位符和冲突锚点 |

成功样本：一个泄露值能从原始行号追到实体标签、订单或商品，再追到卡密/下载链接/回调样本。失败样本：只有格式相似但无锚点，或同一前缀被多个实体冲突占用。

## Evidence

| 项 | 记录内容 |
|---|---|
| 原始输入 | dump 文件 hash、大小、来源类型、解析脚本版本 |
| 结构识别 | HTML/JSON/SQL/log/plaintext 判定依据、字段路径或原始行号 |
| 聚类结果 | top 前缀、长度分布、字符集、计数器归一化规则 |
| 锚点证据 | 订单/API/商品目录/字段名如何把 prefix 绑定到实体 |
| 成功样本 | classified CSV/SQLite 中可复查的实体映射、可用 URL/token/CDK/订单字段 |
| 失败样本 | 噪声规则、无法归类前缀、冲突锚点、格式相似但实体不一致的样本 |
| 下一跳 | 转 `12-payment`、`23-paywall-bypass`、`04-config-exposure` 或 SQLi 抽取链的文件路径 |

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 database dump、data cleaning、leak triage 搜索 |
| 文件哈希 | `hash_file` | 记录原始 dump、清洗后 CSV/SQLite 的完整性 |
| 模式搜索 | `search_pattern` | 扫描邮箱、手机号、卡密、token、订单号等模式 |
| 脚本执行 | `run_ctf_tool` | 调用清洗、去重、聚类、格式转换脚本 |
| 证据记录 | `workspace_write_text` | 保存字段字典、字段样例、置信度规则和输出索引 |

## 9. 关联技术

- [[00-overview]] — 数据库攻击全景
- [[01-sqli-fundamentals]] — SQL 注入
- [[04-config-exposure]] — 配置泄露
