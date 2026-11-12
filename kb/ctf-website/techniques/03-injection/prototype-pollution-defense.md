---
id: "ctf-website/03-injection/prototype-pollution-defense"
title: "Prototype Pollution (原型链污染) 纵深防御"
title_en: "Prototype Pollution Defense"
summary: >
  针对服务端与客户端 Prototype Pollution 的全面防御指南，涵盖源头解析器（JSON/QS/Form/YAML/postMessage/Hash）危险键拦截、无原型字典与 Map 容器替代、核心 Sink（鉴权默认值、模板引擎 options、child_process、Logger、HTTP Client、前端 Store）隔离与加固，以及可运行 Python 策略校验脚本。
summary_en: >
  Comprehensive defense guide against server-side and client-side Prototype Pollution, covering source parser key filtering (JSON/QS/Form/YAML/postMessage/Hash), null-prototype dictionaries and Map containers, hardening high-risk sinks (auth defaults, template engine options, child_process, logger, HTTP clients, frontend stores), and runnable validation code.
board: "ctf-website"
category: "03-injection"
signals: ["prototype pollution防御", "__proto__拦截", "Object.create(null)", "hasOwn防御", "deep merge加固", "qs安全配置", "原型冻结"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["原型链污染防御", "Prototype Pollution防护", "__proto__过滤", "constructor.prototype拦截", "Object.freeze", "Object.hasOwn", "safe merge"]
difficulty: "advanced"
tags: ["defense", "blue-team", "injection", "prototype-pollution", "nodejs"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/03-injection/prototype-pollution", "ctf-website/07-client/postmessage", "ctf-website/07-client/postmessage-defense", "ctf-website/03-injection/ssti-defense"]
track: "blue"
defends: "ctf-website/03-injection/prototype-pollution"
---

# Prototype Pollution (原型链污染) 纵深防御

原型链污染依赖三个串联环节：**可控键名进入递归合并/路径赋值（Source & Merge）** → **修改共享原型 `Object.prototype`（Polluted Key）** → **下游依赖原型回退的危险消费点（Sink）**。防御必须在“入口阻断危险键”、“运行期隔离原型链”与“Sink 显式白名单取值”三处同时落锁，仅过滤字面量 `"__proto__"` 会被 `constructor.prototype`、`__%70roto__` 或点号路径轻松绕过。

## 防御工作流

```text
入口解码后规范化所有嵌套键（JSON/QS/Form/Hash/postMessage）
  → 在递归 merge / path setter 中拦截 __proto__ / constructor / prototype
  → 内部配置与路由映射改用 Map 或 Object.create(null)
  → 关键业务启动时校验 Object.hasOwn 并按需锁定 Object.prototype
  → 对鉴权/模板/子进程/HTTP Client/前端 Store 实施严格 Schema 与显式属性绑定
```

## 1. 入口解析器与 Merge / Path Setter 加固

1. **封堵 Dangerous Keys 全变体**：所有对象合并（`merge`、`extend`、`cloneDeep`）与路径赋值函数（`setByPath`、`dot-prop` 类工具）必须在**解码完成后的每一层键段**执行精确黑名单拦截：
   - 拒绝 `"__proto__"`、`"constructor"`、`"prototype"`；
   - 使用 `Object.hasOwn(src, key)`（或 `Object.prototype.hasOwnProperty.call(src, key)`）遍历源对象，禁止使用裸 `for (const k in src)` 顺带拷贝原型属性；
   - JSON 反序列化可使用 `reviver` 在解析阶段直接丢弃或拒绝 `__proto__` 与 `constructor` 键。
2. **收紧 `qs` / `body-parser` / URL Fragment 解析**：
   - Express/Node.js 中将 `qs` 配置为禁用深层原型解析（`allowPrototypes: false` 已是较新版本默认，勿设为 `true`），限制 `depth <= 3` 与 `allowDots: false`；
   - 浏览器端解析 `location.hash` 或 query 时直接调用原生 `URLSearchParams`，禁止手写 `out[m[1]][m[2]]` 括号赋值逻辑；需要键值映射时使用 `new Map()`。
3. **YAML / TOML 与 `postMessage` 防护**：使用 `js-yaml` 等安全加载器（`yaml.load` v4+ 默认安全 schema）并配合结构化 Schema 校验，不直接将 `postMessage` 解析对象并入状态树。

## 2. 运行期原型隔离与容器替换

```javascript
// 1. 使用无原型对象或 Map 存储动态键值对，彻底切断原型链继承
const userSettings = Object.create(null);
const dynamicMap = new Map();

// 2. 启动期冻结内建原型（确认第三方依赖不修改内建原型后启用）
// Object.freeze(Object.prototype);
// Object.freeze(Array.prototype);

// 3. 安全路径赋值实现（阻断任何原型链跳转）
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target, source) {
  if (!source || typeof source !== "object") return target;
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new Error(`Blocked prototype pollution key: ${key}`);
    }
    if (!Object.hasOwn(target, key) && key in target) {
      // 命中 Object.prototype 上已存在的属性名（如 toString/valueOf），拒绝覆写
      throw new Error(`Blocked inherited property overwrite: ${key}`);
    }
    const val = source[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      if (!Object.hasOwn(target, key) || typeof target[key] !== "object" || target[key] === null) {
        target[key] = Object.create(null);
      }
      safeMerge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}
```

> [!IMPORTANT]
> 仅检查 `FORBIDDEN_KEYS` 仍可能漏掉在运行时动态继承自 `Object.prototype` 的方法键；判断 `!Object.hasOwn(target, key) && key in target` 可防止污染或覆盖内置属性。

## 3. 高危 Sink 逐类隔离矩阵

| Sink 类别 | 常见被污染属性 | 加固改造要求 |
|---|---|---|
| 鉴权默认值 | `isAdmin`, `role`, `permissions` | 读取权限字段必须用 `Object.hasOwn(user, "role") && user.role === "admin"`；默认权限由服务端显式构造并初始化为 `false` |
| 模板引擎 (EJS/Pug/Handlebars) | `outputFunctionName`, `compileDebug`, `client`, `escapeFunction` | 升级模板引擎至已免疫 PP 的版本；传给 `render()` 的 `options` 对象使用 `Object.create(null)` 构建并显式置空危险键 |
| 子进程 (`child_process`) | `shell`, `env`, `argv0`, `NODE_OPTIONS` | 显式传入完整 options `{ shell: false, env: cleanEnv }`，避免 `options` 缺省某键时回退到 `Object.prototype`；优先使用 `execFile` 替代 `exec` |
| 日志与 HTTP Client | `format`, `level`, `baseURL`, `headers` | Logger 与 HTTP Client 配置通过白名单 DTO 显式拷贝构造完整 URL 与请求头，禁止从普通 `{}` 读取可选配置 |
| 前端 Store / Router | `apiBase`, `redirect`, `isAdmin` | 前端全局配置使用 `Object.freeze(defaultConfig)` 与 Zod/Ajv `additionalProperties: false` 校验 |

## 4. 载荷拦截与安全合并自测脚本

以下可运行 Python 脚本可在网关策略测试或静态规则验证中使用：递归扫描 JSON/QS/Dotted-Path 输入中的原型污染变体（含 URL 编码还原后检测），并验证安全合并不改变默认对象属性：

```python
#!/usr/bin/env python3
"""Prototype Pollution 多编码与路径键名拦截校验器。"""
import json
import re
from urllib.parse import unquote

DANGEROUS_SEGMENTS = {"__proto__", "constructor", "prototype"}


class PrototypePollutionBlocked(ValueError):
    pass


def normalize_segment(seg: str) -> str:
    # 多次解码以捕捉 __%70roto__ 或双重编码变体
    cur = seg
    for _ in range(3):
        nxt = unquote(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur.strip()


def check_key_path(key: str) -> None:
    # 拆分 a[b][c] 与 a.b.c 路径形式
    parts = [p for p in re.split(r"[\.\[\]]+", key) if p]
    for raw_part in parts:
        norm = normalize_segment(raw_part)
        if norm in DANGEROUS_SEGMENTS:
            raise PrototypePollutionBlocked(f"blocked dangerous key segment: {norm!r} in {key!r}")


def validate_json_tree(node) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            check_key_path(str(k))
            validate_json_tree(v)
    elif isinstance(node, list):
        for item in node:
            validate_json_tree(item)


def validate_qs_keys(raw_qs: str) -> None:
    for pair in raw_qs.split("&"):
        if not pair:
            continue
        k, _, _ = pair.partition("=")
        check_key_path(k)


if __name__ == "__main__":
    evil_json_cases = [
        '{"__proto__":{"pp_marker":"pp_yes"}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{"a.__proto__.x":1}',
        '{"__%70roto__":{"role":"admin"}}',
    ]
    for raw in evil_json_cases:
        try:
            validate_json_tree(json.loads(raw))
            raise AssertionError(f"expected block for {raw}")
        except PrototypePollutionBlocked as exc:
            print(f"[PASS JSON] {exc}")

    evil_qs_cases = [
        "__proto__[pp_marker]=pp_yes",
        "constructor[prototype][isAdmin]=true",
        "a[__%70roto__][shell]=true",
    ]
    for qs in evil_qs_cases:
        try:
            validate_qs_keys(qs)
            raise AssertionError(f"expected block for {qs}")
        except PrototypePollutionBlocked as exc:
            print(f"[PASS QS] {exc}")

    validate_json_tree({"profile": {"displayName": "alice", "theme": "dark"}})
    validate_qs_keys("page=1&sort=desc")
    print("[PASS] benign payloads accepted")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| JSON/QS/Form 键过滤 | `__proto__`、`constructor.prototype`、`__%70roto__` 与括号/点号变体均被拒绝返回 `400` | 任意新构造 `{}` 继承 `pp_marker` 或 `isAdmin` |
| 鉴权与业务默认值 | 仅通过 `Object.hasOwn` 读取权限属性，全局默认值不可从原型注入 | 发送污染载荷后未授权账号进入管理分支 |
| 模板与子进程 Sink | 模板 options 使用无原型对象，子进程显式 `shell: false` 且不受额外环境变量影响 | 渲染输出报错或模板/命令执行行为因载荷改变 |
| 客户端 Hash/postMessage | `location.hash` 与 `postMessage` 数据不触发前端 `store`/`router` 变更 | `apiBase`、`redirect` 或 DOM 状态被跨源载荷改写 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `prototype pollution`、`safe merge`、`postmessage`、`ssti` 搜索加固方案 |
| 读取攻击链路 | `kb_read_file` | 对照 `ctf-website/03-injection/prototype-pollution` 验证 Source/Sink 封堵 |
| 浏览目录索引 | `kb_catalog` | 核对 `03-injection` 与 `07-client` 关联防御条目 |
| 入口回归验证 | `http_probe` | 切换到 `red` 或 `both` 轨道后核验污染接口是否返回 `400` 且 oracle 不变 |
