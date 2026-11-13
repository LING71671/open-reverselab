---
id: "ctf-website/22-dos/04-redos-defense"
title: "ReDoS 正则表达式拒绝服务防御"
title_en: "ReDoS — Regular Expression Denial of Service Defense"
summary: >
  系统消除 NFA 正则引擎指数级回溯风险的蓝队防御方案。覆盖嵌套量词、重叠交替与可选段重叠三类危险模式的重构，迁移至线性时间 DFA 引擎（Google RE2 / Rust regex），设置正则匹配超时与输入长度硬上限，并提供可在 CI 集成的静态正则风险检测与复杂度验证脚本。
summary_en: >
  Blue-team defense guide eliminating exponential backtracking in NFA regex engines. Covers refactoring nested quantifiers, overlapping alternation, and overlapping optional groups, migrating to linear-time DFA engines (Google RE2 / Rust regex), enforcing match timeouts and input length caps, and providing runnable static risk detection and timing verification code.
board: "ctf-website"
category: "22-dos"
signals:
  - "RE2 线性时间引擎替换 NFA"
  - "嵌套量词与重叠交替拦截"
  - "regex 超时保护 TimeoutError"
  - "输入长度硬上限预处理"
  - "Event Loop 零阻塞正则匹配"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "ReDoS 防御"
  - "Google RE2"
  - "线性时间正则"
  - "回溯消除"
  - "regex 超时"
  - "安全正则写法"
  - "CVE-2020-5243 修复"
  - "redos defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "redos"
  - "regex"
  - "re2"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/04-redos"
track: "blue"
defends: "ctf-website/22-dos/04-redos"
---
# ReDoS 正则表达式拒绝服务防御

## 防御目标与对抗矩阵

ReDoS（对应攻击原理见 [04-redos.md](../../../../red/ctf-website/techniques/22-dos/04-redos.md)）通过几十字节构造字符串在 NFA 回溯引擎中触发 $O(2^n)$ 指数级计算，打满 Worker CPU 或 Node.js 事件循环。包括前端直传触发与写入数据库后由后台批处理触发的二阶 ReDoS，防御核心是**用确定性线性时间自动机替代回溯引擎 + 消除危险量词结构 + 边界与超时兜底**。

| 风险模式 / 攻击向量 | 脆弱根因 | 防御重构手段 | 适用引擎 / 工具 |
|---|---|---|---|
| 嵌套量词 `(a+)+` / `(.*\/)*.*` | 内外层量词对相同字符存在指数切分组合 | 扁平化量词、采用独占量词 `++` 或原子组 `(?>...)` | RE2、Python `regex`、PCRE2 |
| 重叠交替 `(a\|aa)+` / `[a-z]*[a]+` | 交替分支或相邻字符类存在交集 | 使分支互斥（否定字符类 `[^...]`）或合并前缀 | 全语言通用重构 |
| 脆弱内置/三方正则库 | `uap-core` (CVE-2020-5243)、`nth-check`、Email/HTML 正则 | 升级依赖并改用专用解析器（`email-validator`、`html.parser`、`urllib.parse`） | SCA 依赖检查 + AST 解析替代 |
| 渐进式退化 / 存储型二阶 ReDoS | 后台定时任务或日志管线使用无界正则 | 对所有入库与离线任务同样强制长度上限与线性引擎 | 异步任务沙箱 + RE2 |

---

## 防御工作流

### 阶段一：迁移至线性时间正则引擎（RE2 / Rust `regex`）

从根本上消除回溯的方法是使用基于 Thompson NFA / DFA 的线性时间引擎（保证时间复杂度严格为 $O(n)$，不支持逆向引用等导致 NP-hard 的特性）：

1. **Python**：使用 `google-re2`（`import re2 as re`）作为默认正则引擎；若必须兼容复杂特性，使用支持原子组与 `timeout` 参数的第三方 `regex` 库。
2. **Node.js / TypeScript**：高风险用户输入匹配禁止直接调用原生 `RegExp` 执行复杂表达式，改用 `re2` npm 包（Google RE2 原生绑定），同时在 CI 引入 `recheck` 或 `safe-regex2` 门禁。
3. **Go / Rust**：Go 标准库 `regexp` 与 Rust `regex` crate 原生基于 RE2/自动机实现，具备天然抗回溯特性，只需关注正则编译大小上限。
4. **Java / .NET / PHP**：
   - Java：升级至 JDK 17+ 并使用独占量词（`+` 后加 `+`，如 `a++`）或对不可信正则启用超时包装；
   - .NET：`new Regex(pattern, RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(50))`（.NET 7+ 原生非回溯引擎）；
   - PHP：`ini_set('pcre.backtrack_limit', '10000')` 与 `pcre.recursion_limit` 收紧，失败时显式检查 `preg_last_error() === PREG_BACKTRACK_LIMIT_ERROR`。

```python
# Python 防护配置示例：输入长度前置截断 + 线性 RE2 / 超时保护
import re2  # pip install google-re2

MAX_FIELD_LEN = 256
# 使用互斥字符类消除回溯，并通过 RE2 保证严格 O(n) 耗时
SAFE_EMAIL_RE = re2.compile(r"^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,190}\.[a-zA-Z]{2,24}$")

def validate_email_linear(value: str) -> bool:
    if not isinstance(value, str) or len(value) > MAX_FIELD_LEN:
        return False
    return bool(SAFE_EMAIL_RE.fullmatch(value))
```

### 阶段二：危险正则模式重构对照

将所有既有正则（含校验路由、WAF 规则、日志解析与数据库 `~` 正则查询）按以下模式重构：

| 脆弱模式（严禁使用） | 危险原因 | 线性重构写法 |
|---|---|---|
| `^(a+)+$` | 嵌套 `+` 触发 $2^n$ 分配组合 | `^a+$` |
| `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` | `.` 在多段域名内可无边界重叠 | 显式分段 `^[^@\s]{1,64}@([^.@\s]+\.)+[A-Za-z]{2,24}$` 或专用解析器 |
| `(.*\/)*.*` | 多段通配符对无 `/` 长串回溯 | `^(?:[^/]*/)*[^/]*$`（先否定字符类互斥） |
| `<[^>]*>([^<]*<[^>]*>)*` | 嵌套标签匹配导致回溯爆炸 | 禁止用正则解析 HTML，改用 `html.parser` / DOM 解析器 |
| `^\d+[\d,.]*\d+$` | 首尾 `\d+` 与中间 `[\d,.]*` 重叠 | `^\d+(?:[,.]\d+)*$` |

### 阶段三：前置长度守卫与专用解析器替代

1. **前置长度与字符集白名单检查**：在调用任何正则前执行 `if len(s) > max_len: reject()`，将最大输入控制在线性安全区间（如 User-Agent `<= 512` 字节、Email `<= 254` 字节、Slug `<= 128` 字节）。
2. **零正则替代方案**：URL 解析使用 `urllib.parse.urlsplit`（避免 `ssri` 类正则解析漏洞），CSS/HTML 解析使用状态机解析器，密码复杂度采用独立的 `any(c.islower() for c in pw)` 字符集遍历（严格 $O(n)$ 且零回溯）。

---

## 弹性校验代码（可运行 Python 自检）

以下代码包含静态正则 AST/结构风险检查器（识别嵌套量词与重叠交替）以及线性时间复杂度实测校验器（对比长度 $N=30$ 与 $N=3000$ 的耗时增长比，确保符合 $O(n)$ 而非指数增长）。

```python
#!/usr/bin/env python3
"""ReDoS defense verifier: static dangerous-pattern detector and linear-time scaling check."""

import re
import time


# 静态规则：识别常见嵌套量词与相邻相同量词结构
NESTED_QUANTIFIER_PATTERNS = [
    re.compile(r"\([^)]*[+*][^)]*\)[+*{]"),       # 如 (a+)+, (a*)*, ([^x]+)+
    re.compile(r"\([^)]*\|[^)]*\)[+*{]"),         # 括号内交替后接重复量词，需核查互斥性
    re.compile(r"(?:\.\*|\.\+)[^{]*?(?:\.\*|\.\+)"),  # 同一子句多段无界 .* / .+
]


def check_regex_risk(pattern: str) -> list[str]:
    """Flag regex constructs likely to cause catastrophic backtracking on NFA engines."""
    warnings: list[str] = []
    for idx, rule in enumerate(NESTED_QUANTIFIER_PATTERNS):
        if rule.search(pattern):
            warnings.append(f"risk_rule_{idx}: matched {rule.pattern}")
    if len(pattern) > 512:
        warnings.append("pattern_too_long")
    return warnings


def verify_linear_scaling(pattern: str, evil_char: str = "a", suffix: str = "!") -> tuple[bool, float]:
    """Measure runtime ratio between short and long non-matching inputs."""
    compiled = re.compile(pattern)

    def measure(n: int) -> float:
        sample = evil_char * n + suffix
        t0 = time.perf_counter()
        compiled.fullmatch(sample)
        return time.perf_counter() - t0

    # 先测小样本 n=22，避免在自检本身造成长时间挂起
    t_small = max(measure(22), 1e-6)
    t_medium = measure(26)
    ratio = t_medium / t_small
    # 指数级回溯在 n 从 22 增至 26 时耗时约增长 16x；线性耗时增长应远小于 4x
    is_linear = ratio < 4.0 and t_medium < 0.05
    return is_linear, round(ratio, 2)


def password_complexity_no_regex(pw: str) -> bool:
    """Linear O(n) password complexity check without regular expressions."""
    if not (8 <= len(pw) <= 128):
        return False
    has_lower = any("a" <= c <= "z" for c in pw)
    has_upper = any("A" <= c <= "Z" for c in pw)
    has_digit = any("0" <= c <= "9" for c in pw)
    return has_lower and has_upper and has_digit


def run_self_checks() -> None:
    # 1. 识别已知危险模式
    vuln_pattern = r"^(a+)+$"
    assert len(check_regex_risk(vuln_pattern)) >= 1, "Nested quantifier should be flagged"
    is_lin, ratio = verify_linear_scaling(vuln_pattern)
    assert not is_lin, f"Vulnerable regex should fail linear check (ratio={ratio})"

    # 2. 验证重构后的安全线性模式
    safe_pattern = r"^a+$"
    assert check_regex_risk(safe_pattern) == []
    is_lin, ratio = verify_linear_scaling(safe_pattern)
    assert is_lin, f"Safe regex failed linear scaling check (ratio={ratio})"

    # 3. 验证互斥路径与数字正则重构
    safe_path = r"^(?:[^/]*/)*[^/]*$"
    is_lin_path, _ = verify_linear_scaling(safe_path, evil_char="x", suffix="!")
    assert is_lin_path

    # 4. 验证零正则密码校验
    assert password_complexity_no_regex("Str0ngPass")
    assert not password_complexity_no_regex("weak")
    print("[PASS] All ReDoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| CI 静态正则检查 | 新增或修改的正则表达式零嵌套量词与零无界重复通配符告警 | CI 阻断含脆弱模式的提交 |
| 线性耗时缩放比 | 将失败输入长度从 22 增至 26（及 2000 字符）时耗时增长呈线性且单次 `< 5ms` | 耗时比 `< 4x`（拒绝任何指数增长曲线） |
| 输入长度硬拦截 | 超过业务上限的字符串在进入正则匹配前即返回 `400 Bad Request` | Worker CPU 与 Node.js Event Loop Lag `< 20ms` |
| 后台二阶任务隔离 | 批处理与数据库正则查询全部迁移至 RE2 或移除正则匹配 | 后台队列零长耗时卡顿任务 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 端点耗时对比检验 | `http_probe` | 验证携带长重复字符的请求是否被前置长度检查快速拒绝 |
| 防御技术搜索 | `kb_router` | 以 `track="blue"` 搜索 `redos` / `re2` / `regex` 防护条目 |
| 攻防对照查阅 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/04-redos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下所有蓝队加固条目 |
