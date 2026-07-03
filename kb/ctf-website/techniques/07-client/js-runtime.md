---
id: "ctf-website/07-client/js-runtime"
title: "JS Runtime / Browser Reversing"
title_en: "JS Runtime / Browser Reversing"
summary: >
  前端 JS 逆向的实战目标是把混淆 bundle、运行时请求、签名函数、crypto 参数、WASM 导出和状态存储还原成可复现脚本。本篇给出入口信号、bundle 路由矩阵、导航前 hook、fetch/XHR/WebSocket/WebCrypto/CryptoJS 打点、AST 去混淆脚手架、签名复现和 Evidence 模板。
summary_en: >
  Front-end JS reversing turns obfuscated bundles, runtime requests, signature functions, crypto parameters, WASM exports, and state storage into reproducible scripts. Includes signal routing, bundle matrices, pre-navigation hooks, fetch/XHR/WebSocket/WebCrypto/CryptoJS instrumentation, AST scaffolds, signature replay, and evidence templates.
board: "ctf-website"
category: "07-client"
signals: ["JS逆向", "AST去混淆", "WebAssembly", "runtime hook", "浏览器逆向", "Babel", "CryptoJS", "webpack"]
mcp_tools: ["http_probe", "kb_router", "jshook"]
keywords: ["JS运行时逆向", "Babel AST", "代码去混淆", "WebAssembly", "CryptoJS Hook", "前端逆向", "runtime hook", "Proxy劫持"]
difficulty: "advanced"
tags: ["reverse-engineering", "javascript", "crypto", "ctf", "browser"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/07-client/web-crypto-abuse", "ctf-website/12-payment/ticket-rush-api-reversing", "ctf-website/13-signature/00-overview"]
---
# JS Runtime / Browser Reversing

JS Runtime 逆向不是把 bundle 从头读完，而是先把请求、签名、加密、状态和 WASM 的关键边界打出来，再决定是动态复现、AST 静态还原，还是直接劫持 runtime oracle。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| bundle 里有 `sign/token/nonce/timestamp` | hook fetch/XHR 与签名函数 | 请求参数与签名输入同步出现 | sign 在服务端生成 |
| Webpack/Vite chunk 分裂 | 提取 chunk map、source map、动态 import | 找到 API path 和 crypto 模块 | chunk 加载前 hook 太晚 |
| CryptoJS/WebCrypto | hook encrypt/decrypt/sign/importKey | key/iv/plain/cipher 出现 | 调用在 Worker/WASM 内 |
| `debugger`/console 检测 | hook timer/toString/Function | 调试不中断，逻辑继续 | 检测在闭包里自校验 |
| WASM 模块 | dump bytes、exports、memory | 导出函数和输入输出可复现 | indirect table 混淆未定位 |
| Worker/Service Worker | hook Worker 构造和 postMessage | worker 脚本 URL/消息可见 | CSP/COOP 影响调试 |

## 工作流

```text
抓 HTML 与所有 JS chunk
  → 导航前注入 runtime hook
  → 触发关键业务动作并保存请求/响应/console
  → 定位签名/crypto/WASM/worker 模块
  → AST 还原或直接复现算法
  → 用 Python/Node 重放 API，记录成功和失败样本
```

## 0. Bundle 路由矩阵

| 入口 | 目标 | 工具/动作 |
|---|---|---|
| `main.*.js` / `app.*.js` | 路由、API client、状态管理 | 搜 `baseURL`, `axios`, `fetch`, `/api/` |
| `vendor.*.js` | crypto/lib/framework gadget | 搜 `CryptoJS`, `subtle`, `protobuf`, `wasm` |
| source map | 还原源码路径和函数名 | 下载 `.map`，按 sourcesContent 检索 |
| dynamic chunk | 登录后/点击后逻辑 | hook script append/import |
| Worker | 签名、加密、WASM | hook `new Worker`、`postMessage` |

## 1. 导航前总 hook

```javascript
(() => {
  const enc = v => {
    if (v instanceof ArrayBuffer) return Array.from(new Uint8Array(v)).map(b=>b.toString(16).padStart(2,"0")).join("");
    if (ArrayBuffer.isView(v)) return Array.from(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)).map(b=>b.toString(16).padStart(2,"0")).join("");
    try { return typeof v === "string" ? v : JSON.stringify(v); } catch { return String(v); }
  };
  const oldFetch = window.fetch;
  window.fetch = async function(input, init = {}) {
    const url = String(input && input.url || input);
    console.log("[fetch:req]", url, enc(init.headers || {}), enc(init.body || ""));
    const r = await oldFetch.apply(this, arguments);
    r.clone().text().then(t => console.log("[fetch:resp]", url, r.status, t.slice(0, 1200))).catch(()=>{});
    return r;
  };
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this.__rt_method = method; this.__rt_url = url;
    return open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    console.log("[xhr:req]", this.__rt_method, this.__rt_url, enc(body || ""));
    this.addEventListener("load", () => console.log("[xhr:resp]", this.__rt_url, this.status, String(this.responseText).slice(0, 1200)));
    return send.apply(this, arguments);
  };
  const oldWorker = window.Worker;
  window.Worker = function(url, opts) {
    console.log("[worker:new]", url, opts || "");
    return new oldWorker(url, opts);
  };
})();
```

## 2. crypto / sign 打点

```javascript
(() => {
  const show = x => {
    try { return JSON.stringify(x); } catch { return String(x); }
  };
  if (window.crypto && crypto.subtle) {
    for (const n of ["importKey","generateKey","deriveKey","encrypt","decrypt","sign","verify"]) {
      const o = crypto.subtle[n].bind(crypto.subtle);
      crypto.subtle[n] = async (...a) => {
        console.log("[subtle:req]", n, a.map(show));
        const r = await o(...a);
        console.log("[subtle:ret]", n, r && r.algorithm, r && r.usages);
        return r;
      };
    }
  }
  const names = ["sign","getSign","makeSign","encrypt","decrypt","encode","decode"];
  for (const k of names) {
    if (typeof window[k] === "function") {
      const o = window[k];
      window[k] = function(...a) {
        console.log("[fn:req]", k, a.map(show));
        const r = o.apply(this, a);
        console.log("[fn:ret]", k, show(r));
        return r;
      };
    }
  }
})();
```

成功样本：同一次业务请求里同时记录到 `params/raw/timestamp/nonce/key/iv/sign`。失败样本：只有密文或签名结果，没有输入；需要 hook 更早或找 Worker/WASM。

## 3. AST 去混淆脚手架

```javascript
#!/usr/bin/env node
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");

const code = fs.readFileSync(process.argv[2], "utf8");
const ast = parser.parse(code, {sourceType: "unambiguous"});

traverse(ast, {
  BinaryExpression(path) {
    const ev = path.evaluate();
    if (ev.confident && ["string","number","boolean"].includes(typeof ev.value)) {
      path.replaceWith(t.valueToNode(ev.value));
    }
  },
  MemberExpression(path) {
    const prop = path.node.property;
    if (path.node.computed && t.isStringLiteral(prop)) {
      path.node.computed = false;
      path.node.property = t.identifier(prop.value);
    }
  },
  IfStatement(path) {
    const ev = path.get("test").evaluate();
    if (ev.confident && typeof ev.value === "boolean") {
      path.replaceWith(ev.value ? path.node.consequent : (path.node.alternate || t.emptyStatement()));
    }
  }
});

fs.writeFileSync(process.argv[3] || "deobfuscated.js", generate(ast, {comments:false}).code);
```

## 4. Webpack chunk 抽取

```javascript
(() => {
  const scripts = [...document.scripts].map(s => s.src).filter(Boolean);
  console.log("[scripts]", scripts);
  const oldAppend = Element.prototype.appendChild;
  Element.prototype.appendChild = function(n) {
    if (n && n.tagName === "SCRIPT") console.log("[script:append]", n.src || n.textContent.slice(0, 120));
    return oldAppend.call(this, n);
  };
  for (const k of Object.keys(window)) {
    if (/webpackJsonp|webpackChunk|__LOADABLE_LOADED_CHUNKS__/.test(k)) console.log("[webpack-global]", k, window[k]);
  }
})();
```

## 5. WASM 打点

```javascript
(() => {
  const oldInstantiate = WebAssembly.instantiate;
  WebAssembly.instantiate = async function(src, imports) {
    const bytes = src instanceof ArrayBuffer ? new Uint8Array(src) : null;
    if (bytes) {
      console.log("[wasm:bytes]", bytes.length);
      window.__wasm_dump = Array.from(bytes);
    }
    const r = await oldInstantiate.apply(this, arguments);
    const inst = r.instance || r;
    console.log("[wasm:exports]", Object.keys(inst.exports));
    for (const [name, fn] of Object.entries(inst.exports)) {
      if (typeof fn === "function") {
        inst.exports[name] = new Proxy(fn, {
          apply(target, self, args) {
            console.log("[wasm:req]", name, args);
            const out = Reflect.apply(target, self, args);
            console.log("[wasm:ret]", name, out);
            return out;
          }
        });
      }
    }
    return r;
  };
})();
```

## 6. 签名复现骨架

```python
#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import time

def canonical(params):
    return "&".join(f"{k}={params[k]}" for k in sorted(params))

def sign(params, secret, algo="sha256"):
    raw = canonical(params)
    digest = hmac.new(secret.encode(), raw.encode(), getattr(hashlib, algo)).hexdigest()
    return raw, digest

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", required=True, help="JSON params from hook")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--algo", default="sha256")
    args = ap.parse_args()
    params = json.loads(args.params)
    params.setdefault("timestamp", str(int(time.time())))
    raw, sig = sign(params, args.secret, args.algo)
    print(json.dumps({"raw": raw, "sign": sig, "params": {**params, "sign": sig}}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

判定：复现脚本生成的 `sign/token` 与浏览器 hook 结果一致，才进入 API 重放；不一致时回到 canonicalization、编码、timestamp、nonce、salt。

## 攻击链

```text
bundle/chunk 枚举
  → runtime hook 捕获请求和 crypto 输入
  → AST 还原签名/加密模块
  → Python/Node 复现算法
  → 重放 API 或生成 payload
  → 转支付、JWT、签名、WebCrypto、WASM 下一跳
```

## Evidence

| 项 | 记录内容 |
|---|---|
| bundle 来源 | HTML、script URL、chunk map、source map、hash |
| runtime 日志 | fetch/XHR/WS、Worker、crypto、WASM 的输入输出 |
| 静态还原 | AST 脚本、还原前后片段、关键函数名 |
| 复现结果 | canonical string、secret/key、timestamp/nonce、签名值 |
| 成功样本 | 复现签名后 API 接受、flag/订单/token/权限数据返回 |
| 失败样本 | hook 太晚、签名不一致、nonce 过期、服务端二次校验 |
| 下一跳 | crypto 转 `web-crypto-abuse`；支付转 `12-payment`；签名转 `13-signature` |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| JS 行为探测 | `jshook` | 导航前注入 fetch/XHR/crypto/WASM hook |
| 端点与 bundle | `http_probe` | 下载 HTML、JS、source map、API 样本 |
| 知识路由 | `kb_router` | 按 JS runtime、CryptoJS、WASM、签名信号搜索 |
