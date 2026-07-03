export const meta = {
  name: 'ctf-attack-client',
  description: 'Client-side worker: XSS, CORS, CSP, CSRF, postMessage, WebSocket, Web Crypto, admin bot',
  phases: [
    { title: 'KB 路由' },
    { title: '客户端攻击验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-client requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-client requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 client-side 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "xss cors csp csrf postmessage websocket web crypto admin bot"
\`\`\`
读取 07-client、18-cors-csp-advanced。`,
  { label: 'client-kb', phase: 'KB 路由' },
)

phase('客户端攻击验证')
const result = await agent(
  `对 ${target} 做一轮 client worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute client payload/probe → observe reflection/CORS/CSP/browser sink → mutate context/encoding/event/source → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. Reflected/DOM/stored XSS：上下文识别、payload 编码、CSP 影响。
2. CORS：Origin 反射、ACAC、null origin、子域伪造。
3. CSP：nonce/hash、unsafe-inline、JSONP/script gadget、base-uri/form-action。
4. CSRF：敏感 POST 是否缺 token/SameSite，结合 XSS/CORS。
5. postMessage：origin check、targetOrigin、token leak。
6. WebSocket：CSWSH、message injection、auth token in URL。
7. Web Crypto：前端签名/加密 key、可重放 nonce、client-side trust。
8. Admin bot：XSS -> cookie/localStorage/SSRF/RCE 链。

输出 JSON: evidence_added, dead_ends_added, next_round_focus, poc_files, signals_seen。`,
  { label: 'client-run', phase: '客户端攻击验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 client 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-client.md。

Client result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'client-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
