export const meta = {
  name: 'ctf-attack-router',
  description: 'Route Web CTF signals/focus items to concrete attack workflows and run selected workers in parallel',
  phases: [
    { title: '攻击信号路由' },
    { title: '并行攻击 worker' },
    { title: '路由汇总' },
  ],
}

// args: { target, caseName, manifest, signals?, focus?, maxWorkflows?, execute? }
const target = typeof args === 'string' ? args : args?.target || ''
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : 'ctf-case'
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : `cases/${caseName}/ai_manifest.json`
const signals = typeof args === 'object' && args?.signals ? args.signals : []
const focus = typeof args === 'object' && args?.focus ? args.focus : []
const maxWorkflows = typeof args === 'object' && args?.maxWorkflows ? Number(args.maxWorkflows) : 4
const execute = !(typeof args === 'object' && args?.execute === false)

phase('攻击信号路由')

const routePlan = await agent(
  `你是 Web CTF 攻击 workflow 路由器。根据 manifest、signals、focus 选择本轮要跑的攻击 worker。

## Target
${target}

## Case / Manifest
- Case: ${caseName}
- Manifest: ${manifest}

## Signals
${JSON.stringify(signals, null, 2)}

## Focus
${JSON.stringify(focus, null, 2)}

## 可选 worker

- recon: 资产/路由/JS/API/fingerprint/子域接管
- auth: JWT/OAuth/SAML/Host Header/session/cookie
- injection: SQLi/NoSQLi/SSTI/GraphQL/HPP/CRLF/Prototype Pollution
- file_ssrf: LFI/path traversal/upload/XXE/SSRF/open redirect
- client: XSS/CORS/CSP/postMessage/WebSocket/admin bot
- api_business: API discovery/IDOR/mass assignment/rate limit/payment/signature
- cve_cloud_dos: CVE graph/cloud/supply chain/DoS/database DoS

## 规则

1. 先读 \`kb/ctf-website/techniques/attack-network.md\`。
2. 为每个信号运行 \`python3 scripts/ctf-website/kb_router.py "<signal>"\`。
3. 本轮最多选择 ${maxWorkflows} 个 worker，优先能通向 Credential/DB/Admin/RCE/Flag 的路径。
4. 输出 JSON，routes 数组只使用上面的 worker id：

{
  "routes": ["recon", "injection"],
  "reason": "why these workers",
  "kb_signals": ["sqli", "jwt"]
}`,
  { label: 'attack-router', phase: '攻击信号路由' },
)

phase('并行攻击 worker')

const routeText = String(routePlan).toLowerCase()
const selected = []
if (routeText.includes('recon')) selected.push('recon')
if (routeText.includes('auth')) selected.push('auth')
if (routeText.includes('injection')) selected.push('injection')
if (routeText.includes('file_ssrf')) selected.push('file_ssrf')
if (routeText.includes('client')) selected.push('client')
if (routeText.includes('api_business')) selected.push('api_business')
if (routeText.includes('cve_cloud_dos')) selected.push('cve_cloud_dos')

const routes = (selected.length ? selected : ['recon', 'injection']).slice(0, maxWorkflows)
const workers = routes.map(route => () => workflow(`ctf-attack-${route}`, {
  target,
  caseName,
  manifest,
  signals,
  focus,
  execute,
}))

const workerResults = await parallel(workers)

phase('路由汇总')

const summary = await agent(
  `汇总本轮攻击 worker 输出并写回 manifest。

## Route plan
${routePlan}

## Worker results
${JSON.stringify(workerResults, null, 2)}

## 写回要求

1. 读取 ${manifest}。
2. 将每个 worker 的 confirmed evidence 合并到 \`evidence[]\`。
3. 将失败但有价值的路径合并到 \`dead_ends[]\`。
4. 将下一轮建议合并到 \`next_round_focus[]\`。
5. 写 \`reports/ctf-website/${caseName}/attack-router-round-<timestamp>.md\`。

## 输出 JSON

{
  "status": "CONTINUE|DONE|EXHAUSTED",
  "evidence_added": [],
  "dead_ends_added": [],
  "next_round_focus": [],
  "report": "<path>"
}`,
  { label: 'attack-router-summary', phase: '路由汇总' },
)

return {
  target,
  caseName,
  manifest,
  routePlan,
  routes,
  workerResults,
  summary,
}
