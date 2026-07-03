export const meta = {
  name: 'ctf-attack-router',
  description: 'Route Web CTF signals/focus items to concrete attack workflows and run selected workers in parallel',
  phases: [
    { title: '攻击信号路由' },
    { title: '并行攻击 worker' },
    { title: '路由汇总' },
  ],
}

// args: { target, caseName, manifest, signals?, focus?, maxWorkflows?, workerIds?, reportRoot?, execute? }
const target = typeof args === 'string' ? args : args?.target || ''
if (!target) {
  throw new Error('ctf-attack-router requires args.target or string target')
}
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) {
  throw new Error('ctf-attack-router requires args.caseName and args.manifest')
}
const signals = typeof args === 'object' && args?.signals ? args.signals : []
const focus = typeof args === 'object' && args?.focus ? args.focus : []
const maxWorkflows = typeof args === 'object' && args?.maxWorkflows ? Number(args.maxWorkflows) : 0
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0
const workerIds = typeof args === 'object' && args?.workerIds ? args.workerIds : []
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const testOrigin = typeof args === 'object' && args?.testOrigin ? args.testOrigin : undefined
const redirectProbeHost = typeof args === 'object' && args?.redirectProbeHost ? args.redirectProbeHost : undefined
const ssrfProbeTargets = typeof args === 'object' && args?.ssrfProbeTargets ? args.ssrfProbeTargets : undefined
const credentialPairs = typeof args === 'object' && args?.credentialPairs ? args.credentialPairs : undefined
const forwardedIp = typeof args === 'object' && args?.forwardedIp ? args.forwardedIp : undefined
const execute = !(typeof args === 'object' && args?.execute === false)
const allowedWorkerIds = workerIds.length ? workerIds : [
  'recon',
  'auth',
  'injection',
  'file_ssrf',
  'client',
  'api_business',
  'cve_cloud_dos',
]

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

${allowedWorkerIds.map(id => `- ${id}`).join('\n')}

## 规则

1. 先读 \`kb/ctf-website/techniques/attack-network.md\`。
2. 为每个信号运行 \`python3 scripts/ctf-website/kb_router.py "<signal>"\`。
3. 本轮 worker 数量参数：${maxWorkflows || 'all allowed workers'}；优先能通向 Credential/DB/Admin/RCE/Flag 的路径。
4. 输出 JSON，routes 数组只使用允许的 worker id：

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

const filtered = selected.filter(route => allowedWorkerIds.includes(route))
const fallback = allowedWorkerIds.filter(route => ['recon', 'injection'].includes(route))
const routeCandidates = filtered.length ? filtered : fallback.length ? fallback : allowedWorkerIds
const routes = maxWorkflows > 0 ? routeCandidates.slice(0, maxWorkflows) : routeCandidates
const workers = routes.map(route => () => workflow(`ctf-attack-${route}`, {
  target,
  caseName,
  manifest,
  signals,
  focus,
  reportRoot,
  testOrigin,
  redirectProbeHost,
  ssrfProbeTargets,
  credentialPairs,
  forwardedIp,
  innerIterations,
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
5. 写 \`${reportRoot}/${caseName}/attack-router-round-<timestamp>.md\`。

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
