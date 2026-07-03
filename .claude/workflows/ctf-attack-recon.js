export const meta = {
  name: 'ctf-attack-recon',
  description: 'Recon worker: asset discovery, route discovery, JS/API mining, fingerprint, subdomain takeover',
  phases: [
    { title: 'KB 路由' },
    { title: '资产与路由发现' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-recon requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-recon requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 recon / fingerprint / route discovery / subdomain takeover 读取 KB。

必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "recon fingerprint route api subdomain takeover"
\`\`\`
然后读取 top 技术文档，尤其是 01-recon、17-api-attacks、19-dns-email。`,
  { label: 'recon-kb', phase: 'KB 路由' },
)

phase('资产与路由发现')
const result = await agent(
  `对 ${target} 做一轮有界 recon。

Manifest: ${manifest}
Case: ${caseName}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → enumerate → observe new endpoints/fingerprints → expand route/JS/API/subdomain set → retry。不要只做首页一次；未设置 innerIterations 时迭代到无新增资产/信号。
1. HTTP baseline、redirect、headers、cookies、TLS 证书 SAN。
2. robots.txt / sitemap.xml / .well-known / swagger / api-docs / graphql / actuator。
3. 首页和 JS bundle：提取 fetch/XHR/WebSocket/API base URL、source map、硬编码 key。
4. 子域/虚拟主机信号：CNAME、dangling DNS、GitHub/search exposure。
5. 版本指纹：写入 cases/<case>/fingerprints.json 或补充 manifest fingerprints。

证据写入 exports/ctf-website/${caseName}/ 和 notes/ctf-website/${caseName}/。
输出 JSON: evidence_added, dead_ends_added, next_round_focus, signals_seen。`,
  { label: 'recon-run', phase: '资产与路由发现' },
)

phase('证据写回')
const summary = await agent(
  `把 recon 结果合并到 ${manifest}，并写 ${reportRoot}/${caseName}/attack-recon.md。

Recon result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'recon-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
