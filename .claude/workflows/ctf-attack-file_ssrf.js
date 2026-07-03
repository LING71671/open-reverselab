export const meta = {
  name: 'ctf-attack-file_ssrf',
  description: 'File and SSRF worker: LFI/path traversal/upload/XXE/file wrappers/SSRF/open redirect',
  phases: [
    { title: 'KB 路由' },
    { title: '文件与 SSRF 验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-file_ssrf requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-file_ssrf requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0
const ssrfProbeTargets = typeof args === 'object' && args?.ssrfProbeTargets ? args.ssrfProbeTargets : [
  'http://127.0.0.1/',
  'http://localhost/',
  'http://169.254.169.254/',
]

phase('KB 路由')
const kb = await agent(
  `为 file/SSRF 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "lfi path traversal file upload xxe ssrf open redirect"
\`\`\`
读取 04-ssrf、06-file-attacks、08-infra 相关文件。`,
  { label: 'file-ssrf-kb', phase: 'KB 路由' },
)

phase('文件与 SSRF 验证')
const result = await agent(
  `对 ${target} 做一轮 file/SSRF worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute file/URL payload → observe status/body/timing → mutate traversal encoding/protocol/host/path → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. LFI/path traversal 参数：file/path/page/include/download/view/img/doc。
2. 平台特定文件：/etc/passwd、/proc/self/environ、WEB-INF/web.xml、web.config、.env、config.php。
3. Upload/XXE：上传表单、content-type 绕过、SVG/XML XXE、zip slip，仅做有界验证。
4. SSRF 参数：url/uri/redirect/callback/proxy/fetch/webhook/avatar/image。
5. SSRF 目标使用 args.ssrfProbeTargets；当前配置：${ssrfProbeTargets.join(', ')}，优先 timing/response 差异。
6. Open Redirect：OAuth/CAS service/redirect_uri 链接到凭据/SSRF。

输出 JSON: evidence_added, dead_ends_added, next_round_focus, payloads_tested, saved_requests。`,
  { label: 'file-ssrf-run', phase: '文件与 SSRF 验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 file/SSRF 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-file-ssrf.md。

File/SSRF result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'file-ssrf-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
