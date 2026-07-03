export const meta = {
  name: 'ctf-attack-cve_cloud_dos',
  description: 'CVE/cloud/supply/DoS/database worker: fingerprint-to-CVE, cloud metadata, CI/CD, Kubernetes, DoS, database chains',
  phases: [
    { title: 'KB 路由' },
    { title: 'CVE/Cloud/DoS/Database 验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-cve_cloud_dos requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-cve_cloud_dos requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 CVE/cloud/supply/DoS/database 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "cve cloud kubernetes lambda ci cd dependency confusion dos database backup config"
\`\`\`
读取 09-cve、10-cloud、11-supply-chain、22-dos、24-database。`,
  { label: 'cve-cloud-dos-kb', phase: 'KB 路由' },
)

phase('CVE/Cloud/DoS/Database 验证')
const result = await agent(
  `对 ${target} 做一轮 CVE/cloud/DoS/database worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute fingerprint/CVE/cloud/DoS/database probe → observe version/status/timing/config evidence → mutate CVE candidate/path/payload → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. 如果 fingerprints.json 存在，运行 fingerprint_cve_pipeline.py，生成 CVE graph/chain。
2. 对 CVE 候选做非破坏验证：版本证据、路径证据、PoC 响应差异。
3. Cloud：SSRF metadata、AWS/Aliyun/Tencent metadata、K8s service account、Lambda/env、CI/CD secrets。
4. Supply chain：package name、CI workflow injection、dependency confusion 信号。
5. DoS：按 workflow 参数执行应用层/协议/资源耗尽验证，记录可利用条件和防护缺口。
6. Database：SQLi 深入、NoSQLi、配置泄露、备份/log 泄露、发卡/卡密/数据清洗链。

输出 JSON: evidence_added, dead_ends_added, next_round_focus, cve_candidates, attack_chains。`,
  { label: 'cve-cloud-dos-run', phase: 'CVE/Cloud/DoS/Database 验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 CVE/cloud/DoS/database 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-cve-cloud-dos.md。

CVE/cloud/DoS/database result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'cve-cloud-dos-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
