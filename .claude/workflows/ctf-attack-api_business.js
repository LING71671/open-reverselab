export const meta = {
  name: 'ctf-attack-api_business',
  description: 'API and business-logic worker: API discovery, IDOR/BAC, mass assignment, rate limit, payment, signature',
  phases: [
    { title: 'KB 路由' },
    { title: 'API 与业务逻辑验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-api_business requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-api_business requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 API/business 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "api idor bac mass assignment rate limit payment signature replay nonce"
\`\`\`
读取 14-idor、15-mass-assignment、16-rate-limit、17-api-attacks、12-payment、13-signature。`,
  { label: 'api-business-kb', phase: 'KB 路由' },
)

phase('API 与业务逻辑验证')
const result = await agent(
  `对 ${target} 做一轮 API/business worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute API/business mutation → observe object/state/price/signature difference → mutate parameter/order/replay/race key → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. API discovery：swagger/openapi/graphql/actuator/.well-known/JS endpoints。
2. IDOR/BAC：对象 ID、订单 ID、用户 ID、文件 ID、horizontal/vertical access。
3. Mass assignment：role/isAdmin/price/quota/status/user_id/order_id 字段覆盖。
4. Rate limit：登录/OTP/优惠券/兑换/抢购/搜索 API 的绕过与 key 选择。
5. Payment：金额/币种/优惠券/回调/replay/idempotency/lost update。
6. Signature：canonicalization、alg downgrade、key leak、length extension、nonce/replay。

所有状态变更类测试要先保存 request，并用最小差异验证；证据写入 exports/notes/reports。
输出 JSON: evidence_added, dead_ends_added, next_round_focus, saved_requests, attack_chains。`,
  { label: 'api-business-run', phase: 'API 与业务逻辑验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 API/business 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-api-business.md。

API/business result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'api-business-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
