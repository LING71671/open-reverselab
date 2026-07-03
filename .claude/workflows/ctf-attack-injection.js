export const meta = {
  name: 'ctf-attack-injection',
  description: 'Injection worker: SQLi/NoSQLi/SSTI/GraphQL/HPP/CRLF/prototype pollution/gRPC',
  phases: [
    { title: 'KB 路由' },
    { title: '注入面验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-injection requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-injection requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 injection 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "sqli nosqli ssti graphql hpp crlf prototype pollution grpc"
\`\`\`
读取 03-injection 与 24-database 相关文件。`,
  { label: 'injection-kb', phase: 'KB 路由' },
)

phase('注入面验证')
const result = await agent(
  `对 ${target} 做一轮注入 worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute payload/request → observe response/evidence → mutate payload/encoding/context → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. 参数/表单/API/GraphQL endpoint 枚举。
2. SQLi/NoSQLi：error/boolean/time 差异；可疑 request 用 ctf_save_request 保存，SQLi 交给 run_sqlmap_request。
3. SSTI：{{7*7}}, ${7*7}, <%= 7*7 %>，按模板引擎确认上下文。
4. GraphQL：introspection、field suggestion、batch/alias amplification、SQLi via args。
5. HPP/CRLF：重复参数、数组参数、header splitting、cache poisoning。
6. Prototype pollution：__proto__/constructor/prototype 到模板/RCE 或权限绕过。
7. gRPC/protobuf：反射、proto 泄露、字段 fuzz。

输出 JSON: confirmed/probable/false_positive, saved_requests, evidence_added, dead_ends_added, next_round_focus。`,
  { label: 'injection-run', phase: '注入面验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 injection 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-injection.md。

Injection result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'injection-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
