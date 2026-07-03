export const meta = {
  name: 'ctf-24h-fleet',
  description: 'Multi-target Web CTF 24h loop orchestrator: normalize targets, shard into batches, run ctf-24h-round for each target, synthesize fleet status',
  phases: [
    { title: '阶段一：目标归一化' },
    { title: '阶段二：批量并行 round' },
    { title: '阶段三：fleet 汇总与下一轮调度' },
  ],
}

// ================================================================
// args 规范：
//   string              → 单个 target，或逗号/空白/换行分隔的多个 targets
//   object.target       → 单个 target
//   object.targets      → target 数组或分隔字符串
//   object.fleetName    → fleet 名称；未传时从 targets hash/slug 生成
//   object.caseRoot     → case 根目录，默认 cases
//   object.casePrefix   → case 前缀；默认 fleetName
//   object.reportRoot   → report 根目录，默认 reports/ctf-website
//   object.batchSize    → 可选；每轮并行目标数，不传/0 表示全部并行
//   object.maxActions   → 可选数量参数；不传/0 表示全部
//   object.maxWorkflows → 可选数量参数；不传/0 表示全部
//   object.innerIterations → 可选；每个攻击 worker 内部迭代次数，不传表示迭代到收敛/状态变化
//   object.workerIds    → 每个 target 允许的 worker 列表
//   object.execute      → 是否执行 allowlist 动作，默认 true
// ================================================================

function slugify(value) {
  return String(value || 'target')
    .replace(/^https?:\/\//, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .slice(0, 80) || 'target'
}

function normalizeTargets(input) {
  if (Array.isArray(input)) return input.map(String).map(x => x.trim()).filter(Boolean)
  return String(input || '')
    .split(/[\s,]+/)
    .map(x => x.trim())
    .filter(Boolean)
}

const rawTargets =
  typeof args === 'string'
    ? args
    : args?.targets || args?.target || ''
const targets = [...new Set(normalizeTargets(rawTargets))]
if (targets.length === 0) {
  throw new Error('ctf-24h-fleet requires args.targets, args.target, or string targets')
}
const derivedFleetName = targets.length === 1 ? `fleet-${slugify(targets[0])}` : `fleet-${targets.length}-targets`
const fleetName = typeof args === 'object' && args?.fleetName ? slugify(args.fleetName) : derivedFleetName
const caseRoot = typeof args === 'object' && args?.caseRoot ? args.caseRoot : 'cases'
const casePrefix = typeof args === 'object' && args?.casePrefix ? slugify(args.casePrefix) : fleetName
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const batchSize = typeof args === 'object' && args?.batchSize ? Math.max(1, Number(args.batchSize)) : 0
const maxActions = typeof args === 'object' && args?.maxActions ? Number(args.maxActions) : 0
const maxWorkflows = typeof args === 'object' && args?.maxWorkflows ? Number(args.maxWorkflows) : 0
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0
const workerIds = typeof args === 'object' && args?.workerIds ? args.workerIds : []
const testOrigin = typeof args === 'object' && args?.testOrigin ? args.testOrigin : undefined
const redirectProbeHost = typeof args === 'object' && args?.redirectProbeHost ? args.redirectProbeHost : undefined
const ssrfProbeTargets = typeof args === 'object' && args?.ssrfProbeTargets ? args.ssrfProbeTargets : undefined
const credentialPairs = typeof args === 'object' && args?.credentialPairs ? args.credentialPairs : undefined
const forwardedIp = typeof args === 'object' && args?.forwardedIp ? args.forwardedIp : undefined
const execute = !(typeof args === 'object' && args?.execute === false)

phase('阶段一：目标归一化')

const targetPlan = await agent(
  `你是 Web CTF fleet controller。当前 workflow 负责多个/单个网站的同轮调度，不直接攻击。

## Fleet

- Fleet name: ${fleetName}
- Case root: ${caseRoot}
- Case prefix: ${casePrefix}
- Report root: ${reportRoot}
- Batch size: ${batchSize || 'all targets'}
- Max actions per target: ${maxActions || 'all'}
- Max attack workflows per target: ${maxWorkflows || 'all'}
- Inner iterations per attack worker: ${innerIterations || 'until convergence/status change'}
- Worker allowlist: ${JSON.stringify(workerIds)}
- Execute allowlist actions: ${execute}

## Targets

${targets.map((target, index) => `${index + 1}. ${target}`).join('\n') || '(empty)'}

## 任务

1. 为每个 target 生成稳定 caseName：\`${casePrefix}-<target-slug>\`。
2. 所有 case 必须落在 \`${caseRoot}/<caseName>\`。
3. 标记明显重复、格式异常或空目标。
4. 输出 JSON：

{
  "fleet": "${fleetName}",
  "batch_size": ${batchSize},
  "targets": [
    {"target": "<target>", "caseName": "${casePrefix}-<target-slug>", "enabled": true, "reason": ""}
  ]
}`,
  { label: 'fleet-plan', phase: '阶段一：目标归一化' },
)

phase('阶段二：批量并行 round')

const enabledTargets = targets.map(target => ({
  target,
  caseName: `${casePrefix}-${slugify(target)}`,
}))

const batches = []
const effectiveBatchSize = batchSize || enabledTargets.length
for (let i = 0; i < enabledTargets.length; i += effectiveBatchSize) {
  batches.push(enabledTargets.slice(i, i + effectiveBatchSize))
}

const batchResults = []
for (const [batchIndex, batch] of batches.entries()) {
  phase(`阶段二：批量并行 round ${batchIndex + 1}/${batches.length}`)
  const results = await parallel(
    batch.map(item => () =>
      workflow('ctf-24h-round', {
        target: item.target,
        caseName: item.caseName,
        manifest: `${caseRoot}/${item.caseName}/ai_manifest.json`,
        caseRoot,
        reportRoot,
        maxActions,
        maxWorkflows,
        innerIterations,
        workerIds,
        testOrigin,
        redirectProbeHost,
        ssrfProbeTargets,
        credentialPairs,
        forwardedIp,
        execute,
        stopOnExhausted: true,
      }),
    ),
  )
  batchResults.push({ batch: batchIndex + 1, targets: batch, results })
}

phase('阶段三：fleet 汇总与下一轮调度')

const final = await agent(
  `你是 fleet 汇总器。根据所有 target round 输出，生成 fleet-level 状态。

## Target plan

${targetPlan}

## Batch results

${JSON.stringify(batchResults, null, 2)}

## 判定

- 如果任一 target 是 DONE，fleet 状态仍可 CONTINUE，除非所有目标都 DONE/EXHAUSTED。
- 如果所有目标 DONE，输出 DONE。
- 如果所有目标 EXHAUSTED，输出 EXHAUSTED。
- 其他情况输出 CONTINUE。

## 写回

在 \`${reportRoot}/${fleetName}/fleet-round-<timestamp>.md\` 写 fleet 汇总：

- 每个 target 的 STATUS / MANIFEST / NEXT
- 哪些目标下一轮继续
- 哪些目标已 DONE/EXHAUSTED
- fleet 级下一轮 batch 建议

## 最终输出格式

只输出：

STATUS: CONTINUE|DONE|EXHAUSTED
FLEET: ${fleetName}
TARGETS: ${enabledTargets.length}
REPORT: <path>
NEXT: <one-line next batch focus>`,
  { label: 'fleet-status', phase: '阶段三：fleet 汇总与下一轮调度' },
)

return {
  fleetName,
  targets: enabledTargets,
  batchSize,
  maxActions,
  maxWorkflows,
  innerIterations,
  caseRoot,
  casePrefix,
  reportRoot,
  workerIds,
  execute,
  batchResults,
  final,
}
