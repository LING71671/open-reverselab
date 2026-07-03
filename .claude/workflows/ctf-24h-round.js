export const meta = {
  name: 'ctf-24h-round',
  description: 'Web CTF 24h loop 的单轮有状态 workflow：初始化/读取 manifest → 执行一轮推进 → 写 checkpoint → 返回 CONTINUE/DONE/EXHAUSTED',
  phases: [
    { title: '阶段一：读取 checkpoint' },
    { title: '阶段二：单轮自动推进' },
    { title: '阶段三：Agent 攻击网推进' },
    { title: '阶段四：写回与停止判断' },
  ],
}

// ================================================================
// args 规范：
//   string             → target URL/domain
//   object.target      → 目标 URL/domain
//   object.caseName    → case 名；默认从 target 生成
//   object.manifest    → ai_manifest.json 路径；有则优先使用
//   object.caseRoot    → case 根目录，默认 cases
//   object.reportRoot  → report 根目录，默认 reports/ctf-website
//   object.maxActions  → 可选数量参数；不传/0 表示全部
//   object.maxWorkflows → 可选数量参数；不传/0 表示全部
//   object.innerIterations → 可选；每个 attack worker 内部迭代次数，不传表示迭代到收敛/状态变化
//   object.workerIds   → 可选攻击 worker allowlist
//   object.execute     → 是否执行 allowlist 动作，默认 true
//   object.stopOnExhausted → 全路径耗尽时停止，默认 true
// ================================================================

const rawTarget = typeof args === 'string' ? args : args?.target || ''
if (!rawTarget) {
  throw new Error('ctf-24h-round requires args.target or string target')
}
const target = rawTarget
const safeTarget = target
  .replace(/^https?:\/\//, '')
  .replace(/[^a-zA-Z0-9._-]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .toLowerCase()
const caseRoot = typeof args === 'object' && args?.caseRoot ? args.caseRoot : 'cases'
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : safeTarget
const caseDir = `${caseRoot}/${caseName}`
const manifest =
  typeof args === 'object' && args?.manifest
    ? args.manifest
    : `${caseDir}/ai_manifest.json`
const maxActions = typeof args === 'object' && args?.maxActions ? args.maxActions : 0
const maxWorkflows = typeof args === 'object' && args?.maxWorkflows ? args.maxWorkflows : 0
const innerIterations = typeof args === 'object' && args?.innerIterations ? args.innerIterations : 0
const workerIds = typeof args === 'object' && args?.workerIds ? args.workerIds : []
const testOrigin = typeof args === 'object' && args?.testOrigin ? args.testOrigin : undefined
const redirectProbeHost = typeof args === 'object' && args?.redirectProbeHost ? args.redirectProbeHost : undefined
const ssrfProbeTargets = typeof args === 'object' && args?.ssrfProbeTargets ? args.ssrfProbeTargets : undefined
const credentialPairs = typeof args === 'object' && args?.credentialPairs ? args.credentialPairs : undefined
const forwardedIp = typeof args === 'object' && args?.forwardedIp ? args.forwardedIp : undefined
const execute = !(typeof args === 'object' && args?.execute === false)
const stopOnExhausted = !(typeof args === 'object' && args?.stopOnExhausted === false)

phase('阶段一：读取 checkpoint')

const checkpoint = await agent(
  `你是 Claude Code /loop 中的一轮 Web CTF controller。当前目标不是一次性跑完 24 小时，而是完成一个有界 round，写 checkpoint，然后返回明确状态。全流程无人值守，不等待人工审批；平台权限/审批由 Claude Code 或 Codex 启动参数负责。

## 输入

- Target: ${target}
- Case name: ${caseName}
- Manifest path: ${manifest}
- Case root: ${caseRoot}
- Report root: ${reportRoot}
- Max actions: ${maxActions || 'all'}
- Max attack workflows: ${maxWorkflows || 'all'}
- Inner iterations per attack worker: ${innerIterations || 'until convergence/status change'}
- Execute allowlist actions: ${execute}

## 必读

1. 读取 \`AI-USAGE.md\`
2. 读取 \`boards/ctf-website/AI-USAGE.md\`
3. 读取 \`kb/ctf-website/techniques/attack-network.md\`

## 初始化 / 恢复

如果 \`${manifest}\` 不存在：

\`\`\`bash
python3 scripts/ctf-website/ctf_intake.py "${caseName}" --url "${target}" --root . --case-dir "${caseDir}" --case-name "${caseName}"
\`\`\`

该命令确保 manifest 固定为 \`${manifest}\`。如果旧 case 已存在且路径不同，以现有 manifest 为准，并在本轮报告中说明。

如果 manifest 已存在，先读取它的 \`autopilot.last_round_id\`、\`next_actions\`、\`evidence\`、\`dead_ends\`，不要从头开始。

## 输出

返回 JSON，不要 Markdown：

{
  "manifest": "<实际 manifest 路径>",
  "case": "<case>",
  "checkpoint_loaded": true,
  "last_round_id": "<如果有>",
  "known_next_actions": [],
  "known_dead_ends": []
}`,
  { label: 'checkpoint', phase: '阶段一：读取 checkpoint' },
)

phase('阶段二：单轮自动推进')

const autopilot = await agent(
  `基于上一阶段 checkpoint，执行一轮确定性 autopilot。不要开启无限循环；只跑一轮。

## 优先命令

\`\`\`bash
python3 scripts/ctf-website/ctf_autopilot.py ${manifest} --max-actions ${maxActions} ${execute ? '--execute' : ''}
\`\`\`

如果 manifest 路径与 checkpoint 输出不同，改用 checkpoint 中的实际路径。

## 要求

1. 命令失败时读取错误，修正路径或依赖问题后重试一次。
2. 不要把真实请求/响应输出到最终回答；原始证据写入 \`exports/ctf-website/<case>/\`。
3. 总结本轮 autopilot 的 executed/planned/agent_required/error 动作。

## 输出

返回 JSON，不要 Markdown：

{
  "manifest": "<实际 manifest 路径>",
  "executed": [],
  "planned": [],
  "agent_required": [],
  "errors": []
}`,
  { label: 'autopilot-round', phase: '阶段二：单轮自动推进' },
)

phase('阶段三：Agent 攻击网推进')

const attackRound = await workflow('ctf-attack-router', {
  target,
  caseName,
  manifest,
  signals: [autopilot],
  focus: [checkpoint, autopilot],
  maxWorkflows,
  innerIterations,
  workerIds,
  caseRoot,
  reportRoot,
  testOrigin,
  redirectProbeHost,
  ssrfProbeTargets,
  credentialPairs,
  forwardedIp,
  execute,
})

phase('阶段四：写回与停止判断')

const final = await agent(
  `整合本轮结果并写回 manifest/notes。必须只输出一个明确 loop 状态。不要把“等待人工确认/人工审批”作为状态；无人值守执行失败时，记录证据并切换路径。

## 输入

Checkpoint:
${checkpoint}

Autopilot:
${autopilot}

Attack round:
${attackRound}

## 写回要求

1. 读取实际 \`ai_manifest.json\`。
2. 如果 attack round 有 \`evidence_added\` / \`dead_ends_added\` / \`next_round_focus\`，合并到 manifest。
3. 在 case 或 reports 目录写一份本轮摘要，例如 \`${reportRoot}/<case>/loop-round-<timestamp>.md\`。
4. 写回后运行程序化状态判定：
   \`\`\`bash
   python3 scripts/ctf-website/ctf_loop_status.py <实际 manifest 路径> --write
   \`\`\`
5. 输出状态：
   - DONE：已拿到 flag / 已生成完整复现报告。
   - EXHAUSTED：全路径耗尽、目标长期不可达或关键依赖缺失且无替代路径。
   - CONTINUE：仍有 next_round_focus 或 pending hypotheses。
6. stopOnExhausted 当前为 ${stopOnExhausted}；如果 false，即使路径暂时耗尽也生成新的 recon/fingerprint/route-discovery 焦点并返回 CONTINUE。

## 最终输出格式

只输出以下格式，不要额外解释：

STATUS: CONTINUE|DONE|EXHAUSTED
MANIFEST: <path>
CASE: <case>
ROUND_REPORT: <path>
REASON: <one-line reason>
NEXT: <one-line next focus or empty>`,
  { label: 'loop-status', phase: '阶段四：写回与停止判断' },
)

return {
  target,
  caseName,
  manifest,
  checkpoint,
  autopilot,
  attackRound,
  final,
}
