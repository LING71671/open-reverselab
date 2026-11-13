import type { PipelineCallbacks, PipelineContext, RunBudget } from "../../core/contracts/pipeline";
import type { TrackVerification } from "./contract";
import { isHashObjective, verifyTargetEvidence } from "./evidence";
import { verifyGoalWithModel } from "../pipeline/goalVerifier";

/** A final assessment of the original objective, after both scoped assessments. */
export async function verifyBothGoal(
  branches: Record<"red" | "blue", PipelineContext>, target: string, objective: string,
  budget: RunBudget, started: number, goalId: string, signal: AbortSignal | undefined, callbacks: PipelineCallbacks,
): Promise<{ verification: TrackVerification; context: PipelineContext }> {
  const contexts = [branches.red, branches.blue];
  const combined: PipelineContext = {
    ...branches.red, sessionId: goalId, track: "both", target, prompt: objective, signal,
    budget: { ...branches.red.budget, maxTokens: budget.maxTokens ?? Infinity, maxDurationMs: budget.maxDurationMs ?? Infinity,
      tokensUsed: contexts.reduce((sum, ctx) => sum + ctx.budget.tokensUsed, 0), usageEstimated: contexts.some(ctx => ctx.budget.usageEstimated),
      monotonicDeadline: started + (budget.maxDurationMs ?? Infinity) },
    state: { modelSnapshot: branches.red.state.modelSnapshot },
  };
  const initial: TrackVerification = { executionSucceeded: true, evidenceAccepted: false, goalVerified: false,
    reason: "尚未核验完整目标", goal: { objective, status: "in_progress", passRate: "0/1", assertions: [], timestamp: Date.now() } };
  if (isHashObjective(objective) && contexts.every(ctx => {
    const output = ctx.deliverables?.executionOutput;
    return ctx.state.builtinHash && output && verifyTargetEvidence(ctx, { ...output, stdout: output.stdout || "", stderr: output.stderr || "" }).goalVerified;
  })) {
    return { verification: { ...initial, evidenceAccepted: true, goalVerified: true, reason: "两条分支的 SHA256 均与独立初筛一致",
      goal: { ...initial.goal!, status: "verified", passRate: "2/2", assertions: contexts.flatMap(ctx => ctx.deliverables?.goalVerification?.assertions || []) } }, context: combined };
  }
  const evidence: Record<string, string> = {};
  const checks = [];
  const scripts = [];
  const programs: Record<string, unknown> = {};
  for (const ctx of contexts) {
    const plan = ctx.state.acceptancePlan;
    const output = ctx.deliverables?.executionOutput;
    if (ctx.target !== target || ctx.prompt !== objective || plan?.target !== target || plan?.objective !== objective || !plan?.checks?.length || !output?.success) {
      return { verification: { ...initial, reason: `${ctx.track} 缺少与当前目标绑定的验收计划或执行证据` }, context: combined };
    }
    checks.push(...plan.checks.map((check: { id: string; criterion: string; expected: string }) => ({ ...check, id: `${ctx.track}.${check.id}`, criterion: `${ctx.track}: ${check.criterion}` })));
    const sources: Record<string, string> = ctx.state.executionEvidence ?? { "execution.stdout": output.stdout || "" };
    for (const [ref, text] of Object.entries(sources)) evidence[`${ctx.track}.${ref}`] = text;
    scripts.push(`# ${ctx.track}\n${ctx.deliverables?.script || ""}`);
    programs[ctx.track] = ctx.state.verificationProgram || { script: ctx.deliverables?.script || "" };
  }
  combined.state.acceptancePlan = { target, objective, scope: "goal", checks };
  combined.state.executionEvidence = evidence;
  combined.state.verificationProgram = programs;
  callbacks.onStepNode?.({ id: "branch:join", parentIds: contexts.flatMap(ctx => ctx.state.lastStepId ? [`${ctx.track}:${ctx.state.lastStepId}`] : [`branch:${ctx.track}`]), agentId: "coordinator", title: "核验完整目标", status: "running", timestamp: Date.now() });
  try {
    const verification = await verifyGoalWithModel(combined, { success: true, stdout: JSON.stringify(evidence), stderr: "" }, scripts.join("\n\n"), initial, callbacks);
    return { verification, context: combined };
  } catch (error) {
    return { verification: { ...initial, reason: error instanceof Error ? error.message : String(error) }, context: combined };
  }
}
