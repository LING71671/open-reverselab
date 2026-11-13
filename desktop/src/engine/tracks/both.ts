import type { PipelineContext, PipelineCallbacks, RunBudget, RunProgress } from "../../core/contracts/pipeline";
import { DagScheduler, type DagNode } from "../runtime/dagScheduler";
import { AgentMessageBus } from "../runtime/agentMessages";
import { nativeBridge, type PythonExecResult } from "../../services/native/nativeBridge";
import { verifyBothGoal } from "./verifyBothGoal";
import { isHashObjective } from "./evidence";

type BranchRunner = (track: "red" | "blue", budget: RunBudget, callbacks: PipelineCallbacks, state: Record<string, any>, signal: AbortSignal) => Promise<PipelineContext>;

/** Compose isolated policies with a single outer budget and explicit evidence handoff. */
export async function runBothTracks(
  target: string,
  objective: string,
  budget: RunBudget,
  callbacks: PipelineCallbacks,
  signal: AbortSignal | undefined,
  runBranch: BranchRunner,
  goalId: string,
): Promise<PipelineContext> {
  const started = performance.now();
  const verificationReserve = budget.maxTokens === undefined || isHashObjective(objective) ? 0 : Math.min(8192, Math.floor(budget.maxTokens / 3));
  const branchTokens = budget.maxTokens === undefined ? undefined : budget.maxTokens - verificationReserve;
  const results: Partial<Record<"red" | "blue", PipelineContext>> = {};
  const texts = { red: "", blue: "" };
  const lastStepIds: Partial<Record<"red" | "blue", string>> = {};
  const joinParents = () => (["red", "blue"] as const).map(track => lastStepIds[track] || `branch:${track}`);
  const content = () => `## red\n\n${texts.red}\n\n## blue\n\n${texts.blue}`;
  const sumUsage = () => Object.values(results).reduce((total, ctx) => total + ctx.budget.tokensUsed, 0);
  const sumAttempts = () => Object.values(results).reduce((total, ctx) => total + ctx.budget.attempts, 0);
  const progressByTrack: Partial<Record<"red" | "blue", RunProgress>> = {};
  const bus = new AgentMessageBus({ goalId, agents: ["red", "blue", "coordinator"] });
  const sharedExecutions = new Map<string, Promise<PythonExecResult>>();
  const executeAction = (fingerprint: string, script: string) => {
    if (!sharedExecutions.has(fingerprint)) {
      sharedExecutions.set(fingerprint, nativeBridge.execPython(script, {
        executionId: `${goalId}:${fingerprint}`,
        timeoutMs: Math.min(60000, Math.max(1, (budget.maxDurationMs ?? Infinity) - (performance.now() - started))),
        signal,
      }));
    }
    return sharedExecutions.get(fingerprint)!;
  };
  let messageSequence = 0;
  const notifyPeer = (from: "red" | "blue", type: "evidence" | "blocked" | "result", content: string, paths: string[] = [], nodeId?: string) => {
    const message = { id: `${goalId}:message-${++messageSequence}`, goalId, from, to: from === "red" ? "blue" : "red", type, payload: { content, evidenceRefs: [...paths.map((path) => ({ id: path, path })), ...(nodeId ? [{ id: nodeId, nodeId }] : [])] } };
    bus.dispatch(message);
    callbacks.onToolCall?.({ id: message.id, tool: "agent_message", title: `${message.from} → ${message.to}`, status: "done", detail: content, output: message });
  };
  const nodes: DagNode<PipelineContext | undefined>[] = (["red", "blue"] as const).map((track, index) => ({
    id: track,
    run: async ({ signal: branchSignal }) => {
      const branchBudget = {
        maxDurationMs: budget.maxDurationMs === undefined ? undefined : Math.max(1, budget.maxDurationMs - (performance.now() - started)),
        maxTokens: branchTokens === undefined ? undefined : index === 0 ? Math.floor(branchTokens / 2) : branchTokens - Math.floor(branchTokens / 2),
      };
      const branchCallbacks: PipelineCallbacks = {
        ...callbacks,
        onToken: (text) => { texts[track] = text; callbacks.onToken?.(content()); },
        onStepNode: (step) => {
          lastStepIds[track] = `${track}:${step.id}`;
          const parents = [...new Set<string>([...(step.parentIds || (step.parentId ? [step.parentId] : [])).map((id: string) => `${track}:${id}`), ...(step.evidenceParentIds || [])])];
          callbacks.onStepNode?.({ ...step, id: `${track}:${step.id}`, parentId: parents[0] || `branch:${track}`, parentIds: parents.length ? parents : [`branch:${track}`], evidenceParentIds: undefined, title: `${track} · ${step.title}` });
          callbacks.onStepNode?.({ id: "branch:join", parentId: joinParents()[0], parentIds: joinParents(), agentId: "coordinator", title: "both", status: "pending", detail: "等待 red 与 blue 汇合", timestamp: Date.now() });
        },
        onToolCall: (tool) => {
          callbacks.onToolCall?.({ ...tool, id: `${track}:${tool.id}`, title: `${track} · ${tool.title}` });
          const paths = typeof tool.output === "object" ? tool.output?.matchedTechniques : undefined;
          if (tool.status === "done" && Array.isArray(paths)) notifyPeer(track, "evidence", `Indexed document references from ${track}`, paths);
        },
        onDeliverables: (deliverables) => {
          callbacks.onDeliverables?.(deliverables);
          // Action-level observations are already published; do not feed a
          // verifier timestamp or aggregate envelope back as new evidence.
          if (deliverables.executionOutput && !deliverables.script?.startsWith("# Action:")) notifyPeer(track, "evidence", JSON.stringify({ execution: deliverables.executionOutput }), [], lastStepIds[track]);
        },
        onDiagnosticUpdate: (diagnostic) => callbacks.onDiagnosticUpdate?.({ ...diagnostic, stageId: `${track}:${diagnostic.stageId}`, stageName: `${track} · ${diagnostic.stageName}` }),
        onHealthEvent: (event) => callbacks.onHealthEvent?.({ ...event, goalId, branchId: track }),
        onRunProgress: (progress) => {
          progressByTrack[track] = progress;
          callbacks.onRunProgress?.({ ...progress, ...budget, status: "running", reason: `${track}: ${progress.reason || "运行中"}`, tokensUsed: Object.values(progressByTrack).reduce((sum, value) => sum + value.tokensUsed, 0), attempts: Object.values(progressByTrack).reduce((sum, value) => sum + value.attempts, 0), usageEstimated: Object.values(progressByTrack).some((value) => value.usageEstimated), elapsedMs: Math.round(performance.now() - started) });
        },
      };
      results[track] = await runBranch(track, branchBudget, branchCallbacks, {
        executeAction,
        verificationScope: track,
        refreshTokenBudget: () => {
          if (branchTokens === undefined) return Infinity;
          const peer = results[track === "red" ? "blue" : "red"];
          return peer ? Math.max(0, branchTokens - peer.budget.tokensUsed) : branchBudget.maxTokens!;
        },
        readPeerMessages: () => bus.readInbox(track),
        readPeerEvidence: () => {
          const messages = bus.readInbox(track).filter(message => message.type === "evidence").slice(-8);
          return { messages, parentIds: [...new Set(messages.flatMap(message => message.payload.evidenceRefs?.flatMap(ref => ref.nodeId ? [ref.nodeId] : []) || []))] };
        },
        publishEvidence: (nodeId: string, title: string, output: unknown) => notifyPeer(track, "evidence", JSON.stringify({ title, output }), [], `${track}:${nodeId}`),
        notifyPeer: (reason: string) => notifyPeer(track, "blocked", reason),
      }, branchSignal);
      texts[track] = results[track]?.state.fullContent || "";
      notifyPeer(track, "result", results[track]?.runProgress?.reason || "Branch finished");
      return results[track];
    },
  }));
  nodes.push({ id: "join", parentIds: ["red", "blue"], dependencyPolicy: "allSettled", run: async ({ parentResults }) => {
    for (const track of ["red", "blue"] as const) {
      const result = parentResults.get(track);
      if (!results[track]) texts[track] = String(result?.error || result?.cancellationReason || "Branch did not complete");
    }
    return results.blue || results.red;
  } });
  const scheduler = new DagScheduler(nodes, {
    concurrency: 2,
    signal,
    onNodeUpdate: (node) => callbacks.onStepNode?.({ id: `branch:${node.id}`, parentId: node.parentIds.length ? `branch:${node.parentIds[0]}` : null, parentIds: node.parentIds.map((id) => `branch:${id}`), agentId: node.id === "join" ? "coordinator" : node.id, title: node.id, status: node.status === "succeeded" ? node.value?.runProgress?.status === "completed" ? "done" : "failed" : node.status === "failed" || node.status === "cancelled" ? "failed" : node.status === "running" ? "running" : "pending", detail: node.value?.runProgress?.reason || node.status, timestamp: Date.now(), evidence: { status: node.status, error: node.error ? String(node.error) : undefined } }),
  });
  await scheduler.run();
  const last = results.blue || results.red;
  if (!last) throw new Error(signal?.aborted ? "任务已停止" : "both 预算不足");
  const scopedComplete = results.red?.runProgress?.status === "completed" && results.blue?.runProgress?.status === "completed";
  const combined = scopedComplete && !signal?.aborted && !callbacks.shouldYield?.() && performance.now() - started < (budget.maxDurationMs ?? Infinity)
    ? await verifyBothGoal(results as Record<"red" | "blue", PipelineContext>, target, objective, budget, started, goalId, signal, callbacks) : undefined;
  const elapsedMs = Math.round(performance.now() - started);
  const tokensUsed = combined?.context.budget.tokensUsed ?? sumUsage();
  const yielding = !!callbacks.shouldYield?.();
  const completed = !yielding && !signal?.aborted && elapsedMs < (budget.maxDurationMs ?? Infinity) && tokensUsed <= (budget.maxTokens ?? Infinity) && !!combined?.verification.goalVerified;
  const status: RunProgress["status"] = signal?.aborted ? "cancelled" : yielding ? "running" : completed ? "completed"
    : elapsedMs >= (budget.maxDurationMs ?? Infinity) || tokensUsed >= (budget.maxTokens ?? Infinity) || combined?.context.state.tokenBudgetExhausted || Object.values(results).some(ctx => ctx.runProgress?.status === "exhausted") ? "exhausted" : "blocked";
  const reason = signal?.aborted ? "用户已停止运行" : yielding ? "正在应用补充要求" : completed ? "red、blue 分别通过核验，完整目标已核验"
    : combined?.verification.reason || (["red", "blue"] as const).map((track) => `${track}: ${results[track]?.runProgress?.reason || "未运行"}`).join("；");
  const checkpoint = {
    target,
    objective,
    track: "both" as const,
    visitedPaths: [...new Set(Object.values(results).flatMap((ctx) => ctx.state.attemptedKbPaths || []))] as string[],
    actionFingerprints: [...new Set(Object.values(results).flatMap((ctx) => ctx.state.executedActionFingerprints || []))] as string[],
    blockedReasons: Object.values(results).flatMap((ctx) => (ctx.state.routeHistory || []).map((route: { reason: string }) => route.reason)),
  };
  const runProgress: RunProgress = { ...budget, status, reason, elapsedMs, tokensUsed, attempts: sumAttempts(), usageEstimated: combined?.context.budget.usageEstimated ?? Object.values(results).some((ctx) => ctx.budget.usageEstimated), checkpoint };
  callbacks.onRunProgress?.(runProgress);
  if (!yielding) callbacks.onHealthEvent?.({ eventId: `${goalId}:both-final`, goalId, layer: "goal", nodeId: "join", status: completed ? "healthy" : signal?.aborted ? "cancelled" : "degraded", timestamp: Date.now(), reason });
  callbacks.onStepNode?.({ id: "branch:join", parentId: joinParents()[0], parentIds: joinParents(), agentId: "coordinator", title: "both", status: yielding ? "pending" : completed ? "done" : "failed", detail: reason, timestamp: Date.now(), evidence: { status, tokensUsed, branches: Object.fromEntries(Object.entries(results).map(([track, ctx]) => [track, ctx.runProgress])) } });
  callbacks.onToken?.(content());
  const deliverables = {
    branches: Object.fromEntries(Object.entries(results).filter(([, ctx]) => ctx.deliverables).map(([track, ctx]) => [track, ctx.deliverables!])),
    summary: content(),
    goalVerification: {
      objective,
      status: completed ? "verified" as const : "in_progress" as const,
      passRate: combined?.verification.goal?.passRate || `${Number(results.red?.state.routeVerified) + Number(results.blue?.state.routeVerified)}/2 branches`,
      assertions: combined?.verification.goal?.assertions || Object.entries(results).flatMap(([track, ctx]) => (ctx.deliverables?.goalVerification?.assertions || []).map((assertion) => ({ ...assertion, name: `${track}: ${assertion.name}` }))),
      timestamp: Date.now(),
    },
  };
  if (!yielding) callbacks.onDeliverables?.(deliverables);
  return { ...last, track: "both", runProgress, deliverables, budget: { ...last.budget, ...budget, tokensUsed, attempts: sumAttempts() }, state: { branches: results, messages: bus.readHistory(), fullContent: content(), routeVerified: completed, combinedVerification: combined?.verification } };
}
