import type { PipelineContext, PipelineCallbacks, RunBudget, RunProgress } from "../../core/contracts/pipeline";
import { DagScheduler, type DagNode } from "../runtime/dagScheduler";
import { AgentMessageBus } from "../runtime/agentMessages";
import { nativeBridge, type PythonExecResult } from "../../services/native/nativeBridge";

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
        timeoutMs: Math.max(1, budget.maxDurationMs - (performance.now() - started)),
        signal,
      }));
    }
    return sharedExecutions.get(fingerprint)!;
  };
  let messageSequence = 0;
  const notifyPeer = (from: "red" | "blue", type: "evidence" | "blocked" | "result", content: string, paths: string[] = []) => {
    const message = { id: `${goalId}:message-${++messageSequence}`, goalId, from, to: from === "red" ? "blue" : "red", type, payload: { content, evidenceRefs: paths.map((path) => ({ id: path, path })) } };
    bus.dispatch(message);
    callbacks.onToolCall?.({ id: message.id, tool: "agent_message", title: `${message.from} → ${message.to}`, status: "done", detail: content, output: message });
  };
  const nodes: DagNode<PipelineContext | undefined>[] = (["red", "blue"] as const).map((track, index) => ({
    id: track,
    run: async ({ signal: branchSignal }) => {
      const branchBudget = {
        maxDurationMs: Math.max(1, budget.maxDurationMs - (performance.now() - started)),
        maxTokens: index === 0 ? Math.floor(budget.maxTokens / 2) : budget.maxTokens - Math.floor(budget.maxTokens / 2),
      };
      const branchCallbacks: PipelineCallbacks = {
        ...callbacks,
        onToken: (text) => { texts[track] = text; callbacks.onToken?.(content()); },
        onStepNode: (step) => {
          lastStepIds[track] = `${track}:${step.id}`;
          callbacks.onStepNode?.({ ...step, id: `${track}:${step.id}`, parentId: step.parentId ? `${track}:${step.parentId}` : `branch:${track}`, parentIds: step.parentIds?.map((id: string) => `${track}:${id}`), title: `${track} · ${step.title}` });
          callbacks.onStepNode?.({ id: "branch:join", parentId: joinParents()[0], parentIds: joinParents(), agentId: "coordinator", title: "both", status: "pending", detail: "等待 red 与 blue 汇合", timestamp: Date.now() });
        },
        onToolCall: (tool) => {
          callbacks.onToolCall?.({ ...tool, id: `${track}:${tool.id}`, title: `${track} · ${tool.title}` });
          const paths = typeof tool.output === "object" ? tool.output?.matchedTechniques : undefined;
          if (tool.status === "done" && Array.isArray(paths)) notifyPeer(track, "evidence", `Indexed document references from ${track}`, paths);
        },
        onDeliverables: (deliverables) => {
          callbacks.onDeliverables?.(deliverables);
          if (deliverables.executionOutput) notifyPeer(track, "evidence", JSON.stringify({ execution: deliverables.executionOutput, verification: deliverables.goalVerification }).slice(0, 12000));
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
        readPeerMessages: () => bus.readInbox(track),
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
  const elapsedMs = Math.round(performance.now() - started);
  const tokensUsed = sumUsage();
  const completed = results.red?.runProgress?.status === "completed" && results.blue?.runProgress?.status === "completed";
  const status: RunProgress["status"] = signal?.aborted ? "cancelled" : completed ? "completed"
    : elapsedMs >= budget.maxDurationMs || tokensUsed >= budget.maxTokens ? "exhausted" : "blocked";
  const reason = completed ? "red 和 blue 均完成独立目标核验"
    : (["red", "blue"] as const).map((track) => `${track}: ${results[track]?.runProgress?.reason || "未运行"}`).join("；");
  const checkpoint = {
    target,
    objective,
    track: "both" as const,
    visitedPaths: [...new Set(Object.values(results).flatMap((ctx) => ctx.state.attemptedKbPaths || []))] as string[],
    actionFingerprints: [...new Set(Object.values(results).flatMap((ctx) => ctx.state.executedActionFingerprints || []))] as string[],
    blockedReasons: Object.values(results).flatMap((ctx) => (ctx.state.routeHistory || []).map((route: { reason: string }) => route.reason)),
  };
  const runProgress: RunProgress = { ...budget, status, reason, elapsedMs, tokensUsed, attempts: sumAttempts(), usageEstimated: Object.values(results).some((ctx) => ctx.budget.usageEstimated), checkpoint };
  callbacks.onRunProgress?.(runProgress);
  callbacks.onHealthEvent?.({ eventId: `${goalId}:both-final`, goalId, layer: "goal", nodeId: "join", status: completed ? "healthy" : signal?.aborted ? "cancelled" : "degraded", timestamp: Date.now(), reason });
  callbacks.onStepNode?.({ id: "branch:join", parentId: joinParents()[0], parentIds: joinParents(), agentId: "coordinator", title: "both", status: completed ? "done" : "failed", detail: reason, timestamp: Date.now(), evidence: { status, tokensUsed, branches: Object.fromEntries(Object.entries(results).map(([track, ctx]) => [track, ctx.runProgress])) } });
  callbacks.onToken?.(content());
  const deliverables = {
    branches: Object.fromEntries(Object.entries(results).filter(([, ctx]) => ctx.deliverables).map(([track, ctx]) => [track, ctx.deliverables!])),
    summary: content(),
    goalVerification: {
      objective,
      status: completed ? "verified" as const : "in_progress" as const,
      passRate: `${Number(results.red?.state.routeVerified) + Number(results.blue?.state.routeVerified)}/2 branches`,
      assertions: Object.entries(results).flatMap(([track, ctx]) => (ctx.deliverables?.goalVerification?.assertions || []).map((assertion) => ({ ...assertion, name: `${track}: ${assertion.name}` }))),
      timestamp: Date.now(),
    },
  };
  callbacks.onDeliverables?.(deliverables);
  return { ...last, track: "both", runProgress, deliverables, budget: { ...last.budget, ...budget, tokensUsed, attempts: sumAttempts() }, state: { branches: results, messages: bus.readHistory(), fullContent: content(), routeVerified: completed } };
}
