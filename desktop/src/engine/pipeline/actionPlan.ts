import type { PipelineCallbacks, PipelineContext } from "../../core/contracts/pipeline";
import { DagScheduler } from "../runtime/dagScheduler";
import { nativeBridge, type PythonExecResult } from "../../services/native/nativeBridge";
import { classifyFailure } from "../../services/health/healthMonitor";
import { structuredPlanCandidates } from "./structuredPlans";
import { fingerprint, observationIdentity, peerObservationIdentity, stableJson } from "./observationIdentity";
import { HealthFault } from "../../core/contracts/health";

export interface AnalysisAction {
  id: string;
  title: string;
  dependsOn: string[];
  script: string;
}

/** Explicit plans fail closed; a malformed graph must never become a single-script run. */
export function parseActionPlan(content: string): AnalysisAction[] | undefined {
  const fence = content.match(/```action-plan\s*([\s\S]*?)\s*```/i);
  let value: any;
  if (!fence) {
    if (/```action-plan\b/i.test(content)) throw new Error("动作计划未完整输出");
    value = structuredPlanCandidates(content).find(plan => plan && Object.prototype.hasOwnProperty.call(plan, "actions"));
    if (value === undefined) return undefined;
  }
  else try { value = JSON.parse(fence[1]); } catch { throw new Error("动作计划不是有效 JSON"); }
  if (!Array.isArray(value?.actions) || value.actions.length < 1) throw new Error("动作计划需包含至少一个动作");
  const actions: AnalysisAction[] = value.actions.map((action: any) => {
    if (!action || typeof action.id !== "string" || !/^[a-zA-Z][\w-]{0,47}$/.test(action.id) || typeof action.title !== "string" || !action.title.trim() ||
        typeof action.script !== "string" || !action.script.trim() || action.script.length > 60000 ||
        !Array.isArray(action.dependsOn) || !action.dependsOn.every((id: unknown) => typeof id === "string")) throw new Error("动作计划缺少有效 ID、标题、脚本或依赖");
    return { id: action.id, title: action.title.trim().slice(0, 100), script: action.script, dependsOn: [...action.dependsOn] };
  });
  // Reuse the runtime's validation before any tool executes.
  new DagScheduler(actions.map(action => ({ id: action.id, parentIds: action.dependsOn, run: async () => undefined })));
  return actions;
}

function pythonData(name: string, value: unknown): string {
  return `${name} = __import__("json").loads(${JSON.stringify(JSON.stringify(value))})\n`;
}

function summarizeOutput(output: PythonExecResult) {
  return { success: output.success, stdout: output.stdout.slice(0, 12000), stderr: output.stderr.slice(0, 2000), executionTimeMs: output.executionTimeMs };
}

/** Execute independent observations concurrently; dependencies receive real parent outputs. */
export async function executeActionPlan(actions: AnalysisAction[], ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<PythonExecResult> {
  const started = performance.now();
  const rootParent = ctx.state.lastStepId || null;
  const idFor = (id: string) => `${ctx.sessionId}:${ctx.budget.attempts}:action:${id}`;
  const peerParents = new Map<string, string[]>();
  const outputs = new Map<string, PythonExecResult>();
  const scripts = new Map<string, string>();
  ctx.state.executionEvidence = {};
  const bindings: Record<string, unknown> = {};
  const bindingIds = new Map<string, string>();
  const programs: Record<string, unknown> = {};
  const bind = (value: unknown) => {
    const serialized = stableJson(value);
    let id = bindingIds.get(serialized);
    if (!id) { id = `input-${bindingIds.size + 1}`; bindingIds.set(serialized, id); bindings[id] = value; }
    return id;
  };
  const scheduler = new DagScheduler<PythonExecResult>(actions.map(action => ({
    id: action.id,
    parentIds: action.dependsOn,
    run: async ({ signal, parentResults }) => {
      if (callbacks.shouldYield?.()) throw new Error("目标已调整，后续动作未执行");
      if (ctx.state.globalBlocker) throw new Error("执行服务不可用，后续动作未执行");
      if (signal.aborted || performance.now() >= ctx.budget.monotonicDeadline) throw new Error("执行前已停止或时间预算耗尽");
      const inputs = Object.fromEntries([...parentResults].map(([id, result]) => [id, result.value ? summarizeOutput(result.value) : { status: result.status }]));
      const peer = ctx.state.readPeerEvidence?.() || { messages: [], parentIds: [] };
      peerParents.set(action.id, peer.parentIds);
      const script = pythonData("REVERSELAB_INPUTS", inputs) + pythonData("REVERSELAB_PEER_EVIDENCE", peer.messages) + action.script;
      scripts.set(action.id, script);
      programs[action.id] = { script: action.script, dependsOn: action.dependsOn,
        bindings: { REVERSELAB_INPUTS: bind(inputs), REVERSELAB_PEER_EVIDENCE: bind(peer.messages) } };
      const actionFingerprint = await fingerprint({ target: ctx.target, script: action.script.trim(),
        inputs: Object.fromEntries([...parentResults].map(([id, result]) => [id, result.value ? observationIdentity(result.value) : { status: result.status }])),
        peers: peerObservationIdentity(peer.messages) });
      const fingerprints: string[] = ctx.state.executedActionFingerprints || [];
      if (fingerprints.includes(actionFingerprint)) throw new Error("已阻止重复执行相同动作与输入");
      ctx.state.executedActionFingerprints = [...fingerprints, actionFingerprint];
      callbacks.onToolCall?.({ id: idFor(action.id), tool: "python", title: action.title, status: "running" });
      const output = await (ctx.state.executeAction
        ? ctx.state.executeAction(actionFingerprint, script)
        : nativeBridge.execPython(script, { executionId: idFor(action.id), timeoutMs: ctx.budget.monotonicDeadline - performance.now(), signal })).catch((error: unknown) => {
          if (error instanceof HealthFault && error.code === "TOOL_UNAVAILABLE") ctx.state.globalBlocker = true;
          throw error;
        });
      outputs.set(action.id, output);
      ctx.state.actionResults = { ...(ctx.state.actionResults || {}), [actionFingerprint]: output };
      if (output.success) ctx.state.executionEvidence[`actions.${action.id}.stdout`] = output.stdout;
      ctx.state.publishEvidence?.(idFor(action.id), action.title, summarizeOutput(output));
      callbacks.onToolCall?.({ id: idFor(action.id), tool: "python", title: action.title, status: output.success ? "done" : "failed", output, detail: output.stderr, durationMs: output.executionTimeMs });
      if (!output.success) throw new Error(output.stderr || "动作执行失败");
      return output;
    },
  })), {
    signal: ctx.signal,
    onNodeUpdate: node => {
      const action = actions.find(item => item.id === node.id)!;
      const parents = action.dependsOn.map(idFor);
      callbacks.onStepNode?.({ id: idFor(node.id), parentId: parents[0] || rootParent, parentIds: parents.length ? parents : rootParent ? [rootParent] : [],
        evidenceParentIds: peerParents.get(node.id), agentId: "python", title: action.title,
        status: node.status === "succeeded" ? "done" : node.status === "running" ? "running" : node.status === "queued" ? "pending" : "failed",
        detail: node.status === "cancelled" ? "前置动作未完成或任务已停止" : node.error ? String(node.error) : action.title,
        timestamp: Date.now(), evidence: { actionId: action.id, dependsOn: action.dependsOn, execution: outputs.get(node.id), status: node.status } });
      if (node.status !== "queued") callbacks.onHealthEvent?.({ eventId: `${idFor(node.id)}:${node.status}`, goalId: ctx.sessionId, branchId: ctx.track, nodeId: idFor(node.id), layer: "tool", timestamp: Date.now(),
        status: node.status === "succeeded" ? "healthy" : node.status === "running" ? "running" : node.status === "cancelled" ? "cancelled" : "failed",
        ...(node.error ? classifyFailure(node.error, "tool") : {}) });
      if (node.status === "failed" && !outputs.has(node.id)) callbacks.onToolCall?.({ id: idFor(node.id), tool: "python", title: action.title, status: "failed", detail: String(node.error) });
    },
  });
  const result = await scheduler.run();
  const records = actions.map(action => {
    const node = result.nodes.get(action.id)!;
    return { id: action.id, title: action.title, dependsOn: action.dependsOn, status: node.status, output: outputs.has(action.id) ? summarizeOutput(outputs.get(action.id)!) : undefined, error: node.error ? String(node.error) : undefined };
  });
  ctx.state.actionExecutions = [...(ctx.state.actionExecutions || []), ...records.map(record => ({ ...record, nodeId: idFor(record.id), attempt: ctx.budget.attempts }))];
  ctx.state.actionObservationIdentity = [...outputs.values()].map(output => observationIdentity(output));
  ctx.state.verificationParentIds = actions.filter(action => !actions.some(other => other.dependsOn.includes(action.id))).map(action => idFor(action.id));
  ctx.state.executedPlanScript = actions.map(action => `# Action: ${action.id} (${action.title})\n${scripts.get(action.id) || action.script}`).join("\n\n");
  // Keep exact executed scripts in the report, but serialize shared data once
  // for assessment instead of repeating escaped Python JSON literals per action.
  ctx.state.verificationProgram = { actions: programs, bindings };
  return { success: result.status === "succeeded", stdout: JSON.stringify({ target: ctx.target, actions: records }),
    stderr: records.filter(record => record.status !== "succeeded").map(record => `${record.id}: ${record.error || record.status}`).join("\n"), executionTimeMs: Math.round(performance.now() - started) };
}
