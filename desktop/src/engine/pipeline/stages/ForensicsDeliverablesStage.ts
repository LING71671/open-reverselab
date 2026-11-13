import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic, Deliverables } from "../../../core";
import { nativeBridge, type PythonExecResult } from "../../../services/native/nativeBridge";
import { trackPolicies } from "../../tracks";
import { parseAcceptancePlan, verifyGoalWithModel } from "../goalVerifier";
import { classifyFailure } from "../../../services/health/healthMonitor";

export function normalizeFailure(value: string): string {
  return value.toLowerCase().replace(/0x[\da-f]+/g, "<address>")
    .replace(/line \d+/g, "line <n>").replace(/\d+(\.\d+)?\s*(ms|seconds?)/g, "<duration>")
    .replace(/\s+/g, " ").trim().slice(-1500);
}

export class ForensicsDeliverablesStage implements PipelineStage {
  readonly id = "forensics-deliverables";
  readonly name = "执行与核验";
  readonly description = "Verifies a unique forensic script and records actual execution and persistence results";
  readonly category = "forensics" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const fullContent: string = ctx.state.fullContent || "";
    const script = fullContent.match(/```python\s*([\s\S]*?)\s*```/i)?.[1]?.trim() || "";
    const parsedPlan = parseAcceptancePlan(fullContent, ctx);
    ctx.state.acceptancePlan ||= parsedPlan;
    const canonicalScript = script.split("\n").map((line) => line.trimEnd()).filter((line) => line.trim() && !line.trim().startsWith("#")).join("\n");
    const executedScripts: string[] = ctx.state.executedScripts || [];
    const fingerprintBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${ctx.target}\n${canonicalScript}`));
    const actionFingerprint = [...new Uint8Array(fingerprintBytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    let executionOutput: PythonExecResult | undefined;
    let blockedReason = "";
    if (!ctx.state.builtinHash && !ctx.state.acceptancePlan) blockedReason = "执行前缺少与原目标绑定的验收条件";
    else if (!script) blockedReason = "模型未提供可执行的取证脚本";
    else if (executedScripts.includes(canonicalScript)) blockedReason = "已阻止重复执行相同脚本";
    else if (ctx.signal?.aborted || performance.now() >= ctx.budget.monotonicDeadline) blockedReason = "执行前时间预算已耗尽或任务已取消";
    else {
      ctx.state.executedScripts = [...executedScripts, canonicalScript];
      ctx.state.executedActionFingerprints = [...(ctx.state.executedActionFingerprints || []), actionFingerprint];
      callbacks.onToolCall?.({ id: actionFingerprint, tool: "python", title: "执行观察", status: "running" });
      callbacks.onHealthEvent?.({ eventId: `${ctx.sessionId}:exec-start:${ctx.budget.attempts}`, goalId: ctx.sessionId, layer: "tool", status: "running", timestamp: Date.now(), branchId: ctx.track, nodeId: actionFingerprint });
      try {
        const output: PythonExecResult = ctx.state.executeAction
          ? await ctx.state.executeAction(actionFingerprint, script)
          : await nativeBridge.execPython(script, { timeoutMs: ctx.budget.monotonicDeadline - performance.now(), executionId: `${ctx.sessionId}:${actionFingerprint}`, signal: ctx.signal });
        executionOutput = output;
        ctx.state.actionResults = { ...(ctx.state.actionResults || {}), [actionFingerprint]: output };
        if (!output.success) blockedReason = output.stderr || "取证脚本执行失败";
        else if (!output.stdout.trim()) blockedReason = "取证脚本未返回可核查输出";
      } catch (error) {
        blockedReason = error instanceof Error ? error.message : String(error);
        executionOutput = { success: false, stdout: "", stderr: blockedReason };
      }
      callbacks.onToolCall?.({ id: actionFingerprint, tool: "python", title: "执行观察", status: executionOutput?.success ? "done" : "failed", detail: blockedReason, output: executionOutput, durationMs: Date.now() - startTime });
      callbacks.onHealthEvent?.({ eventId: `${ctx.sessionId}:exec-end:${ctx.budget.attempts}`, goalId: ctx.sessionId, layer: "tool", status: executionOutput?.success ? "healthy" : "failed", timestamp: Date.now(), branchId: ctx.track, nodeId: actionFingerprint, ...(executionOutput?.success ? {} : classifyFailure(blockedReason, "tool")) });
    }
    if (ctx.track === "both") throw new Error("both must verify each branch independently");
    let verification = trackPolicies[ctx.track].verify(ctx, executionOutput);
    if (!blockedReason && !ctx.state.builtinHash && executionOutput) {
      verification = await verifyGoalWithModel(ctx, executionOutput, script, verification, callbacks);
    }
    if (!blockedReason && !verification.goalVerified) blockedReason = verification.reason;
    ctx.state.executionSucceeded = verification.executionSucceeded;
    ctx.state.evidenceAccepted = verification.evidenceAccepted;
    ctx.state.routeBlocked = !!blockedReason;
    ctx.state.routeVerified = verification.goalVerified;
    ctx.state.blockedReason = blockedReason;
    ctx.state.failureFingerprint = normalizeFailure(blockedReason);
    const observation = executionOutput?.success ? executionOutput.stdout.trim() : normalizeFailure(executionOutput?.stderr || blockedReason);
    const observationDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(observation));
    ctx.state.evidenceFingerprint = [...new Uint8Array(observationDigest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    ctx.state.lastExecutionOutput = executionOutput;

    const deliverables: Deliverables = {
      summary: fullContent,
      script: script || undefined,
      key: ctx.triage?.sha256,
      executionOutput,
      goalVerification: verification.goal,
    };
    let saveError = "";
    if (fullContent && !ctx.signal?.aborted && performance.now() < ctx.budget.monotonicDeadline) {
      try {
        const saved = await nativeBridge.saveReport({
          target: ctx.target,
          summary: fullContent,
          script,
          key: deliverables.key,
          track: ctx.track,
          executionOutput,
          goalId: ctx.state.reportNamespace || ctx.sessionId,
          attempt: ctx.budget.attempts,
          workspaceRoot: ctx.state.workspaceRoot,
          goalVerification: verification.goal,
        });
        if (saved.status === "saved") {
          deliverables.savedArtifacts = { report_path: saved.report_path, script_path: saved.script_path };
        } else saveError = "Report storage unavailable";
      } catch (error) {
        saveError = error instanceof Error ? error.message : String(error);
      }
    }
    ctx.deliverables = deliverables;
    callbacks.onHealthEvent?.({
      eventId: `${ctx.sessionId}:storage:${ctx.budget.attempts}`, goalId: ctx.sessionId, layer: "storage",
      status: deliverables.savedArtifacts ? "healthy" : "degraded", timestamp: Date.now(), branchId: ctx.track, nodeId: this.id,
      ...(deliverables.savedArtifacts ? {} : classifyFailure(saveError || "Report was not saved", "storage")),
    });
    callbacks.onDeliverables?.(deliverables);
    const durationMs = Date.now() - startTime;
    const diag: StageDiagnostic = {
      stageId: this.id,
      stageName: this.name,
      status: blockedReason ? "warn" : saveError ? "warn" : "pass",
      durationMs,
      timestamp: Date.now(),
      summary: blockedReason || (saveError ? `取证已执行；${saveError}` : "取证已执行，报告已保存"),
      metrics: [
        { label: "Track", value: ctx.track, status: "info" },
        { label: "Execution", value: executionOutput?.success ? "Succeeded" : "Unverified", status: blockedReason ? "warn" : "pass" },
        { label: "Report Saved", value: deliverables.savedArtifacts?.report_path || "Not saved", status: deliverables.savedArtifacts ? "pass" : "warn" },
      ],
      evidence: { paths: ctx.kbRouting?.matchedTechniques, savedArtifacts: deliverables.savedArtifacts, executionOutput },
      error: blockedReason || saveError || undefined,
    };
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
