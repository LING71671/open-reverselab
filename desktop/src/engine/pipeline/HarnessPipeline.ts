import {
  PipelineStage,
  PipelineContext,
  PipelineCallbacks,
  StageDiagnostic,
  RunBudget,
  RunProgress,
} from "../../core";
import { TargetDiscoveryStage } from "./stages/TargetDiscoveryStage";
import { StaticTriageStage } from "./stages/StaticTriageStage";
import { KbRoutingStage } from "./stages/KbRoutingStage";
import { LlmStreamStage } from "./stages/LlmStreamStage";
import { ForensicsDeliverablesStage } from "./stages/ForensicsDeliverablesStage";
import type { SecurityTrack } from "../../core/contracts/track";
import { runBothTracks } from "../tracks/both";
import { llmService } from "../../services/llm/llmService";
import { classifyFailure } from "../../services/health/healthMonitor";
import type { HealthLayer, HealthStatus, ClassifiedFailure } from "../../core/contracts/health";

export class HarnessPipeline {
  private stages: PipelineStage[] = [];

  constructor(defaultStages?: PipelineStage[]) {
    if (defaultStages) {
      this.stages = [...defaultStages];
    } else {
      // Default low-coupling standard reverse engineering pipeline
      this.stages = [
        new TargetDiscoveryStage(),
        new StaticTriageStage(),
        new KbRoutingStage(),
        new LlmStreamStage(),
        new ForensicsDeliverablesStage(),
      ];
    }
  }

  /**
   * Register a new custom stage to expand pipeline capabilities (e.g. Frida hook, Ghidra decompilation)
   */
  public registerStage(stage: PipelineStage, index?: number): void {
    if (typeof index === "number" && index >= 0 && index <= this.stages.length) {
      this.stages.splice(index, 0, stage);
    } else {
      this.stages.push(stage);
    }
  }

  /**
   * Remove a stage by ID to reduce features or decouple modules
   */
  public removeStage(stageId: string): boolean {
    const prevLen = this.stages.length;
    this.stages = this.stages.filter((s) => s.id !== stageId);
    return this.stages.length < prevLen;
  }

  /**
   * Enable or disable an existing stage dynamically
   */
  public setStageEnabled(stageId: string, enabled: boolean): void {
    const stage = this.stages.find((s) => s.id === stageId);
    if (stage) {
      stage.enabled = enabled;
    }
  }

  /**
   * Inspect all registered stages
   */
  public getStages(): readonly PipelineStage[] {
    return this.stages;
  }

  /**
   * Execute the full pipeline sequentially with per-stage telemetry & diagnostics
   */
  public async run(
    target: string,
    prompt: string,
    history: Array<{ role: string; content: string }>,
    callbacks: PipelineCallbacks,
    signal?: AbortSignal,
    sessionId: string = `session-${Date.now()}`,
    track: SecurityTrack = "blue",
    budget: RunBudget = {},
    initialState: Record<string, any> = {}
  ): Promise<PipelineContext> {
    if ((budget.maxDurationMs !== undefined && (!Number.isFinite(budget.maxDurationMs) || budget.maxDurationMs <= 0)) ||
        (budget.maxTokens !== undefined && (!Number.isSafeInteger(budget.maxTokens) || budget.maxTokens <= 0))) {
      throw new Error("Optional run limits must be positive; tokens must be an integer");
    }
    const modelSnapshot = initialState.modelSnapshot || {
      model: llmService.getModel(),
      provider: { id: llmService.getActiveProviderId(), name: llmService.getActiveProvider()?.name || "Custom", baseUrl: llmService.getBaseUrl(), apiKey: llmService.getApiKey() },
    };
    if (track === "both") {
      return runBothTracks(target, prompt, budget, callbacks, signal,
        (branch, branchBudget, branchCallbacks, state, branchSignal) => this.run(target, prompt, history, branchCallbacks, branchSignal, `${sessionId}:${branch}`, branch, branchBudget, { ...initialState, ...state, modelSnapshot }), sessionId);
    }
    const startedAt = Date.now();
    const startedMonotonic = performance.now();
    const controller = new AbortController();
    const forwardAbort = () => controller.abort(signal?.reason);
    if (signal?.aborted) forwardAbort();
    else signal?.addEventListener("abort", forwardAbort, { once: true });
    const maxDurationMs = budget.maxDurationMs ?? Infinity;
    const maxTokens = budget.maxTokens ?? Infinity;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const scheduleDeadline = () => {
      const remaining = startedMonotonic + maxDurationMs - performance.now();
      if (remaining <= 0) controller.abort("Time budget exhausted");
      else timer = setTimeout(scheduleDeadline, Math.min(remaining, 2_147_483_647));
    };
    if (Number.isFinite(maxDurationMs)) scheduleDeadline();
    const ctx: PipelineContext = {
      sessionId,
      track,
      target,
      prompt,
      history,
      signal: controller.signal,
      budget: { maxDurationMs, maxTokens, startedAt, deadline: startedAt + maxDurationMs, monotonicDeadline: startedMonotonic + maxDurationMs, tokensUsed: 0, usageEstimated: false, attempts: 0 },
      diagnostics: {},
      state: { ...initialState, modelSnapshot },
    };
    let healthSequence = 0;
    const health = (layer: HealthLayer, status: Exclude<HealthStatus, "unknown">, nodeId: string, failure?: ClassifiedFailure) => callbacks.onHealthEvent?.({
      eventId: `${sessionId}:health-${++healthSequence}`, goalId: sessionId, layer, status, nodeId, branchId: track, timestamp: Date.now(), ...failure,
    });
    const progress = (status: RunProgress["status"], reason?: string) => {
      ctx.runProgress = {
        ...budget,
        status,
        reason,
        elapsedMs: Math.round(performance.now() - startedMonotonic),
        tokensUsed: ctx.budget.tokensUsed,
        usageEstimated: ctx.budget.usageEstimated,
        attempts: ctx.budget.attempts,
        checkpoint: {
          target: ctx.target,
          objective: ctx.prompt,
          track: ctx.track,
          visitedPaths: ctx.state.attemptedKbPaths || [],
          actionFingerprints: ctx.state.executedActionFingerprints || [],
          blockedReasons: (ctx.state.routeHistory || []).map((entry: { reason: string }) => entry.reason),
        },
      };
      callbacks.onRunProgress?.(ctx.runProgress);
      if (status !== "running") {
        const failure = status === "completed" ? undefined : classifyFailure(reason || status, "goal", {
          code: status === "cancelled" ? "USER_CANCELLED" : status === "exhausted" ? ctx.state.tokenBudgetExhausted || ctx.budget.tokensUsed >= ctx.budget.maxTokens ? "BUDGET_TOKENS" : "BUDGET_TIME" : undefined,
        });
        health("goal", status === "completed" ? "healthy" : status === "cancelled" ? "cancelled" : "degraded", "goal", failure);
      }
    };
    const stopReason = () => {
      if (signal?.aborted) return "用户已停止运行";
      if (performance.now() >= ctx.budget.monotonicDeadline) return "时间预算已耗尽";
      if (ctx.budget.tokensUsed >= ctx.budget.maxTokens) return "Token 额度已耗尽";
      return undefined;
    };
    const kbStageIndex = this.stages.findIndex((stage) => stage.id === "kb-routing" && stage.enabled);
    const yieldForAdjustment = () => {
      if (!callbacks.shouldYield?.()) return false;
      ctx.state.yieldedForAdjustment = true;
      progress("running", "正在应用补充要求");
      return true;
    };
    progress("running");
    health("goal", "running", "goal");
    try {
    for (let stageIndex = 0; stageIndex < this.stages.length; stageIndex++) {
      if (yieldForAdjustment()) break;
      const stage = this.stages[stageIndex];
      const layer: HealthLayer = stage.category === "llm" ? ctx.state.builtinHash ? "tool" : "model" : stage.category === "kb" ? "agent" : stage.category === "forensics" ? "agent" : "tool";
      if (!stage.enabled) {
        const skippedDiag: StageDiagnostic = {
          stageId: stage.id,
          stageName: stage.name,
          status: "skipped",
          durationMs: 0,
          timestamp: Date.now(),
          summary: `Stage [${stage.name}] is disabled`,
          metrics: [{ label: "Stage Status", value: "Skipped", status: "info" }],
        };
        ctx.diagnostics[stage.id] = skippedDiag;
        callbacks.onDiagnosticUpdate?.(skippedDiag);
        continue;
      }

      const budgetStop = stopReason();
      if (budgetStop || controller.signal.aborted) {
        progress(signal?.aborted ? "cancelled" : "exhausted", budgetStop || "时间预算已耗尽");
        break;
      }

      try {
        if (stage.id === "kb-routing") {
          ctx.budget.attempts++;
          progress("running");
        }
        const stageNodeId = `${ctx.sessionId}:${ctx.budget.attempts}:${stage.id}`;
        const parentStep = ctx.state.lastStepId || null;
        health(layer, "running", stageNodeId);
        callbacks.onStepNode?.({ id: stageNodeId, parentId: parentStep, agentId: stage.id, title: stage.name, status: "running", detail: `${ctx.track} · ${ctx.target}`, timestamp: Date.now() });
        await stage.execute(ctx, callbacks);
        const stageDiagnostic = ctx.diagnostics[stage.id];
        if (stage.category === "kb" && stageDiagnostic && stageDiagnostic.status !== "skipped") health("kb", stageDiagnostic.status === "pass" ? "healthy" : "degraded", stageNodeId,
          stageDiagnostic.error ? classifyFailure(stageDiagnostic.error, "kb") : undefined);
        const stageFailure = (stage.category === "forensics" ? ctx.state.routeBlocked : stageDiagnostic?.status === "fail" || stageDiagnostic?.status === "warn")
          ? classifyFailure(stageDiagnostic?.error || stageDiagnostic?.summary || ctx.state.blockedReason, layer, { code: stage.category === "forensics" ? "EVIDENCE_INVALID" : undefined }) : undefined;
        health(layer, stageFailure ? "degraded" : "healthy", stageNodeId, stageFailure);
        const verificationParents: string[] | undefined = stage.id === "forensics-deliverables" ? ctx.state.verificationParentIds : undefined;
        callbacks.onStepNode?.({ id: stageNodeId, parentId: verificationParents?.[0] || parentStep, parentIds: verificationParents, agentId: stage.id, title: stage.name, status: ctx.diagnostics[stage.id]?.status === "fail" ? "failed" : "done", detail: ctx.diagnostics[stage.id]?.summary || stage.name, timestamp: Date.now(), evidence: ctx.diagnostics[stage.id]?.evidence });
        ctx.state.lastStepId = stageNodeId;
        progress("running");
        if (yieldForAdjustment()) break;
        if (ctx.state.pathsExhausted) {
          progress("blocked", ctx.state.blockedReason || "没有未尝试的匹配路线");
          break;
        }
        if (stage.id === "forensics-deliverables" && ctx.state.routeBlocked) {
          const reason = ctx.state.blockedReason || "当前路线未产生可验证证据";
          const previous = ctx.state.routeHistory || [];
          const failure = String(ctx.state.failureFingerprint || reason);
          const evidenceFingerprint = ctx.state.evidenceFingerprint || "";
          const repeats = previous.filter((entry: { failure: string; evidenceFingerprint: string }) => entry.failure === failure && entry.evidenceFingerprint === evidenceFingerprint).length;
          const paths = ctx.kbRouting?.matchedTechniques || [];
          const sameRouteFailure = previous.some((entry: { failure: string; evidenceFingerprint: string; paths: string[] }) => entry.failure === failure && entry.evidenceFingerprint === evidenceFingerprint && JSON.stringify([...entry.paths].sort()) === JSON.stringify([...paths].sort()));
          const routeId = `route-${ctx.budget.attempts}`;
          callbacks.onStepNode?.({
            id: routeId,
            parentId: ctx.state.lastStepId || null,
            agentId: "route-coordinator",
            title: `${ctx.track} · Route ${ctx.budget.attempts}`,
            status: "failed",
            detail: reason,
            timestamp: Date.now(),
            evidence: { paths: ctx.kbRouting?.matchedTechniques || [], failure, tokensUsed: ctx.budget.tokensUsed },
          });
          ctx.state.lastStepId = routeId;
          ctx.state.routeHistory = [...previous, { paths: ctx.kbRouting?.matchedTechniques || [], failure, reason, evidenceFingerprint }];
          ctx.state.notifyPeer?.(reason);
          const exhausted = stopReason();
          if (exhausted) {
            progress(signal?.aborted ? "cancelled" : "exhausted", exhausted);
            break;
          }
          if (repeats > 0) health("agent", "degraded", routeId, classifyFailure(reason, "agent", { code: "LOOP_DETECTED" }));
          if (ctx.state.globalBlocker || sameRouteFailure || kbStageIndex < 0) {
            progress("blocked", ctx.state.globalBlocker ? reason : sameRouteFailure ? `停止重复失败：${reason}` : "已尝试可用路线，未获得可验证结果");
            break;
          }
          ctx.state.routeBlocked = false;
          ctx.state.fullContent = "";
          stageIndex = kbStageIndex - 1;
        }
      } catch (err: any) {
        health(layer, "failed", `${ctx.sessionId}:${ctx.budget.attempts}:${stage.id}`, classifyFailure(err, layer, { code: ctx.state.tokenBudgetExhausted ? "BUDGET_TOKENS" : undefined }));
        callbacks.onStepNode?.({ id: `${ctx.sessionId}:${ctx.budget.attempts}:${stage.id}`, parentId: ctx.state.lastStepId || null, agentId: stage.id, title: stage.name, status: "failed", detail: err.message || String(err), timestamp: Date.now() });
        // Capture error in stage diagnostics
        if (!ctx.diagnostics[stage.id]) {
          const errDiag: StageDiagnostic = {
            stageId: stage.id,
            stageName: stage.name,
            status: "fail",
            durationMs: 0,
            timestamp: Date.now(),
            summary: `Error in ${stage.name}: ${err.message || String(err)}`,
            metrics: [{ label: "Execution", value: "Failed", status: "fail" }],
            error: err.message || String(err),
          };
          ctx.diagnostics[stage.id] = errDiag;
          callbacks.onDiagnosticUpdate?.(errDiag);
        }
        // If LLM or vital stage throws abort, stop further pipeline execution
        const reason = stopReason();
        progress(signal?.aborted ? "cancelled" : reason || ctx.state.tokenBudgetExhausted ? "exhausted" : "blocked",
          reason || err.message || String(err));
        break;
      }
    }
    if (ctx.runProgress?.status === "running" && !ctx.state.yieldedForAdjustment) {
      const reason = stopReason();
      if (reason) progress(signal?.aborted ? "cancelled" : "exhausted", reason);
      else if (ctx.state.routeVerified) progress("completed", "目标条件已通过独立核验；结果见报告");
      else progress("blocked", "流程结束，但尚无已验证的执行结果");
    }
    if (ctx.runProgress?.status !== "completed" && !ctx.state.yieldedForAdjustment) {
      const notice = `\n\n[${ctx.runProgress?.status}: ${ctx.runProgress?.reason}]`;
      ctx.state.fullContent = (ctx.state.fullContent || "") + notice;
      callbacks.onToken?.(ctx.state.fullContent);
    }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", forwardAbort);
    }
    return ctx;
  }
}

// Global default pipeline instance
export const defaultHarnessPipeline = new HarnessPipeline();
