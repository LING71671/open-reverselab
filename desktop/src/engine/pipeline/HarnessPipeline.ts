import {
  PipelineStage,
  PipelineContext,
  PipelineCallbacks,
  StageDiagnostic,
} from "../../core";
import { TargetDiscoveryStage } from "./stages/TargetDiscoveryStage";
import { StaticTriageStage } from "./stages/StaticTriageStage";
import { KbRoutingStage } from "./stages/KbRoutingStage";
import { LlmStreamStage } from "./stages/LlmStreamStage";
import { ForensicsDeliverablesStage } from "./stages/ForensicsDeliverablesStage";

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
    sessionId: string = `session-${Date.now()}`
  ): Promise<PipelineContext> {
    const ctx: PipelineContext = {
      sessionId,
      target,
      prompt,
      history,
      signal,
      diagnostics: {},
      state: {},
    };

    for (const stage of this.stages) {
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

      if (signal?.aborted) {
        break;
      }

      try {
        await stage.execute(ctx, callbacks);
      } catch (err: any) {
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
        if (signal?.aborted || err?.name === "AbortError") {
          break;
        }
        throw err;
      }
    }

    return ctx;
  }
}

// Global default pipeline instance
export const defaultHarnessPipeline = new HarnessPipeline();
