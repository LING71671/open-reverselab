import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { nativeBridge } from "../../../services";

export class TargetDiscoveryStage implements PipelineStage {
  readonly id = "target-discovery";
  readonly name = "Target & Sample Discovery";
  readonly description = "Probes target file or container directory, discovers associated binaries and components";
  readonly category = "discovery" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const target = ctx.target.trim();

    if (!target) {
      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: "warn",
        durationMs: 0,
        timestamp: Date.now(),
        summary: "No target specified; proceeding with generic reverse environment",
        metrics: [
          { label: "Target", value: "None", status: "warn" },
          { label: "Mode", value: "Ad-hoc Request", status: "info" },
        ],
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      return;
    }

    const toolId = `tool-discovery-${Date.now()}`;
    callbacks.onToolCall?.({
      id: toolId,
      tool: "target_discovery",
      title: "Discovering Target & Samples",
      status: "running",
      detail: `Scanning ${target}`,
    });

    try {
      const triage = await nativeBridge.triage(target);
      ctx.triage = triage;
      ctx.discoveredSamples = triage.discoveredSamples || [];
      ctx.containerDirectory = triage.containerDirectory;
      ctx.resolvedBinary = triage.resolvedBinary;

      const durationMs = Date.now() - startTime;
      const isDir = !!triage.isContainerDirectory;
      const samplesCount = ctx.discoveredSamples.length;

      callbacks.onDiscoveredSamples?.(
        ctx.discoveredSamples,
        ctx.containerDirectory,
        ctx.resolvedBinary
      );

      callbacks.onToolCall?.({
        id: toolId,
        tool: "target_discovery",
        title: isDir ? `Sample Directory Discovered (${samplesCount} items)` : `Target Binary Verified`,
        status: "done",
        detail: isDir
          ? `Primary: ${triage.resolvedBinary || "none"} in ${triage.containerDirectory} (${samplesCount} samples inventory)`
          : `Binary: ${target} (${triage.fileType || "PE/Binary"})`,
        output: {
          containerDirectory: triage.containerDirectory,
          resolvedBinary: triage.resolvedBinary,
          samples: ctx.discoveredSamples,
        },
        durationMs,
      });

      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: "pass",
        durationMs,
        timestamp: Date.now(),
        summary: isDir
          ? `Found ${samplesCount} samples in ${triage.containerDirectory}; selected [${triage.resolvedBinary}]`
          : `Target file verified: ${target}`,
        metrics: [
          { label: "Mode", value: isDir ? "Container Directory" : "Single Sample", status: "pass" },
          { label: "Inventory Count", value: samplesCount, unit: "files", status: "pass" },
          { label: "Primary Target", value: triage.resolvedBinary || target, status: "pass" },
          { label: "Scan Latency", value: durationMs, unit: "ms", status: "pass" },
        ],
        evidence: {
          containerDirectory: triage.containerDirectory,
          resolvedBinary: triage.resolvedBinary,
          samples: ctx.discoveredSamples,
        },
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      callbacks.onToolCall?.({
        id: toolId,
        tool: "target_discovery",
        title: "Target Discovery Exception",
        status: "error",
        detail: err.message || String(err),
        durationMs,
      });

      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: "fail",
        durationMs,
        timestamp: Date.now(),
        summary: `Discovery error: ${err.message || String(err)}`,
        metrics: [
          { label: "Status", value: "Error", status: "fail" },
          { label: "Target", value: target, status: "warn" },
        ],
        error: err.message || String(err),
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
    }
  }
}
