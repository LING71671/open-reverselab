import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { nativeBridge } from "../../../services/native/nativeBridge";

export class TargetDiscoveryStage implements PipelineStage {
  readonly id = "target-discovery";
  readonly name = "目标识别";
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
        summary: "未指定 target，无法开始任务",
        metrics: [
          { label: "Target", value: "None", status: "warn" },
        ],
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      throw new Error("请填写 target");
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
      const triage = await nativeBridge.triage(target, { timeoutMs: ctx.budget.monotonicDeadline - performance.now(), executionId: `${ctx.sessionId}:triage`, signal: ctx.signal });
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
        title: isDir ? `样本目录 · ${samplesCount} 项` : "目标识别",
        status: "done",
        detail: isDir
          ? `Primary: ${triage.resolvedBinary || "none"} in ${triage.containerDirectory} (${samplesCount} samples inventory)`
          : `${target} · ${triage.fileType || "类型未识别"}`,
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
        status: triage.httpError ? "warn" : "pass",
        durationMs,
        timestamp: Date.now(),
        summary: isDir
          ? `Found ${samplesCount} samples in ${triage.containerDirectory}; selected [${triage.resolvedBinary}]`
          : triage.targetUrl ? triage.httpError || `HTTP ${triage.httpStatus} · ${triage.targetUrl}` : `文件已读取：${target}`,
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
      throw err;
    }
  }
}
