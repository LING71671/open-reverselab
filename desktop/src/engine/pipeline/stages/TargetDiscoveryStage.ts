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
      const samplesCount = triage.inventoryScan?.sampleCount ?? ctx.discoveredSamples.length;
      const limitLabels = { bytes: "样本总大小", depth: "子目录深度", entries: "目录项数量", unreadable: "部分目录项无法读取" };
      const limitedBy = triage.inventoryScan?.limitsReached.map(reason => limitLabels[reason]).join("、");
      const scanNote = limitedBy ? `扫描未覆盖整个目录（${limitedBy}）` : "";

      callbacks.onDiscoveredSamples?.(
        ctx.discoveredSamples,
        ctx.containerDirectory,
        ctx.resolvedBinary
      );

      if (isDir && !samplesCount) {
        const reason = scanNote ? `${scanNote}，已扫描范围内未找到支持的样本` : "目录中未找到支持的样本";
        throw new Error(`${reason}。请选择包含样本的子目录或直接选择文件。`);
      }
      const inventorySummary = [`已发现 ${samplesCount} 个样本`, triage.resolvedBinary && `主样本 ${triage.resolvedBinary}`, scanNote]
        .filter(Boolean).join(" · ");

      callbacks.onToolCall?.({
        id: toolId,
        tool: "target_discovery",
        title: isDir ? `样本目录 · ${samplesCount} 项` : "目标识别",
        status: "done",
        detail: isDir
          ? inventorySummary
          : `${target} · ${triage.fileType || "类型未识别"}`,
        output: {
          containerDirectory: triage.containerDirectory,
          resolvedBinary: triage.resolvedBinary,
          samples: ctx.discoveredSamples,
          inventoryScan: triage.inventoryScan,
        },
        durationMs,
      });

      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: triage.httpError || limitedBy ? "warn" : "pass",
        durationMs,
        timestamp: Date.now(),
        summary: isDir
          ? inventorySummary
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
          inventoryScan: triage.inventoryScan,
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
