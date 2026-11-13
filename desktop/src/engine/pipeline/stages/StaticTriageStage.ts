import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";

export class StaticTriageStage implements PipelineStage {
  readonly id = "static-triage";
  readonly name = "静态初筛";
  readonly description = "Summarizes observed headers, sections and capabilities";
  readonly category = "triage" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const triage = ctx.triage;
    const sections = triage?.sections;
    const entropy = sections?.length ? Math.max(...sections.map(section => section.entropy)) : undefined;
    const summary = triage ? [triage.fileType, triage.arch, sections && `${sections.length} 个节区`].filter(Boolean).join(" · ") : "未获得静态元数据";
    const diag: StageDiagnostic = {
      stageId: this.id, stageName: this.name, status: !triage || triage.parseWarning ? "warn" : "pass", durationMs: 0, timestamp: Date.now(),
      summary: triage?.parseWarning ? `${summary}；解析未完成：${triage.parseWarning}` : summary,
      metrics: [
        { label: "Architecture", value: triage?.arch || "未识别", status: triage?.arch ? "pass" : "info" },
        { label: "Max Entropy", value: entropy ?? "未观测", status: entropy === undefined ? "info" : entropy > 7.2 ? "warn" : "pass" },
        { label: "Packer", value: triage?.packer || "未观测", status: "info" },
      ],
      evidence: triage,
      error: triage?.parseWarning,
    };
    callbacks.onToolCall?.({ id: `${ctx.sessionId}:triage-summary`, tool: "triage_target", title: "静态初筛", status: triage ? "done" : "error", detail: diag.summary, output: triage });
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
