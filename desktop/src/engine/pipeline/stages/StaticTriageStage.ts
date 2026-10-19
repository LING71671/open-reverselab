import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic, GraphStep } from "../../../core";

export class StaticTriageStage implements PipelineStage {
  readonly id = "static-triage";
  readonly name = "Binary Static Triage";
  readonly description = "Extracts headers, sections, entropy, anti-debug capabilities and packer indicators";
  readonly category = "triage" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const triage = ctx.triage;

    if (!triage) {
      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: "warn",
        durationMs: 0,
        timestamp: Date.now(),
        summary: "No static binary metadata available for triage",
        metrics: [{ label: "Triage Status", value: "Skipped", status: "warn" }],
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      return;
    }

    const toolId = `triage-${Date.now()}`;
    const triageStep: GraphStep = {
      id: toolId,
      parentId: null,
      agentId: "triage_target",
      title: "PE & Binary Triage",
      status: "running",
      detail: `Extracting headers and entropy for ${triage.resolvedBinary || ctx.target}`,
      timestamp: Date.now(),
    };
    callbacks.onStepNode?.(triageStep);

    // Calculate entropy metrics
    const sections = triage.sections || [];
    const maxEntropy = sections.length > 0 ? Math.max(...sections.map((s) => s.entropy)) : 0;
    const antiDebugApis = triage.capabilities?.antiDebug || [];
    const durationMs = Date.now() - startTime;

    callbacks.onToolCall?.({
      id: toolId,
      tool: "triage_target",
      title: "Static Binary Analysis",
      status: "done",
      detail: `${triage.fileType} | Arch: ${triage.arch || "unknown"} | Entropy: ${maxEntropy} | Packer: ${triage.packer || "None"}`,
      output: triage,
      durationMs,
    });

    callbacks.onStepNode?.({
      ...triageStep,
      status: "done",
      detail: `Identified ${triage.fileType} (${triage.arch || "x86/x64"}) - ${sections.length} sections`,
      evidence: triage,
    });

    const diag: StageDiagnostic = {
      stageId: this.id,
      stageName: this.name,
      status: "pass",
      durationMs,
      timestamp: Date.now(),
      summary: `Analyzed ${triage.fileType} (${triage.arch || "x86_64"}), Max Entropy: ${maxEntropy}, Packer: ${triage.packer || "None"}`,
      metrics: [
        { label: "Architecture", value: triage.arch || "Unknown", status: "pass" },
        { label: "Max Entropy", value: maxEntropy, unit: "bits", status: maxEntropy > 7.2 ? "warn" : "pass" },
        { label: "Packer Status", value: triage.packer || "None", status: triage.packer?.includes("Packed") ? "warn" : "pass" },
        { label: "Anti-Debug APIs", value: antiDebugApis.length, unit: "APIs", status: antiDebugApis.length > 0 ? "warn" : "pass" },
        { label: "Sections", value: sections.length, unit: "sections", status: "pass" },
      ],
      evidence: {
        entryPoint: triage.entryPoint,
        sha256: triage.sha256,
        antiDebug: antiDebugApis,
        importedDlls: triage.importedDlls,
      },
    };
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
