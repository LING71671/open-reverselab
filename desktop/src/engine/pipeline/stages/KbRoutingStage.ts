import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { nativeBridge } from "../../../services";

export class KbRoutingStage implements PipelineStage {
  readonly id = "kb-routing";
  readonly name = "KB Attack Network Routing";
  readonly description = "Matches domain knowledge base and consults attack network trees";
  readonly category = "kb" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const board = ctx.triage?.board || "pe-reverse";
    const kbPath = `kb/${board}/techniques/attack-network.md`;
    const toolId = `kb-${Date.now()}`;

    callbacks.onToolCall?.({
      id: toolId,
      tool: "read_kb_doc",
      title: `Attack Network Routing (${board})`,
      status: "running",
      detail: `Loading ${kbPath}`,
      kbRef: kbPath,
    });

    let docLength = 0;
    let docLoaded = false;
    let docError = "";
    let loadedContent = "";

    try {
      const kbContent = await nativeBridge.readKb(kbPath);
      if (kbContent) {
        loadedContent = kbContent;
        docLength = kbContent.length;
        docLoaded = true;
      }
    } catch (e: any) {
      docError = e.message || String(e);
    }

    // Match concrete open-reverseLab attack network primitives
    const matchedTechniques: string[] = [];
    const triage = ctx.triage;
    if (triage?.capabilities?.antiDebug && triage.capabilities.antiDebug.length > 0) {
      matchedTechniques.push("kb/pe-reverse/techniques/04-dynamic-analysis/05-anti-debug-bypass.md");
    }
    if (triage?.capabilities?.registryPersistence && triage.capabilities.registryPersistence.length > 0) {
      matchedTechniques.push("kb/pe-reverse/techniques/06-ioc-extraction/08-procmon-patterns.md");
    }
    if (triage?.sections && triage.sections.length > 0) {
      matchedTechniques.push("kb/pe-reverse/techniques/02-pe-structure/01-pe-header-parsing.md");
    }
    if (ctx.discoveredSamples?.some((s) => s.ext === ".sys")) {
      matchedTechniques.push("kb/pe-reverse/techniques/09-av-evasion/ (Driver Filter Review)");
    }

    const durationMs = Date.now() - startTime;
    ctx.kbRouting = {
      board,
      kbPath,
      length: docLength,
      content: loadedContent,
      matchedTechniques,
    };

    callbacks.onToolCall?.({
      id: toolId,
      tool: "read_kb_doc",
      title: `Attack Network Routing (${board})`,
      status: "done",
      detail: docLoaded
        ? `Loaded ${kbPath} (${docLength} chars), Matched ${matchedTechniques.length} techniques`
        : `Using default reverse guidelines for ${board}`,
      output: {
        board,
        kbPath,
        docLength,
        matchedTechniques,
        status: docLoaded ? "loaded" : "fallback",
      },
      durationMs,
    });

    const diag: StageDiagnostic = {
      stageId: this.id,
      stageName: this.name,
      status: docLoaded ? "pass" : "warn",
      durationMs,
      timestamp: Date.now(),
      summary: docLoaded
        ? `Active Board: [${board}], Attack Network Document: ${docLength} bytes`
        : `Active Board: [${board}], Standard rule set active`,
      metrics: [
        { label: "Target Board", value: board, status: "pass" },
        { label: "Attack Network", value: kbPath, status: docLoaded ? "pass" : "info" },
        { label: "Rules Loaded", value: docLoaded ? `${docLength} chars` : "Default", status: docLoaded ? "pass" : "warn" },
        { label: "Lookup Time", value: durationMs, unit: "ms", status: "pass" },
      ],
      evidence: { board, kbPath, docLength },
      error: docError || undefined,
    };
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
