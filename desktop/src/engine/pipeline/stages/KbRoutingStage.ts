import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { nativeBridge, type KbTechnique } from "../../../services/native/nativeBridge";
import { inferKbBoard, selectKbTechniques } from "../kbSelection";
import { isHashObjective } from "../../tracks/evidence";

export class KbRoutingStage implements PipelineStage {
  readonly id = "kb-routing";
  readonly name = "知识检索";
  readonly description = "Selects indexed red, blue, or shared techniques from observed signals";
  readonly category = "kb" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    if (isHashObjective(ctx.prompt) && ctx.triage?.sha256) {
      ctx.state.builtinHash = true;
      const diag: StageDiagnostic = { stageId: this.id, stageName: this.name, status: "skipped", durationMs: 0, timestamp: Date.now(), summary: "SHA256 可直接核验，无需知识检索", metrics: [] };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      return;
    }
    let board = ctx.triage?.board || inferKbBoard(ctx.target);
    const toolId = `kb-${Date.now()}`;
    callbacks.onToolCall?.({
      id: toolId,
      tool: "list_kb_techniques",
      title: `Knowledge Base · ${ctx.track}`,
      status: "running",
      detail: `Matching ${ctx.track} techniques${board ? ` in ${board}` : ""}`,
    });

    const loaded: Array<{ path: string; content: string }> = [];
    const errors: string[] = [];
    let catalogLoaded = false;
    let selectedCount = 0;
    try {
      const catalog: KbTechnique[] = ctx.state.kbCatalog || await nativeBridge.listKb(ctx.track);
      ctx.state.kbCatalog = catalog;
      catalogLoaded = true;
      const query = [
        ctx.prompt,
        ...Object.values(ctx.triage?.capabilities || {}).flat(),
        ctx.triage?.packer || "",
        ctx.triage?.sections?.length ? "section" : "",
        ...(ctx.triage?.importedDlls || []),
      ].join(" ");
      const attempted = new Set<string>(ctx.state.attemptedKbPaths || []);
      while (!loaded.length && !ctx.signal?.aborted && performance.now() < ctx.budget.monotonicDeadline) {
        const available = catalog.filter((item: { path: string }) => !attempted.has(item.path));
        const peerPaths = (ctx.state.readPeerMessages?.() || []).flatMap((message: { payload: { evidenceRefs?: Array<{ path?: string }> } }) => message.payload.evidenceRefs?.map((ref) => ref.path) || []);
        const preferred = available.filter((item) => ctx.state.preferredKbPaths?.includes(item.path) || item.related_paths.some((path) => peerPaths.includes(path)));
        const selected = preferred.length ? preferred.slice(0, 4) : selectKbTechniques(available, ctx.track, query, board);
        if (!selected.length) {
          // Documents inform analysis; exhausting search results does not
          // exhaust observations or prevent repairing a failed action.
          break;
        }
        selectedCount += selected.length;
        board ||= selected[0]?.board || "general";
        selected.forEach((item) => attempted.add(item.path));
        ctx.state.attemptedKbPaths = [...attempted];
        const results = await Promise.allSettled(selected.map(async (item) => {
          const content = await nativeBridge.readKb(item.path);
          if (!content) throw new Error(`Document unavailable: ${item.path}`);
          return { path: item.path, content: `### ${item.title} [${item.track}]\nSource: ${item.path}\n${content.slice(0, 3000)}` };
        }));
        for (const result of results) {
          if (result.status === "fulfilled") loaded.push(result.value);
          else errors.push(String(result.reason?.message || result.reason));
        }
      }
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
      ctx.state.pathsExhausted = true;
      ctx.state.blockedReason = `知识库服务不可用：${errors[0]}`;
    }

    const documents: Array<{ path: string; content: string }> = [...(ctx.state.kbDocuments || []), ...loaded];
    ctx.state.kbDocuments = documents;
    const references = documents.slice(-4);
    const content = references.map((doc) => doc.content).join("\n\n");
    const matchedTechniques = references.map((doc) => doc.path);
    const kbPath = `kb/${board || "general"}/techniques/kb-index.json`;
    ctx.kbRouting = {
      board: board || "general",
      track: ctx.track,
      kbPath,
      length: content.length,
      content,
      matchedTechniques,
    };
    const durationMs = Date.now() - startTime;
    const summary = loaded.length
      ? `${ctx.track}: loaded ${loaded.length}/${selectedCount} matching documents`
      : catalogLoaded ? `${ctx.track}: no new matches; continuing with available evidence` : `Knowledge base unavailable: ${errors[0]}`;
    callbacks.onToolCall?.({
      id: toolId,
      tool: "list_kb_techniques",
      title: `Knowledge Base · ${ctx.track}`,
      status: errors.length ? "error" : "done",
      detail: summary,
      output: { board, track: ctx.track, matchedTechniques, errors },
      kbRef: matchedTechniques[0],
      durationMs,
    });
    const diag: StageDiagnostic = {
      stageId: this.id,
      stageName: this.name,
      status: errors.length ? "warn" : "pass",
      durationMs,
      timestamp: Date.now(),
      summary,
      metrics: [
        { label: "Track", value: ctx.track, status: "info" },
        { label: "Target Board", value: board || "general", status: "info" },
        { label: "Documents Loaded", value: loaded.length, status: loaded.length ? "pass" : "info" },
        { label: "Lookup Time", value: durationMs, unit: "ms", status: "info" },
      ],
      evidence: { board, track: ctx.track, matchedTechniques, selectedCount },
      error: errors.length ? errors.join("; ") : undefined,
    };
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
