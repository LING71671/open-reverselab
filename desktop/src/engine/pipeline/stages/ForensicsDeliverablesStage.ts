import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic, Deliverables } from "../../../core";
import { nativeBridge } from "../../../services";

export class ForensicsDeliverablesStage implements PipelineStage {
  readonly id = "forensics-deliverables";
  readonly name = "Forensics & Deliverables Synthesis";
  readonly description = "Extracts runnable forensic verification scripts, formats findings, and persists reports to disk";
  readonly category = "forensics" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const fullContent: string = ctx.state.fullContent || "";
    const target = ctx.resolvedBinary || ctx.target;
    const cleanTargetName = target.split(/[\\/]/).pop() || "target";

    const pyMatch = fullContent.match(/```python\s*([\s\S]*?)\s*```/i);
    let scriptExtracted = false;
    let scriptLines = 0;
    let script = "";

    if (pyMatch && pyMatch[1].trim()) {
      script = pyMatch[1].trim();
      scriptExtracted = true;
      scriptLines = script.split("\n").length;
    }

    let execOutput: any = undefined;
    if (script) {
      try {
        const execRes = await nativeBridge.execPython(script);
        execOutput = {
          success: execRes.success,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          executionTimeMs: execRes.executionTimeMs || execRes.durationMs,
        };
      } catch (err: any) {
        execOutput = {
          success: false,
          stderr: String(err?.message || err),
          executionTimeMs: 0,
        };
      }
    }

    const reportPath = `reports/${cleanTargetName}_analysis.md`;
    const scriptPath = `exports/${cleanTargetName}_forensics.py`;

    const deliverables: Deliverables = {
      summary: fullContent.split("\n\n")[0] || "Reverse engineering triage complete.",
      script: script || undefined,
      key: ctx.triage?.sha256 || "Extracted from binary stream",
      flag: "Verdict: Analyzed by ReverseLab Modular Harness",
      savedArtifacts: {
        report_path: reportPath,
        script_path: script ? scriptPath : undefined,
      },
      executionOutput: execOutput,
    };

    ctx.deliverables = deliverables;
    callbacks.onDeliverables?.(deliverables);

    let saved = false;
    let saveError = "";

    if (scriptExtracted || fullContent) {
      try {
        const res = await fetch("/api/system/save-report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: ctx.target,
            summary: deliverables.summary,
            script: deliverables.script,
            key: deliverables.key,
            flag: deliverables.flag,
            executionOutput: execOutput,
          }),
        });
        saved = res.ok;
      } catch (err: any) {
        saveError = err.message || String(err);
      }
    }

    const durationMs = Date.now() - startTime;
    const diag: StageDiagnostic = {
      stageId: this.id,
      stageName: this.name,
      status: scriptExtracted ? "pass" : "warn",
      durationMs,
      timestamp: Date.now(),
      summary: scriptExtracted
        ? `Generated ${scriptLines}-line forensic script, persisted to ${reportPath}`
        : "Forensics summary extracted (no standalone Python script block)",
      metrics: [
        { label: "Script Extracted", value: scriptExtracted ? "Yes" : "No", status: scriptExtracted ? "pass" : "warn" },
        { label: "Script Size", value: scriptLines, unit: "lines", status: scriptLines > 0 ? "pass" : "info" },
        { label: "Report Saved", value: saved ? "OK" : (saveError ? "Failed" : "Local"), status: saved ? "pass" : "info" },
        { label: "Synthesis Time", value: durationMs, unit: "ms", status: "pass" },
      ],
      evidence: {
        reportPath,
        scriptPath,
        scriptLines,
      },
      error: saveError || undefined,
    };
    ctx.diagnostics[this.id] = diag;
    callbacks.onDiagnosticUpdate?.(diag);
  }
}
