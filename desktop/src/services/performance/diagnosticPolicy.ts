import config from "../../../diagnostics.config.json" with { type: "json" };
export interface DiagnosticPolicy { sampleMs: number; sustainedMs: number; cpuPercent: number; memoryBytes: number; maxFrameGapMs: number }
export const defaultDiagnosticPolicy: DiagnosticPolicy = Object.freeze(config.local);
if (Object.values(defaultDiagnosticPolicy).some(value => !Number.isFinite(value) || value <= 0) || defaultDiagnosticPolicy.cpuPercent > 100 || defaultDiagnosticPolicy.sampleMs < 1000) throw new Error("Invalid local diagnostic policy");
export type PerformanceWarning = "unresponsive" | "memory" | "cpu";
export class PerformanceWarnings {
  private since = new Map<PerformanceWarning, number>();
  private dismissed = new Set<PerformanceWarning>();
  private policy: DiagnosticPolicy;
  constructor(policy = defaultDiagnosticPolicy) { this.policy = policy; }
  dismiss(warning: PerformanceWarning) { this.dismissed.add(warning); }
  interrupt() { this.since.clear(); }
  reset() { this.since.clear(); this.dismissed.clear(); }
  observe(sample: { cpuPercent: number | null; memoryBytes: number; frameGapMs: number }, now: number): PerformanceWarning | null {
    const states: [PerformanceWarning, boolean][] = [["unresponsive", sample.frameGapMs >= this.policy.maxFrameGapMs], ["memory", sample.memoryBytes >= this.policy.memoryBytes], ["cpu", (sample.cpuPercent ?? 0) >= this.policy.cpuPercent]];
    let warning: PerformanceWarning | null = null;
    for (const [kind, active] of states) {
      if (!active) { this.since.delete(kind); this.dismissed.delete(kind); continue; }
      if (!this.since.has(kind)) this.since.set(kind, now);
      if (!warning && !this.dismissed.has(kind) && now - this.since.get(kind)! >= this.policy.sustainedMs) warning = kind;
    }
    return warning;
  }
}
