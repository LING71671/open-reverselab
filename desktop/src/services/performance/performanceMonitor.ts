import { invoke } from "@tauri-apps/api/core";
import { defaultDiagnosticPolicy, PerformanceWarnings, type DiagnosticPolicy, type PerformanceWarning } from "./diagnosticPolicy";

export interface PerformanceSample { cpuPercent: number | null; memoryBytes: number }
interface NativePerformance {
  sample(): Promise<PerformanceSample>;
  stop(): Promise<unknown>;
}
interface MonitorEnvironment {
  now(): number;
  hidden(): boolean;
  schedule(callback: () => void, delay: number): number;
  cancelTimer(id: number): void;
  requestFrame(callback: (time: number) => void): number;
  cancelFrame(id: number): void;
  onVisibilityChange(callback: () => void): () => void;
}

// Share this queue between mounts so an old sample cannot recreate the native
// sampler after disabling monitoring, or outlive a new monitoring session.
export function createPerformanceMonitor(native: NativePerformance, environment: MonitorEnvironment, policy: DiagnosticPolicy = defaultDiagnosticPolicy) {
  let pending: Promise<unknown> = Promise.resolve();
  const enqueue = <T>(operation: () => Promise<T>) => {
    const result = pending.then(operation);
    pending = result.catch(() => {});
    return result;
  };

  return {
    start(onWarning: (warning: PerformanceWarning | null) => void) {
      const warnings = new PerformanceWarnings(policy);
      let stopped = false;
      let generation = 0;
      let timer: number | undefined;
      let frame: number | undefined;
      let lastFrame = environment.now();
      let maxGap = 0;
      const current = (value: number) => !stopped && !environment.hidden() && generation === value;
      const cancelScheduled = () => {
        if (timer !== undefined) environment.cancelTimer(timer);
        if (frame !== undefined) environment.cancelFrame(frame);
        timer = undefined;
        frame = undefined;
      };
      const count = (time: number, value: number) => {
        if (!current(value)) return;
        maxGap = Math.max(maxGap, time - lastFrame);
        lastFrame = time;
        frame = environment.requestFrame(next => count(next, value));
      };
      const poll = async (value: number) => {
        if (!current(value)) return;
        try {
          const result = await enqueue(() => current(value) ? native.sample() : Promise.resolve(null));
          if (result && current(value)) {
            onWarning(warnings.observe({ ...result, frameGapMs: maxGap }, environment.now()));
            maxGap = 0;
          }
        } catch {
          if (current(value)) {
            // Missing readings cannot extend a period of sustained high load.
            warnings.interrupt();
            onWarning(null);
            maxGap = 0;
          }
        }
        if (current(value)) timer = environment.schedule(() => void poll(value), policy.sampleMs);
      };
      const visibility = () => {
        generation++;
        cancelScheduled();
        warnings.reset();
        onWarning(null);
        maxGap = 0;
        lastFrame = environment.now();
        if (environment.hidden()) void enqueue(() => native.stop()).catch(() => {});
        else {
          const value = generation;
          frame = environment.requestFrame(time => count(time, value));
          void poll(value);
        }
      };
      const unsubscribe = environment.onVisibilityChange(visibility);
      visibility();
      return {
        dismiss(warning: PerformanceWarning) { warnings.dismiss(warning); onWarning(null); },
        stop() {
          if (stopped) return pending.then(() => {});
          stopped = true;
          generation++;
          cancelScheduled();
          unsubscribe();
          warnings.reset();
          return enqueue(() => native.stop()).then(() => {}, () => {});
        },
      };
    },
  };
}

export const performanceMonitor = createPerformanceMonitor({
  sample: () => invoke<PerformanceSample>("performance_sample"),
  stop: () => invoke("performance_stop"),
}, {
  now: () => performance.now(),
  hidden: () => document.hidden,
  schedule: (callback, delay) => window.setTimeout(callback, delay),
  cancelTimer: id => window.clearTimeout(id),
  requestFrame: callback => requestAnimationFrame(callback),
  cancelFrame: id => cancelAnimationFrame(id),
  onVisibilityChange(callback) {
    document.addEventListener("visibilitychange", callback);
    return () => document.removeEventListener("visibilitychange", callback);
  },
});
