export interface ExecutionOptions {
  /** Omitted or positive infinity means no deadline; finite values are remaining user time. */
  timeoutMs?: number;
  executionId?: string;
  signal?: AbortSignal;
}

export function executionTimeout(timeoutMs?: number | null): number | undefined {
  if (timeoutMs === undefined || timeoutMs === null || timeoutMs === Infinity) return undefined;
  if (!Number.isFinite(timeoutMs)) throw new TypeError("Invalid execution timeout");
  if (timeoutMs <= 0) throw new DOMException("Execution time budget exhausted", "TimeoutError");
  return Math.ceil(timeoutMs);
}
