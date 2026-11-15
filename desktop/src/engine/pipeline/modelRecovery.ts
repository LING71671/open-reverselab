import type { PipelineCallbacks, PipelineContext } from "../../core/contracts/pipeline";
import { HealthFault } from "../../core/contracts/health";
import { classifyFailure } from "../../services/health/healthMonitor";

export class ModelRetryYielded extends Error {
  constructor() { super("正在应用补充要求"); }
}

export function canRetryModelRequest(error: unknown): boolean {
  const fault = error as { status?: number; name?: string; message?: string };
  const failure = classifyFailure(error, "model");
  if (["MODEL_AUTH", "MODEL_QUOTA", "INPUT_INVALID", "PROXY_AUTH", "PROXY_CONFIG", "USER_CANCELLED"].includes(failure.code)) return false;
  if (typeof fault?.status === "number") return fault.status === 408 || fault.status === 429 || fault.status >= 500 && fault.status <= 599;
  return ["NETWORK_FAILED", "NETWORK_TIMEOUT", "PROXY_CONNECT", "PROXY_UNAVAILABLE", "MODEL_TIMEOUT", "MODEL_RATE_LIMIT", "MODEL_UNAVAILABLE"].includes(failure.code)
    || /networkerror|network request failed|load failed|connection.*(?:closed|reset)|terminated|econnreset|enotfound|eai_again/i.test(fault?.message || "");
}

/** Retry model inference only: completed tools and their effects are never replayed. */
export async function recoverModelRequest<T>(
  ctx: PipelineContext, callbacks: PipelineCallbacks, operation: (signal: AbortSignal) => Promise<T>,
  node: { id: string; title: string; agentId: string; parentId?: string | null; parentIds?: string[] },
): Promise<T> {
  let retries = 0;
  let sequence = 0;
  const started = performance.now();
  const elapsedBefore = ctx.runProgress?.elapsedMs ?? 0;
  const check = () => {
    if (ctx.signal?.aborted) throw ctx.signal.reason instanceof Error ? ctx.signal.reason : new DOMException("Aborted", "AbortError");
    if (callbacks.shouldYield?.()) throw new ModelRetryYielded();
    if (performance.now() >= ctx.budget.monotonicDeadline) throw new HealthFault("BUDGET_TIME", "时间预算已耗尽");
    if (ctx.state.refreshTokenBudget) ctx.budget.maxTokens = ctx.state.refreshTokenBudget();
    if (ctx.budget.tokensUsed >= ctx.budget.maxTokens) {
      ctx.state.tokenBudgetExhausted = true;
      throw new HealthFault("BUDGET_TOKENS", "Token 额度已耗尽");
    }
  };
  const publish = (detail: string, error?: unknown, recovered = false) => {
    const failure = error === undefined ? undefined : classifyFailure(error, "model");
    callbacks.onStepNode?.({ ...node, status: "running", detail, timestamp: Date.now() });
    callbacks.onHealthEvent?.({ ...failure, eventId: `${ctx.sessionId}:model-recovery:${node.id}:${++sequence}`,
      goalId: ctx.sessionId, nodeId: node.id, branchId: ctx.track, layer: "model", status: recovered ? "healthy" : error === undefined ? "running" : "degraded",
      timestamp: Date.now(), reason: detail, retryable: true, recovery: "retry" });
    if (ctx.runProgress) {
      ctx.runProgress = { ...ctx.runProgress, status: "running", reason: detail, elapsedMs: Math.round(elapsedBefore + performance.now() - started), tokensUsed: ctx.budget.tokensUsed, usageEstimated: ctx.budget.usageEstimated };
      callbacks.onRunProgress?.(ctx.runProgress);
    }
  };
  const wait = (delayMs: number, wakeOnOnline = true) => new Promise<void>((resolve, reject) => {
    const until = performance.now() + delayMs;
    let timer: ReturnType<typeof setTimeout>;
    let settled = false;
    const events = typeof window === "undefined" ? undefined : window;
    const cleanup = () => { clearTimeout(timer); events?.removeEventListener("online", online); ctx.signal?.removeEventListener("abort", aborted); };
    const finish = (error?: unknown) => { if (settled) return; settled = true; cleanup(); error === undefined ? resolve() : reject(error); };
    const tick = () => {
      try {
        check();
        if (performance.now() >= until) { finish(); return; }
        timer = setTimeout(tick, Math.min(500, until - performance.now()));
      } catch (error) { finish(error); }
    };
    const online = () => { try { check(); finish(); } catch (error) { finish(error); } };
    const aborted = () => { try { check(); } catch (error) { finish(error); } };
    if (wakeOnOnline) events?.addEventListener("online", online);
    ctx.signal?.addEventListener("abort", aborted, { once: true });
    tick();
  });
  while (true) {
    check();
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      publish("网络已断开，等待恢复后继续", new HealthFault("NETWORK_FAILED", "设备当前离线"));
      await wait(30_000);
      continue;
    }
    if (retries) publish(`正在重新连接模型 · 第 ${retries} 次重试`);
    const attempt = new AbortController();
    const events = typeof window === "undefined" ? undefined : window;
    const aborted = () => attempt.abort(ctx.signal?.reason);
    const offline = () => attempt.abort(new HealthFault("NETWORK_FAILED", "网络已断开"));
    ctx.signal?.addEventListener("abort", aborted, { once: true });
    events?.addEventListener("offline", offline);
    if (ctx.signal?.aborted) aborted();
    let error: unknown;
    try {
      const result = await operation(attempt.signal);
      check();
      if (retries || sequence) publish("连接已恢复，继续执行", undefined, true);
      return result;
    } catch (failure) {
      error = attempt.signal.aborted ? attempt.signal.reason ?? failure : failure;
    } finally {
      ctx.signal?.removeEventListener("abort", aborted);
      events?.removeEventListener("offline", offline);
    }
    check();
    if (!canRetryModelRequest(error)) throw error;
    retries++;
    const requested = (error as { retryAfterMs?: number }).retryAfterMs;
    const delay = Number.isFinite(requested) ? Math.max(1000, requested!) : Math.min(30_000, 2000 * 2 ** Math.min(retries - 1, 4));
    publish(`${classifyFailure(error, "model").reason}，${Math.ceil(delay / 1000)} 秒后重试 · 第 ${retries} 次`, error);
    await wait(delay, !Number.isFinite(requested));
  }
}
