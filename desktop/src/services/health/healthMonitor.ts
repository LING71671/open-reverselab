import { HEALTH_CODES, HEALTH_LAYERS, HealthFault } from "../../core/contracts/health.ts";
import type {
  ClassifiedFailure, FailureDetails, HealthCode, HealthEvent, HealthLayer,
  HealthLayerSnapshot, HealthSnapshot, HealthStatus,
} from "../../core/contracts/health.ts";

type FailureRule = Omit<ClassifiedFailure, "code" | "detail" | "layer"> & { layer?: HealthLayer };
const RULES: Record<HealthCode, FailureRule> = {
  INPUT_INVALID: { layer: "goal", severity: "warning", retryable: false, recovery: "revise", reason: "输入无效" },
  MODEL_AUTH: { layer: "model", severity: "error", retryable: false, recovery: "configure", reason: "模型认证失败" },
  MODEL_QUOTA: { layer: "model", severity: "error", retryable: false, recovery: "configure", reason: "模型额度不足" },
  MODEL_RATE_LIMIT: { layer: "model", severity: "warning", retryable: true, recovery: "retry", reason: "模型请求过于频繁" },
  MODEL_TIMEOUT: { layer: "model", severity: "warning", retryable: true, recovery: "retry", reason: "模型响应超时" },
  MODEL_UNAVAILABLE: { layer: "model", severity: "error", retryable: true, recovery: "alternate", reason: "模型暂不可用" },
  KB_UNAVAILABLE: { layer: "kb", severity: "error", retryable: false, recovery: "configure", reason: "知识库不可用" },
  KB_DOC_MISSING: { layer: "kb", severity: "warning", retryable: false, recovery: "alternate", reason: "知识文档不存在" },
  TOOL_MISSING: { layer: "tool", severity: "error", retryable: false, recovery: "configure", reason: "工具未安装" },
  TOOL_TIMEOUT: { layer: "tool", severity: "warning", retryable: true, recovery: "alternate", reason: "工具执行超时" },
  TOOL_FAILED: { layer: "tool", severity: "error", retryable: false, recovery: "alternate", reason: "工具执行失败" },
  TOOL_UNAVAILABLE: { layer: "tool", severity: "error", retryable: true, recovery: "configure", reason: "执行服务不可用" },
  EVIDENCE_INVALID: { layer: "agent", severity: "warning", retryable: false, recovery: "alternate", reason: "证据未通过验证" },
  LOOP_DETECTED: { layer: "agent", severity: "warning", retryable: false, recovery: "alternate", reason: "检测到重复执行" },
  BUDGET_TIME: { layer: "goal", severity: "warning", retryable: false, recovery: "stop", reason: "时间预算已耗尽" },
  BUDGET_TOKENS: { layer: "goal", severity: "warning", retryable: false, recovery: "stop", reason: "Token 预算已耗尽" },
  USER_CANCELLED: { layer: "goal", severity: "info", retryable: false, recovery: "stop", reason: "运行已停止" },
  STORAGE_FAILED: { layer: "storage", severity: "error", retryable: false, recovery: "configure", reason: "结果保存失败" },
  UNKNOWN: { severity: "error", retryable: false, recovery: "inspect", reason: "发生未知错误" },
};
const knownCodes = new Set<string>(HEALTH_CODES);
const recordOf = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
const stringOf = (value: unknown): string => typeof value === "string" ? value : "";

function inferCode(error: unknown, layer: HealthLayer, details: FailureDetails): HealthCode {
  const source = recordOf(error);
  if (details.code && knownCodes.has(details.code)) return details.code;
  if (error instanceof HealthFault) return error.code;
  if (typeof source.code === "string" && knownCodes.has(source.code)) return source.code as HealthCode;

  const response = recordOf(source.response);
  const nested = recordOf(source.error);
  const data = recordOf(recordOf(response.data).error);
  let body: Record<string, unknown> = {};
  if (typeof source.responseBody === "string") {
    try { body = recordOf(recordOf(JSON.parse(source.responseBody)).error); } catch { /* Non-JSON response. */ }
  }
  const status = details.status ?? source.status ?? source.statusCode ?? response.status;
  const text = [
    typeof error === "string" ? error : "", source.name, source.message, source.code,
    nested.message, nested.code, data.message, data.code, body.message, body.code, details.detail,
  ].map(stringOf).join(" ").toLowerCase();

  if (/token (?:budget|limit).*(?:exhausted|exceeded)|token.*预算.*(?:耗尽|用尽)/i.test(text)) return "BUDGET_TOKENS";
  if (/time budget.*(?:exhausted|exceeded)|时间预算.*(?:耗尽|用尽)/.test(text)) return "BUDGET_TIME";
  if (/loop detected|duplicate action|repeated action|检测到重复|重复执行/.test(text)) return "LOOP_DETECTED";
  if (/user[_ -]?cancel|用户.*(?:停止|取消)|aborterror/.test(text)) return "USER_CANCELLED";

  if (layer === "model") {
    // Quota failures commonly use HTTP 429 too; do not treat them as a retryable rate limit.
    if (/insufficient[_ -]?quota|quota[_ -]?(?:exceeded|exhausted)|billing[_ -]?hard[_ -]?limit|credit[_ -]?(?:balance|exhausted)|余额不足|额度不足/.test(text)) return "MODEL_QUOTA";
    if (status === 401 || status === 403 || /invalid[_ -]?api[_ -]?key|authentication|unauthorized/.test(text)) return "MODEL_AUTH";
    if (status === 429 || /rate[_ -]?limit|too many requests/.test(text)) return "MODEL_RATE_LIMIT";
    if (status === 408 || status === 504 || /timeout|timed out|etimedout|超时/.test(text)) return "MODEL_TIMEOUT";
    if (status === 400 || status === 422) return "INPUT_INVALID";
    if (status === 404 || (typeof status === "number" && status >= 500) || /network|fetch failed|failed to fetch|econn|unavailable/.test(text)) return "MODEL_UNAVAILABLE";
  }
  if (layer === "kb") {
    if (status === 404 || /enoent|document not found|file not found|文档不存在/.test(text)) return "KB_DOC_MISSING";
    return "KB_UNAVAILABLE";
  }
  if (layer === "tool") {
    if (/enoent|not installed|command not found|not recognized|未安装/.test(text)) return "TOOL_MISSING";
    if (status === 408 || status === 504 || /timeout|timed out|etimedout|超时/.test(text)) return "TOOL_TIMEOUT";
    return "TOOL_FAILED";
  }
  if (layer === "storage") return "STORAGE_FAILED";
  return "UNKNOWN";
}

export function classifyFailure(error: unknown, layer: HealthLayer, details: FailureDetails = {}): ClassifiedFailure {
  const code = inferCode(error, layer, details);
  const source = recordOf(error);
  const detail = details.detail ?? (typeof error === "string" ? error : stringOf(source.message) || stringOf(source.code));
  const rule = RULES[code];
  return Object.freeze({ ...rule, code, layer: rule.layer ?? layer, detail });
}

const statusPriority: Record<HealthStatus, number> = {
  unknown: 0, healthy: 1, cancelled: 2, running: 3, degraded: 4, failed: 5,
};
const eventStatuses = new Set<HealthStatus>(["running", "healthy", "degraded", "failed", "cancelled"]);
const traceKey = (event: HealthEvent) => JSON.stringify([event.branchId, event.agentId, event.nodeId]);

/** Records actual observations; it does not probe services or assume they are ready. */
export class HealthMonitor {
  readonly goalId: string;
  private readonly maxHistory: number;
  private readonly history: HealthEvent[] = [];
  private readonly retainedIds = new Set<string>();
  private observedEvents = 0;
  private readonly counts = new Map<HealthLayer, number>();
  private readonly latest = new Map<HealthLayer, HealthEvent>();

  constructor(options: { goalId: string; maxHistory?: number }) {
    if (!options.goalId.trim()) throw new Error("Health monitor requires a goal ID");
    this.goalId = options.goalId;
    this.maxHistory = options.maxHistory ?? 256;
    if (!Number.isSafeInteger(this.maxHistory) || this.maxHistory < 1) throw new Error("Invalid health history limit");
  }

  record(event: HealthEvent): boolean {
    if (event.goalId !== this.goalId) throw new Error("Health event belongs to another goal");
    if (!event.eventId.trim()) throw new Error("Health event ID is required");
    if (!HEALTH_LAYERS.includes(event.layer) || !eventStatuses.has(event.status)) throw new Error("Invalid health layer or status");
    if (!Number.isFinite(event.timestamp) || event.timestamp < 0) throw new Error("Invalid health timestamp");
    if (event.durationMs !== undefined && (!Number.isFinite(event.durationMs) || event.durationMs < 0)) throw new Error("Invalid health duration");
    if (event.code !== undefined && !knownCodes.has(event.code)) throw new Error("Invalid health code");
    if (this.retainedIds.has(event.eventId)) return false;
    const accepted = Object.freeze({ ...event });
    this.history.push(accepted);
    this.retainedIds.add(accepted.eventId);
    if (this.history.length > this.maxHistory) this.retainedIds.delete(this.history.shift()!.eventId);
    this.observedEvents++;
    this.counts.set(accepted.layer, (this.counts.get(accepted.layer) ?? 0) + 1);
    const latest = this.latest.get(accepted.layer);
    if (!latest || accepted.timestamp >= latest.timestamp) this.latest.set(accepted.layer, accepted);
    return true;
  }

  readHistory(): readonly HealthEvent[] {
    return Object.freeze([...this.history]);
  }

  snapshot(): HealthSnapshot {
    const layers = {} as Record<HealthLayer, HealthLayerSnapshot>;
    for (const layer of HEALTH_LAYERS) {
      const traces = new Map<string, HealthEvent>();
      for (const event of this.history) {
        if (event.layer !== layer) continue;
        const key = traceKey(event);
        const previous = traces.get(key);
        if (!previous || event.timestamp >= previous.timestamp) traces.set(key, event);
      }
      const lastEvent = this.latest.get(layer);
      let status: HealthStatus = traces.size ? "unknown" : lastEvent?.status ?? "unknown";
      for (const event of traces.values()) {
        if (statusPriority[event.status] > statusPriority[status]) status = event.status;
      }
      layers[layer] = Object.freeze({ layer, status, observedEvents: this.counts.get(layer) ?? 0, lastEvent });
    }
    return Object.freeze({
      goalId: this.goalId, observedEvents: this.observedEvents,
      retainedEvents: this.history.length, layers: Object.freeze(layers),
    });
  }
}
