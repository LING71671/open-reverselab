export const HEALTH_LAYERS = ["goal", "agent", "model", "kb", "tool", "storage"] as const;
export type HealthLayer = typeof HEALTH_LAYERS[number];

export const HEALTH_CODES = [
  "INPUT_INVALID", "MODEL_AUTH", "MODEL_QUOTA", "MODEL_RATE_LIMIT", "MODEL_TIMEOUT",
  "MODEL_UNAVAILABLE", "KB_UNAVAILABLE", "KB_DOC_MISSING", "TOOL_MISSING", "TOOL_TIMEOUT",
  "TOOL_FAILED", "TOOL_UNAVAILABLE", "EVIDENCE_INVALID", "LOOP_DETECTED", "BUDGET_TIME", "BUDGET_TOKENS",
  "USER_CANCELLED", "STORAGE_FAILED", "UNKNOWN",
  "PROXY_CONFIG", "PROXY_CONNECT", "PROXY_AUTH", "PROXY_UNAVAILABLE", "NETWORK_TIMEOUT", "NETWORK_FAILED",
] as const;
export type HealthCode = typeof HEALTH_CODES[number];
export type HealthSeverity = "info" | "warning" | "error";
export type HealthRecovery = "retry" | "alternate" | "configure" | "revise" | "stop" | "inspect";
export type HealthStatus = "unknown" | "running" | "healthy" | "degraded" | "failed" | "cancelled";

export interface ClassifiedFailure {
  readonly code: HealthCode;
  readonly layer: HealthLayer;
  readonly severity: HealthSeverity;
  readonly retryable: boolean;
  readonly recovery: HealthRecovery;
  /** Short text suitable for the interface. */
  readonly reason: string;
  /** Diagnostic context, kept separate from the short reason. */
  readonly detail: string;
}

export interface FailureDetails {
  readonly code?: HealthCode;
  readonly status?: number;
  readonly detail?: string;
}

/** Use explicit codes at the failure source; normalization is only a fallback. */
export class HealthFault extends Error {
  readonly code: HealthCode;
  constructor(code: HealthCode, detail = "") {
    super(detail || code);
    this.name = "HealthFault";
    this.code = code;
  }
}

export interface HealthEvent {
  readonly eventId: string;
  readonly goalId: string;
  readonly layer: HealthLayer;
  readonly status: Exclude<HealthStatus, "unknown">;
  readonly timestamp: number;
  readonly branchId?: string;
  readonly agentId?: string;
  readonly nodeId?: string;
  readonly correlationId?: string;
  readonly durationMs?: number;
  readonly code?: HealthCode;
  readonly severity?: HealthSeverity;
  readonly retryable?: boolean;
  readonly recovery?: HealthRecovery;
  readonly reason?: string;
  readonly detail?: string;
}

export interface HealthLayerSnapshot {
  readonly layer: HealthLayer;
  /** Aggregate of the latest trace observations in the retained event window. */
  readonly status: HealthStatus;
  readonly observedEvents: number;
  readonly lastEvent?: HealthEvent;
}

export interface HealthSnapshot {
  readonly goalId: string;
  readonly observedEvents: number;
  readonly retainedEvents: number;
  readonly layers: Readonly<Record<HealthLayer, HealthLayerSnapshot>>;
}
