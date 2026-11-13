import { Deliverables } from "./graph";
import { ToolExecutionRecord } from "./chat";
import type { SecurityTrack } from "./track";
import type { HealthEvent } from "./health";

import { TriageResult } from "../../services/native/nativeBridge";

export type StageStatus = "pending" | "running" | "pass" | "warn" | "fail" | "skipped";

export interface RunBudget {
  maxDurationMs?: number;
  maxTokens?: number;
}

export interface AcceptancePlan {
  target: string;
  objective: string;
  scope?: "goal" | "red" | "blue";
  checks: Array<{ id: string; criterion: string; expected: string }>;
}

export interface RunProgress extends RunBudget {
  status: "running" | "completed" | "exhausted" | "blocked" | "cancelled";
  reason?: string;
  elapsedMs: number;
  tokensUsed: number;
  usageEstimated?: boolean;
  attempts: number;
  checkpoint?: {
    target: string;
    objective: string;
    track: SecurityTrack;
    visitedPaths: string[];
    actionFingerprints: string[];
    blockedReasons: string[];
  };
}

export interface PipelineBudget extends RunBudget {
  maxDurationMs: number;
  maxTokens: number;
  startedAt: number;
  deadline: number;
  monotonicDeadline: number;
  tokensUsed: number;
  usageEstimated: boolean;
  attempts: number;
}

export interface DiagnosticMetric {
  label: string;
  value: string | number;
  unit?: string;
  status?: "pass" | "warn" | "fail" | "info";
}

export interface StageDiagnostic {
  stageId: string;
  stageName: string;
  status: StageStatus;
  durationMs: number;
  timestamp: number;
  summary: string;
  metrics: DiagnosticMetric[];
  evidence?: Record<string, any>;
  error?: string;
}

export interface DiscoveredSample {
  name: string;
  path: string;
  sizeBytes: number;
  ext: string;
  type: string;
  isPrimary?: boolean;
}

export interface PipelineContext {
  sessionId: string;
  readonly track: SecurityTrack;
  budget: PipelineBudget;
  runProgress?: RunProgress;
  readonly target: string;
  readonly prompt: string;
  history: Array<{ role: string; content: string }>;
  signal?: AbortSignal;
  diagnostics: Record<string, StageDiagnostic>;
  discoveredSamples?: DiscoveredSample[];
  resolvedBinary?: string;
  containerDirectory?: string;
  triage?: TriageResult;
  kbRouting?: {
    board: string;
    track: SecurityTrack;
    kbPath: string;
    length: number;
    content?: string;
    matchedTechniques?: string[];
  };
  llmTelemetry?: {
    provider: string;
    model: string;
    ttftMs: number;
    totalDurationMs: number;
    tokensCount: number;
    speedTokPerSec: number;
  };
  deliverables?: Deliverables;
  state: Record<string, any>;
}

export interface PipelineCallbacks {
  /** A user adjustment yields after the current bounded stage has settled. */
  shouldYield?: () => boolean;
  onToken?: (text: string) => void;
  onTitle?: (title: string) => void;
  onToolCall?: (toolRecord: ToolExecutionRecord) => void;
  onStepNode?: (step: any) => void;
  onDeliverables?: (deliverables: Deliverables) => void;
  onDiagnosticUpdate?: (diagnostic: StageDiagnostic) => void;
  onDiscoveredSamples?: (samples: DiscoveredSample[], containerDir?: string, primary?: string) => void;
  onRunProgress?: (progress: RunProgress) => void;
  onHealthEvent?: (event: HealthEvent) => void;
}

export interface PipelineStage {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly category: "discovery" | "triage" | "kb" | "llm" | "forensics" | "custom";
  enabled: boolean;
  execute: (ctx: PipelineContext, callbacks: PipelineCallbacks) => Promise<void>;
}
