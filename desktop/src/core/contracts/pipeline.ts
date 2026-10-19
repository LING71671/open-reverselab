import { Deliverables } from "./graph";
import { ToolExecutionRecord } from "./chat";

import { TriageResult } from "../../services/native/nativeBridge";

export type StageStatus = "pending" | "running" | "pass" | "warn" | "fail" | "skipped";

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
  target: string;
  prompt: string;
  history: Array<{ role: string; content: string }>;
  signal?: AbortSignal;
  diagnostics: Record<string, StageDiagnostic>;
  discoveredSamples?: DiscoveredSample[];
  resolvedBinary?: string;
  containerDirectory?: string;
  triage?: TriageResult;
  kbRouting?: {
    board: string;
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
  onToken?: (text: string) => void;
  onToolCall?: (toolRecord: ToolExecutionRecord) => void;
  onStepNode?: (step: any) => void;
  onDeliverables?: (deliverables: Deliverables) => void;
  onDiagnosticUpdate?: (diagnostic: StageDiagnostic) => void;
  onDiscoveredSamples?: (samples: DiscoveredSample[], containerDir?: string, primary?: string) => void;
}

export interface PipelineStage {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly category: "discovery" | "triage" | "kb" | "llm" | "forensics" | "custom";
  enabled: boolean;
  execute: (ctx: PipelineContext, callbacks: PipelineCallbacks) => Promise<void>;
}
