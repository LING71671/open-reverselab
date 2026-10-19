import { Deliverables, StepStatus } from "./graph";
import { StageDiagnostic, DiscoveredSample } from "./pipeline";

export interface ToolExecutionRecord {
  id: string;
  tool: string;
  title: string;
  status: StepStatus | "error";
  detail?: string;
  args?: Record<string, any>;
  output?: Record<string, any> | string;
  kbRef?: string;
  durationMs?: number;
}

export interface HarnessChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: number;
  target?: string;
  model?: string;
  reasoning?: string;
  toolCalls?: ToolExecutionRecord[];
  deliverables?: Deliverables;
  diagnostics?: Record<string, StageDiagnostic>;
  discoveredSamples?: DiscoveredSample[];
  containerDirectory?: string;
  resolvedBinary?: string;
  isRunning?: boolean;
}

