import {
  GraphStep,
  Deliverables,
  ToolExecutionRecord,
  StageDiagnostic,
  DiscoveredSample,
  PipelineCallbacks,
  RunBudget,
  RunProgress,
} from "../core";
import { defaultHarnessPipeline, HarnessPipeline } from "./pipeline";
import type { SecurityTrack } from "../core/contracts/track";
import type { HealthEvent } from "../core/contracts/health";

export interface AgentRunCallbacks {
  onToken?: (text: string) => void;
  onToolCall?: (toolRecord: ToolExecutionRecord) => void;
  onStepNode?: (step: GraphStep) => void;
  onDeliverables?: (deliverables: Deliverables) => void;
  onDiagnosticUpdate?: (diagnostic: StageDiagnostic) => void;
  onDiscoveredSamples?: (samples: DiscoveredSample[], containerDir?: string, primary?: string) => void;
  onRunProgress?: (progress: RunProgress) => void;
  onHealthEvent?: (event: HealthEvent) => void;
}

export { defaultHarnessPipeline, HarnessPipeline };

/**
 * Runs the modular, decoupled reverse engineering pipeline
 */
export async function runOpenSourceAgent(
  target: string,
  prompt: string,
  history: Array<{ role: string; content: string }>,
  callbacks: AgentRunCallbacks,
  signal?: AbortSignal,
  track: SecurityTrack = "blue",
  budget?: RunBudget,
  goalId?: string,
  workspaceRoot?: string
): Promise<string> {
  const pipelineCallbacks: PipelineCallbacks = {
    onToken: callbacks.onToken,
    onToolCall: callbacks.onToolCall,
    onStepNode: callbacks.onStepNode,
    onDeliverables: callbacks.onDeliverables,
    onDiagnosticUpdate: callbacks.onDiagnosticUpdate,
    onDiscoveredSamples: callbacks.onDiscoveredSamples,
    onRunProgress: callbacks.onRunProgress,
    onHealthEvent: callbacks.onHealthEvent,
  };

  const resultCtx = await defaultHarnessPipeline.run(
    target,
    prompt,
    history,
    pipelineCallbacks,
    signal,
    goalId,
    track,
    budget,
    { workspaceRoot }
  );

  return resultCtx.state.fullContent || "";
}
