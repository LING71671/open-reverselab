import {
  GraphStep,
  Deliverables,
  ToolExecutionRecord,
  StageDiagnostic,
  DiscoveredSample,
  PipelineCallbacks,
} from "../core";
import { defaultHarnessPipeline, HarnessPipeline } from "./pipeline";

export interface AgentRunCallbacks {
  onToken?: (text: string) => void;
  onToolCall?: (toolRecord: ToolExecutionRecord) => void;
  onStepNode?: (step: GraphStep) => void;
  onDeliverables?: (deliverables: Deliverables) => void;
  onDiagnosticUpdate?: (diagnostic: StageDiagnostic) => void;
  onDiscoveredSamples?: (samples: DiscoveredSample[], containerDir?: string, primary?: string) => void;
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
  signal?: AbortSignal
): Promise<string> {
  const pipelineCallbacks: PipelineCallbacks = {
    onToken: callbacks.onToken,
    onToolCall: callbacks.onToolCall,
    onStepNode: callbacks.onStepNode,
    onDeliverables: callbacks.onDeliverables,
    onDiagnosticUpdate: callbacks.onDiagnosticUpdate,
    onDiscoveredSamples: callbacks.onDiscoveredSamples,
  };

  const resultCtx = await defaultHarnessPipeline.run(
    target,
    prompt,
    history,
    pipelineCallbacks,
    signal
  );

  return resultCtx.state.fullContent || "";
}
