import type { PipelineContext } from "../../core/contracts/pipeline";
import type { GoalVerification } from "../../core/contracts/graph";
import type { PythonExecResult } from "../../services/native/nativeBridge";

export interface TrackVerification {
  executionSucceeded: boolean;
  evidenceAccepted: boolean;
  goalVerified: boolean;
  reason: string;
  goal: GoalVerification;
}

export interface TrackPolicy {
  readonly track: "red" | "blue";
  readonly objective: string;
  readonly allowedActions: readonly string[];
  instructions(ctx: PipelineContext): string;
  verify(ctx: PipelineContext, result?: PythonExecResult): TrackVerification;
}
