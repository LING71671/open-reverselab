export type StepStatus = "pending" | "running" | "done" | "failed";

export interface GraphStep {
  id: string;
  parentId: string | null;
  parentIds?: string[];
  agentId: string;
  title: string;
  status: StepStatus;
  detail: string;
  kbRef?: string;
  evidence?: Record<string, any>;
  timestamp: number;
}

export interface GoalAssertion {
  name: string;
  expected: string;
  actual: string;
  passed: boolean;
}

export interface GoalVerification {
  objective: string;
  status: "verified" | "failed" | "in_progress";
  passRate: string;
  assertions: GoalAssertion[];
  timestamp: number;
}

export interface Deliverables {
  script?: string;
  key?: string;
  flag?: string;
  summary?: string;
  goalVerification?: GoalVerification;
  savedArtifacts?: {
    report_path?: string;
    script_path?: string;
  };
  executionOutput?: {
    success: boolean;
    stdout?: string;
    stderr?: string;
    executionTimeMs?: number;
  };
}
