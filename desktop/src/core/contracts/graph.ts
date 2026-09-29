export type StepStatus = "pending" | "running" | "done" | "failed";

export interface GraphStep {
  id: string;
  parentId: string | null;
  agentId: string;
  title: string;
  status: StepStatus;
  detail: string;
  kbRef?: string;
  evidence?: Record<string, any>;
  timestamp: number;
}

export interface Deliverables {
  script?: string;
  key?: string;
  flag?: string;
  summary?: string;
  executionOutput?: {
    success: boolean;
    stdout?: string;
    stderr?: string;
    executionTimeMs?: number;
  };
}
