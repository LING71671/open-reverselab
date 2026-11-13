import { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { Loader2, Check, X } from "lucide-react";
import type { GraphStep } from "../../../core";
export interface HarnessNodeData extends Record<string, unknown> { step: GraphStep; isSelected?: boolean; onSelect?: (step: GraphStep) => void }
export const HarnessNode = memo(({ data }: { data: HarnessNodeData }) => {
  const { step, isSelected, onSelect } = data;
  return <div className="harness-node" data-status={step.status} data-selected={isSelected} role="button" tabIndex={0} aria-label={`${step.title} · ${step.status}`} onClick={() => onSelect?.(step)} onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect?.(step); } }}>
    <Handle type="target" position={Position.Left} style={{ background: "var(--border-hover)", borderColor: "var(--bg-canvas)" }} />
    <header><span>{step.agentId}</span><span>{step.status === "running" ? <Loader2 size={11} className="loading-spinner" /> : step.status === "done" ? <Check size={11} /> : step.status === "failed" ? <X size={11} /> : null}{step.status === "running" ? "运行" : step.status === "done" ? "完成" : step.status === "failed" ? "阻塞" : "等待"}</span></header>
    <h3>{step.title}</h3><p>{step.detail}</p>
    <Handle type="source" position={Position.Right} style={{ background: "var(--border-hover)", borderColor: "var(--bg-canvas)" }} />
  </div>;
});
HarnessNode.displayName = "HarnessNode";
