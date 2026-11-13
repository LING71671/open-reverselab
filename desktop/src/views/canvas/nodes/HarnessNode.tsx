import { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { Loader2, Check, X, ChevronDown, ChevronUp, ArrowUpRight } from "lucide-react";
import type { GraphStep } from "../../../core";
export interface HarnessNodeData extends Record<string, unknown> { step: GraphStep; isSelected?: boolean; expanded?: boolean; onToggle?: (id: string) => void; onSelect?: (step: GraphStep) => void }
export const HarnessNode = memo(({ data }: { data: HarnessNodeData }) => {
  const { step, isSelected, expanded, onToggle, onSelect } = data;
  return <article className="harness-node" data-status={step.status} data-selected={isSelected}>
    <Handle type="target" position={Position.Left} style={{ background: "var(--border-hover)", borderColor: "var(--bg-canvas)" }} />
    <button type="button" className="harness-node-summary" aria-expanded={expanded} aria-label={`${step.title} · ${expanded ? "收起" : "展开"}详情`} onClick={() => onToggle?.(step.id)}>
    <header><span>{step.agentId}</span><span>{step.status === "running" ? <Loader2 size={11} className="loading-spinner" /> : step.status === "done" ? <Check size={11} /> : step.status === "failed" ? <X size={11} /> : null}{step.status === "running" ? "运行" : step.status === "done" ? "完成" : step.status === "failed" ? "阻塞" : "等待"}</span></header>
    <h3>{step.title}</h3>{!expanded && <p>{step.detail}</p>}{expanded ? <ChevronUp className="node-expand-icon" size={14} /> : <ChevronDown className="node-expand-icon" size={14} />}
    </button>
    {expanded && <div className="harness-node-detail nodrag nopan nowheel"><p>{step.detail || "尚无执行详情"}</p>{step.kbRef && <span className="node-evidence-label">知识库 · {step.kbRef}</span>}<button className="text-button" onClick={() => onSelect?.(step)}>查看执行记录<ArrowUpRight size={14} /></button></div>}
    <Handle type="source" position={Position.Right} style={{ background: "var(--border-hover)", borderColor: "var(--bg-canvas)" }} />
  </article>;
});
HarnessNode.displayName = "HarnessNode";
