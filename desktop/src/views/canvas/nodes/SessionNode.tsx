import { memo } from "react";
import { ChevronDown, ChevronUp, Layers2 } from "lucide-react";
import type { SessionGroup } from "../sessionGroups";
import { NodePorts } from "./HarnessNode";

export interface SessionNodeData extends Record<string, unknown> {
  group: SessionGroup;
  expanded: boolean;
  isSelected: boolean;
  height: number;
  onToggle: (id: string) => void;
}

const statuses = { pending: "等待", running: "运行", done: "完成", failed: "阻塞" };

export const SessionNode = memo(({ data }: { data: SessionNodeData }) => {
  const { group, expanded, onToggle } = data;
  const segment = group.part && `分段 ${group.part}`;
  const subtitle = [segment, group.target, group.sessionId].filter(Boolean).join(" · ");
  return <>{expanded && <span aria-hidden="true" className="session-bracket" style={{ height: data.height }} />}
  <article className="harness-node session-node" data-status={group.status} data-selected={data.isSelected}>
    <NodePorts type="target" />
    <button type="button" className="harness-node-summary" aria-expanded={expanded}
      aria-label={`${group.tool}${segment ? ` · ${segment}` : ""} · ${group.members.length} 步 · ${expanded ? "收起" : "展开"}会话`} onClick={() => onToggle(group.id)}>
      <header><span className="session-target" title={subtitle}>{subtitle}</span><span>{group.failed ? `${group.running ? "运行 · " : ""}${group.failed} 步阻塞` : statuses[group.status]}</span></header>
      <div className="session-title"><Layers2 size={16} /><h3>{group.tool}</h3><span className="session-count">{group.members.length} 步 {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</span></div>
    </button>
    <NodePorts type="source" />
  </article></>;
});
SessionNode.displayName = "SessionNode";
