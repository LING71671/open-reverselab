import type { GraphStep, StepStatus } from "../../core/contracts/graph";
import { readToolSession } from "../../core/contracts/toolSession.ts";
import { dependencyOrder, expandLayout, parentIds, type LayoutPoint } from "./graphLayout.ts";

export interface SessionGroup {
  id: string;
  tool: string;
  target: string;
  sessionId?: string;
  part?: string;
  members: GraphStep[];
  status: StepStatus;
  failed: number;
  running: boolean;
}

const priority: Record<StepStatus, number> = { done: 0, pending: 1, running: 2, failed: 3 };

// A direct parent in the same group is internal. An external parent that is
// already downstream of the group would become both predecessor and successor.
function canJoin(group: string, parents: string[], compact: Map<string, Set<string>>) {
  const pending = parents.filter(id => id !== group && !compact.get(group)?.has(id));
  const seen = new Set<string>();
  while (pending.length) {
    const id = pending.pop()!;
    if (id === group) return false;
    if (seen.has(id)) continue;
    seen.add(id);
    for (const parent of compact.get(id) || []) pending.push(parent);
  }
  return true;
}

function sessionIdentity(step: GraphStep) {
  const receipt = readToolSession(step.evidence?.execution?.mcp);
  const session = receipt?.sessionId ? receipt : step.toolSession || receipt;
  if (!session || typeof session.connectionId !== "string" || !session.connectionId || typeof session.target !== "string" || !session.target) return;
  // MCP transports can reconnect per request. Without a tool-issued session
  // handle, scope a logical session to this branch's recorded action plan.
  const plan = step.id.match(/^(.*:\d+):action:[\w-]+$/)?.[1];
  if (!session.sessionId && !plan) return;
  const scope = session.sessionId ? ["session", session.sessionId] : ["plan", plan];
  const key = "tool-session:" + JSON.stringify([session.connectionId, session.target, session.subject, scope]);
  return { key, session };
}

export function canvasSessions(steps: GraphStep[]) {
  const groups = new Map<string, SessionGroup>();
  const owner = new Map<string, string>();
  const segments = new Map<string, SessionGroup[]>();
  const compact = new Map<string, Set<string>>();
  const byId = new Map(steps.map(step => [step.id, step]));
  const projectedParents = (step: GraphStep) => parentIds(step).filter(id => byId.has(id)).map(id => owner.get(id) || id);

  // Process dependencies first, even when historical steps arrived out of order.
  for (const id of dependencyOrder(steps).order) {
    const step = byId.get(id)!;
    const parents = projectedParents(step);
    const identity = sessionIdentity(step);
    if (!identity) {
      compact.set(id, new Set(parents));
      continue;
    }
    const { key, session } = identity;
    const parts = segments.get(key) || [];
    let group: SessionGroup | undefined;
    for (let i = parts.length - 1; i >= 0; i--) {
      if (canJoin(parts[i].id, parents, compact)) { group = parts[i]; break; }
    }
    if (!group) {
      let id = parts.length ? `${key}:part:${parts.length + 1}` : key;
      while (byId.has(id)) id += ":";
      group = { id, tool: session.connectionId, target: session.subject || session.target, sessionId: session.sessionId, members: [], status: "done", failed: 0, running: false };
      parts.push(group);
      segments.set(key, parts);
      groups.set(id, group);
      compact.set(id, new Set());
    }
    const external = compact.get(group.id)!;
    for (const parent of parents) if (parent !== group.id) external.add(parent);
    group.members.push(step);
    if (step.status === "running") group.running = true;
    if (priority[step.status] > priority[group.status]) group.status = step.status;
    if (step.status === "failed") group.failed++;
    owner.set(id, group.id);
  }
  for (const parts of segments.values()) if (parts.length > 1) {
    parts.forEach((part, i) => { part.part = `${i + 1}/${parts.length}`; });
  }
  // Keep malformed historical cycles and their dependents visible individually.
  for (const step of steps) if (!owner.has(step.id) && !compact.has(step.id)) {
    compact.set(step.id, new Set(projectedParents(step)));
  }
  return { groups, owner, topology: [...compact].map(([id, parents]) => ({ id, parentId: null, parentIds: [...parents] })) };
}

export function visibleStep(id: string, owner: Map<string, string>, expanded: ReadonlySet<string>): string {
  const group = owner.get(id);
  return group && !expanded.has(group) ? group : id;
}

export function sessionEdges(steps: GraphStep[], owner: Map<string, string>, expanded: ReadonlySet<string>) {
  const ids = new Set(steps.map(step => step.id));
  const edges = new Map<string, { id: string; source: string; target: string; status: StepStatus; joined: boolean; count: number }>();
  for (const step of steps) {
    const parents = parentIds(step);
    const target = visibleStep(step.id, owner, expanded);
    for (const parent of new Set(parents)) {
      const source = visibleStep(parent, owner, expanded);
      if (!ids.has(parent) || source === target) continue;
      const id = JSON.stringify([source, target]);
      const edge = edges.get(id) || { id, source, target, status: step.status, joined: false, count: 0 };
      if (priority[step.status] > priority[edge.status]) edge.status = step.status;
      edge.joined ||= parents.length > 1;
      edge.count++;
      edges.set(id, edge);
    }
  }
  return [...edges.values()];
}

export function positionSessions(base: Map<string, LayoutPoint>, groups: Map<string, SessionGroup>, expanded: ReadonlySet<string>,
  heightOf: (id: string) => number, anchor: { id: string; x: number; y: number } | null) {
  const heights = new Map([...base.keys()].map(id => [id, heightOf(id)]));
  const gap = 32;
  for (const [id, group] of groups) if (expanded.has(id)) {
    heights.set(id, heightOf(id) + group.members.reduce((sum, member) => sum + gap + heightOf(member.id), 0));
  }
  const positions = expandLayout(base, heights, anchor);
  for (const [id, group] of groups) if (expanded.has(id)) {
    const top = positions.get(id)!;
    let y = top.y + heightOf(id);
    for (const step of group.members) {
      const height = heightOf(step.id);
      y += gap;
      positions.set(step.id, { x: top.x, y, rank: top.rank, height });
      y += height;
    }
    top.height = heightOf(id);
  }
  return positions;
}
