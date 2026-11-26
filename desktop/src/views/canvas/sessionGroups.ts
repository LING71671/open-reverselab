import type { GraphStep, StepStatus } from "../../core/contracts/graph";
import { readToolSession } from "../../core/contracts/toolSession.ts";
import { expandLayout, parentIds, type LayoutPoint } from "./graphLayout.ts";

export interface SessionGroup {
  id: string;
  tool: string;
  target: string;
  sessionId?: string;
  members: GraphStep[];
  status: StepStatus;
  failed: number;
  running: boolean;
}

const priority: Record<StepStatus, number> = { done: 0, pending: 1, running: 2, failed: 3 };

export function canvasSessions(steps: GraphStep[]) {
  const groups = new Map<string, SessionGroup>();
  const owner = new Map<string, string>();
  const ids = new Set(steps.map(step => step.id));
  for (const step of steps) {
    const receipt = readToolSession(step.evidence?.execution?.mcp);
    const session = receipt?.sessionId ? receipt : step.toolSession || receipt;
    if (!session || typeof session.connectionId !== "string" || !session.connectionId || typeof session.target !== "string" || !session.target) continue;
    // MCP transports can reconnect per request. Without a tool-issued session
    // handle, scope a logical session to this branch's recorded action plan.
    const plan = step.id.match(/^(.*:\d+):action:[\w-]+$/)?.[1];
    if (!session.sessionId && !plan) continue;
    const scope = session.sessionId ? ["session", session.sessionId] : ["plan", plan];
    let id = "tool-session:" + JSON.stringify([session.connectionId, session.target, session.subject, scope]);
    while (ids.has(id)) id += ":";
    let group = groups.get(id);
    if (!group) {
      group = { id, tool: session.connectionId, target: session.subject || session.target, sessionId: session.sessionId, members: [], status: "done", failed: 0, running: false };
      groups.set(id, group);
    }
    group.members.push(step);
    if (step.status === "running") group.running = true;
    if (priority[step.status] > priority[group.status]) group.status = step.status;
    if (step.status === "failed") group.failed++;
    owner.set(step.id, id);
  }
  const compact = new Map<string, Set<string>>();
  for (const step of steps) {
    const id = owner.get(step.id) || step.id;
    const parents = compact.get(id) || new Set<string>();
    compact.set(id, parents);
    for (const parent of parentIds(step)) {
      const source = owner.get(parent) || parent;
      if (source !== id && ids.has(parent)) parents.add(source);
    }
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
