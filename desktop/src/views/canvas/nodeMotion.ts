import type { Node } from "@xyflow/react";

export type Point = { x: number; y: number };
export type NodeMotion = { from: Point; to: Point };
export const samePosition = (a: Point, b: Point) => a.x === b.x && a.y === b.y;

/** Keep React Flow's measurements and interaction state when only application data changes. */
export function reconcileNodes<T extends Node>(current: T[], incoming: T[]): T[] {
  const previous = new Map(current.map(node => [node.id, node]));
  return incoming.map(node => {
    const existing = previous.get(node.id);
    return existing ? { ...existing, ...node, position: existing.position } : node;
  });
}

export function planNodeMotion(current: Node[], targets: ReadonlyMap<string, Point>, pinned: ReadonlySet<string>): Map<string, NodeMotion> {
  const motion = new Map<string, NodeMotion>();
  for (const node of current) {
    const to = targets.get(node.id);
    if (to && !pinned.has(node.id) && !samePosition(node.position, to)) motion.set(node.id, { from: node.position, to });
  }
  return motion;
}

/** Each frame uses the latest nodes, so measurements, streamed text and drags survive it. */
export function applyNodeMotion<T extends Node>(nodes: T[], motion: ReadonlyMap<string, NodeMotion>, progress: number, pinned: ReadonlySet<string>): T[] {
  const eased = 1 - (1 - Math.min(1, Math.max(0, progress))) ** 3;
  return nodes.map(node => {
    const path = motion.get(node.id);
    if (!path || pinned.has(node.id)) return node;
    const position = { x: path.from.x + (path.to.x - path.from.x) * eased, y: path.from.y + (path.to.y - path.from.y) * eased };
    return samePosition(node.position, position) ? node : { ...node, position };
  });
}
