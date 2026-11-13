import type { GraphStep } from "../../core/contracts/graph";

export const CARD_WIDTH = 300;
const NODE_GAP = 52;
export type PortSide = "left" | "right" | "top" | "bottom";
export interface LayoutPoint { x: number; y: number; rank: number; height: number }
export interface CanvasSize { width: number; height: number }
type LayoutStep = Pick<GraphStep, "id" | "parentId" | "parentIds">;

export function parentIds(step: LayoutStep): string[] {
  return step.parentIds?.length ? step.parentIds : step.parentId ? [step.parentId] : [];
}

/** Advance dependencies rightward and place cards in the nearest free vertical space. */
export function layoutGraph(steps: LayoutStep[], viewport: CanvasSize, heights: ReadonlyMap<string, number> = new Map()): Map<string, LayoutPoint> {
  const byId = new Map(steps.map(step => [step.id, step]));
  const pending = new Map<string, number>();
  const children = new Map<string, string[]>();
  for (const step of steps) {
    const parents = [...new Set(parentIds(step))].filter(id => byId.has(id) && id !== step.id);
    pending.set(step.id, parents.length);
    for (const parent of parents) children.set(parent, [...children.get(parent) || [], step.id]);
  }
  const queue = steps.filter(step => !pending.get(step.id)).map(step => step.id);
  const ranks = new Map<string, number>();
  for (let index = 0; index < queue.length; index++) {
    const id = queue[index];
    const rank = ranks.get(id) || 0;
    ranks.set(id, rank);
    for (const child of children.get(id) || []) {
      ranks.set(child, Math.max(ranks.get(child) || 0, rank + 1));
      pending.set(child, pending.get(child)! - 1);
      if (!pending.get(child)) queue.push(child);
    }
  }
  // Keep malformed historical cycles visible without inventing or dropping edges.
  for (const step of steps) if (pending.get(step.id)) ranks.set(step.id, ranks.get(step.id) || 0);
  if (!steps.length) return new Map();
  const heightOf = (id: string) => Math.max(1, heights.get(id) || 174);
  const maxRank = Math.max(0, ...ranks.values());
  const area = steps.reduce((sum, step) => sum + (CARD_WIDTH + NODE_GAP) * (heightOf(step.id) + NODE_GAP), 0);
  // Preserve left-to-right reading even in a portrait window. The viewport
  // influences density, but should not rotate a long history into a tower.
  const aspect = Math.max(1.6, Math.min(2.4, viewport.width / Math.max(1, viewport.height)));
  const idealWidth = Math.sqrt(area * aspect);
  const advance = Math.max(NODE_GAP, Math.min(CARD_WIDTH + 100, (idealWidth - CARD_WIDTH) / Math.max(1, maxRank)));
  const ordered = [...steps].sort((a, b) => (ranks.get(a.id) || 0) - (ranks.get(b.id) || 0));
  // Compare the resulting envelope, not an estimated number of rows. Cross-
  // branch dependencies and expanded cards can change the required space.
  const advances = new Set([advance, ...Array.from({ length: 15 }, (_, i) => NODE_GAP + i * (CARD_WIDTH + 100 - NODE_GAP) / 14)]);
  let best = new Map<string, LayoutPoint>();
  let bestScore = Infinity;
  for (const spacing of advances) {
    const result = placeCards(ordered, ranks, heightOf, spacing);
    const width = maxRank * spacing + CARD_WIDTH;
    const score = 2 * Math.abs(Math.log(width / result.height / aspect)) + .2 * Math.log(width * result.height / area);
    if (score < bestScore) { bestScore = score; best = result.positions; }
    if (!maxRank) break;
  }
  return best;
}

function placeCards(ordered: LayoutStep[], ranks: Map<string, number>, heightOf: (id: string) => number, advance: number) {
  const positions = new Map<string, LayoutPoint>();
  let top = 0;
  let bottom = 0;
  for (const step of ordered) {
    const rank = ranks.get(step.id) || 0;
    const x = rank * advance;
    const height = heightOf(step.id);
    const parents = parentIds(step).map(id => positions.get(id)).filter((p): p is LayoutPoint => !!p);
    const center = parents.length ? parents.reduce((sum, p) => sum + p.y + p.height / 2, 0) / parents.length : 0;
    const preferred = center - height / 2;
    const neighbors = [...positions.values()].filter(p => x < p.x + CARD_WIDTH + NODE_GAP && x + CARD_WIDTH + NODE_GAP > p.x);
    const candidates = [preferred, ...neighbors.flatMap(p => [p.y - height - NODE_GAP, p.y + p.height + NODE_GAP])];
    // Reuse gaps before growing the envelope. Parent proximity alone makes a
    // long chain drift vertically forever when adjacent ranks overlap in x.
    const score = (y: number) => Math.max(bottom, y + height) - Math.min(top, y)
      + .2 * Math.abs(y - preferred) + .1 * Math.abs(y + height / 2);
    candidates.sort((a, b) => score(a) - score(b) || Math.abs(a + height / 2) - Math.abs(b + height / 2));
    const y = candidates.find(y => neighbors.every(p => y + height + NODE_GAP <= p.y + .01 || y >= p.y + p.height + NODE_GAP - .01)) ?? preferred;
    positions.set(step.id, { x, y, rank, height });
    top = Math.min(top, y);
    bottom = Math.max(bottom, y + height);
  }
  return { positions, height: bottom - top };
}

export function edgePorts(source: LayoutPoint, target: LayoutPoint): { source: PortSide; target: PortSide } {
  if (Math.abs(target.x - source.x) >= CARD_WIDTH + 24) return source.x <= target.x ? { source: "right", target: "left" } : { source: "left", target: "right" };
  return source.y <= target.y ? { source: "bottom", target: "top" } : { source: "top", target: "bottom" };
}
