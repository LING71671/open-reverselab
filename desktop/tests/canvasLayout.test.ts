import assert from "node:assert/strict";
import test from "node:test";
import type { GraphStep } from "../src/core/contracts/graph.ts";
import { CARD_WIDTH, edgePorts, expandLayout, layoutGraph, parentIds, type LayoutPoint } from "../src/views/canvas/graphLayout.ts";

const step = (id: string, parents: string[] = []): GraphStep => ({
  id, parentId: parents[0] || null, parentIds: parents, agentId: "analysis",
  title: id, detail: "Synthetic observation", status: "done", timestamp: 0,
});
const chain = (count: number) => Array.from({ length: count }, (_, i) => step(`s${i}`, i ? [`s${i - 1}`] : []));
const bounds = (layout: Map<string, LayoutPoint>) => {
  const points = [...layout.values()];
  return {
    width: Math.max(...points.map(p => p.x + CARD_WIDTH)) - Math.min(...points.map(p => p.x)),
    height: Math.max(...points.map(p => p.y + p.height)) - Math.min(...points.map(p => p.y)),
  };
};
function noOverlap(layout: Map<string, LayoutPoint>) {
  const entries = [...layout];
  for (let i = 0; i < entries.length; i++) for (let j = i + 1; j < entries.length; j++) {
    const [a, b] = [entries[i][1], entries[j][1]];
    assert.ok(a.x + CARD_WIDTH <= b.x || b.x + CARD_WIDTH <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y,
      `${entries[i][0]} overlaps ${entries[j][0]}`);
  }
}

test("long histories spread in both dimensions while every dependency advances right", () => {
  const steps = chain(38);
  const layout = layoutGraph(steps, { width: 1000, height: 800 });
  const size = bounds(layout);
  assert.equal(layout.size, steps.length);
  assert.ok(size.height > 5 * 174, "history must not be capped at four card rows");
  assert.ok(size.width > CARD_WIDTH * 3);
  assert.ok(size.width / size.height > 1.3, "history must keep a horizontal reading direction");
  assert.ok(size.width / size.height < 3, "history must not become an unreadable horizontal strip");
  for (const s of steps) for (const parent of parentIds(s)) assert.ok(layout.get(s.id)!.x > layout.get(parent)!.x);
  noOverlap(layout);
  const portrait = bounds(layoutGraph(steps, { width: 600, height: 1000 }));
  assert.ok(portrait.width / portrait.height > 1.3, "portrait viewports must not turn the graph into a vertical tower");
});

test("parallel branches and cross-branch joins retain all dependencies regardless of arrival order", () => {
  const roots = Array.from({ length: 9 }, (_, i) => step(`branch${i}`, ["root"]));
  const steps = [step("join", roots.map(s => s.id)), ...roots, step("root")];
  const original = structuredClone(steps);
  const layout = layoutGraph(steps, { width: 1200, height: 800 });
  assert.equal(layout.size, steps.length);
  assert.equal(new Set(roots.map(s => layout.get(s.id)!.y)).size, roots.length);
  for (const s of steps) for (const parent of parentIds(s)) assert.ok(layout.get(s.id)!.x > layout.get(parent)!.x);
  assert.deepEqual(steps, original);
  noOverlap(layout);
});

test("expanded cards, viewport changes and incremental arrivals produce deterministic non-overlapping positions", () => {
  const steps = chain(12);
  const sizes = new Map(steps.map((s, i) => [s.id, i % 3 === 0 ? 420 : 155]));
  const narrow = layoutGraph(steps, { width: 700, height: 900 }, sizes);
  const wide = layoutGraph(steps, { width: 1800, height: 800 }, sizes);
  assert.notDeepEqual([...narrow], [...wide]);
  assert.deepEqual([...wide], [...layoutGraph(steps, { width: 1800, height: 800 }, sizes)]);
  noOverlap(narrow);
  noOverlap(wide);
  for (let count = 1; count <= steps.length; count++) noOverlap(layoutGraph(steps.slice(0, count), { width: 1000, height: 800 }, sizes));
  assert.equal(wide.get("s0")!.height, 420);
});

test("missing parents and malformed historical cycles stay visible", () => {
  const steps = [step("orphan", ["missing"]), step("a", ["b"]), step("b", ["a"]), step("self", ["self"])];
  const layout = layoutGraph(steps, { width: 0, height: 0 });
  assert.equal(layout.size, steps.length);
  assert.ok([...layout.values()].every(p => Number.isFinite(p.x) && Number.isFinite(p.y)));
  noOverlap(layout);
  assert.equal(layoutGraph([], { width: 0, height: 0 }).size, 0);
});

test("edge anchors follow lateral and vertical card separation", () => {
  const source = { x: 0, y: 0, rank: 0, height: 174 };
  assert.deepEqual(edgePorts(source, { ...source, x: 400 }), { source: "right", target: "left" });
  assert.deepEqual(edgePorts(source, { ...source, x: 80, y: 230 }), { source: "bottom", target: "top" });
  assert.deepEqual(edgePorts(source, { ...source, x: 80, y: -230 }), { source: "top", target: "bottom" });
});

test("expanding details anchors the clicked card and only pushes intersecting neighbors", () => {
  const base = new Map<string, LayoutPoint>([
    ["above", { x: 0, y: -230, rank: 0, height: 174 }],
    ["clicked", { x: 80, y: 0, rank: 1, height: 174 }],
    ["below", { x: 160, y: 230, rank: 2, height: 174 }],
    ["far", { x: 1000, y: 230, rank: 3, height: 174 }],
  ]);
  const snapshot = structuredClone(base);
  const anchor = { id: "clicked", x: 80, y: 0 };
  const expanded = expandLayout(base, new Map([["clicked", 420]]), anchor);
  assert.equal(expanded.get("clicked")!.y, anchor.y);
  assert.equal(expanded.get("clicked")!.x, anchor.x);
  assert.deepEqual(expanded.get("above"), base.get("above"));
  assert.deepEqual(expanded.get("far"), base.get("far"));
  assert.ok(expanded.get("below")!.y > base.get("below")!.y);
  for (const [id, point] of expanded) assert.equal(point.x, base.get(id)!.x);
  noOverlap(expanded);
  assert.deepEqual(expandLayout(base, new Map(), anchor), base, "collapse restores surrounding cards without moving the anchor");
  assert.deepEqual(base, snapshot, "detail layout must not mutate the compact layout");
});

test("multiple expanded cards and later measurements retain the latest clicked position", () => {
  const base = layoutGraph(chain(38), { width: 1000, height: 800 });
  const first = { id: "s12", ...base.get("s12")! };
  const heights = new Map([[first.id, 430]]);
  const expanded = expandLayout(base, heights, first);
  const second = { id: "s13", ...expanded.get("s13")! };
  heights.set(second.id, 410);
  const again = expandLayout(base, heights, second);
  assert.equal(again.get(second.id)!.x, second.x);
  assert.equal(again.get(second.id)!.y, second.y);
  noOverlap(again);
  heights.set(second.id, 486);
  const measured = expandLayout(base, heights, second);
  assert.equal(measured.get(second.id)!.y, second.y);
  noOverlap(measured);
  heights.delete(second.id);
  const collapsed = expandLayout(base, heights, second);
  assert.equal(collapsed.get(second.id)!.y, second.y);
  noOverlap(collapsed);
});
