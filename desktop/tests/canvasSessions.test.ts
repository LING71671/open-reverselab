import assert from "node:assert/strict";
import test from "node:test";
import type { GraphStep } from "../src/core/contracts/graph.ts";
import { readToolSession } from "../src/core/contracts/toolSession.ts";
import { layoutGraph } from "../src/views/canvas/graphLayout.ts";
import { canvasSessions, positionSessions, sessionEdges, visibleStep } from "../src/views/canvas/sessionGroups.ts";

const context = { connectionId: "Ghidra", target: "fixture.bin", sessionId: "open-1" };
function step(id: string, parents: string[] = [], session = true): GraphStep {
  return { id, parentId: parents[0] || null, parentIds: parents, agentId: "inspect", title: id, detail: "observation",
    status: "done", timestamp: 1, ...(session ? { toolSession: context } : {}) };
}

test("group identity follows connection, target, and recorded tool session including legacy receipts", () => {
  const opened = { ...step("open", [], false), evidence: { execution: { mcp: { connectionId: "Ghidra", target: "fixture.bin",
    arguments: { target: "fixture.bin" }, result: { structuredContent: { session_id: "open-1" } } } } } };
  const steps = [opened, { ...step("progress"), status: "running" as const }, { ...step("blocked"), status: "failed" as const },
    ...[{ sessionId: "open-2" }, { connectionId: "other" }, { target: "other.bin" }, { subject: "other.bin" }]
      .map((changes, i) => ({ ...step(String(i)), toolSession: { ...context, ...changes } }))];
  const { owner, groups } = canvasSessions(steps);
  assert.equal(groups.size, 5);
  const group = groups.get(owner.get("open")!)!;
  assert.deepEqual(group.members, steps.slice(0, 3));
  assert.equal(group.failed, 1);
  assert.equal(group.running, true);
  assert.equal(group.status, "failed");
  assert.equal(readToolSession({ target: "fixture.bin" }), undefined);
  assert.equal(readToolSession({ connectionId: "Ghidra" }), undefined);
});

test("implicit sessions require an identified action plan and keep branches, plans, targets and connections separate", () => {
  const ids = ["blue:goal:1:action:a", "blue:goal:1:action:b", "red:goal:1:action:a", "blue:goal:2:action:a", "unscoped",
    "blue:goal:1:action:c", "blue:goal:1:action:d", "blue:goal:1:action:e", "blue:goal:1:action:f"];
  const steps = ids.map((id, index) => ({ ...step(id, [], false), evidence: { execution: { mcp: {
    connectionId: index === 6 ? "B" : index === 7 ? undefined : "A", target: index === 5 ? "other" : index === 8 ? undefined : "fixture",
    arguments: {},
  } } } }));
  const { owner, groups } = canvasSessions(steps);
  assert.equal(groups.size, 5);
  assert.equal(owner.get(ids[0]), owner.get(ids[1]));
  for (const id of ids.slice(2, 4).concat(ids.slice(5, 7))) assert.notEqual(owner.get(ids[0]), owner.get(id));
  for (const id of [ids[4], ids[7], ids[8]]) assert.equal(owner.has(id), false);
});

test("collapsed edges preserve every boundary and restore original branch references on expansion", () => {
  const steps = [step("sample", [], false), step("other", [], false), step("a", ["sample"]),
    step("b", ["a", "other", "sample"]), step("peer", ["a"], false), step("report", ["b", "peer"], false)];
  const { groups, owner } = canvasSessions(steps);
  const group = [...groups.keys()][0];
  const summary = sessionEdges(steps, owner, new Set());
  assert.deepEqual(summary.map(e => [e.source, e.target, e.count]), [
    ["sample", group, 2], ["other", group, 1], [group, "peer", 1], [group, "report", 1], ["peer", "report", 1],
  ]);
  const opened = new Set([group]);
  assert.deepEqual(sessionEdges(steps, owner, opened).map(e => [e.source, e.target]), steps.flatMap(s => s.parentIds!.map(p => [p, s.id])));
  const updated = canvasSessions([...steps, step("c", ["b"])]);
  assert.equal(visibleStep("c", updated.owner, opened), "c");
  assert.equal(updated.groups.get(group)?.members.length, 3);
});

test("session expansion keeps the measured header anchored and makes room for visible steps", () => {
  const steps = [step("sample", [], false), step("a", ["sample"]), step("b", ["a"]), step("report", ["b"], false)];
  const { groups, topology } = canvasSessions(steps);
  const group = [...groups.keys()][0];
  const base = layoutGraph(topology, { width: 1100, height: 800 });
  const anchor = { id: group, x: 220, y: 56 };
  const height = (id: string) => id === group ? 96 : id === "a" ? 244 : 142;
  for (const expanded of [new Set([group]), new Set<string>()]) {
    const positions = positionSessions(base, groups, expanded, height, anchor);
    assert.equal(positions.get(group)?.x, 220);
    assert.equal(positions.get(group)?.y, 56);
    assert.equal(positions.has("a"), expanded.size > 0);
    const points = [...positions.values()];
    for (const [i, a] of points.entries()) for (const b of points.slice(i + 1)) {
      assert.ok(a.x + 300 <= b.x || b.x + 300 <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y);
    }
  }
});

for (const length of [1, 3]) {
  test(`returning after ${length} external nodes splits only at the causal boundary`, () => {
    const chain = Array.from({ length }, (_, i) => step(`outside-${i}`, [i ? `outside-${i - 1}` : "a1"], false));
    const last = chain[chain.length - 1].id;
    const steps = [step("a0"), step("a1", ["a0"]), ...chain, step("a2", ["a1", last]), step("a3", ["a2"])];
    for (const history of [steps, steps.slice().reverse()]) {
      const { groups, owner, topology } = canvasSessions(history);
      const before = owner.get("a1")!, after = owner.get("a2")!;
      assert.equal(groups.size, 2);
      assert.notEqual(before, after);
      assert.equal(owner.get("a0"), before);
      assert.equal(owner.get("a3"), after);
      assert.equal(groups.get(before)?.sessionId, groups.get(after)?.sessionId);
      assert.deepEqual([groups.get(before)?.part, groups.get(after)?.part], ["1/2", "2/2"]);
      const layout = layoutGraph(topology, { width: 1000, height: 800 });
      const edges = sessionEdges(history, owner, new Set());
      const expected = [[before, "outside-0"], ...chain.slice(1).map((s, i) => [chain[i].id, s.id]), [before, after], [last, after]];
      assert.deepEqual(new Set(edges.map(e => JSON.stringify([e.source, e.target]))), new Set(expected.map(e => JSON.stringify(e))));
      for (const e of edges) assert.ok(layout.get(e.source)!.rank < layout.get(e.target)!.rank);
      const open = sessionEdges(history, owner, new Set(groups.keys()));
      assert.deepEqual(open.map(e => [e.source, e.target]), history.flatMap(s => s.parentIds!.map(parent => [parent, s.id])));
    }
  });
}

test("an interleaved external branch without a return dependency does not split the session", () => {
  const steps = [step("a1"), step("external", ["a1"], false), step("independent", [], false), step("a2", ["a1", "independent"])];
  const { groups, owner } = canvasSessions(steps);
  assert.equal(groups.size, 1);
  assert.equal(owner.get("a1"), owner.get("a2"));
  assert.equal([...groups.values()][0].part, undefined);
});
