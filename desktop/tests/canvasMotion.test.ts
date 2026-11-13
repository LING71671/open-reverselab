import assert from "node:assert/strict";
import test from "node:test";
import type { Node } from "@xyflow/react";
import { reconcileNodes, planNodeMotion, applyNodeMotion } from "../src/views/canvas/nodeMotion.ts";

const node = (id: string, x = 0, y = 0): Node => ({ id, position: { x, y }, data: { text: "Working" } });

test("streamed card updates retain measured dimensions, selection and the current position", () => {
  const current = { ...node("a", 20), measured: { width: 300, height: 176 }, selected: true, dragging: true };
  const incoming = { ...node("a", 400), data: { text: "New observation" } };
  const [updated] = reconcileNodes([current], [incoming]);
  assert.deepEqual(updated.measured, current.measured);
  assert.equal(updated.selected, true);
  assert.equal(updated.dragging, true);
  assert.deepEqual(updated.position, current.position);
  assert.equal(updated.data.text, "New observation");
});

test("new cards start at their layout position and only displaced existing cards move", () => {
  const current = [node("a"), node("pinned", 19, 28)];
  const targets = [node("a", 400), node("pinned", 800), node("new", 1200)];
  const merged = reconcileNodes(current, targets);
  const pinned = new Set(["pinned"]);
  const motion = planNodeMotion(merged, new Map(targets.map(n => [n.id, n.position])), pinned);
  assert.deepEqual([...motion.keys()], ["a"]);
  const next = applyNodeMotion(merged, motion, 1, pinned);
  assert.deepEqual(next.map(n => n.position), [{ x: 400, y: 0 }, { x: 19, y: 28 }, { x: 1200, y: 0 }]);
});

test("measurement, streamed data and a user drag arriving mid-animation are preserved", () => {
  const initial = [node("a"), node("b")];
  const motion = planNodeMotion(initial, new Map([["a", { x: 400, y: 0 }], ["b", { x: 400, y: 200 }]]), new Set());
  const half = applyNodeMotion(initial, motion, .5, new Set());
  const live = half.map(n => ({ ...n, measured: { width: 300, height: 176 }, data: { text: "Latest text" } }));
  live[1].position = { x: 55, y: 66 };
  const settled = applyNodeMotion(live, motion, 1, new Set(["b"]));
  assert.deepEqual(settled[0].position, { x: 400, y: 0 });
  assert.deepEqual(settled[0].measured, { width: 300, height: 176 });
  assert.equal(settled[0].data.text, "Latest text");
  assert.equal(settled[1], live[1]);
});
