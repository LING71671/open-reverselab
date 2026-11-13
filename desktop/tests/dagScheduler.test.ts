import assert from "node:assert/strict";
import { test } from "node:test";
import { DagScheduler, DagResourcePool } from "../src/engine/runtime/dagScheduler.ts";
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
};
const tick = () => new Promise(resolve => setImmediate(resolve));

test("parallel parents start together and the join runs once after both settle", async () => {
  const gate = deferred();
  const starts: string[] = [];
  let joins = 0;
  const scheduler = new DagScheduler([
    { id: "a", run: async () => { starts.push("a"); await gate.promise; return 1; } },
    { id: "b", run: async () => { starts.push("b"); throw new Error("fixture failure"); } },
    { id: "join", parentIds: ["a", "b"], dependencyPolicy: "allSettled", run: async ({ parentResults }) => { joins++; assert.equal(parentResults.get("a")?.value, 1); assert.equal(parentResults.get("b")?.status, "failed"); return 2; } },
  ], { concurrency: 2 });
  const run = scheduler.run();
  await tick();
  assert.deepEqual(starts, ["a", "b"]);
  assert.equal(joins, 0);
  gate.resolve();
  await run;
  assert.equal(joins, 1);
});

test("shared resource locks remain held until a cancelled runner really exits", async () => {
  const resourcePool = new DagResourcePool();
  const gate = deferred();
  const controller = new AbortController();
  let secondStarted = false;
  const first = new DagScheduler([{ id: "a", resourceKeys: ["device"], run: async () => { await gate.promise; return 1; } }], { resourcePool, signal: controller.signal }).run();
  await tick();
  controller.abort();
  const second = new DagScheduler([{ id: "b", resourceKeys: ["device"], run: async () => { secondStarted = true; return 2; } }], { resourcePool }).run();
  await tick();
  assert.equal(secondStarted, false);
  gate.resolve();
  await Promise.all([first, second]);
  assert.equal(secondStarted, true);
});

test("ordinary descendants cancel after a failed prerequisite while unrelated work continues", async () => {
  let dependent = false;
  let unrelated = false;
  const result = await new DagScheduler([
    { id: "a", run: async () => { throw new Error("failed"); } },
    { id: "b", parentIds: ["a"], run: async () => { dependent = true; } },
    { id: "c", run: async () => { unrelated = true; } },
  ]).run();
  assert.equal(dependent, false);
  assert.equal(unrelated, true);
  assert.equal(result.nodes.get("b")?.status, "cancelled");
});

test("invalid dependency graphs are rejected before work starts", () => {
  const run = async () => 1;
  assert.throws(() => new DagScheduler([{ id: "a", run }, { id: "a", run }]));
  assert.throws(() => new DagScheduler([{ id: "a", parentIds: ["missing"], run }]));
  assert.throws(() => new DagScheduler([{ id: "a", parentIds: ["b"], run }, { id: "b", parentIds: ["a"], run }]));
});
