import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../runtime/dagScheduler.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { DagScheduler, DagResourcePool } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const tick = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

test("default scheduling starts all ready nodes before any finishes and joins their outputs", async () => {
  const gate = deferred();
  const started = [];
  const ids = Array.from({ length: 64 }, (_, index) => `node-${index}`);
  let joined = false;
  const scheduler = new DagScheduler([
    ...ids.map(id => ({ id, run: async () => { started.push(id); await gate.promise; return id; } })),
    { id: "join", parentIds: ids, run: async ({ parentResults }) => {
      joined = true;
      assert.deepEqual([...parentResults.values()].map(result => result.value), ids);
      return "joined";
    } },
  ]);
  const running = scheduler.run();
  try {
    await tick();
    assert.deepEqual(started, ids);
    assert.equal(joined, false);
  } finally { gate.resolve(); }
  assert.equal((await running).status, "succeeded");
  assert.equal(joined, true);
});

test("independent nodes execute concurrently up to the configured limit", async () => {
  const gates = Array.from({ length: 5 }, deferred);
  const started = [];
  let active = 0;
  let maximum = 0;
  const scheduler = new DagScheduler(gates.map((gate, index) => ({
    id: `node-${index}`,
    run: async () => {
      started.push(index);
      maximum = Math.max(maximum, ++active);
      await gate.promise;
      active--;
      return index;
    },
  })), { concurrency: 2 });
  const running = scheduler.run();
  assert.equal(scheduler.run(), running);
  await tick();
  assert.deepEqual(started, [0, 1]);
  gates[0].resolve();
  await tick();
  assert.deepEqual(started, [0, 1, 2]);
  for (const gate of gates) gate.resolve();
  const result = await running;
  assert.equal(maximum, 2);
  assert.equal(result.status, "succeeded");
  assert.equal(started.length, 5);
  assert.deepEqual([...result.nodes.values()].map((node) => node.value), [0, 1, 2, 3, 4]);
});

test("allSettled join runs once with every parent result while unrelated branches survive failures", async () => {
  let joins = 0;
  let forbiddenRuns = 0;
  const failure = new Error("red failed");
  const result = await new DagScheduler([
    { id: "join", parentIds: ["red", "blue", "dependent"], dependencyPolicy: "allSettled", run: async ({ parentResults }) => {
      joins++;
      assert.equal(parentResults.size, 3);
      assert.equal(parentResults.get("red").error, failure);
      assert.equal(parentResults.get("blue").value, "blue evidence");
      assert.equal(parentResults.get("dependent").status, "cancelled");
      return "merged evidence and failure";
    } },
    { id: "dependent", parentIds: ["red"], run: async () => { forbiddenRuns++; } },
    { id: "red", run: async () => { throw failure; } },
    { id: "blue", run: async () => "blue evidence" },
  ], { concurrency: 2 }).run();
  assert.equal(result.status, "failed");
  assert.equal(result.nodes.get("join").status, "succeeded");
  assert.equal(joins, 1);
  assert.equal(forbiddenRuns, 0);
});

test("branch cancellation stops descendants and leaves an allSettled merge and unrelated branch runnable", async () => {
  const entered = deferred();
  let cancelledSignal;
  const scheduler = new DagScheduler([
    { id: "red", run: async ({ signal }) => {
      cancelledSignal = signal;
      entered.resolve();
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      return "late result";
    } },
    { id: "red-followup", parentIds: ["red"], run: async () => assert.fail("Cancelled descendant ran") },
    { id: "blue", run: async () => "blue evidence" },
    { id: "join", parentIds: ["red-followup", "blue"], dependencyPolicy: "allSettled", run: async ({ parentResults }) => {
      assert.equal(parentResults.get("red-followup").status, "cancelled");
      return parentResults.get("blue").value;
    } },
  ]);
  const running = scheduler.run();
  await entered.promise;
  assert.equal(scheduler.cancelBranch("red", "different route selected"), 2);
  const result = await running;
  assert.equal(cancelledSignal.aborted, true);
  assert.equal(result.nodes.get("red").status, "cancelled");
  assert.equal(result.nodes.get("red").value, undefined);
  assert.equal(result.nodes.get("blue").status, "succeeded");
  assert.equal(result.nodes.get("join").value, "blue evidence");
});

test("global cancellation does not launch queued nodes or release a running slot before settlement", async () => {
  const controller = new AbortController();
  const entered = deferred();
  const finish = deferred();
  const scheduler = new DagScheduler([
    { id: "running", run: async ({ signal }) => { entered.resolve(); await finish.promise; assert.equal(signal.aborted, true); return "ignored"; } },
    { id: "queued", run: async () => assert.fail("Queued node ran after cancellation") },
  ], { signal: controller.signal, concurrency: 1 });
  let settled = false;
  const running = scheduler.run().then((result) => { settled = true; return result; });
  await entered.promise;
  controller.abort("user stopped goal");
  await tick();
  assert.equal(settled, false);
  assert.equal(scheduler.getSnapshot().get("running").status, "running");
  assert.equal(scheduler.getSnapshot().get("running").cancellationRequested, true);
  assert.equal(scheduler.getSnapshot().get("queued").status, "cancelled");
  finish.resolve();
  const result = await running;
  assert.equal(result.status, "cancelled");
  assert.equal(result.nodes.get("running").status, "cancelled");
});

test("shared resource keys serialize conflicting runners while independent work remains parallel", async () => {
  const release = deferred();
  const entered = deferred();
  const started = [];
  let resourceUsers = 0;
  let maxResourceUsers = 0;
  const scheduler = new DagScheduler([
    { id: "first", resourceKeys: ["device:fixture"], run: async () => {
      started.push("first");
      maxResourceUsers = Math.max(maxResourceUsers, ++resourceUsers);
      entered.resolve();
      await release.promise;
      resourceUsers--;
    } },
    { id: "second", resourceKeys: ["device:fixture"], run: async () => {
      started.push("second");
      maxResourceUsers = Math.max(maxResourceUsers, ++resourceUsers);
      resourceUsers--;
    } },
    { id: "independent", resourceKeys: ["file:other"], run: async () => { started.push("independent"); } },
  ], { concurrency: 3 });
  const running = scheduler.run();
  await entered.promise;
  await tick();
  assert.deepEqual(started, ["first", "independent"]);
  scheduler.cancelNode("first");
  await tick();
  assert.deepEqual(started, ["first", "independent"]);
  release.resolve();
  await running;
  assert.deepEqual(started, ["first", "independent", "second"]);
  assert.equal(maxResourceUsers, 1);
});

test("invalid graph structure is rejected before any runner executes", () => {
  const run = async () => assert.fail("Invalid DAG executed");
  assert.throws(() => new DagScheduler([{ id: "a", run }, { id: "a", run }]), /Duplicate DAG node/);
  assert.throws(() => new DagScheduler([{ id: "a", parentIds: ["missing"], run }]), /Missing DAG dependency/);
  assert.throws(() => new DagScheduler([{ id: "a", parentIds: ["b"], run }, { id: "b", parentIds: ["a"], run }]), /dependency cycle/);
  assert.throws(() => new DagScheduler([{ id: "a", parentIds: ["a"], run }]), /dependency cycle/);
  assert.throws(() => new DagScheduler([{ id: "a", run }], { concurrency: 0 }), /positive integer/);
});

test("an injected resource pool serializes conflicts across goals and wakes waiting schedulers", async () => {
  const resourcePool = new DagResourcePool();
  const entered = deferred();
  const release = deferred();
  const started = [];
  const first = new DagScheduler([{ id: "first-goal", resourceKeys: ["debugger:fixture"], run: async () => {
    started.push("first"); entered.resolve(); await release.promise;
  } }], { resourcePool });
  const second = new DagScheduler([{ id: "second-goal", resourceKeys: ["debugger:fixture"], run: async () => { started.push("second"); } }], { resourcePool });
  const firstRun = first.run();
  await entered.promise;
  const secondRun = second.run();
  await tick();
  assert.deepEqual(started, ["first"]);
  assert.equal(second.getSnapshot().get("second-goal").status, "queued");
  release.resolve();
  const results = await Promise.all([firstRun, secondRun]);
  assert.deepEqual(started, ["first", "second"]);
  assert.equal(results.every((result) => result.status === "succeeded"), true);
});

test("pre-aborted runs do not call runners and observer failures cannot stall scheduling", async () => {
  const controller = new AbortController();
  controller.abort("already stopped");
  const cancelled = await new DagScheduler([{ id: "a", run: async () => assert.fail("Pre-aborted node ran") }], { signal: controller.signal }).run();
  assert.equal(cancelled.status, "cancelled");
  const result = await new DagScheduler([{ id: "a", run: async () => 1 }], { onNodeUpdate: () => { throw new Error("View disconnected"); } }).run();
  assert.equal(result.status, "succeeded");
  assert.equal(result.observerErrors.length, 3);
  assert.equal((await new DagScheduler([]).run()).status, "succeeded");
});
