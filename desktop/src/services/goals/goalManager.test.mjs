import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("./goalManager.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { GoalManager } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const tick = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const storage = (entries = []) => {
  const values = new Map(entries);
  return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
};
const session = (manager, id) => manager.getSnapshot().sessions.find((entry) => entry.id === id);
const progress = (status = "completed") => ({ status, maxDurationMs: 1000, maxTokens: 1000, elapsedMs: 10, tokensUsed: 10, attempts: 1 });

test("two goals run simultaneously, the third queues, and each callback updates only its own goal", async () => {
  const tasks = new Map();
  let active = 0;
  let maximum = 0;
  const manager = new GoalManager(async (request, callbacks) => {
    const gate = deferred();
    tasks.set(request.id, { gate, callbacks });
    maximum = Math.max(maximum, ++active);
    await gate.promise;
    active--;
    callbacks.onRunProgress(progress());
  }, storage(), 2);
  const first = manager.submit("first.bin", "first goal", "red");
  const second = manager.submit("second.bin", "second goal", "blue");
  const third = manager.submit("third.bin", "third goal", "both");
  assert.equal(tasks.size, 2);
  assert.equal(session(manager, third).status, "queued");
  tasks.get(first).callbacks.onToken("first response");
  tasks.get(second).callbacks.onToken("second response");
  tasks.get(first).callbacks.onStepNode({ id: "shared-node-id", parentId: null, agentId: "red", title: "First", detail: "first evidence", status: "done", timestamp: 1 });
  tasks.get(second).callbacks.onStepNode({ id: "shared-node-id", parentId: null, agentId: "blue", title: "Second", detail: "second evidence", status: "done", timestamp: 1 });
  assert.equal(manager.getSnapshot().records[first].messages.at(-1).content, "first response");
  assert.equal(manager.getSnapshot().records[second].messages.at(-1).content, "second response");
  assert.equal(manager.getSnapshot().records[first].steps[0].detail, "first evidence");
  assert.equal(manager.getSnapshot().records[second].steps[0].detail, "second evidence");
  tasks.get(first).gate.resolve();
  await tick();
  assert.equal(tasks.size, 3);
  assert.equal(session(manager, third).status, "running");
  tasks.get(second).gate.resolve();
  tasks.get(third).gate.resolve();
  await tick();
  assert.equal(maximum, 2);
  assert.equal(manager.getSnapshot().sessions.every((entry) => entry.status === "completed"), true);
  manager.flush();
});

test("cancelling a queued goal never calls its executor", async () => {
  const firstGate = deferred();
  const executed = [];
  const manager = new GoalManager(async (request, callbacks) => {
    executed.push(request.id);
    await firstGate.promise;
    callbacks.onRunProgress(progress());
  }, storage(), 1);
  const first = manager.submit("first.bin", "first goal", "red");
  const queued = manager.submit("queued.bin", "queued goal", "blue");
  manager.cancel(queued);
  firstGate.resolve();
  await tick();
  assert.deepEqual(executed, [first]);
  assert.equal(session(manager, queued).status, "cancelled");
  manager.flush();
});

test("submitted target and budget are fixed while a goal waits in the queue", async () => {
  const firstGate = deferred();
  const requests = [];
  const manager = new GoalManager(async (request, callbacks) => {
    requests.push(request);
    if (requests.length === 1) await firstGate.promise;
    callbacks.onRunProgress(progress());
  }, storage(), 1);
  manager.submit("first.bin", "first goal", "red");
  const budget = { maxDurationMs: 1000, maxTokens: 2000 };
  const queued = manager.submit("fixed.bin", "fixed goal", "blue", budget);
  budget.maxTokens = 1;
  firstGate.resolve();
  await tick();
  assert.equal(requests[1].budget.maxTokens, 2000);
  assert.throws(() => { requests[1].target = "other.bin"; }, TypeError);
  assert.equal(session(manager, queued).target, "fixed.bin");
  manager.flush();
});

test("completed goals ignore late streaming and progress callbacks", async () => {
  let callbacks;
  const manager = new GoalManager(async (_request, update) => {
    callbacks = update;
    update.onToken("accepted final response");
    update.onRunProgress(progress());
  }, storage());
  const id = manager.submit("fixture.bin", "inspect goal", "blue");
  await tick();
  callbacks.onToken("late stale response");
  callbacks.onRunProgress(progress("running"));
  const record = manager.getSnapshot().records[id];
  assert.equal(record.messages.at(-1).content, "accepted final response");
  assert.equal(record.progress.status, "completed");
  assert.equal(record.messages.at(-1).isRunning, false);
  manager.flush();
});

test("legacy migration excludes seeded sessions and restores interrupted messages as stopped", () => {
  const saved = storage([
    ["reverselab_sessions", JSON.stringify([
      { id: "sess-revo-pro-verified", target: "seed.bin", title: "Seed", status: "completed" },
      { id: "legacy-goal", target: "fixture.bin", title: "Real saved goal", status: "running" },
    ])],
    ["reverselab_session_data_legacy-goal", JSON.stringify({ messages: [{ id: "assistant", role: "assistant", content: "partial result", timestamp: 1, isRunning: true }] })],
  ]);
  const manager = new GoalManager(async () => assert.fail("Restoring history ran a goal"), saved);
  assert.equal(manager.getSnapshot().sessions.length, 1);
  assert.equal(session(manager, "legacy-goal").status, "cancelled");
  assert.equal(manager.getSnapshot().records["legacy-goal"].messages[0].isRunning, false);
  assert.equal(new GoalManager(async () => {}).getSnapshot().sessions.length, 0);
  manager.flush();
});

test("report references and completed results survive storage and restoration", async () => {
  const saved = storage();
  const report = { summary: "Verified fixture evidence", savedArtifacts: { report_path: "reports/fixture-analysis.md", script_path: "exports/fixture-check.py" } };
  const manager = new GoalManager(async (_request, callbacks) => {
    callbacks.onDeliverables(report);
    callbacks.onRunProgress(progress());
  }, saved);
  const id = manager.submit("fixture.bin", "inspect fixture", "blue");
  await tick();
  manager.flush();
  const restored = new GoalManager(async () => assert.fail("Completed history ran again"), saved);
  assert.deepEqual(restored.getSnapshot().records[id].deliverables, report);
  assert.deepEqual(restored.getSnapshot().records[id].messages.at(-1).deliverables, report);
  assert.equal(session(restored, id).status, "completed");
});

test("interrupted history stops messages and health traces even before progress was recorded", () => {
  const saved = storage([["reverselab_goals_v2", JSON.stringify({ sessions: [{ id: "interrupted", track: "blue", status: "running" }], records: { interrupted: { messages: [{ isRunning: true }], steps: [{ status: "running" }], healthEvents: [{ eventId: "tool-start", goalId: "interrupted", nodeId: "tool", layer: "tool", status: "running", timestamp: 1 }] } } })]]);
  const manager = new GoalManager(async () => assert.fail("restoration ran a goal"), saved);
  const snapshot = manager.getSnapshot();
  assert.equal(snapshot.sessions[0].status, "cancelled");
  assert.equal(snapshot.records.interrupted.messages[0].isRunning, false);
  assert.equal(snapshot.records.interrupted.steps[0].status, "failed");
  assert.equal(snapshot.records.interrupted.healthEvents.at(-1).status, "cancelled");
});

test("asynchronous persistence failures remain visible until the latest disk write succeeds", async () => {
  const writes = [];
  const saved = { ...storage(), setItem: () => new Promise((resolve, reject) => writes.push({ resolve, reject })) };
  const manager = new GoalManager(async () => {}, saved);
  manager.create("blue");
  manager.flush();
  writes[0].reject(new Error("disk unavailable"));
  await tick();
  assert.equal(manager.getSnapshot().persistenceError, "disk unavailable");
  manager.flush();
  assert.equal(manager.getSnapshot().persistenceError, "disk unavailable");
  writes[1].resolve();
  await tick();
  assert.equal(manager.getSnapshot().persistenceError, undefined);
  manager.flush();
  manager.flush();
  writes[3].resolve();
  await tick();
  writes[2].reject(new Error("older failed write"));
  await tick();
  assert.equal(manager.getSnapshot().persistenceError, undefined);
});
