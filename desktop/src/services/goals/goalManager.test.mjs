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

test("renamed drafts keep their title when submitted and restored", async () => {
  const saved = storage();
  const manager = new GoalManager(async (_request, callbacks) => callbacks.onRunProgress(progress()), saved);
  const id = manager.create("red");
  manager.rename(id, "  Crackme review  ");
  assert.equal(session(manager, id).title, "Crackme review");
  manager.submit("fixture.bin", "Compute the file hash", "red", undefined, id);
  await tick();
  assert.equal(session(manager, id).title, "Crackme review");
  assert.equal(manager.getSnapshot().records[id].messages[0].content, "Compute the file hash");
  assert.equal(session(new GoalManager(async () => {}, saved), id).title, "Crackme review");
  assert.throws(() => manager.rename(id, "   "));
  assert.throws(() => manager.rename(id, "x".repeat(121)));
});

test("model titles summarize the goal while manual names and completed runs remain stable", async () => {
  const wait = deferred();
  const saved = storage();
  let stream;
  const manager = new GoalManager(async (_request, callbacks) => { stream = callbacks; await wait.promise; callbacks.onRunProgress(progress()); }, saved);
  const objective = "Read a UTF-8 file and count its characters and bytes without changing its content";
  const id = manager.submit("fixture.txt", objective, "red");
  assert.equal(session(manager, id).title, "分析任务");
  stream.onTitle("UTF-8 内容与长度核验");
  assert.equal(session(manager, id).title, "UTF-8 内容与长度核验");
  stream.onTitle("Unrelated later title");
  assert.equal(session(manager, id).title, "UTF-8 内容与长度核验");
  manager.rename(id, "My sample check");
  stream.onTitle("Model cannot replace this");
  wait.resolve(); await tick();
  stream.onTitle("Late title");
  assert.equal(session(new GoalManager(async () => {}, saved), id).title, "My sample check");
  assert.equal(manager.getSnapshot().records[id].messages[0].content, objective);
});

test("steering preserves a goal, waits for the active stage, and spends only the remaining budget", async () => {
  const first = deferred();
  const second = deferred();
  const runs = [];
  const manager = new GoalManager(async (request, callbacks) => {
    runs.push({ request, callbacks });
    if (!request.revision) {
      callbacks.onToken("Original analysis");
      callbacks.onStepNode({ id: "step", parentId: null, agentId: "tool", title: "Observed", detail: "Evidence A", status: "done", timestamp: 1 });
      callbacks.onToolCall({ id: "tool", tool: "observe", title: "Read evidence", status: "done", output: { observed: "A" } });
      await first.promise;
      assert.equal(callbacks.shouldYield(), true);
      callbacks.onDeliverables({ summary: "Stale success" });
      callbacks.onRunProgress({ ...progress(), tokensUsed: 40 });
    } else {
      await second.promise;
      callbacks.onToken("Updated analysis");
      callbacks.onStepNode({ id: "step", parentId: null, agentId: "tool", title: "New check", detail: "Evidence B", status: "done", timestamp: 2 });
      callbacks.onRunProgress({ ...progress(), tokensUsed: 20 });
    }
  }, storage(), 1);
  const id = manager.submit("fixture.bin", "Inspect", "both", { maxTokens: 100, maxDurationMs: 10000 });
  manager.steer(id, "Also check the signature");
  manager.steer(id, "Use offline evidence");
  assert.equal(runs.length, 1);
  assert.equal(manager.getSnapshot().records[id].messages.at(-1).adjustment.status, "pending");
  first.resolve(); await tick();
  assert.equal(runs.length, 2);
  assert.equal(runs[1].request.id, id);
  assert.equal(runs[1].request.revision, 2);
  assert.match(runs[1].request.objective, /signature[\s\S]*offline/);
  assert.equal(runs[1].request.budget.maxTokens, 60);
  assert.ok(runs[1].request.budget.maxDurationMs <= 10000);
  assert.ok(runs[1].request.history.some(message => message.content.includes('"observed":"A"')));
  assert.equal(manager.getSnapshot().records[id].deliverables, null);
  assert.equal(session(manager, id).status, "running");
  runs[0].callbacks.onToken("Late old stream");
  second.resolve(); await tick();
  const record = manager.getSnapshot().records[id];
  assert.equal(record.progress.tokensUsed, 60);
  assert.equal(record.messages.filter(message => message.role === "assistant").length, 2);
  assert.equal(record.messages.find(message => message.id === `${id}-agent`).content, "Original analysis");
  assert.equal(record.steps.filter(step => step.id.endsWith("step")).length, 2);
  assert.equal(record.messages.filter(message => message.adjustment).every(message => message.adjustment.status === "applied"), true);
  assert.equal(manager.getSnapshot().sessions.length, 1);
  assert.equal(session(manager, id).status, "completed");
  manager.flush();
});

test("cancelling an adjusted goal prevents automatic continuation", async () => {
  const gate = deferred();
  let runs = 0;
  const manager = new GoalManager(async () => { runs++; await gate.promise; }, storage());
  const id = manager.submit("fixture.bin", "Inspect", "red");
  manager.steer(id, "Check imports");
  manager.cancel(id);
  gate.resolve(); await tick();
  assert.equal(runs, 1);
  assert.equal(session(manager, id).status, "cancelled");
  assert.equal(manager.getSnapshot().records[id].messages.find(message => message.adjustment).adjustment.status, "cancelled");
  manager.flush();
});

test("steering cannot reset an exhausted quota", async () => {
  const gate = deferred();
  let runs = 0;
  const manager = new GoalManager(async (_request, callbacks) => {
    runs++; await gate.promise;
    callbacks.onRunProgress({ ...progress(), tokensUsed: 100 });
  }, storage());
  const id = manager.submit("fixture.bin", "Inspect", "red", { maxTokens: 100 });
  manager.steer(id, "Check imports");
  gate.resolve(); await tick();
  assert.equal(runs, 1);
  assert.equal(session(manager, id).status, "exhausted");
  assert.equal(manager.getSnapshot().records[id].progress.tokensUsed, 100);
  manager.flush();
});

test("default scheduling starts every goal and isolates cancellation and output", async () => {
  const gate = deferred();
  const tasks = new Map();
  const manager = new GoalManager(async (request, callbacks, signal) => {
    tasks.set(request.id, { callbacks, signal });
    await gate.promise;
    callbacks.onToken(`result:${request.target}`);
    callbacks.onRunProgress(progress());
  }, storage());
  const ids = Array.from({ length: 32 }, (_, index) => manager.submit(`fixture-${index}.bin`, "inspect", index % 2 ? "blue" : "red"));
  try {
    assert.equal(tasks.size, ids.length);
    assert.ok(manager.getSnapshot().sessions.every(item => item.status === "running"));
    manager.cancel(ids[0]);
    assert.equal(tasks.get(ids[0]).signal.aborted, true);
    assert.ok(ids.slice(1).every(id => !tasks.get(id).signal.aborted));
  } finally { gate.resolve(); await tick(); manager.flush(); }
  assert.equal(session(manager, ids[0]).status, "cancelled");
  assert.equal(manager.getSnapshot().records[ids[0]].messages.at(-1).content, "");
  for (const [index, id] of ids.entries()) {
    if (!index) continue;
    assert.equal(session(manager, id).status, "completed");
    assert.equal(manager.getSnapshot().records[id].messages.at(-1).content, `result:fixture-${index}.bin`);
  }
});

test("an explicit two-goal limit queues the third and keeps callbacks isolated", async () => {
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
