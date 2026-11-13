import assert from "node:assert/strict";
import { test, after } from "node:test";
import { readFile, writeFile, mkdir, mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

// Load the real TypeScript modules without adding a test framework or browser.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-engine-test-"));
const compiled = new Map();
async function compile(file) {
  if (compiled.has(file)) return compiled.get(file);
  const output = path.join(temporary, path.relative(root, file).replace(/\.ts$/, ".mjs"));
  compiled.set(file, output);
  let code = ts.transpileModule(await readFile(file, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText.replaceAll("import.meta.env", "{}")
    .replaceAll('"@tauri-apps/api/core"', JSON.stringify(import.meta.resolve("@tauri-apps/api/core")));
  for (const match of [...code.matchAll(/(?:from\s*|import\s*)["'](\.[^"']+)["']/g)]) {
    const location = path.resolve(path.dirname(file), match[1]);
    let dependency = location.endsWith(".ts") ? location : `${location}.ts`;
    try { await access(dependency); } catch { dependency = path.join(location, "index.ts"); }
    const url = pathToFileURL(await compile(dependency)).href;
    code = code.replaceAll(`"${match[1]}"`, JSON.stringify(url));
  }
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, code);
  return output;
}
const storage = new Map();
globalThis.localStorage = { getItem: (key) => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) };
const load = async (relative) => import(pathToFileURL(await compile(path.join(root, relative))).href);
const { selectKbTechniques } = await load("engine/pipeline/kbSelection.ts");
const { HarnessPipeline } = await load("engine/pipeline/HarnessPipeline.ts");
const { nativeBridge } = await load("services/native/nativeBridge.ts");
const { llmService } = await load("services/llm/llmService.ts");
const { parseAcceptancePlan, verifyGoalWithModel } = await load("engine/pipeline/goalVerifier.ts");
const { verifyTargetEvidence } = await load("engine/tracks/evidence.ts");
const { ForensicsDeliverablesStage } = await load("engine/pipeline/stages/ForensicsDeliverablesStage.ts");
const { KbRoutingStage } = await load("engine/pipeline/stages/KbRoutingStage.ts");
const { TargetDiscoveryStage } = await load("engine/pipeline/stages/TargetDiscoveryStage.ts");
const { parseActionPlan, executeActionPlan } = await load("engine/pipeline/actionPlan.ts");
const { runBothTracks } = await load("engine/tracks/both.ts");
const { StaticTriageStage } = await load("engine/pipeline/stages/StaticTriageStage.ts");
const { LlmStreamStage } = await load("engine/pipeline/stages/LlmStreamStage.ts");
const { HealthFault } = await load("core/contracts/health.ts");
const { presentAgentContent } = await load("views/chat/agentContent.ts");
const { buildAnalysisMessages, estimateMessageTokens } = await load("engine/pipeline/analysisPrompt.ts");
after(async () => { await rm(temporary, { recursive: true, force: true }); });

const item = (track, name, related = []) => ({ id: name, board: "pe-reverse", title: name, category: "memory", signals: ["hook"], mcp_tools: [], path: `kb/pe-reverse/${name}.md`, track, related_paths: related });
const catalog = [item("red", "hook", ["kb/pe-reverse/hook-defense.md"]), item("blue", "hook-defense", ["kb/pe-reverse/hook.md"]), item("both", "shared")];
const context = (extra = {}) => ({ sessionId: "test", target: "fixture.bin", prompt: "inspect hook", track: "blue", history: [], diagnostics: {}, state: {}, budget: { maxTokens: 20000, maxDurationMs: 10000, startedAt: Date.now(), deadline: Date.now() + 10000, monotonicDeadline: performance.now() + 10000, tokensUsed: 0, attempts: 1, usageEstimated: false }, ...extra });
const stage = (id, execute) => ({ id, name: id, description: id, category: "custom", enabled: true, execute });

test("streaming protocol stays in details while prose and branch headings remain readable", () => {
  const plan = JSON.stringify({ hypothesis: "核对真实请求记录", checks: [{ id: "C1" }] });
  const action = JSON.stringify({ actions: [{ script: 'print({"text": "} \\\" {"})' }] });
  const raw = `## red\n${plan}${action}\n已发现请求差异。\n## blue\n正在检查防守记录。\n\`\`\`python\nprint('private script')\n\`\`\``;
  const shown = presentAgentContent(raw);
  assert.match(shown.prose, /red[\s\S]*核查计划：核对真实请求记录[\s\S]*已发现请求差异[\s\S]*blue[\s\S]*正在检查/);
  assert.doesNotMatch(shown.prose, /checks|actions|script|print\(/);
  assert.equal(shown.details.length, 3);
  assert.match(shown.details[1].content, /print/);
  for (const partial of ['{"actions":[{"script":"', '```action-plan\n{"actions":[', '```python\nprint(']) {
    assert.equal(presentAgentContent(`已读取目标。\n${partial}`).prose, "已读取目标。");
  }
  assert.equal(presentAgentContent("普通正文与 `API` 名称。").prose, "普通正文与 `API` 名称。");
});

test("receipt and timing changes cannot replay the same action, but changed observations can", async () => {
  let calls = 0, revision = 1, observed = "first";
  const ctx = context({ state: {
    executeAction: async () => { calls++; return { success: true, stdout: "observed", stderr: "" }; },
    readPeerEvidence: () => ({ parentIds: [`peer-${revision}`], messages: [{ id: `receipt-${revision}`, goalId: "test", from: "red", to: "blue", type: "evidence", payload: {
      content: JSON.stringify({ title: `label-${revision}`, output: { success: true, stdout: JSON.stringify({ value: observed, timestamp: 123 }), stderr: "", executionTimeMs: revision } }), evidenceRefs: [{ id: `peer-${revision}`, nodeId: `peer-${revision}` }],
    } }] }),
  } });
  const actions = [{ id: "read", title: "read", script: "read_target()", dependsOn: [] }];
  assert.equal((await executeActionPlan(actions, ctx, {})).success, true);
  revision++;
  assert.equal((await executeActionPlan(actions, ctx, {})).success, false);
  assert.equal(calls, 1);
  observed = "changed";
  assert.equal((await executeActionPlan(actions, ctx, {})).success, true);
  assert.equal(calls, 2);
});

test("action evidence quotes use decoded stdout and require the exact source", async () => {
  const original = llmService.complete;
  const ctx = context();
  ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "request observed", expected: "denied" }] };
  ctx.state.executionEvidence = { "actions.read.stdout": '{"request":"r-1","result":"denied"}', "actions.other.stdout": "unrelated" };
  const output = { success: true, stdout: JSON.stringify(ctx.state.executionEvidence), stderr: "" };
  let ref = "actions.read.stdout", quote = '"result":"denied"';
  try {
    llmService.complete = async messages => {
      const payload = JSON.parse(messages[1].content);
      assert.equal(payload.evidence["actions.read.stdout"], ctx.state.executionEvidence["actions.read.stdout"]);
      return { content: JSON.stringify({ status: "verified", reason: "All checks passed", nextHypothesis: "Finished", checks: [{ id: "C1", passed: true, evidenceRef: ref, evidenceQuote: quote }] }), usage: { totalTokens: 100 } };
    };
    const verify = () => verifyGoalWithModel(ctx, output, "read_target()", verifyTargetEvidence(ctx, output), {});
    assert.equal((await verify()).goalVerified, true);
    ref = "actions.other.stdout";
    const wrongSource = await verify();
    assert.equal(wrongSource.goalVerified, false);
    assert.match(wrongSource.reason, /C1：引用文字未出现在指定输出中/);
    assert.doesNotMatch(wrongSource.reason, /All checks passed/);
    assert.match(buildAnalysisMessages(ctx).at(-1).content, /引用文字未出现在指定输出中/);
    assert.doesNotMatch(ctx.state.nextHypothesis, /Finished/);
    ref = "actions.read.stdout"; quote = '"result":"allowed"';
    assert.equal((await verify()).goalVerified, false);
    ref = "missing";
    assert.match((await verify()).reason, /C1：证据引用不存在/);
    ref = "actions.read.stdout"; quote = "";
    assert.match((await verify()).reason, /C1：缺少证据原文/);
  } finally { llmService.complete = original; }
});

test("malformed verifier results explain the fixed checks that still need evidence", async () => {
  const original = llmService.complete;
  const ctx = context();
  ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "read", expected: "observation" }] };
  const output = { success: true, stdout: "observation", stderr: "" };
  try {
    for (const content of ["null", "[]", JSON.stringify({ status: "verified", reason: "All checks passed", checks: [{ id: "extra", passed: true }] })]) {
      llmService.complete = async () => ({ content, usage: { totalTokens: 100 } });
      const result = await verifyGoalWithModel(ctx, output, "read_target()", verifyTargetEvidence(ctx, output), {});
      assert.equal(result.goalVerified, false);
      assert.match(result.reason, /固定计划一一对应：C1/);
      assert.match(result.goal.assertions[0].actual, /缺少该项核验结果/);
      assert.match(ctx.state.nextHypothesis, /沿用原验收条件/);
    }
  } finally { llmService.complete = original; }
});

test("an unavailable executor stops at the failed round without model replanning", async () => {
  const original = { execPython: nativeBridge.execPython, saveReport: nativeBridge.saveReport };
  let calls = 0;
  try {
    nativeBridge.execPython = async () => { calls++; throw new HealthFault("TOOL_UNAVAILABLE", "Execution service unavailable (HTTP 503)"); };
    nativeBridge.saveReport = async () => ({ status: "saved" });
    const pipeline = new HarnessPipeline([stage("kb-routing", async ctx => {
      ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "read", expected: "data" }] };
      ctx.state.fullContent = '```action-plan\n' + JSON.stringify({ actions: [{ id: "read", title: "read", script: "read_target()", dependsOn: [] }, { id: "next", title: "next", script: "check()", dependsOn: ["read"] }] }) + '\n```';
    }), new ForensicsDeliverablesStage()]);
    const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "tool-unavailable", "blue");
    assert.equal(result.runProgress.status, "blocked");
    assert.equal(result.budget.attempts, 1);
    assert.equal(calls, 1);
    assert.match(result.runProgress.reason, /503/);
    assert.equal(result.state.actionExecutions[1].status, "cancelled");
  } finally { Object.assign(nativeBridge, original); }
});

test("both scopes branch checks but requires an independent whole-objective verdict", async () => {
  const original = llmService.complete;
  let globalPass = false, requests = 0;
  const runBranch = async (track, budget, _callbacks, state) => {
    const ctx = context({ track, target: "fixture.bin", prompt: "review attack and defense", state,
      runProgress: { status: "completed", tokensUsed: 10, attempts: 1 },
      deliverables: { script: "read_target()", executionOutput: { success: true, stdout: `${track} observation`, stderr: "" } },
    });
    ctx.budget.tokensUsed = 10;
    ctx.state.acceptancePlan = parseAcceptancePlan(JSON.stringify({ checks: [{ id: "C1", criterion: `${track} requirement`, expected: "observation" }] }), ctx);
    assert.equal(ctx.state.acceptancePlan.scope, track);
    assert.match(buildAnalysisMessages(ctx)[0].content, /当前是 both/);
    assert.ok(budget.maxTokens < 10000);
    return ctx;
  };
  try {
    llmService.complete = async messages => {
      requests++;
      const payload = JSON.parse(messages[1].content);
      assert.equal(payload.objective, "review attack and defense");
      assert.equal(payload.plan.scope, "goal");
      assert.deepEqual(payload.plan.checks.map(check => check.id), ["red.C1", "blue.C1"]);
      return { content: JSON.stringify({ status: globalPass ? "verified" : "continue", reason: globalPass ? "all observed" : "missing original requirement",
        checks: ["red", "blue"].map(track => ({ id: `${track}.C1`, passed: true, evidenceRef: `${track}.execution.stdout`, evidenceQuote: `${track} observation` })) }), usage: { totalTokens: 80 } };
    };
    const run = () => runBothTracks("fixture.bin", "review attack and defense", { maxTokens: 20000 }, {}, undefined, runBranch, "combined");
    assert.equal((await run()).runProgress.status, "blocked");
    globalPass = true;
    const passed = await run();
    assert.equal(passed.runProgress.status, "completed");
    assert.equal(passed.budget.tokensUsed, 100);
    assert.equal(requests, 2);
  } finally { llmService.complete = original; }
});

test("a goal adjustment during combined verification cannot publish stale success", async () => {
  const original = llmService.complete;
  let yielding = false;
  try {
    llmService.complete = async () => {
      yielding = true;
      return { content: JSON.stringify({ status: "verified", checks: ["red", "blue"].map(track => ({ id: `${track}.C1`, passed: true, evidenceRef: `${track}.execution.stdout`, evidenceQuote: "observation" })) }), usage: { totalTokens: 30 } };
    };
    const result = await runBothTracks("fixture.bin", "inspect", {}, { shouldYield: () => yielding }, undefined, async (track, _budget, _callbacks, state) => {
      const ctx = context({ track, state, runProgress: { status: "completed" }, deliverables: { script: "read_target()", executionOutput: { success: true, stdout: "observation", stderr: "" } } });
      ctx.prompt = "inspect";
      ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, scope: track, checks: [{ id: "C1", criterion: "check", expected: "data" }] };
      return ctx;
    }, "adjust-combined");
    assert.equal(result.runProgress.status, "running");
    assert.equal(result.state.routeVerified, false);
    assert.equal(result.deliverables.goalVerification.status, "in_progress");
  } finally { llmService.complete = original; }
});

test("combined branches release unused model allowance after a peer settles", async () => {
  const limits = [];
  const result = await runBothTracks("fixture.bin", "inspect", { maxTokens: 30000 }, {}, undefined, async (track, budget, _callbacks, state) => {
    if (track === "blue") {
      limits.push(state.refreshTokenBudget());
      await new Promise(resolve => setImmediate(resolve));
      limits.push(state.refreshTokenBudget());
    }
    const ctx = context({ track, state, runProgress: { status: "blocked", reason: "fixture" } });
    ctx.budget.tokensUsed = 100;
    return ctx;
  }, "transfer-budget");
  assert.deepEqual(limits, [10904, 21708]);
  assert.equal(result.budget.tokensUsed, 200);
});

test("verification programs keep real input bindings without repeating Python-escaped data", async () => {
  const messages = [{ id: "receipt", goalId: "test", from: "red", to: "blue", type: "evidence", payload: { content: 'observed "quote"' } }];
  const ctx = context({ state: {
    readPeerEvidence: () => ({ messages, parentIds: [] }),
    executeAction: async () => ({ success: true, stdout: "actual output", stderr: "" }),
  } });
  await executeActionPlan(["a", "b"].map(id => ({ id, title: id, dependsOn: [], script: "read_target()" + id })), ctx, {});
  const { actions, bindings } = ctx.state.verificationProgram;
  assert.equal(actions.a.script, "read_target()a");
  assert.equal(actions.a.bindings.REVERSELAB_PEER_EVIDENCE, actions.b.bindings.REVERSELAB_PEER_EVIDENCE);
  assert.deepEqual(bindings[actions.a.bindings.REVERSELAB_PEER_EVIDENCE], messages);
  assert.equal(Object.keys(bindings).length, 2);
  assert.match(ctx.state.executedPlanScript, /json.*loads/);
});

test("browser executor distinguishes service failure, script failure and cancellation", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    await assert.rejects(nativeBridge.execPython("read_target()"), error => error.code === "TOOL_UNAVAILABLE" && /503/.test(error.message));
    globalThis.fetch = async () => Response.json({ success: false, stdout: "", stderr: "ModuleNotFoundError" });
    assert.equal((await nativeBridge.execPython("read_target()")).stderr, "ModuleNotFoundError");
    const controller = new AbortController();
    globalThis.fetch = async () => { controller.abort(); throw new Error("cancelled"); };
    await assert.rejects(nativeBridge.execPython("read_target()", { signal: controller.signal }), error => error.name === "AbortError");
  } finally { globalThis.fetch = original; }
});

test("action plans reject cycles, missing dependencies and duplicate IDs before execution", () => {
  const content = actions => "```action-plan\n" + JSON.stringify({ actions }) + "\n```";
  const action = (id, dependsOn = []) => ({ id, dependsOn, title: id, script: "print(1)" });
  assert.equal(parseActionPlan("```python\nprint(1)\n```"), undefined);
  assert.throws(() => parseActionPlan("```action-plan\n{"));
  assert.throws(() => parseActionPlan(content([action("a", ["b"]), action("b", ["a"])])));
  assert.throws(() => parseActionPlan(content([action("a", ["missing"])])));
  assert.throws(() => parseActionPlan(content([action("a"), action("a")])));
  assert.deepEqual(parseActionPlan(content([action("a"), action("b"), action("join", ["a", "b"])]))[2].dependsOn, ["a", "b"]);
});

test("acceptance and action plans tolerate adjacent JSON while braces in scripts remain data", () => {
  const plan = { title: "检查组合限制", checks: [{ id: "C1", criterion: "inspect policy", expected: "actual output" }] };
  const actions = { actions: [{ id: "inspect", title: "inspect", dependsOn: [], script: 'print({"text": "} \\\" {"})' }] };
  const content = JSON.stringify(plan) + JSON.stringify(actions);
  const ctx = context();
  assert.equal(parseAcceptancePlan(content, ctx).checks[0].id, "C1");
  assert.deepEqual(parseActionPlan(content), actions.actions);
  assert.equal(parseAcceptancePlan(content, ctx).objective, ctx.prompt);
  assert.throws(() => parseActionPlan(JSON.stringify(plan) + JSON.stringify({ actions: [{ ...actions.actions[0], dependsOn: ["missing"] }] })));
});

test("action network runs independent observations together and gives a join both actual outputs", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const started = [];
  const nodes = new Map();
  const ctx = context({ state: { executeAction: async (_fingerprint, script) => {
    const id = script.split("\n").at(-1);
    started.push(id);
    if (id !== "join") {
      if (started.length === 2) release();
      await gate;
    } else {
      const encoded = script.split("\n")[0].slice('REVERSELAB_INPUTS = __import__("json").loads('.length, -1);
      const inputs = JSON.parse(JSON.parse(encoded));
      assert.equal(inputs.a.stdout, "observed-a");
      assert.equal(inputs.b.stdout, "observed-b");
    }
    return { success: true, stdout: `observed-${id}`, stderr: "" };
  } } });
  const actions = ["a", "b", "join"].map(id => ({ id, title: id, dependsOn: id === "join" ? ["a", "b"] : [], script: id }));
  const result = await executeActionPlan(actions, ctx, { onStepNode: node => nodes.set(node.id, node) });
  assert.equal(result.success, true);
  assert.deepEqual(started, ["a", "b", "join"]);
  assert.deepEqual(nodes.get("test:1:action:join").parentIds, ["test:1:action:a", "test:1:action:b"]);
  assert.equal(ctx.state.actionExecutions.length, 3);
});

test("plans beyond six actions start every independent observation before joining", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let ready;
  const allStarted = new Promise(resolve => { ready = resolve; });
  const ids = Array.from({ length: 16 }, (_, index) => `observe-${index}`);
  const started = [];
  let joined = false;
  const ctx = context({ state: { executeAction: async (_fingerprint, script) => {
    const id = script.split("\n").at(-1);
    started.push(id);
    if (id === "join") {
      joined = true;
      const encoded = script.split("\n")[0].slice('REVERSELAB_INPUTS = __import__("json").loads('.length, -1);
      const inputs = JSON.parse(JSON.parse(encoded));
      assert.deepEqual(Object.keys(inputs), ids);
      assert.ok(ids.every(parent => inputs[parent].stdout === `observed:${parent}`));
    } else {
      if (started.length === ids.length) ready();
      await gate;
    }
    return { success: true, stdout: `observed:${id}`, stderr: "", executionTimeMs: 1 };
  } } });
  const actions = parseActionPlan(JSON.stringify({ actions: [...ids, "join"].map(id => ({ id, title: id, dependsOn: id === "join" ? ids : [], script: id })) }));
  const running = executeActionPlan(actions, ctx, {});
  let timeout;
  try {
    await Promise.race([allStarted, new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Independent actions were queued behind a fixed limit")), 2000); })]);
    assert.deepEqual(new Set(started), new Set(ids));
    assert.equal(joined, false);
  } finally { clearTimeout(timeout); release(); await running; }
  assert.equal((await running).success, true);
  assert.equal(joined, true);
  assert.equal(ctx.state.actionExecutions.length, 17);
});

test("failed action skips dependent work while unrelated evidence is retained", async () => {
  const calls = [];
  const ctx = context({ state: { executeAction: async (_id, script) => {
    const id = script.split("\n").at(-1); calls.push(id);
    return { success: id !== "broken", stdout: id === "broken" ? "" : "actual evidence", stderr: id === "broken" ? "missing dependency" : "" };
  } } });
  const result = await executeActionPlan([
    { id: "broken", title: "broken", dependsOn: [], script: "broken" },
    { id: "other", title: "other", dependsOn: [], script: "other" },
    { id: "dependent", title: "dependent", dependsOn: ["broken"], script: "dependent" },
  ], ctx, {});
  assert.equal(result.success, false);
  assert.deepEqual(calls.sort(), ["broken", "other"]);
  assert.match(result.stdout, /actual evidence/);
  assert.equal(ctx.state.actionExecutions.find(action => action.id === "dependent").status, "cancelled");
});

test("a goal adjustment stops queued actions and preserves completed evidence", async () => {
  let yielding = false;
  const calls = [];
  const ctx = context({ state: { executeAction: async (_id, script) => {
    calls.push(script); yielding = true;
    return { success: true, stdout: "first observation", stderr: "" };
  } } });
  const result = await executeActionPlan([
    { id: "first", title: "first", dependsOn: [], script: "first" },
    { id: "later", title: "later", dependsOn: ["first"], script: "later" },
  ], ctx, { shouldYield: () => yielding });
  assert.equal(calls.length, 1);
  assert.equal(result.success, false);
  assert.match(result.stdout, /first observation/);
});

test("both passes real action evidence across tracks and records reciprocal graph dependencies", async () => {
  const oldExec = nativeBridge.execPython;
  let blueObserved, redObserved;
  const blueGate = new Promise(resolve => { blueObserved = resolve; });
  const redGate = new Promise(resolve => { redObserved = resolve; });
  const received = {};
  const graph = new Map();
  try {
    nativeBridge.execPython = async script => {
      const id = script.split("\n").at(-1);
      if (id === "red-first") await blueGate;
      if (id === "blue-first") blueObserved();
      if (id === "red-check") redObserved();
      if (id === "blue-wait") await redGate;
      const encoded = script.split("\n")[1].slice('REVERSELAB_PEER_EVIDENCE = __import__("json").loads('.length, -1);
      received[id] = JSON.parse(JSON.parse(encoded));
      return { success: true, stdout: `actual-${id}`, stderr: "" };
    };
    await runBothTracks("fixture.bin", "cross-check", {}, { onStepNode: node => graph.set(node.id, node) }, undefined,
      async (track, _budget, callbacks, state, signal) => {
        const names = track === "red" ? ["red-first", "red-check"] : ["blue-first", "blue-wait", "blue-check"];
        const ctx = context({ sessionId: track, track, signal, state });
        const actions = names.map((id, index) => ({ id, title: id, script: id, dependsOn: index ? [names[index - 1]] : [] }));
        await executeActionPlan(actions, ctx, callbacks);
        ctx.runProgress = { status: "blocked", reason: "Requires independent verification", tokensUsed: 0, attempts: 1, elapsedMs: 1 };
        return ctx;
      }, "cross-goal");
    assert.ok(received["red-check"].some(message => message.from === "blue" && message.payload.content.includes("actual-blue-first")));
    assert.ok(received["blue-check"].some(message => message.from === "red"));
    assert.ok(graph.get("red:red:1:action:red-check").parentIds.some(id => id.startsWith("blue:")));
    assert.ok(graph.get("blue:blue:1:action:blue-check").parentIds.some(id => id.startsWith("red:")));
    assert.equal(graph.get("branch:join").status, "failed");
  } finally { nativeBridge.execPython = oldExec; }
});

test("an adjustment yields at a stage boundary without verifying the stale objective", async () => {
  let pending = false;
  const pipeline = new HarnessPipeline([
    stage("observe", async ctx => { ctx.budget.tokensUsed = 25; pending = true; }),
    stage("forensics-deliverables", async () => assert.fail("executed stale plan")),
  ]);
  const result = await pipeline.run("fixture.bin", "old objective", [], { shouldYield: () => pending }, undefined, "steer", "red");
  assert.equal(result.state.yieldedForAdjustment, true);
  assert.equal(result.runProgress.status, "running");
  assert.equal(result.runProgress.tokensUsed, 25);
  assert.notEqual(result.state.routeVerified, true);
});

test("both yields both branches before publishing an old merged success", async () => {
  let pending = false;
  const finals = [];
  const pipeline = new HarnessPipeline([
    stage("observe", async () => { pending = true; }),
    stage("forensics-deliverables", async () => assert.fail("executed old branch plan")),
  ]);
  const result = await pipeline.run("fixture.bin", "old objective", [], { shouldYield: () => pending, onDeliverables: value => finals.push(value) }, undefined, "steer-both", "both");
  assert.equal(result.runProgress.status, "running");
  assert.equal(result.state.routeVerified, false);
  assert.equal(finals.length, 0);
});

test("track selection includes shared documents and follows actual pair paths", () => {
  assert.deepEqual(selectKbTechniques(catalog, "blue", "hook").map((entry) => entry.track).sort(), ["blue", "both"]);
  assert.deepEqual(selectKbTechniques(catalog, "red", "hook").map((entry) => entry.track).sort(), ["both", "red"]);
  assert.equal(selectKbTechniques(catalog, "both", "hook").length, 3);
  assert.equal(selectKbTechniques(catalog, "blue", "unrelated").length, 0);
});

test("a missing target stops before model planning or tool execution", async () => {
  const original = nativeBridge.triage;
  try {
    nativeBridge.triage = async () => { throw new Error("Target does not exist"); };
    const pipeline = new HarnessPipeline([new TargetDiscoveryStage(), stage("llm-stream", async () => assert.fail("planned an unobserved target"))]);
    const result = await pipeline.run("missing.exe", "inspect", [], {}, undefined, "test", "blue");
    assert.equal(result.runProgress.status, "blocked");
    assert.match(result.runProgress.reason, /does not exist/);
  } finally { nativeBridge.triage = original; }
});

test("static summaries preserve unknown architecture and entropy", async () => {
  const ctx = context({ triage: { fileType: "Generic Binary", sha256: "a".repeat(64) } });
  await new StaticTriageStage().execute(ctx, {});
  const diagnostic = ctx.diagnostics["static-triage"];
  assert.doesNotMatch(diagnostic.summary, /x86|Unpacked/);
  assert.equal(diagnostic.metrics.find(item => item.label === "Architecture").value, "未识别");
  assert.equal(diagnostic.metrics.find(item => item.label === "Max Entropy").value, "未观测");
});

test("acceptance checks bind to the immutable goal and reject duplicate IDs", () => {
  const ctx = context();
  const plan = parseAcceptancePlan('```goal-plan\n{"target":"other","checks":[{"id":"C1","criterion":"Find hook","expected":"observed API"}]}\n```', ctx);
  assert.equal(plan.target, ctx.target);
  assert.equal(plan.objective, ctx.prompt);
  assert.equal(parseAcceptancePlan('```goal-plan\n{"checks":[{"id":"C1","criterion":"x","expected":"y"},{"id":"C1","criterion":"x","expected":"y"}]}\n```', ctx), undefined);
});

test("valid plans tolerate JSON or omitted fences without relaxing their schema", () => {
  const ctx = context();
  const json = JSON.stringify({ title: "Inspect text encoding", checks: [{ id: "C1", criterion: "Read actual bytes", expected: "UTF-8 data" }] });
  for (const content of [json + '\n\n```python\nread()\n```', '```json\n' + json + '\n```']) {
    assert.equal(parseAcceptancePlan(content, ctx).objective, ctx.prompt);
    assert.equal(ctx.state.suggestedTitle, "Inspect text encoding");
  }
  assert.equal(parseAcceptancePlan('{"checks":[]}', ctx), undefined);
  assert.equal(parseAcceptancePlan('null', ctx), undefined);
});

test("acceptance plans retain every criterion beyond eight checks", () => {
  const checks = Array.from({ length: 32 }, (_, index) => ({ id: `C${index + 1}`, criterion: `Inspect record ${index}`, expected: `Observed record ${index}` }));
  assert.deepEqual(parseAcceptancePlan(JSON.stringify({ checks }), context()).checks, checks);
});

const modelSnapshot = { provider: { id: "fixture", name: "Fixture", baseUrl: "https://model.example.test/v1", apiKey: "" }, model: "fixture" };
const modelRequest = (input, init) => input instanceof Request ? input : new Request(input, init);

test("native bridge omits implicit execution deadlines and preserves larger explicit budgets", async (t) => {
  const requests = [];
  t.mock.method(globalThis, "fetch", async (_, init) => {
    requests.push(JSON.parse(init.body));
    return Response.json({ success: true, stdout: "observed", stderr: "", fileType: "Generic Binary" });
  });
  for (const timeoutMs of [undefined, Infinity, 120000, 0.5]) {
    await nativeBridge.execPython("print('observed')", { timeoutMs });
    await nativeBridge.triage("fixture.txt", { timeoutMs });
  }
  assert.deepEqual(requests.map(request => request.timeoutMs), [undefined, undefined, undefined, undefined, 120000, 120000, 1, 1]);
  for (const timeoutMs of [0, -1]) {
    await assert.rejects(nativeBridge.execPython("print('too late')", { timeoutMs }), { name: "TimeoutError" });
    await assert.rejects(nativeBridge.triage("fixture.txt", { timeoutMs }), { name: "TimeoutError" });
  }
  assert.equal(requests.length, 8);
});

test("native cancellation is reasserted after execution registration", async (t) => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "window");
  const controller = new AbortController();
  let acknowledge, finish;
  const cancellations = [];
  Object.defineProperty(globalThis, "window", { configurable: true, value: { __TAURI_INTERNALS__: {
    transformCallback: () => 1, unregisterCallback() {},
    invoke(command, args) {
      if (command === "cancel_python_execution") { cancellations.push(args.executionId); return Promise.resolve(false); }
      assert.equal(command, "run_python_code");
      assert.equal(args.timeoutMs, undefined);
      acknowledge = () => args.onStarted.onmessage({ kind: "started" });
      return new Promise(resolve => { finish = resolve; });
    },
  } } });
  try {
    const running = nativeBridge.execPython("print('observed')", { executionId: "cancel-registration-fixture", signal: controller.signal });
    const rejected = assert.rejects(running, { name: "AbortError" });
    while (!acknowledge) await new Promise(resolve => setImmediate(resolve));
    controller.abort(); acknowledge();
    finish({ success: false, stdout: "", stderr: "cancelled" });
    await rejected;
    assert.deepEqual(cancellations, ["cancel-registration-fixture", "cancel-registration-fixture"]);
  } finally {
    if (previous) Object.defineProperty(globalThis, "window", previous); else delete globalThis.window;
  }
});

test("both shared actions inherit only the remaining explicit Goal duration", async (t) => {
  const timeouts = [];
  let now = 0;
  t.mock.method(performance, "now", () => now);
  t.mock.method(nativeBridge, "execPython", async (_, options) => { timeouts.push(options.timeoutMs); return { success: true, stdout: "observed", stderr: "" }; });
  for (const budget of [{}, { maxDurationMs: 120000 }]) {
    now = 0;
    await runBothTracks("fixture.txt", "inspect observations", budget, {}, undefined, async (track, branchBudget, _, state) => {
      now = 7500;
      await state.executeAction(track, "print('observed')");
      return context({ track, budget: { ...branchBudget, tokensUsed: 0, attempts: 1 }, state: {}, runProgress: { status: "blocked", reason: "Fixture completed" } });
    }, "execution-budget-fixture");
  }
  assert.deepEqual(timeouts, [undefined, undefined, 112500, 112500]);
});

test("completion requests omit implicit output limits and timers", async (t) => {
  const timers = [];
  t.mock.method(globalThis, "setTimeout", (...args) => { timers.push(args); return 0; });
  const responseText = "observed ".repeat(5000);
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const request = modelRequest(input, init);
    const body = await request.json();
    assert.equal(Object.hasOwn(body, "max_tokens"), false);
    assert.equal(request.signal.aborted, false);
    return Response.json({ choices: [{ message: { content: responseText } }], usage: { total_tokens: 15000 } });
  });
  for (const options of [{}, { maxTokens: Infinity, timeoutMs: Infinity }]) {
    const result = await llmService.complete([{ role: "user", content: "inspect" }], { ...modelSnapshot, ...options });
    assert.equal(result.content, responseText);
    assert.equal(result.usage.totalTokens, 15000);
  }
  assert.equal(timers.length, 0);
});

test("completion requests honor explicit budgets without timer overflow", async (t) => {
  let now = 0;
  const timers = [];
  const cleared = [];
  t.mock.method(performance, "now", () => now);
  t.mock.method(globalThis, "setTimeout", (callback, delay) => {
    const timer = { callback, delay };
    timers.push(timer);
    return timer;
  });
  t.mock.method(globalThis, "clearTimeout", timer => cleared.push(timer));
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  let requestSignal;
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const request = modelRequest(input, init);
    assert.equal((await request.json()).max_tokens, 12000);
    requestSignal = request.signal;
    ready();
    return new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true }));
  });
  const timeoutMs = 2147483647 + 60000;
  const running = llmService.complete([{ role: "user", content: "inspect" }], { ...modelSnapshot, maxTokens: 12000, timeoutMs });
  const rejected = assert.rejects(running, { name: "TimeoutError" });
  await started;
  assert.equal(timers[0].delay, 2147483647);
  now = 2147483647;
  timers[0].callback();
  assert.equal(requestSignal.aborted, false);
  assert.equal(timers[1].delay, 60000);
  now = timeoutMs;
  timers[1].callback();
  await rejected;
  assert.ok(cleared.includes(timers[1]));
});

test("unbounded completion remains manually cancellable", async (t) => {
  const controller = new AbortController();
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const request = modelRequest(input, init);
    ready();
    return new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true }));
  });
  const running = llmService.complete([{ role: "user", content: "inspect" }], { ...modelSnapshot, signal: controller.signal });
  const rejected = assert.rejects(running, { name: "AbortError" });
  await started;
  controller.abort();
  await rejected;
});

test("planning streams send only the user's token budget and preserve long output", async (t) => {
  const text = "observed ".repeat(5000);
  for (const maxTokens of [Infinity, 50000]) {
    const ctx = context({ state: { modelSnapshot } });
    ctx.budget.maxTokens = maxTokens;
    ctx.budget.tokensUsed = 50;
    const expected = Number.isFinite(maxTokens) ? maxTokens - 50 - estimateMessageTokens(buildAnalysisMessages(ctx)) : undefined;
    t.mock.method(globalThis, "fetch", async (input, init) => {
      const body = await modelRequest(input, init).json();
      assert.equal(body.max_tokens, expected);
      assert.equal(Object.hasOwn(body, "max_tokens"), Number.isFinite(maxTokens));
      const content = JSON.stringify({ choices: [{ delta: { content: text } }] });
      const usage = JSON.stringify({ usage: { total_tokens: 15000 } });
      return new Response(`data: ${content}\n\ndata: ${usage}\n\ndata: [DONE]\n\n`);
    });
    await new LlmStreamStage().execute(ctx, {});
    assert.equal(ctx.state.fullContent, text);
    assert.equal(ctx.budget.tokensUsed, 15050);
    assert.equal(ctx.budget.usageEstimated, false);
  }
});

test("independent verification uses remaining user budgets with no implicit limits", async (t) => {
  for (const bounded of [false, true]) {
    const ctx = context({ state: { modelSnapshot } });
    ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "read", expected: "observation" }] };
    ctx.budget.maxTokens = bounded ? 50000 : Infinity;
    ctx.budget.monotonicDeadline = bounded ? performance.now() + 120000 : Infinity;
    ctx.budget.tokensUsed = 50;
    t.mock.method(llmService, "complete", async (messages, options) => {
      assert.equal(options.maxTokens, bounded ? 50000 - 50 - estimateMessageTokens(messages) : undefined);
      if (bounded) assert.ok(options.timeoutMs > 110000 && options.timeoutMs <= 120000);
      else assert.equal(options.timeoutMs, undefined);
      return { content: JSON.stringify({ status: "verified", checks: [{ id: "C1", passed: true, evidenceRef: "execution.stdout", evidenceQuote: "observation" }] }), usage: { totalTokens: 100 } };
    });
    const result = { success: true, stdout: "observation", stderr: "" };
    assert.equal((await verifyGoalWithModel(ctx, result, "read_target()", verifyTargetEvidence(ctx, result), {})).goalVerified, true);
    assert.equal(ctx.budget.tokensUsed, 150);
  }
});

test("no additional KB matches still allows repairing a failed observation", async () => {
  const original = nativeBridge.listKb;
  try {
    nativeBridge.listKb = async () => [];
    let attempts = 0;
    const pipeline = new HarnessPipeline([new KbRoutingStage(), stage("forensics-deliverables", async ctx => {
      attempts++;
      ctx.state.routeBlocked = attempts === 1;
      ctx.state.routeVerified = attempts === 2;
      ctx.state.blockedReason = "Repair the malformed plan";
    })]);
    const result = await pipeline.run("fixture.txt", "count characters", [], {}, undefined, "kb-fallback", "red");
    assert.equal(attempts, 2);
    assert.equal(result.runProgress.status, "completed");
    assert.equal(result.diagnostics["kb-routing"].status, "pass");
  } finally { nativeBridge.listKb = original; }
});

test("independent verifier requires actual quoted evidence and accounts for input plus output", async () => {
  const ctx = context();
  ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "API observed", expected: "hook" }] };
  const output = { success: true, stdout: "Observed API: hook", stderr: "" };
  const original = llmService.complete;
  try {
    llmService.complete = async () => ({ content: JSON.stringify({ status: "verified", reason: "API observed", checks: [{ id: "C1", passed: true, observed: "hook", evidenceRef: "execution.stdout", evidenceQuote: "Observed API: hook" }] }), usage: { totalTokens: 100 }, model: "fixture", durationMs: 1 });
    const verified = await verifyGoalWithModel(ctx, output, "read_target()", verifyTargetEvidence(ctx, output), {});
    assert.equal(verified.goalVerified, true);
    assert.equal(ctx.budget.tokensUsed, 100);
    llmService.complete = async () => ({ content: JSON.stringify({ status: "verified", checks: [{ id: "C1", passed: true, observed: "hook", evidenceRef: "invented", evidenceQuote: "not in stdout" }] }), usage: { totalTokens: 80 } });
    assert.equal((await verifyGoalWithModel(ctx, output, "read_target()", verified, {})).goalVerified, false);
    assert.equal(ctx.budget.tokensUsed, 180);
  } finally { llmService.complete = original; }
});

test("a blocked route triggers a distinct next route and leaves a checkpoint", async () => {
  const routes = [];
  const pipeline = new HarnessPipeline([
    stage("kb-routing", async (ctx) => { ctx.state.attemptedKbPaths = [...(ctx.state.attemptedKbPaths || []), `path-${ctx.budget.attempts}`]; routes.push(ctx.budget.attempts); }),
    stage("forensics-deliverables", async (ctx) => { ctx.state.routeBlocked = ctx.budget.attempts === 1; ctx.state.routeVerified = ctx.budget.attempts === 2; ctx.state.blockedReason = "missing evidence"; }),
  ]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "test", "red");
  assert.deepEqual(routes, [1, 2]);
  assert.equal(result.runProgress.status, "completed");
  assert.deepEqual(result.runProgress.checkpoint.visitedPaths, ["path-1", "path-2"]);
  assert.equal(result.track, "red");
});

test("repeated blockers stop without an infinite retry loop", async () => {
  const pipeline = new HarnessPipeline([stage("kb-routing", async () => {}), stage("forensics-deliverables", async (ctx) => { ctx.state.routeBlocked = true; ctx.state.blockedReason = "same error"; ctx.state.failureFingerprint = "same error"; })]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "test", "blue");
  assert.equal(result.budget.attempts, 2);
  assert.equal(result.runProgress.status, "blocked");
});

test("the same symptom on distinct routes does not abandon an untried route", async () => {
  const pipeline = new HarnessPipeline([
    stage("kb-routing", async (ctx) => { ctx.kbRouting = { matchedTechniques: [`route-${ctx.budget.attempts}.md`] }; }),
    stage("forensics-deliverables", async (ctx) => { ctx.state.routeBlocked = ctx.budget.attempts < 3; ctx.state.routeVerified = ctx.budget.attempts === 3; ctx.state.blockedReason = "same symptom"; ctx.state.failureFingerprint = "same symptom"; }),
  ]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "test", "blue");
  assert.equal(result.budget.attempts, 3);
  assert.equal(result.runProgress.status, "completed");
});

test("deadline aborts an in-flight operation and reports exhaustion", async () => {
  const pipeline = new HarnessPipeline([stage("wait", async (ctx) => new Promise((resolve) => ctx.signal.addEventListener("abort", resolve, { once: true })))]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "test", "blue", { maxTokens: 100, maxDurationMs: 20 });
  assert.equal(result.runProgress.status, "exhausted");
});

test("omitted limits remain unlimited and are not serialized as implicit quotas", async () => {
  const pipeline = new HarnessPipeline([stage("observe", async (ctx) => {
    assert.equal(ctx.budget.monotonicDeadline, Infinity);
    assert.equal(ctx.budget.maxTokens, Infinity);
    ctx.budget.tokensUsed = 100_000;
    await new Promise(resolve => setTimeout(resolve, 15));
    assert.equal(ctx.signal.aborted, false);
    ctx.state.routeVerified = true;
  })]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "unlimited", "blue");
  assert.equal(result.runProgress.status, "completed");
  const saved = JSON.parse(JSON.stringify(result.runProgress));
  assert.equal(saved.maxTokens, undefined);
  assert.equal(saved.maxDurationMs, undefined);
});

test("time-only and token-only limits do not add an unrelated default limit", async () => {
  const pipeline = new HarnessPipeline([stage("observe", async ctx => { ctx.budget.tokensUsed = 20; ctx.state.routeVerified = true; })]);
  const timed = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "time-only", "blue", { maxDurationMs: 5000 });
  assert.equal(timed.budget.maxTokens, Infinity);
  assert.equal(timed.runProgress.status, "completed");
  const capped = await pipeline.run("fixture.bin", "inspect", [], {}, undefined, "tokens-only", "blue", { maxTokens: 10 });
  assert.equal(capped.budget.monotonicDeadline, Infinity);
  assert.equal(capped.runProgress.status, "exhausted");
});

test("unlimited both keeps both branches unbounded and remains cancellable", async () => {
  const controller = new AbortController();
  const observed = [];
  const pipeline = new HarnessPipeline([stage("wait", async ctx => {
    observed.push([ctx.budget.maxTokens, ctx.budget.monotonicDeadline]);
    if (observed.length === 2) controller.abort();
    if (!ctx.signal.aborted) await new Promise(resolve => ctx.signal.addEventListener("abort", resolve, { once: true }));
  })]);
  const result = await pipeline.run("fixture.bin", "inspect", [], {}, controller.signal, "both-unlimited", "both");
  assert.deepEqual(observed, [[Infinity, Infinity], [Infinity, Infinity]]);
  assert.equal(result.runProgress.status, "cancelled");
});

test("missing KB files cause a different real document path to be read", async () => {
  const originalList = nativeBridge.listKb;
  const originalRead = nativeBridge.readKb;
  const paths = [];
  try {
    nativeBridge.listKb = async () => Array.from({ length: 5 }, (_, index) => item("blue", `hook-${index}`));
    nativeBridge.readKb = async (document) => { paths.push(document); return document.endsWith("4.md") ? "real content" : null; };
    const ctx = context({ prompt: "hook" });
    await new KbRoutingStage().execute(ctx, {});
    assert.equal(paths.length, 5);
    assert.deepEqual(ctx.kbRouting.matchedTechniques, ["kb/pe-reverse/hook-4.md"]);
  } finally { nativeBridge.listKb = originalList; nativeBridge.readKb = originalRead; }
});

test("both isolates policies and reuses identical real execution evidence", async () => {
  const original = { triage: nativeBridge.triage, execPython: nativeBridge.execPython, saveReport: nativeBridge.saveReport };
  let executions = 0;
  const hash = "a".repeat(64);
  try {
    nativeBridge.triage = async () => ({ board: "pe-reverse", fileType: "fixture", targetPath: "fixture.bin", sha256: hash });
    nativeBridge.execPython = async () => { executions++; return { success: true, stdout: JSON.stringify({ target: "fixture.bin", sha256: hash }), stderr: "" }; };
    nativeBridge.saveReport = async () => ({ status: "saved", report_path: "reports/fixture.md" });
    const graph = new Map();
    const result = await new HarnessPipeline().run("fixture.bin", "calculate sha256", [], { onStepNode: step => graph.set(step.id, step) }, undefined, "test", "both", { maxTokens: 1000, maxDurationMs: 10000 });
    assert.equal(result.runProgress.status, "completed");
    assert.equal(result.state.branches.red.track, "red");
    assert.equal(result.state.branches.blue.track, "blue");
    assert.notEqual(result.state.branches.red.state, result.state.branches.blue.state);
    assert.equal(executions, 1);
    assert.equal(result.budget.tokensUsed, 0);
    assert.equal(graph.get("branch:join").parentIds.length, 2);
    assert.ok(graph.get("branch:join").parentIds.every(id => id.endsWith("forensics-deliverables") && graph.has(id)));
  } finally { Object.assign(nativeBridge, original); }
});

test("repeating a generated script does not execute it twice", async () => {
  const original = nativeBridge.execPython;
  const originalSave = nativeBridge.saveReport;
  let calls = 0;
  try {
    nativeBridge.execPython = async () => { calls++; return { success: false, stdout: "", stderr: "missing dependency" }; };
    nativeBridge.saveReport = async () => ({ status: "offline" });
    const ctx = context();
    ctx.state.fullContent = '```goal-plan\n{"checks":[{"id":"C1","criterion":"inspect","expected":"evidence"}]}\n```\n```python\nread_target()\n```';
    await new ForensicsDeliverablesStage().execute(ctx, {});
    await new ForensicsDeliverablesStage().execute(ctx, {});
    assert.equal(calls, 1);
    assert.equal(ctx.state.routeVerified, false);
    assert.match(ctx.state.blockedReason, /重复/);
    assert.equal(ctx.deliverables.savedArtifacts, undefined);
  } finally { nativeBridge.execPython = original; nativeBridge.saveReport = originalSave; }
});

test("adjusted runs save reports under their own revision without changing goal identity", async () => {
  const originalSave = nativeBridge.saveReport;
  let saved;
  try {
    nativeBridge.saveReport = async value => { saved = value; return { status: "saved", report_path: "reports/revision/analysis.md" }; };
    const ctx = context({ state: { reportNamespace: "test-revision-2", fullContent: "No script yet" } });
    await new ForensicsDeliverablesStage().execute(ctx, {});
    assert.equal(saved.goalId, "test-revision-2");
    assert.equal(ctx.sessionId, "test");
  } finally { nativeBridge.saveReport = originalSave; }
});

test("concurrent goals on one pipeline keep targets, tracks, budgets and provider snapshots isolated", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const priorModel = llmService.getModel();
  const seen = [];
  try {
    llmService.setModel("first-model");
    const pipeline = new HarnessPipeline([stage("capture", async (ctx) => {
      if (ctx.track === "red") await gate;
      seen.push({ track: ctx.track, target: ctx.target, model: ctx.state.modelSnapshot.model });
      ctx.state.routeVerified = true;
      ctx.budget.tokensUsed = ctx.track === "red" ? 9 : 3;
    })]);
    const red = pipeline.run("red.bin", "red goal", [], {}, undefined, "red-session", "red");
    llmService.setModel("second-model");
    const blue = await pipeline.run("blue.bin", "blue goal", [], {}, undefined, "blue-session", "blue");
    release();
    const redResult = await red;
    assert.equal(redResult.budget.tokensUsed, 9);
    assert.equal(blue.budget.tokensUsed, 3);
    assert.deepEqual(seen, [{ track: "blue", target: "blue.bin", model: "second-model" }, { track: "red", target: "red.bin", model: "first-model" }]);
  } finally { llmService.setModel(priorModel); release?.(); }
});

test("verifier respects remaining quota before submitting any request", async () => {
  const ctx = context();
  ctx.budget.maxTokens = 1;
  ctx.state.acceptancePlan = { target: ctx.target, objective: ctx.prompt, checks: [{ id: "C1", criterion: "inspect", expected: "evidence" }] };
  const result = { success: true, stdout: "evidence", stderr: "" };
  let calls = 0;
  const original = llmService.complete;
  try {
    llmService.complete = async () => { calls++; throw new Error("must not be called"); };
    await assert.rejects(verifyGoalWithModel(ctx, result, "read_target()", verifyTargetEvidence(ctx, result), {}), /额度/);
    assert.equal(calls, 0);
    assert.equal(ctx.state.tokenBudgetExhausted, true);
  } finally { llmService.complete = original; }
});

test("runtime health classifies a provider authentication failure without inventing readiness", async () => {
  const events = [];
  const pipeline = new HarnessPipeline([{ ...stage("llm-stream", async () => { throw Object.assign(new Error("LLM HTTP 401"), { status: 401 }); }), category: "llm" }]);
  const result = await pipeline.run("fixture.bin", "inspect", [], { onHealthEvent: (event) => events.push(event) }, undefined, "health-goal", "blue");
  assert.equal(result.runProgress.status, "blocked");
  assert(events.some((event) => event.goalId === "health-goal" && event.layer === "model" && event.code === "MODEL_AUTH" && event.status === "failed"));
  assert.equal(events.some((event) => event.layer === "kb" && event.status === "healthy"), false);
});
