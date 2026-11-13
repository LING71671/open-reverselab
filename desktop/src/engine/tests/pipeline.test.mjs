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
  let code = ts.transpileModule(await readFile(file, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText.replaceAll("import.meta.env", "{}");
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
const { StaticTriageStage } = await load("engine/pipeline/stages/StaticTriageStage.ts");
after(async () => { await rm(temporary, { recursive: true, force: true }); });

const item = (track, name, related = []) => ({ id: name, board: "pe-reverse", title: name, category: "memory", signals: ["hook"], mcp_tools: [], path: `kb/pe-reverse/${name}.md`, track, related_paths: related });
const catalog = [item("red", "hook", ["kb/pe-reverse/hook-defense.md"]), item("blue", "hook-defense", ["kb/pe-reverse/hook.md"]), item("both", "shared")];
const context = (extra = {}) => ({ sessionId: "test", target: "fixture.bin", prompt: "inspect hook", track: "blue", history: [], diagnostics: {}, state: {}, budget: { maxTokens: 20000, maxDurationMs: 10000, startedAt: Date.now(), deadline: Date.now() + 10000, monotonicDeadline: performance.now() + 10000, tokensUsed: 0, attempts: 1, usageEstimated: false }, ...extra });
const stage = (id, execute) => ({ id, name: id, description: id, category: "custom", enabled: true, execute });

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
