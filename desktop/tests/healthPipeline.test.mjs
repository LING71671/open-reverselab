import assert from "node:assert/strict";
import { test, after } from "node:test";
import { readFile, writeFile, mkdir, mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

// Exercise the actual stages with deterministic local service responses.
const root = fileURLToPath(new URL("../src/", import.meta.url));
const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-health-test-"));
const compiled = new Map();
async function compile(file) {
  if (compiled.has(file)) return compiled.get(file);
  const output = path.join(temporary, path.relative(root, file).replace(/\.ts$/, ".mjs"));
  compiled.set(file, output);
  let code = ts.transpileModule(await readFile(file, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
    .replaceAll("import.meta.env", "{}")
    .replaceAll('"@tauri-apps/api/core"', JSON.stringify(import.meta.resolve("@tauri-apps/api/core")));
  for (const match of [...code.matchAll(/(?:from\s*|import\s*)["'](\.[^"']+)["']/g)]) {
    const location = path.resolve(path.dirname(file), match[1]);
    let dependency = location.endsWith(".ts") ? location : `${location}.ts`;
    try { await access(dependency); } catch { dependency = path.join(location, "index.ts"); }
    code = code.replaceAll(`"${match[1]}"`, JSON.stringify(pathToFileURL(await compile(dependency)).href));
  }
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, code);
  return output;
}
const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: () => null, setItem() {} } });
after(async () => {
  if (storageDescriptor) Object.defineProperty(globalThis, "localStorage", storageDescriptor); else delete globalThis.localStorage;
  await rm(temporary, { recursive: true, force: true });
});
const load = async relative => import(pathToFileURL(await compile(path.join(root, relative))).href);
const { HarnessPipeline } = await load("engine/pipeline/HarnessPipeline.ts");
const { KbRoutingStage } = await load("engine/pipeline/stages/KBRoutingStage.ts");
const { LlmStreamStage } = await load("engine/pipeline/stages/LlmStreamStage.ts");
const { ForensicsDeliverablesStage } = await load("engine/pipeline/stages/ForensicsDeliverablesStage.ts");
const { nativeBridge } = await load("services/native/nativeBridge.ts");
const { llmService } = await load("services/llm/llmService.ts");
const { HealthFault, HEALTH_LAYERS } = await load("core/contracts/health.ts");
const { HealthMonitor } = await load("services/health/healthMonitor.ts");
const custom = (id, category, execute) => ({ id, category, name: id, description: id, enabled: true, execute });
const snapshot = (id, events) => {
  const monitor = new HealthMonitor({ goalId: id });
  for (const event of events) monitor.record(event);
  return monitor.snapshot();
};
const catalog = [{ id: "fixture", path: "fixture.md", title: "Inspect fixture", board: "general", category: "inspection", track: "blue", signals: ["fixture"], related_paths: [], mcp_tools: [] }];
const provider = { model: "fixture-model", provider: { id: "fixture", name: "Fixture", baseUrl: "https://model.example.test/v1", apiKey: "" } };
const plan = '```goal-plan\n' + JSON.stringify({ title: "Inspect fixture", checks: [{ id: "C1", criterion: "Observe fixture", expected: "observed fixture" }] }) + '\n```\n```python\nread_fixture()\n```';

test("the actual knowledge, model, execution and persistence stages report all six health layers", async t => {
  const events = [];
  t.mock.method(nativeBridge, "readKb", async () => "Inspect the fixture and record observations.");
  t.mock.method(nativeBridge, "mcp", async () => ({ ok: true, connections: [] }));
  t.mock.method(nativeBridge, "execPython", async () => ({ success: true, stdout: "observed fixture", stderr: "", executionTimeMs: 4 }));
  t.mock.method(nativeBridge, "saveReport", async () => ({ status: "saved", report_path: "report.md", script_path: "script.py" }));
  t.mock.method(globalThis, "fetch", async url => {
    assert.equal(url instanceof Request ? url.url : url, "https://model.example.test/v1/chat/completions");
    return new Response(`data: ${JSON.stringify({ choices: [{ delta: { content: plan } }], usage: { total_tokens: 10 } })}\n\ndata: [DONE]\n\n`);
  });
  t.mock.method(llmService, "complete", async () => ({ content: JSON.stringify({ status: "verified", reason: "Observation matched", checks: [{ id: "C1", passed: true, evidenceRef: "execution.stdout", evidenceQuote: "observed fixture" }] }), usage: { totalTokens: 5 } }));
  const pipeline = new HarnessPipeline([new KbRoutingStage(), new LlmStreamStage(), new ForensicsDeliverablesStage()]);
  const result = await pipeline.run("fixture.txt", "inspect fixture", [], { onHealthEvent: event => events.push(event) }, undefined, "all-layers", "blue", {}, { knowledgeSnapshot: true, kbCatalog: catalog, modelSnapshot: provider });
  assert.equal(result.runProgress.status, "completed", result.runProgress.reason);
  const health = snapshot("all-layers", events);
  for (const layer of HEALTH_LAYERS) {
    assert.equal(health.layers[layer].status, "healthy", layer);
    assert.ok(health.layers[layer].observedEvents > 0, layer);
  }
});

test("a failure classified in another layer closes its original operation and links the cause", async () => {
  for (const [category, originalLayer, code, classifiedLayer] of [["llm", "model", "INPUT_INVALID", "goal"], ["forensics", "agent", "MODEL_AUTH", "model"], ["custom", "tool", "BUDGET_TIME", "goal"]]) {
    const events = [];
    const id = `classified-${code}`;
    const pipeline = new HarnessPipeline([custom("operation", category, async () => { throw new HealthFault(code, "fixture failure"); })]);
    await pipeline.run("fixture.txt", "inspect", [], { onHealthEvent: event => events.push(event) }, undefined, id, "blue");
    const health = snapshot(id, events);
    assert.equal(health.layers[originalLayer].status, "failed", code);
    const operation = events.find(event => event.layer === originalLayer && event.status === "failed");
    const cause = events.find(event => event.layer === classifiedLayer && event.code === code);
    assert.equal(operation.correlationId, cause.eventId);
    assert.equal(cause.correlationId, operation.eventId);
    assert.equal(cause.nodeId, operation.nodeId);
  }
});

test("cancelling a running model or tool settles both the operation and Goal", async () => {
  for (const [category, layer] of [["llm", "model"], ["custom", "tool"]]) {
    const controller = new AbortController(), events = [];
    const id = `cancel-${layer}`;
    const pipeline = new HarnessPipeline([custom("operation", category, async () => {
      controller.abort();
      throw new DOMException("Aborted", "AbortError");
    })]);
    const result = await pipeline.run("fixture.txt", "inspect", [], { onHealthEvent: event => events.push(event) }, controller.signal, id, "blue");
    assert.equal(result.runProgress.status, "cancelled");
    const health = snapshot(id, events);
    assert.equal(health.layers[layer].status, "cancelled");
    assert.equal(health.layers.goal.status, "cancelled");
    assert.equal(health.layers.kb.status, "unknown");
  }
});

test("missing knowledge documents retain their cause and path in the knowledge layer", async t => {
  t.mock.method(nativeBridge, "readKb", async () => null);
  const events = [];
  await new HarnessPipeline([new KbRoutingStage()]).run("fixture.txt", "inspect fixture", [], { onHealthEvent: event => events.push(event) }, undefined, "kb-missing", "blue", {}, { knowledgeSnapshot: true, kbCatalog: catalog });
  const cause = snapshot("kb-missing", events).layers.kb.statusEvent;
  assert.equal(cause.code, "KB_DOC_MISSING");
  assert.match(cause.detail, /fixture\.md/);
});

test("a deadline abort closes its operation with a budget cause instead of user cancellation", async () => {
  const events = [];
  const pipeline = new HarnessPipeline([custom("operation", "custom", async ctx => {
    await new Promise((_, reject) => {
      const abort = () => reject(new DOMException("Aborted", "AbortError"));
      if (ctx.signal.aborted) abort(); else ctx.signal.addEventListener("abort", abort, { once: true });
    });
  })]);
  const result = await pipeline.run("fixture.txt", "inspect", [], { onHealthEvent: event => events.push(event) }, undefined, "deadline", "blue", { maxDurationMs: 20 });
  assert.equal(result.runProgress.status, "exhausted");
  assert.equal(snapshot("deadline", events).layers.tool.status, "failed");
  assert.ok(events.some(event => event.code === "BUDGET_TIME"));
  assert.ok(events.every(event => event.code !== "USER_CANCELLED"));
});

test("stopping during script execution does not invent a storage failure for an unattempted write", async t => {
  const controller = new AbortController(), events = [];
  t.mock.method(nativeBridge, "execPython", async () => {
    controller.abort();
    throw new DOMException("Aborted", "AbortError");
  });
  const save = t.mock.method(nativeBridge, "saveReport", async () => { throw new Error("must not write after cancellation"); });
  const pipeline = new HarnessPipeline([custom("prepare", "llm", async ctx => { ctx.state.fullContent = plan; }), new ForensicsDeliverablesStage()]);
  const result = await pipeline.run("fixture.txt", "inspect fixture", [], { onHealthEvent: event => events.push(event) }, controller.signal, "cancel-script", "blue");
  assert.equal(result.runProgress.status, "cancelled");
  const health = snapshot("cancel-script", events);
  assert.equal(health.layers.tool.status, "cancelled");
  assert.equal(health.layers.agent.status, "cancelled");
  assert.equal(health.layers.storage.status, "unknown");
  assert.equal(save.mock.callCount(), 0);
});

test("single-script executor faults retain their explicit code and persistence failures remain separate", async t => {
  t.mock.method(nativeBridge, "execPython", async () => { throw new HealthFault("TOOL_UNAVAILABLE", "fixture executor is offline"); });
  t.mock.method(nativeBridge, "saveReport", async () => { throw new Error("fixture disk is full"); });
  const events = [];
  const pipeline = new HarnessPipeline([custom("prepare", "llm", async ctx => {
    ctx.state.fullContent = plan;
  }), new ForensicsDeliverablesStage()]);
  const result = await pipeline.run("fixture.txt", "inspect fixture", [], { onHealthEvent: event => events.push(event) }, undefined, "failed-services", "blue");
  const health = snapshot("failed-services", events);
  assert.equal(health.layers.tool.status, "failed");
  assert.equal(health.layers.tool.statusEvent.code, "TOOL_UNAVAILABLE");
  assert.match(health.layers.tool.statusEvent.detail, /executor is offline/);
  assert.equal(health.layers.storage.statusEvent.code, "STORAGE_FAILED");
  assert.match(health.layers.storage.statusEvent.detail, /disk is full/);
  assert.equal(result.runProgress.status, "blocked");
});
