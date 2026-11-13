import assert from "node:assert/strict";
import { test, after, afterEach } from "node:test";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-network-test-"));
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
await writeFile(path.join(temporary, "proxyPool.mjs"), transpile(await readFile(new URL("../src/services/network/proxyPool.ts", import.meta.url), "utf8")));
const source = transpile(await readFile(new URL("../src/services/network/networkService.ts", import.meta.url), "utf8"))
  .replaceAll('"./proxyPool"', '"./proxyPool.mjs"')
  .replaceAll('"@tauri-apps/api/core"', JSON.stringify(import.meta.resolve("@tauri-apps/api/core")));
await writeFile(path.join(temporary, "networkService.mjs"), source);
const { modelFetch, proxyPool } = await import(pathToFileURL(path.join(temporary, "networkService.mjs")).href);
after(async () => { await rm(temporary, { recursive: true, force: true }); });
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
afterEach(() => {
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else delete globalThis.window;
});

function setup(t, invoke, mode = "failover") {
  Object.defineProperty(globalThis, "window", { value: { location: { href: "http://localhost/" }, __TAURI_INTERNALS__: { invoke, transformCallback: () => 1, unregisterCallback() {} } }, configurable: true });
  proxyPool.save({ nodes: ["first", "second"].map(id => ({ id, name: id, url: `http://${id}.invalid:8080`, username: "", password: "", enabled: true })), model: { mode, nodeId: "first" }, tools: { mode: "system", nodeId: "" } });
}
const headers = onEvent => { onEvent.onmessage({ kind: "started" }); onEvent.onmessage({ kind: "headers", status: 200, headers: {} }); };
const chunk = (onEvent, text) => onEvent.onmessage({ kind: "chunk", data: [...new TextEncoder().encode(text)] });

test("connection failover preserves the request and streams through the next node", async t => {
  const requests = [];
  setup(t, async (command, { request, onEvent }) => {
    assert.equal(command, "network_request"); requests.push(request);
    if (requests.length === 1) throw { code: "PROXY_CONNECT", message: "Connection refused", retryable: true };
    headers(onEvent); chunk(onEvent, "中文 observation"); onEvent.onmessage({ kind: "end" });
  });
  const response = await modelFetch("https://model.example.test/v1/chat/completions", { method: "POST", body: "synthetic-prompt", headers: { Authorization: "Bearer fixture" } });
  assert.equal(await response.text(), "中文 observation");
  assert.deepEqual(requests.map(request => request.route.url), ["http://first.invalid:8080", "http://second.invalid:8080"]);
  assert.deepEqual(requests.map(request => request.body), ["synthetic-prompt", "synthetic-prompt"]);
  assert.equal(proxyPool.getSnapshot().health.first.state, "failed");
  assert.equal(proxyPool.getSnapshot().health.second.state, "healthy");
});

test("HTTP model errors and failures after headers never replay the request", async t => {
  let requests = 0;
  setup(t, async (_, { onEvent }) => {
    requests++; onEvent.onmessage({ kind: "headers", status: 429, headers: {} });
    chunk(onEvent, "rate limited"); onEvent.onmessage({ kind: "end" });
  });
  const response = await modelFetch("https://model.example.test/", { method: "POST", body: "prompt" });
  assert.equal(response.status, 429); assert.equal(await response.text(), "rate limited"); assert.equal(requests, 1);
  setup(t, async (_, { onEvent }) => { requests++; headers(onEvent); chunk(onEvent, "partial"); throw { code: "NETWORK_FAILED", message: "Stream interrupted", retryable: true }; });
  const interrupted = await modelFetch("https://model.example.test/");
  await assert.rejects(interrupted.text(), /Stream interrupted/);
  assert.equal(requests, 2);
});

test("fixed nodes do not fail over on connection errors", async t => {
  let requests = 0;
  setup(t, async () => { requests++; throw { code: "PROXY_CONNECT", message: "Connection refused", retryable: true }; }, "fixed");
  await assert.rejects(modelFetch("https://model.example.test/"), { code: "PROXY_CONNECT" });
  assert.equal(requests, 1);
});

test("cancellation before native registration is reasserted and does not cool down the proxy", async t => {
  const controller = new AbortController();
  let acknowledge;
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  const cancellations = [];
  setup(t, async (command, args) => {
    if (command === "network_cancel") { cancellations.push(args.id); return; }
    acknowledge = () => args.onEvent.onmessage({ kind: "started" });
    ready();
  });
  const running = modelFetch("https://model.example.test/", { signal: controller.signal });
  const rejected = assert.rejects(running, { name: "AbortError" });
  await started; controller.abort(); await rejected;
  acknowledge(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancellations.length, 2);
  assert.equal(cancellations[0], cancellations[1]);
  assert.deepEqual(proxyPool.getSnapshot().health, {});
});

test("user deadlines and body cancellation stop native streams", async t => {
  const controller = new AbortController();
  const cancellations = [];
  setup(t, async (command, args) => {
    if (command === "network_cancel") { cancellations.push(args.id); return; }
    headers(args.onEvent); chunk(args.onEvent, "partial");
  });
  const response = await modelFetch("https://model.example.test/", { signal: controller.signal });
  controller.abort(new DOMException("Budget expired", "TimeoutError"));
  await assert.rejects(response.text(), { name: "TimeoutError" });
  const next = await modelFetch("https://model.example.test/");
  await next.body.cancel(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancellations.length, 2);
});

test("already stopped requests never reach the native service", async t => {
  setup(t, async () => assert.fail("Native request was dispatched"));
  await assert.rejects(modelFetch("https://model.example.test/", { signal: AbortSignal.abort() }), { name: "AbortError" });
});
