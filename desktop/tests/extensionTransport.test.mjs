import assert from "node:assert/strict";
import { after, afterEach, test } from "node:test";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-extension-transport-"));
const compile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
for (const name of ["health", "execution"]) {
  await writeFile(path.join(temporary, `${name}.mjs`), compile(await readFile(new URL(`../src/core/contracts/${name}.ts`, import.meta.url), "utf8")));
}
await writeFile(path.join(temporary, "network.mjs"), "export const proxyPool = { routes: () => [{mode:'system'}] }; export const nativeRoute = route => route; export const usesNativeNetwork = () => false;");
const bridge = compile(await readFile(new URL("../src/services/native/nativeBridge.ts", import.meta.url), "utf8"))
  .replaceAll('"../../core/contracts/health"', '"./health.mjs"')
  .replaceAll('"../../core/contracts/execution"', '"./execution.mjs"')
  .replaceAll('"../network/networkService"', '"./network.mjs"')
  .replaceAll('"@tauri-apps/api/core"', JSON.stringify(import.meta.resolve("@tauri-apps/api/core")));
await writeFile(path.join(temporary, "bridge.mjs"), bridge);
const { nativeBridge } = await import(pathToFileURL(path.join(temporary, "bridge.mjs")).href);
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
afterEach(() => { if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow); else delete globalThis.window; });
after(async () => { assert.ok(path.resolve(temporary).startsWith(path.resolve(tmpdir()) + path.sep)); await rm(temporary, { recursive: true, force: true }); });
function native(invoke) { Object.defineProperty(globalThis, "window", { value: { __TAURI_INTERNALS__: { invoke, transformCallback: () => 1, unregisterCallback() {} } }, configurable: true }); }

test("browser extension requests preserve Unicode, credentials and an omitted deadline", async t => {
  delete globalThis.window;
  const request = { operation: "configure", connection: { name: "本地工具", headers: { Authorization: "synthetic-secret" } } };
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, "/api/mcp");
    assert.deepEqual(JSON.parse(options.body), { request });
    return Response.json({ ok: true, connection: { id: "fixture" } });
  });
  assert.deepEqual(await nativeBridge.mcp(request), { ok: true, connection: { id: "fixture" } });
});

test("classified tool failure retains unknown outcome so callers cannot silently replay", async t => {
  delete globalThis.window;
  t.mock.method(globalThis, "fetch", async () => Response.json({ ok: false, error: { code: "connection-lost", message: "Response lost", outcome: "unknown" } }, { status: 400 }));
  await assert.rejects(nativeBridge.mcp({ operation: "call" }), { code: "connection-lost", message: "Response lost", outcome: "unknown" });
});

test("native commands receive the same JSON and only explicit budgets", async () => {
  const calls = [];
  native(async (command, args) => { calls.push({ command, args }); args.onStarted.onmessage({ kind: "started" }); return { entries: [] }; });
  await nativeBridge.extensions({ operation: "list" });
  await nativeBridge.mcp({ operation: "connect", connectionId: "fixture" }, { timeoutMs: 180000 });
  assert.equal(calls[0].command, "extensions_operation");
  assert.deepEqual(calls[0].args.request, { operation: "list" });
  assert.equal(calls[0].args.timeoutMs, undefined);
  assert.equal(calls[1].command, "mcp_operation");
  assert.equal(calls[1].args.timeoutMs, 180000);
});

test("cancellation before native registration is reasserted and waits for termination", async () => {
  const controller = new AbortController();
  let acknowledge, finish, markStarted;
  const started = new Promise(resolve => { markStarted = resolve; });
  const cancellations = [];
  native(async (command, args) => {
    if (command === "cancel_python_execution") { cancellations.push(args.executionId); return true; }
    acknowledge = () => args.onStarted.onmessage({ kind: "started" });
    markStarted(); return new Promise((_, reject) => { finish = reject; });
  });
  const result = nativeBridge.mcp({ operation: "connect" }, { signal: controller.signal });
  const rejected = assert.rejects(result, { name: "AbortError" });
  await started; controller.abort(); acknowledge();
  assert.equal(cancellations.length, 2);
  assert.equal(cancellations[0], cancellations[1]);
  finish("Operation cancelled"); await rejected;
});

test("pre-aborted extension operations never invoke the native process", async () => {
  native(async () => assert.fail("Request was dispatched"));
  await assert.rejects(nativeBridge.extensions({ operation: "install" }, { signal: AbortSignal.abort() }), { name: "AbortError" });
});
